"""Lifecycle manager for an optional dedicated subscription HTTP/TLS listener.

The listener shares the already-built FastAPI application and PlatformRuntime,
but runs with lifespan disabled so schedulers/cores are never started twice.
An ASGI path gate exposes subscription routes only: the admin dashboard and
admin API cannot be reached through the public subscription port.
"""
from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any

import uvicorn

from app.platform.network_settings import PanelNetworkSettings, detect_port_conflicts
from app.portal.models import PortalSettings

logger = logging.getLogger("zagros.subscription.listener")


class SubscriptionOnlyASGI:
    def __init__(self, app) -> None:
        self.app = app

    @staticmethod
    def _allowed(path: str) -> bool:
        if path.startswith("/sub/") or path.startswith("/zagros/"):
            return True
        # Configurable canonical path: /<one/or/more/segments>/<token>.
        # Validation inside the shared router still checks the exact persisted
        # path; this guard only keeps admin/static surfaces off this listener.
        parts = [part for part in path.split("/") if part]
        return len(parts) >= 2 and parts[0] not in {
            "api", "dashboard", "docs", "redoc", "openapi", "openapi.json",
            "client", "statics", "favicon", "health",
        }

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http" and not self._allowed(scope.get("path", "")):
            await send({
                "type": "http.response.start", "status": 404,
                "headers": [(b"content-type", b"text/plain; charset=utf-8"),
                            (b"cache-control", b"no-store")],
            })
            await send({"type": "http.response.body", "body": b"not found"})
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 4404})
            return
        await self.app(scope, receive, send)


class SubscriptionListenerManager:
    def __init__(self) -> None:
        self._app = None
        self._server: uvicorn.Server | None = None
        self._task: asyncio.Task | None = None
        self._settings: PortalSettings | None = None
        self._lock = asyncio.Lock()

    @property
    def running(self) -> bool:
        return bool(self._server and self._server.started
                    and self._task and not self._task.done())

    def public_status(self) -> dict[str, Any]:
        settings = self._settings
        return {
            "running": self.running,
            "mode": settings.listener_mode if settings else "shared",
            "listen_address": settings.listen_address if settings else None,
            "port": settings.public_port if settings else None,
            "scheme": settings.public_scheme if settings else None,
        }

    @staticmethod
    def _data_dir(runtime) -> str:
        url = runtime.database_url
        if url.startswith("sqlite:///"):
            return str(Path(url[10:]).parent)
        return "/var/lib/zagros"

    @classmethod
    def _tls_files(cls, runtime, settings: PortalSettings) -> tuple[str | None, str | None]:
        if settings.public_scheme != "https":
            return None, None
        from app.platform import certificates

        ident = str(settings.tls_certificate_id or "")
        item = next((entry for entry in certificates.scan(
            cls._data_dir(runtime), managed_only=True)
            if entry.id == ident or entry.name == ident), None)
        if item is None:
            raise ValueError(f"TLS certificate '{ident}' does not exist")
        cert = Path(item.path)
        candidates = (cert.parent / "key.pem", cert.with_suffix(".key"))
        key = next((candidate for candidate in candidates if candidate.is_file()), None)
        if key is None:
            raise ValueError(f"TLS certificate '{ident}' has no private key")
        return str(cert), str(key)

    async def _preflight(self, runtime, settings: PortalSettings) -> None:
        panel_shape = PanelNetworkSettings(
            domain=settings.public_domain,
            port=int(settings.public_port or 0),
            scheme=settings.public_scheme,
            bind_address=settings.listen_address,
            tls_certificate_id=settings.tls_certificate_id,
        )
        # ``/settings/portal/test`` preflights the currently running desired
        # state too.  Exempt only this manager's live same-socket listener;
        # initial starts and changed sockets must still fail closed on every
        # kernel listener, including another Python process.
        current_listener_port = -1
        if (self.running and self._settings is not None
                and self._settings.listen_address == settings.listen_address
                and self._settings.public_port == settings.public_port):
            current_listener_port = int(settings.public_port)
        conflicts = await detect_port_conflicts(
            runtime, panel_shape, current_panel_port=current_listener_port)
        if conflicts:
            raise RuntimeError(conflicts[0].message())

    async def _start(self, runtime, app, settings: PortalSettings) -> tuple[uvicorn.Server, asyncio.Task]:
        await self._preflight(runtime, settings)
        cert, key = self._tls_files(runtime, settings)
        config = uvicorn.Config(
            SubscriptionOnlyASGI(app),
            host=settings.listen_address,
            port=int(settings.public_port),
            ssl_certfile=cert,
            ssl_keyfile=key,
            lifespan="off",
            access_log=False,
            log_level="warning",
        )
        server = uvicorn.Server(config)
        task = asyncio.create_task(server.serve(),
                                   name="zagros-dedicated-subscription-listener")
        deadline = asyncio.get_running_loop().time() + 12.0
        while asyncio.get_running_loop().time() < deadline:
            if server.started:
                return server, task
            if task.done():
                error = task.exception()
                raise RuntimeError(
                    f"dedicated subscription listener failed to start: {error or 'bind failed'}")
            await asyncio.sleep(0.05)
        server.should_exit = True
        await asyncio.gather(task, return_exceptions=True)
        raise RuntimeError("dedicated subscription listener start timed out")

    @staticmethod
    async def _stop_pair(server: uvicorn.Server | None,
                         task: asyncio.Task | None) -> None:
        if server is None or task is None:
            return
        server.should_exit = True
        try:
            await asyncio.wait_for(task, timeout=10)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def apply(self, settings: PortalSettings, runtime, app=None) -> dict[str, Any]:
        """Transactionally converge the optional listener to ``settings``."""
        settings = settings.normalize()
        if app is not None:
            self._app = app
        if self._app is None:
            raise RuntimeError("subscription listener has no ASGI application")
        async with self._lock:
            if settings.listener_mode != "dedicated":
                await self._stop_pair(self._server, self._task)
                self._server = None; self._task = None; self._settings = settings
                return self.public_status()

            if (self.running and self._settings is not None
                    and self._settings.model_dump(mode="json")
                    == settings.model_dump(mode="json")):
                return self.public_status()

            old_server, old_task, old_settings = (
                self._server, self._task, self._settings)
            same_socket = bool(
                self.running and old_settings
                and old_settings.listen_address == settings.listen_address
                and old_settings.public_port == settings.public_port)
            if same_socket:
                await self._stop_pair(old_server, old_task)
                self._server = None; self._task = None
            try:
                new_server, new_task = await self._start(
                    runtime, self._app, settings)
            except Exception:
                # Same-port TLS/config replacement needs a short gap; restore
                # the exact previous listener if the candidate failed.
                if same_socket and old_settings is not None:
                    try:
                        self._server, self._task = await self._start(
                            runtime, self._app, old_settings)
                        self._settings = old_settings
                    except Exception as rollback_exc:  # noqa: BLE001
                        logger.critical(
                            "subscription listener rollback failed: %s", rollback_exc)
                raise
            if not same_socket:
                await self._stop_pair(old_server, old_task)
            self._server, self._task, self._settings = (
                new_server, new_task, settings)
            return self.public_status()

    async def stop(self) -> None:
        async with self._lock:
            await self._stop_pair(self._server, self._task)
            self._server = None; self._task = None
