"""Real socket integration tests for the dedicated subscription listener."""
from __future__ import annotations

import asyncio
import socket
import urllib.error
import urllib.request

import pytest
from fastapi import FastAPI

from app.platform.subscription_listener import SubscriptionListenerManager
from app.portal.models import PortalSettings


class _CoreManager:
    def list_cores(self): return []


class _Runtime:
    core_manager = _CoreManager()
    database_url = "sqlite:////tmp/zagros-sub-listener-test.db"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_dedicated_listener_serves_subscription_path_but_not_admin_surface() -> None:
    async def run() -> None:
        app = FastAPI()

        @app.get("/clients/{token}")
        async def subscription(token: str):
            return {"token": token}

        @app.get("/api/private")
        async def private():
            return {"secret": True}

        port = _free_port()
        settings = PortalSettings(
            public_domain="sub.example.test", public_scheme="http",
            public_port=port, listener_mode="dedicated",
            listen_address="127.0.0.1", subscription_path="clients",
        )
        manager = SubscriptionListenerManager()
        try:
            status = await manager.apply(settings, _Runtime(), app)
            assert status["running"] is True and status["port"] == port
            body = await asyncio.to_thread(
                lambda: urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/clients/token-1", timeout=3).read())
            assert b"token-1" in body
            with pytest.raises(urllib.error.HTTPError) as exc:
                await asyncio.to_thread(
                    lambda: urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/api/private", timeout=3))
            assert exc.value.code == 404
        finally:
            await manager.stop()
        # Teardown is symmetric; no listener survives the integration test.
        with pytest.raises(OSError):
            await asyncio.to_thread(
                lambda: socket.create_connection(("127.0.0.1", port), timeout=0.2))

    asyncio.run(run())


def test_dedicated_listener_port_conflict_fails_before_start() -> None:
    async def run() -> None:
        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0)); blocker.listen()
        port = int(blocker.getsockname()[1])
        manager = SubscriptionListenerManager()
        app = FastAPI()
        settings = PortalSettings(
            public_domain="sub.example.test", public_scheme="http",
            public_port=port, listener_mode="dedicated",
            listen_address="127.0.0.1",
        )
        try:
            with pytest.raises(RuntimeError, match="already owned"):
                await manager.apply(settings, _Runtime(), app)
            assert manager.running is False
        finally:
            blocker.close()
            await manager.stop()

    asyncio.run(run())
