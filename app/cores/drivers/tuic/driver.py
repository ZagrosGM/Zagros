"""TUICDriver — TUIC v5 (EAimTY/tuic) as a first-class panel core.

Reality of tuic-server (and how this driver deals with it):
  * The ONLY management surface is the JSON config file — there is no stats
    API, no admin socket, no hot-reload. Users live in ``users: {uuid: pass}``;
    changes are rendered and the server restarted (sub-second, QUIC).
  * Consequently this driver honestly does NOT claim USAGE_ACCOUNTING or
    ONLINE_TRACKING: the protocol exposes **no** per-user counters or session
    lists, and we will not fabricate them. The unified quota therefore treats
    TUIC traffic as unaccounted *and says so* (usage report notes), instead
    of pretending.
  * TLS is mandatory in TUIC — panel self-signed ECDSA cert by default,
    admin certs supported via settings.
  * Chain ingress: sing-box (and any core with a native tuic outbound) can
    tunnel INTO this server; a dedicated chain uuid is provisioned.

Upstream status note (honesty): the EAimTY/tuic repository was archived by
its author; the v5 protocol remains widely implemented in clients
(sing-box, ClashMeta forks, NekoBox). The driver pins a known release and
surfaces the archive status in its description — operators make an
informed choice.
"""
from __future__ import annotations

import asyncio
import json
import uuid as uuid_mod
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from app.cores.base import BaseCoreDriver
from app.cores.exceptions import CoreError
from app.cores.types import (
    Capability,
    ChainEndpoint,
    ClientConfig,
    CoreMetadata,
    CoreState,
    CoreStatus,
    HealthStatus,
    UserAccount,
)


class TUICDriver(BaseCoreDriver):
    """Driver for tuic-server (TUIC protocol v5)."""

    metadata: ClassVar[CoreMetadata] = CoreMetadata(
        id="tuic",
        name="TUIC v5",
        description=(
            "TUIC v5 QUIC tunnel (tuic-server). Config-render + restart; no "
            "stats API exists in the protocol, so usage/online are honestly "
            "unaccounted. Chain ingress via native tuic outbounds. "
            "NOTE: upstream repo (EAimTY/tuic) is archived — pin accordingly."
        ),
        protocols=["tuic"],
        capabilities={
            Capability.USER_MANAGEMENT,
            Capability.SUSPEND_RESUME,
            Capability.SERVICE_CONTROL,
            Capability.SELF_INSTALL,
            Capability.CLIENT_CONFIG,
            Capability.UDP_SUPPORT,
            Capability.CHAIN_ROUTING,
        },
        config_schema={
            "type": "object",
            "properties": {
                "executable_path": {"type": "string"},
                "work_dir": {"type": "string"},
                "listen": {"type": "string", "default": "[::]",
                           "description": "wildcard '[::]' recommended — tuic-server <=1.0.0 "
                                          "aborts on explicit IPv4 binds (dual-stack "
                                          "setsockopt, os error 92; verified live)"},
                "port": {"type": "integer", "default": 8443},
                "congestion_control": {"type": "string",
                                       "enum": ["cubic", "new_reno", "bbr"]},
                "udp_relay_ipv6": {"type": "boolean", "default": True},
                "zero_rtt_handshake": {"type": "boolean", "default": False},
                "cert_path": {"type": "string"},
                "key_path": {"type": "string"},
                "cert_common_name": {"type": "string", "default": "cdn.cloudflare.com"},
                "advertise_host": {"type": "string"},
                "advertise_sni": {"type": "string"},
                "log_level": {"type": "string", "default": "warn"},
                "release_repo": {"type": "string", "default": "EAimTY/tuic"},
                "release_version": {"type": "string", "default": "tuic-server-1.0.0"},
            },
        },
        default_settings={
            "executable_path": "tuic-server",
            "work_dir": "/var/lib/zagros/cores/tuic",
            "listen": "[::]",
            "port": 8443,
            "congestion_control": "bbr",
            "udp_relay_ipv6": True,
            "zero_rtt_handshake": False,
            "cert_path": "",
            "key_path": "",
            "cert_common_name": "cdn.cloudflare.com",
            "advertise_host": "127.0.0.1",
            "advertise_sni": "",
            "log_level": "warn",
            "release_repo": "EAimTY/tuic",
            "release_version": "tuic-server-1.0.0",
        },
        homepage="https://github.com/EAimTY/tuic",
        provides=set(),
        requires=set(),
    )

    def __init__(self, settings: dict[str, Any] | None = None, *, backend: Any | None = None):
        super().__init__(settings)
        if backend is None:
            from app.cores.drivers.tuic.backend import LocalTUICBackend

            backend = LocalTUICBackend(self.settings)
        self._backend = backend
        self._accounts: dict[str, UserAccount] = {}
        self._chain_users: dict[str, tuple[str, str]] = {}   # name → (uuid, password)
        self._bootstrap: tuple[str, str] | None = None
        self._cert: tuple[str, str] | None = None

    # ------------------------------------------------------------------ #
    # config rendering + publishing
    # ------------------------------------------------------------------ #
    def _bootstrap_credentials(self) -> tuple[str, str]:
        if self._bootstrap is None:
            import os

            path = os.path.join(self.settings["work_dir"], ".bootstrap-secret")
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            if os.path.exists(path):
                with open(path, encoding="utf-8") as fh:
                    uuid_, _, password = fh.read().strip().partition(":")
                    self._bootstrap = (uuid_, password)
            else:
                self._bootstrap = (str(uuid_mod.uuid4()), uuid_mod.uuid4().hex)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(f"{self._bootstrap[0]}:{self._bootstrap[1]}\n")
        return self._bootstrap

    def _users_map(self) -> dict[str, str]:
        users: dict[str, str] = {}
        for account in sorted(self._accounts.values(), key=lambda a: a.account_id):
            if account.enabled and account.settings.get("uuid"):
                users[str(account.settings["uuid"])] = str(account.settings["password"])
        for uuid_, password in (self._chain_users.values()):
            users[uuid_] = password
        if not users:
            # tuic-server refuses an empty users map (verified live:
            # "users cannot be empty at line 3 column 14"). Boot fresh with a
            # closed random bootstrap uuid — replaced by real accounts later;
            # persisted (0600) so restarts stay deterministic.
            uuid_, password = self._bootstrap_credentials()
            users[uuid_] = password
        return users

    def render_config(self) -> dict[str, Any]:
        cert, key = self._cert or ("", "")
        if self.settings.get("cert_path") and self.settings.get("key_path"):
            cert, key = self.settings["cert_path"], self.settings["key_path"]
        s = self.settings
        return {
            "server": f"{s['listen']}:{int(s['port'])}",
            "users": self._users_map(),
            "certificate": cert,
            "private_key": key,
            "congestion_control": s["congestion_control"],
            "alpn": ["h3", "spdy/3.1"],
            "udp_relay_ipv6": bool(s["udp_relay_ipv6"]),
            "zero_rtt_handshake": bool(s["zero_rtt_handshake"]),
            # dual-stack only makes sense on a wildcard/IPv6 listen address:
            # with an explicit IPv4 bind the real binary aborts with
            # "endpoint dual-stack socket setting error (os error 92)".
            "dual_stack": s["listen"] in ("[::]", "::", ""),
            "auth_timeout": "3s",
            "task_negotiation_timeout": "3s",
            "max_idle_time": "10s",
            "max_external_packet_size": 1500,
            "gc_interval": "3s",
            "gc_lifetime": "15s",
            "log_level": s["log_level"],
        }

    async def _publish(self) -> None:
        await asyncio.to_thread(self._backend.apply_config, self.render_config())
        if await asyncio.to_thread(self._backend.is_running):
            await asyncio.to_thread(self._backend.restart)

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        if self.settings.get("cert_path") and self.settings.get("key_path"):
            self._cert = (self.settings["cert_path"], self.settings["key_path"])
        else:
            self._cert = await asyncio.to_thread(
                self._backend.ensure_tls, self.settings["cert_common_name"]
            )
        await asyncio.to_thread(self._backend.apply_config, self.render_config())
        await asyncio.to_thread(self._backend.start)

    async def stop(self) -> None:
        await asyncio.to_thread(self._backend.stop)

    async def status(self) -> CoreStatus:
        running = await asyncio.to_thread(self._backend.is_running)
        return CoreStatus(
            core_id=self.metadata.id,
            state=CoreState.RUNNING if running else CoreState.STOPPED,
            health=HealthStatus.HEALTHY if running else HealthStatus.UNKNOWN,
            core_version=await asyncio.to_thread(self._backend.version),
            metrics=await asyncio.to_thread(self._backend.metrics) if running else None,
        )

    async def get_logs(self, tail: int = 200) -> AsyncIterator[str]:
        for line in await asyncio.to_thread(self._backend.logs, tail):
            yield line

    async def install(self) -> None:
        await asyncio.to_thread(self._backend.install_binary)

    async def uninstall(self, purge: bool = False) -> None:
        await self.stop()

    # ------------------------------------------------------------------ #
    # user management
    # ------------------------------------------------------------------ #
    def _ensure_supported(self, protocol: str) -> None:
        if protocol != "tuic":
            raise CoreError(f"TUIC core only serves protocol 'tuic', got '{protocol}'.")

    async def _provision_credentials(self, account: UserAccount) -> None:
        if not account.settings.get("uuid"):
            account.settings["uuid"] = str(uuid_mod.uuid4())
        if not account.settings.get("password"):
            account.settings["password"] = uuid_mod.uuid4().hex[:16]

    async def create_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        await self._provision_credentials(account)
        self._accounts[account.account_id] = account
        await self._publish()

    async def update_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        await self._provision_credentials(account)
        self._accounts[account.account_id] = account
        await self._publish()

    async def delete_account(self, account_id: str) -> None:
        self._accounts.pop(account_id, None)
        await self._publish()

    async def suspend_account(self, account_id: str) -> None:
        existing = self._accounts.get(account_id)
        if existing is not None:
            self._accounts[account_id] = existing.model_copy(update={"enabled": False})
            await self._publish()

    async def resume_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._accounts[account.account_id] = account.model_copy(update={"enabled": True})
        await self._publish()

    async def sync_accounts(self, accounts: list[UserAccount]) -> None:
        for account in accounts:
            self._ensure_supported(account.protocol)
            await self._provision_credentials(account)
        self._accounts = {a.account_id: a for a in accounts}
        await self._publish()

    # ------------------------------------------------------------------ #
    # client config (sealed delivery only)
    # ------------------------------------------------------------------ #
    async def build_client_config(
        self, account: UserAccount, node: Any | None = None
    ) -> ClientConfig:
        self._ensure_supported(account.protocol)
        creds = account.settings
        for key in ("uuid", "password"):
            if not creds.get(key):
                raise CoreError(f"tuic account '{account.account_id}' is missing '{key}'.")
        s = self.settings
        own_cert = not (s.get("cert_path") and s.get("key_path"))
        import urllib.parse

        query = urllib.parse.urlencode({
            "congestion_control": s["congestion_control"],
            "alpn": "h3,spdy/3.1",
            "udp_relay_mode": "native",
            "sni": s["advertise_sni"] or s["cert_common_name"],
            **({"allow_insecure": "1"} if own_cert else {}),
        })
        url = (f"tuic://{creds['uuid']}:{urllib.parse.quote(str(creds['password']), safe='')}"
               f"@{s['advertise_host']}:{int(s['port'])}/?{query}"
               f"#{urllib.parse.quote('TUIC · ' + account.username)}")
        return ClientConfig(
            core_id=self.metadata.id,
            protocol="tuic",
            engine="tuic",
            payload={"format": "share-url", "url": url},
            display_name="TUIC v5",
        )

    # ------------------------------------------------------------------ #
    # chain ingress — real tuic upstream for sing-box outbounds
    # ------------------------------------------------------------------ #
    async def get_chain_endpoints(self) -> list[ChainEndpoint]:
        if "_zg-chain" not in self._chain_users:
            return []
        return [self._chain_endpoint()]

    async def ensure_chain_listener(self, protocol: str, port: int) -> ChainEndpoint:
        if protocol != "tuic":
            raise CoreError(
                f"TUIC cannot host a '{protocol}' chain endpoint — chains into "
                f"this core use the native tuic outbound."
            )
        if "_zg-chain" not in self._chain_users:
            self._chain_users["_zg-chain"] = (str(uuid_mod.uuid4()), uuid_mod.uuid4().hex[:16])
            await self._publish()
        return self._chain_endpoint()

    def _chain_endpoint(self) -> ChainEndpoint:
        s = self.settings
        uuid_, password = self._chain_users["_zg-chain"]
        return ChainEndpoint(
            core_id=self.metadata.id,
            protocol="tuic",
            host=s["advertise_host"],
            port=int(s["port"]),
            network="udp",
            requires_credentials=True,
            metadata={
                "uuid": uuid_,
                "password": password,
                "sni": s["advertise_sni"] or s["cert_common_name"],
                "insecure": not (s.get("cert_path") and s.get("key_path")),
                "congestion_control": s["congestion_control"],
            },
        )


_AS_JSON_MARK = True  # module marker: config renders as JSON (trivia guard for tests)


def _json_dumps_compact(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=False)
