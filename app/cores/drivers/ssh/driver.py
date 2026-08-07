"""SSHTunnelDriver — OpenSSH (system sshd) as a first-class panel core.

Real capabilities used:
  * **User management** = real unix accounts (panel-namespaced ``zg-*``),
    created/locked/deleted with the standard tools (useradd/usermod/userdel
    + chpasswd). Locking applies instantly — no sshd restart (HOT_RELOAD).
  * **Suspend** = ``usermod --lock`` + killing the user's sshd session
    processes (``pkill`` on sshd children of that uid) — immediate cut.
  * **Online detection** = sshd session processes from ``ps`` (``sshd:
    user@notty`` = tunnel, ``sshd: user@pts/N`` = interactive).
  * **Chain ingress**: cores with a native ssh outbound (Xray ≥ 1.8.x has
    one) can tunnel INTO this server with a dedicated chain account.

Honestly NOT claimed (documented, no simulation):
  * USAGE_ACCOUNTING — mainstream per-user byte accounting does not exist
    for sshd (iptables owner-match counts egress only and wrong-direction;
    conntrack knows no users). Rather than report wrong halves, SSH traffic
    is reported as *unaccounted* in unified quota notes.
  * SERVICE_CONTROL — sshd belongs to systemd; the driver manages accounts,
    not the daemon (status still reports sshd liveness, honestly).
  * DEVICE_DETECTION — sshd logs carry no client platform/version.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from app.cores.base import BaseCoreDriver
from app.cores.drivers.ssh.sshtool import sanitize_username
from app.cores.exceptions import CoreError
from app.cores.types import (
    Capability,
    ChainEndpoint,
    ClientConfig,
    CoreMetadata,
    CoreState,
    CoreStatus,
    DeviceSession,
    HealthStatus,
    UserAccount,
)

logger = logging.getLogger("zagros.cores.drivers.ssh")


class SSHTunnelDriver(BaseCoreDriver):
    """Driver for OpenSSH-based tunneling with real system accounts."""

    metadata: ClassVar[CoreMetadata] = CoreMetadata(
        id="ssh",
        name="SSH Tunnel",
        description=(
            "OpenSSH port-forwarding/SOCKS tunnelling with real unix accounts. "
            "Instant lock/unlock suspend, ps-based online detection, native "
            "ssh-outbound chain ingress (xray). Usage is honestly unaccounted."
        ),
        protocols=["ssh"],
        capabilities={
            Capability.USER_MANAGEMENT,
            Capability.SUSPEND_RESUME,
            Capability.ONLINE_TRACKING,
            Capability.HOT_RELOAD,
            Capability.SELF_INSTALL,
            Capability.CLIENT_CONFIG,
            Capability.CHAIN_ROUTING,
        },
        config_schema={
            "type": "object",
            "properties": {
                "shell": {"type": "string", "default": "/bin/bash"},
                "create_home": {"type": "boolean", "default": False},
                "port": {"type": "integer", "default": 2022},
                "advertise_host": {"type": "string"},
                "password_auth": {"type": "boolean", "default": True},
                "pubkey_auth": {"type": "boolean", "default": True},
                "max_sessions": {"type": "integer", "default": 10},
                "banner": {"type": "string"},
                "sftp": {"type": "boolean", "default": True},
                "default_password": {"type": "string",
                                     "description": "fallback account password when a "
                                                    "provisioned user has none set"},
                "default_authorized_key": {"type": "string",
                                           "description": "public key installed for every "
                                                          "tunnel account (panel-owned "
                                                          "authorized_keys)"},
            },
        },
        default_settings={
            "shell": "/bin/bash",
            "create_home": False,
            "port": 2022,
            "advertise_host": "127.0.0.1",
            "password_auth": True,
            "pubkey_auth": True,
            "max_sessions": 10,
            "sftp": True,
            "default_password": "",
            "default_authorized_key": "",
        },
        homepage="https://www.openssh.com/",
        provides=set(),
        requires=set(),
        # sshd binds ONE listener set per daemon — the studio manages it as
        # a single-entry inbound (drop-in rewrite + reload per apply).
        studio_inbounds_path="/inbounds",
        studio_max_inbounds=1,
    )

    def __init__(self, settings: dict[str, Any] | None = None, *, backend: Any | None = None):
        super().__init__(settings)
        if backend is None:
            from app.cores.drivers.ssh.backend import LocalSystemSSHBackend

            backend = LocalSystemSSHBackend(self.settings)
        self._backend = backend
        self._accounts: dict[str, UserAccount] = {}
        self._chain_users: dict[str, tuple[str, str]] = {}

    # ------------------------------------------------------------------ #
    # lifecycle — sshd is owned by systemd; we check, not control
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        # Full bring-up, not just an error: install openssh-server if absent,
        # generate host keys, write the panel-owned drop-in (port 22 always
        # preserved), validate, enable+start (reload when already live), and
        # verify the daemon actually answers.
        how = await asyncio.to_thread(self._backend.ensure_service)
        logger.info("ssh core ready — sshd brought up via %s", how)

    async def stop(self) -> None:
        # intentional no-op: stopping the host's ssh service is out of scope
        # for a panel core (and dangerous); accounts remain provisioned.
        pass

    async def status(self) -> CoreStatus:
        running = await asyncio.to_thread(self._backend.sshd_running)
        sessions = await self.get_online_devices() if running else []
        metrics = None
        if running:
            from app.cores.types import CoreMetrics

            metrics = CoreMetrics(active_accounts=len(self._accounts),
                                  active_sessions=len(sessions))
        return CoreStatus(
            core_id=self.metadata.id,
            state=CoreState.RUNNING if running else CoreState.STOPPED,
            health=HealthStatus.HEALTHY if running else HealthStatus.UNHEALTHY,
            metrics=metrics,
            message=None if running else "sshd is not running (system service).",
        )

    async def get_logs(self, tail: int = 200) -> AsyncIterator[str]:
        for line in await asyncio.to_thread(self._backend.logs, tail):
            yield line

    async def install(self) -> None:
        await asyncio.to_thread(self._backend.install_packages)

    async def uninstall(self, purge: bool = False) -> None:
        # remove every panel-managed account (purge=True), else leave them
        if purge:
            for account_id in list(self._accounts):
                await self.delete_account(account_id)

    # ------------------------------------------------------------------ #
    # Config Studio bridge (sshd single listener — drop-in rewrite + reload)
    # ------------------------------------------------------------------ #
    def export_config_document(self) -> dict[str, Any]:
        """Studio seed: the sshd listener modelled as a one-entry inbound
        (pure settings read — the wizard rewrites exactly these levers)."""
        s = self.settings
        password_auth = bool(s.get("password_auth", True))
        pubkey_auth = bool(s.get("pubkey_auth", True))
        return {
            "inbounds": [{
                "tag": "ssh",
                "protocol": "ssh",
                "listen": "0.0.0.0",
                "port": int(s.get("port") or 2022),
                "authentication": ("both" if password_auth and pubkey_auth
                                   else "password" if password_auth else "publickey"),
                "password": "",
                "public_key": "",
                "shell": s.get("shell") or "/bin/bash",
                "sftp": bool(s.get("sftp", True)),
                "max_sessions": int(s.get("max_sessions") or 10),
                "banner": "",
                "has_default_password": bool(s.get("default_password")),
                "has_default_key": bool(s.get("default_authorized_key")),
                "has_banner": bool(s.get("banner")),
            }],
        }

    async def apply_studio_document(self, document: dict[str, Any]) -> None:
        """Adopt the studio document's single entry as THE sshd config:
        settings updated → drop-in rewritten → sshd validated+reloaded
        (non-disruptive when already running — port 22 is never removed)."""
        inbounds = (document or {}).get("inbounds") or []
        if len(inbounds) != 1:
            raise CoreError(
                f"sshd serves ONE listener set; the studio document carries "
                f"{len(inbounds)} inbounds — keep exactly one."
            )
        ib = inbounds[0]
        if str(ib.get("protocol") or "ssh") != "ssh":
            raise CoreError(f"an ssh core cannot host a '{ib.get('protocol')}' listener.")
        s = self.settings
        if ib.get("port") is not None:
            port = int(ib["port"])
            if not 1 <= port <= 65535:
                raise CoreError(f"ssh port out of range: {port}")
            s["port"] = port
        authentication = str(ib.get("authentication") or "").lower()
        if authentication in ("password", "publickey", "both"):
            s["password_auth"] = authentication in ("password", "both")
            s["pubkey_auth"] = authentication in ("publickey", "both")
        if not s["password_auth"] and not s["pubkey_auth"]:
            raise CoreError(
                "refusing an sshd with BOTH password AND public-key auth off — "
                "nobody (including you) could ever log in."
            )
        if ib.get("shell"):
            s["shell"] = str(ib["shell"])
        if ib.get("sftp") is not None:
            s["sftp"] = bool(ib["sftp"])
        if ib.get("max_sessions") is not None:
            s["max_sessions"] = int(ib["max_sessions"])
        if str(ib.get("password") or ""):
            s["default_password"] = str(ib["password"])
        if str(ib.get("banner") or ""):
            s["banner"] = str(ib["banner"])
        if str(ib.get("public_key") or ""):
            s["default_authorized_key"] = str(ib["public_key"])
            # install for accounts that already exist as well
            for account in list(self._accounts.values()):
                name = self._unix_name(account)
                if await asyncio.to_thread(self._backend.user_exists, name):
                    await asyncio.to_thread(
                        self._backend.authorize_key, name, s["default_authorized_key"]
                    )
        # push through the same validated path the Start button uses
        how = await asyncio.to_thread(self._backend.ensure_service)
        logger.info("ssh: studio document applied — sshd via %s", how)

    # ------------------------------------------------------------------ #
    # user management — real unix accounts
    # ------------------------------------------------------------------ #
    def _ensure_supported(self, protocol: str) -> None:
        if protocol != "ssh":
            raise CoreError(f"SSH core only serves protocol 'ssh', got '{protocol}'.")

    def _unix_name(self, account: UserAccount) -> str:
        try:
            return sanitize_username(account.account_id)
        except ValueError as exc:
            raise CoreError(str(exc)) from exc

    def _ensure_credentials(self, account: UserAccount) -> None:
        if not account.settings.get("password") and not self.settings.get("default_password"):
            raise CoreError(f"SSH account '{account.account_id}' needs settings.password.")

    def _account_password(self, account: UserAccount) -> str:
        """Explicit account password wins; the studio-set DEFAULT password
        (the wizard's Password field) is the fallback for accounts that carry
        none."""
        return str(account.settings.get("password")
                   or self.settings.get("default_password") or "")

    async def create_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._ensure_credentials(account)
        password = self._account_password(account)
        name = self._unix_name(account)
        if not await asyncio.to_thread(self._backend.user_exists, name):
            await asyncio.to_thread(
                self._backend.create_user, name, password,
                self.settings["shell"], bool(self.settings["create_home"]),
            )
        elif account.enabled:
            await asyncio.to_thread(
                self._backend.set_password, name, password
            )
        # panel-level default public key (the SSH wizard's Public Key field):
        # installed for every tunnel account, panel-owned AuthorizedKeysFile
        default_key = str(self.settings.get("default_authorized_key") or "").strip()
        if default_key and self.settings.get("pubkey_auth", True):
            await asyncio.to_thread(self._backend.authorize_key, name, default_key)
        self._accounts[account.account_id] = account
        if account.enabled:
            await asyncio.to_thread(self._backend.unlock_user, name)
        else:
            await self._lock_and_kill(name)

    async def update_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._ensure_credentials(account)
        previous = self._accounts.get(account.account_id)
        name = self._unix_name(account)
        if previous is None:
            await self.create_account(account)
            return
        if previous.settings.get("password") != account.settings.get("password"):
            await asyncio.to_thread(
                self._backend.set_password, name, self._account_password(account)
            )
            await self._kill_sessions(name)  # force re-auth
        self._accounts[account.account_id] = account
        if not account.enabled:
            await self._lock_and_kill(name)
        else:
            await asyncio.to_thread(self._backend.unlock_user, name)

    async def delete_account(self, account_id: str) -> None:
        account = self._accounts.pop(account_id, None)
        if account is None:
            # still try: the unix account may exist from a previous panel life
            try:
                name = sanitize_username(account_id)
            except ValueError:
                return
        else:
            name = self._unix_name(account)
        await self._lock_and_kill(name)
        await asyncio.to_thread(self._backend.delete_user, name)

    async def suspend_account(self, account_id: str) -> None:
        existing = self._accounts.get(account_id)
        if existing is not None:
            self._accounts[account_id] = existing.model_copy(update={"enabled": False})
            await self._lock_and_kill(self._unix_name(existing))

    async def resume_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._accounts[account.account_id] = account.model_copy(update={"enabled": True})
        await asyncio.to_thread(self._backend.unlock_user, self._unix_name(account))

    async def sync_accounts(self, accounts: list[UserAccount]) -> None:
        # reconcile: (re)create desired accounts; delete panel accounts that
        # are no longer desired (only zg-* names are ever touched)
        desired = {a.account_id for a in accounts if a.settings.get("password")}
        for account in accounts:
            if account.account_id in desired:
                await self.create_account(account)
        for stale in set(self._accounts) - desired:
            await self.delete_account(stale)

    async def _lock_and_kill(self, name: str) -> None:
        await asyncio.to_thread(self._backend.lock_user, name)
        await self._kill_sessions(name)

    async def _kill_sessions(self, name: str) -> None:
        await asyncio.to_thread(self._backend.kill_sessions, name)

    # ------------------------------------------------------------------ #
    # statistics — online sessions only (usage honestly unsupported)
    # ------------------------------------------------------------------ #
    async def get_online_devices(
        self, account_ids: list[str] | None = None
    ) -> list[DeviceSession]:
        sessions = await asyncio.to_thread(self._backend.sessions)
        by_unix = {sanitize_username(a): a for a in self._accounts}
        if self._chain_users:
            by_unix.update({name: name for name, _pw in self._chain_users.values()})
        out: list[DeviceSession] = []
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        for session in sessions:
            account_id = by_unix.get(session.user)
            if account_id is None:
                continue
            if account_ids is not None and account_id not in account_ids:
                continue
            out.append(DeviceSession(
                core_id=self.metadata.id,
                account_id=account_id,
                ip=None,  # sshd session rows carry no client IP (honest)
                connected_at=now - timedelta(seconds=session.elapsed_seconds),
                metadata={
                    "pid": session.pid,
                    "terminal": session.terminal,   # "notty" = port-forward tunnel
                    "session_kind": "tunnel" if session.terminal == "notty" else "interactive",
                },
            ))
        return out

    # ------------------------------------------------------------------ #
    # client config (sealed delivery only)
    # ------------------------------------------------------------------ #
    async def build_client_config(
        self, account: UserAccount, node: Any | None = None
    ) -> ClientConfig:
        self._ensure_supported(account.protocol)
        self._ensure_credentials(account)
        s = self.settings
        return ClientConfig(
            core_id=self.metadata.id,
            protocol="ssh",
            engine="ssh",
            payload={
                "format": "ssh",
                "host": s["advertise_host"],
                "port": int(s["port"]),
                "username": self._unix_name(account),
                "password": str(account.settings["password"]),
                "hint": "ssh -D 1080 (SOCKS) or ssh -L/-R port forwards",
            },
            display_name="SSH Tunnel",
        )

    # ------------------------------------------------------------------ #
    # chain ingress — native ssh outbounds (xray ssh outbound)
    # ------------------------------------------------------------------ #
    async def get_chain_endpoints(self) -> list[ChainEndpoint]:
        if "_zg-chain" not in self._chain_users:
            return []
        return [self._chain_endpoint()]

    async def ensure_chain_listener(self, protocol: str, port: int) -> ChainEndpoint:
        if protocol != "ssh":
            raise CoreError(
                f"SSH cannot host a '{protocol}' chain endpoint — chains into "
                f"this core use the native ssh outbound."
            )
        if "_zg-chain" not in self._chain_users:
            import uuid as uuid_mod

            name = "zg-chain"
            password = uuid_mod.uuid4().hex[:16]
            if not await asyncio.to_thread(self._backend.user_exists, name):
                await asyncio.to_thread(
                    self._backend.create_user, name, password,
                    self.settings["shell"], False,
                )
            else:
                await asyncio.to_thread(self._backend.set_password, name, password)
            self._chain_users["_zg-chain"] = (name, password)
        return self._chain_endpoint()

    def _chain_endpoint(self) -> ChainEndpoint:
        s = self.settings
        name, password = self._chain_users["_zg-chain"]
        return ChainEndpoint(
            core_id=self.metadata.id,
            protocol="ssh",
            host=s["advertise_host"],
            port=int(s["port"]),
            requires_credentials=True,
            metadata={"username": name, "password": password},
        )
