"""SSHTunnelDriver — OpenSSH (system sshd) as a first-class panel core.

Real capabilities used:
  * **User management** = real unix accounts (panel-namespaced ``zg-*``),
    created/locked/deleted with the standard tools (useradd/usermod/userdel
    + chpasswd). Locking applies instantly — no sshd restart (HOT_RELOAD).
  * **Suspend** = ``usermod --lock`` + killing the user's sshd session
    processes (``pkill`` on sshd children of that uid) — immediate cut.
  * **Online detection** = sshd session processes from ``ps`` (legacy
    ``sshd: user@notty`` and OpenSSH 10 ``sshd-session: user`` titles).
  * **Chain ingress**: a dedicated account can terminate a real managed
    OpenSSH application-proxy chain; no nonexistent Xray SSH codec is claimed.

  * USAGE_ACCOUNTING — generic forwarding is counted bidirectionally from
    accepted SSH transport socket counters and the dropped-UID sshd-session
    PID. A decrypted SFTP/SCP stream collector is a non-overlapping fallback.
    Each source degrades independently and never fabricates successful totals.

Honestly NOT claimed (documented, no simulation):
  * SERVICE_CONTROL — sshd belongs to systemd; the driver manages accounts,
    not the daemon (status still reports sshd liveness, honestly).
  * DEVICE_DETECTION — sshd logs carry no client platform/version.
"""
from __future__ import annotations

import asyncio
import logging
import secrets
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from app.cores.base import BaseCoreDriver
from app.cores.drivers.ssh.sshtool import sanitize_username
from app.cores.exceptions import CapabilityNotSupportedError, CoreError
from app.cores.stats import DeltaTracker
from app.cores.types import (
    Capability,
    ChainEndpoint,
    ClientConfig,
    CoreMetadata,
    CoreState,
    CoreStatus,
    DeviceSession,
    HealthStatus,
    ListenerClaim,
    UsageRecord,
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
            "ssh-outbound chain ingress (xray), and bidirectional SFTP/SCP "
            "traffic accounting."
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
            Capability.USAGE_ACCOUNTING,
        },
        config_schema={
            "type": "object",
            "properties": {
                "shell": {"type": "string", "default": "/bin/bash"},
                "work_dir": {"type": "string", "default": "/var/lib/zagros/cores/ssh"},
                "create_home": {"type": "boolean", "default": False},
                "port": {"type": "integer", "default": 2022},
                "listeners": {"type": "array",
                              "description": "sshd listener set (xray-style "
                                             "multi-inbound): [{'tag': str, "
                                             "'port': int}[, ...]] — empty = "
                                             "derive from the legacy 'port' "
                                             "setting"},
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
            "work_dir": "/var/lib/zagros/cores/ssh",
            "create_home": False,
            "port": 2022,
            "listeners": [],
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
        # sshd natively serves ANY number of `Port` directives from one
        # daemon — multi-inbound exactly like xray: N entries,
        # distinct tags, distinct ports, one drop-in rewrite + reload.
        studio_inbounds_path="/inbounds",
    )

    def __init__(self, settings: dict[str, Any] | None = None, *, backend: Any | None = None):
        super().__init__(settings)
        # multi-inbound settings bridge: a persisted earlier
        # settings blob has no "listeners" — derive it from the legacy
        # single "port" so old cores keep answering on their port.
        self._listeners = self._derive_listeners(self.settings)
        self.settings["listeners"] = [dict(l) for l in self._listeners]
        if backend is None:
            from app.cores.drivers.ssh.backend import LocalSystemSSHBackend

            backend = LocalSystemSSHBackend(self.settings)
        self._backend = backend
        self._accounts: dict[str, UserAccount] = {}
        self._chain_users: dict[str, tuple[str, str]] = {}
        self._usage = DeltaTracker()
        self._acct_error: str | None = None
        self._tunnel_acct_error: str | None = None
        self._sftp_acct_error: str | None = None
        self._legacy_tunnel_acct = False

    # ------------------------------------------------------------------ #
    # listeners (xray-style multi-inbound over the ONE sshd listener set)   #
    # ------------------------------------------------------------------ #
    _RESERVED_PORT = 22  # operator access — always kept, never panel-owned

    @classmethod
    def _derive_listeners(cls, settings: dict[str, Any]) -> list[dict[str, Any]]:
        """settings['listeners'] normalized; empty/missing → single listener
        seeded from the legacy 'port' key (pre- compatibility)."""
        raw = settings.get("listeners") or []
        out: list[dict[str, Any]] = []
        for row in raw:
            if not isinstance(row, dict):
                continue
            try:
                port = int(row.get("port"))
            except (TypeError, ValueError):
                continue
            tag = str(row.get("tag") or "").strip() or f"ssh-{port}"
            entry: dict[str, Any] = {"tag": tag, "port": port}
            if row.get("listen"):
                entry["listen"] = str(row["listen"])
            out.append(entry)
        if not out:
            port = int(settings.get("port") or 2022)
            out.append({"tag": "ssh", "port": port})
        return out

    async def listener_claims(self) -> list[ListenerClaim]:
        return [ListenerClaim(
            core_id=self.metadata.id, protocol="ssh", transport="tcp",
            address=str(listener.get("listen") or "0.0.0.0"),
            port=int(listener["port"]), label=str(listener["tag"]),
        ) for listener in self._listeners]

    @classmethod
    def _validate_listener_set(cls, listeners: list[dict[str, Any]]) -> None:
        """Cardinality/uniqueness guards — named offenders in the error."""
        if not listeners:
            raise CoreError("ssh needs at least ONE listener (inbound).")
        seen_tags: set[str] = set()
        seen_ports: set[int] = set()
        for listener in listeners:
            tag, port = listener["tag"], listener["port"]
            if not 1 <= int(port) <= 65535:
                raise CoreError(f"ssh listener '{tag}': port out of range ({port}).")
            if int(port) == cls._RESERVED_PORT:
                raise CoreError(
                    f"ssh listener '{tag}': port 22 is reserved for operator "
                    f"access — the panel never binds its own listener there."
                )
            if tag in seen_tags:
                raise CoreError(f"duplicate ssh inbound name '{tag}'.")
            if int(port) in seen_ports:
                raise CoreError(
                    f"ssh listeners share port {port} — like xray, every "
                    f"inbound needs its OWN port (check '{tag}')."
                )
            seen_tags.add(tag)
            seen_ports.add(int(port))

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
        # SFTP/scp stream accounting is capability-independent and records
        # both directions after OpenSSH decrypts them. Forwarding uplink uses
        # owner-match when the host kernel supports it; one source may degrade
        # without disabling the other.
        start_sftp = getattr(self._backend, "sftp_acct_start", None)
        self._sftp_acct_error = None
        if callable(start_sftp) and self.settings.get("sftp", True):
            try:
                await asyncio.to_thread(start_sftp)
            except Exception as exc:  # noqa: BLE001
                self._sftp_acct_error = f"SFTP accounting collector failed: {exc}"
        elif self.settings.get("sftp", True):
            self._sftp_acct_error = "backend has no SFTP accounting collector"

        start_transport = getattr(self._backend, "transport_acct_start", None)
        self._legacy_tunnel_acct = False
        self._tunnel_acct_error = None
        if callable(start_transport):
            try:
                await asyncio.to_thread(
                    start_transport,
                    {int(listener["port"]) for listener in self._listeners},
                )
                teardown_legacy = getattr(self._backend, "acct_teardown", None)
                if callable(teardown_legacy):
                    await asyncio.to_thread(teardown_legacy)
            except Exception as exc:  # noqa: BLE001 — honest degrade
                self._tunnel_acct_error = (
                    f"SSH bidirectional transport accounting failed: {exc}")
        else:
            self._tunnel_acct_error = (
                "backend has no bidirectional SSH transport accounting")

        # Compatibility fallback: an older/external backend may still provide
        # real owner-match uplink. Keep it, but never label it bidirectional.
        if self._tunnel_acct_error:
            unavailable = await asyncio.to_thread(
                getattr(self._backend, "acct_available",
                        lambda: "backend has no forwarding accounting support"))
            if unavailable is None:
                try:
                    await asyncio.to_thread(self._backend.acct_ensure)
                    self._legacy_tunnel_acct = True
                except Exception as exc:  # noqa: BLE001 — honest degrade
                    self._tunnel_acct_error += f" | uplink fallback failed: {exc}"

        errors = [e for e in (self._tunnel_acct_error,
                              self._sftp_acct_error) if e]
        # Full capability is unavailable only when every accounting source is
        # gone. A partial source remains useful and status says exactly which.
        self._acct_error = " | ".join(errors) if len(errors) == 2 else None
        for error in errors:
            logger.warning("ssh accounting source degraded: %s", error)

    async def stop(self) -> None:
        # sshd itself stays system-owned (stopping it could lock out the
        # operator), but the panel-owned accounting receiver must release its
        # socket/thread when this core is stopped or reloaded.
        stop_transport = getattr(self._backend, "transport_acct_stop", None)
        if callable(stop_transport):
            await asyncio.to_thread(stop_transport)
        stop_sftp = getattr(self._backend, "sftp_acct_stop", None)
        if callable(stop_sftp):
            await asyncio.to_thread(stop_sftp)

    async def _refresh_transport_accounting_status(self) -> None:
        """Reconcile host-agent health without requiring an SSH-core restart.

        ``start()`` used to cache the first missing/stale snapshot forever, so
        a successful later ``zagros install-host-agent`` kept the UI yellow
        until the whole core or Panel restarted.  The cores endpoint already
        performs a live status probe; use that probe to transition both ways:
        stale/missing → degraded, and a fresh host heartbeat → healthy.
        """
        available = getattr(self._backend, "transport_acct_available", None)
        start_transport = getattr(self._backend, "transport_acct_start", None)
        if not callable(available) or not callable(start_transport):
            return
        reason = await asyncio.to_thread(available)
        if reason is not None:
            self._tunnel_acct_error = (
                f"SSH bidirectional transport accounting failed: {reason}")
            return
        if self._tunnel_acct_error is None:
            return
        try:
            await asyncio.to_thread(
                start_transport,
                {int(listener["port"]) for listener in self._listeners},
            )
            teardown_legacy = getattr(self._backend, "acct_teardown", None)
            if callable(teardown_legacy):
                await asyncio.to_thread(teardown_legacy)
            self._legacy_tunnel_acct = False
            self._tunnel_acct_error = None
        except Exception as exc:  # noqa: BLE001 — status remains honest
            self._tunnel_acct_error = (
                f"SSH bidirectional transport accounting failed: {exc}")

    async def status(self) -> CoreStatus:
        running = await asyncio.to_thread(self._backend.sshd_running)
        if running:
            await self._refresh_transport_accounting_status()
        version = await self.version()
        sessions = await self.get_online_devices() if running else []
        metrics = None
        if running:
            from app.cores.types import CoreMetrics

            metrics = CoreMetrics(active_accounts=len(self._accounts),
                                  active_sessions=len(sessions))
        accounting_message = " | ".join(e for e in (
            self._tunnel_acct_error, self._sftp_acct_error) if e)
        return CoreStatus(
            core_id=self.metadata.id,
            state=CoreState.RUNNING if running else CoreState.STOPPED,
            health=(HealthStatus.DEGRADED if (running and accounting_message)
                    else HealthStatus.HEALTHY if running else HealthStatus.UNHEALTHY),
            core_version=version.version,
            version_reason=version.reason,
            metrics=metrics,
            message=(accounting_message or None if running
                     else "sshd is not running (system service)."),
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
        """Studio seed: one entry per sshd listener (xray-style); daemon-wide
        knobs (auth/shell/sftp/…) mirrored on every entry — the apply path
        rejects conflicting values because ONE sshd serves them all."""
        s = self.settings
        password_auth = bool(s.get("password_auth", True))
        pubkey_auth = bool(s.get("pubkey_auth", True))
        authentication = ("both" if password_auth and pubkey_auth
                          else "password" if password_auth else "publickey")
        entries = []
        for listener in self._listeners:
            entries.append({
                "tag": listener["tag"],
                "protocol": "ssh",
                "listen": listener.get("listen") or "0.0.0.0",
                "port": int(listener["port"]),
                "authentication": authentication,
                "password": "",
                "public_key": "",
                "shell": s.get("shell") or "/bin/bash",
                "sftp": bool(s.get("sftp", True)),
                "max_sessions": int(s.get("max_sessions") or 10),
                "banner": "",
                "has_default_password": bool(s.get("default_password")),
                "has_default_key": bool(s.get("default_authorized_key")),
                "has_banner": bool(s.get("banner")),
            })
        return {"inbounds": entries}

    async def apply_studio_document(self, document: dict[str, Any]) -> None:
        """Adopt the studio document's entries as THE sshd listener set —
        xray-style multi-inbound: N entries, distinct tags, distinct ports,
        served by the ONE sshd via repeated `Port` directives (drop-in
        rewrite + validated reload; port 22 is never removed).

        Auth/shell/sftp knobs are physically daemon-wide: entries may carry
        them, but a CONFLICTING pair is a hard error naming the field and
        both tags — never a silent last-write-wins."""
        inbounds = (document or {}).get("inbounds") or []
        if not inbounds:
            raise CoreError(
                "an ssh core needs at least ONE inbound — the studio document "
                "carries none."
            )
        s = self.settings

        # 1) structural pass (fail BEFORE touching any setting). Port stays
        # optional per entry: missing →
        # inherit the current listener of the same name, else the legacy
        # single port. Blank tag → "ssh" for a single-entry doc (legacy
        # shape), deterministic ssh-<port> otherwise.
        listeners: list[dict[str, Any]] = []
        single = len(inbounds) == 1
        for ib in inbounds:
            if str(ib.get("protocol") or "ssh") != "ssh":
                raise CoreError(f"an ssh core cannot host a '{ib.get('protocol')}' listener.")
            tag = str(ib.get("tag") or "").strip()
            raw_port = ib.get("port")
            if raw_port is None:
                probe = tag or "ssh"
                existing = next(
                    (l for l in self._listeners if l["tag"] == probe), None)
                port = (int(existing["port"]) if existing
                        else int(s.get("port") or 2022))
            else:
                try:
                    port = int(raw_port)
                except (TypeError, ValueError):
                    raise CoreError(
                        f"ssh inbound '{tag or '?'}': invalid port {raw_port!r}."
                    ) from None
            entry = {"tag": tag or ("ssh" if single else f"ssh-{port}"),
                     "port": port}
            if ib.get("listen"):
                entry["listen"] = str(ib["listen"])
            listeners.append(entry)
        self._validate_listener_set(listeners)

        # 2) daemon-wide knobs — identical values only; conflicts are named
        def _norm(field: str, value: Any) -> Any:
            if field == "max_sessions":
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return value
            if field == "sftp":
                if isinstance(value, str):
                    return value.strip().lower() in ("1", "true", "yes", "on")
                return bool(value)
            if field == "authentication":
                return str(value).strip().lower()
            return value

        def _shared(field: str) -> Any:
            base_value: Any = None
            base_tag: str | None = None
            for ib, listener in zip(inbounds, listeners):
                value = ib.get(field)
                if value is None or value == "":
                    continue
                value = _norm(field, value)
                if base_tag is None:
                    base_tag, base_value = listener["tag"], value
                elif value != base_value:
                    raise CoreError(
                        f"'{field}' is a daemon-wide sshd setting but inbound "
                        f"'{base_tag}' and inbound '{listener['tag']}' "
                        f"disagree — ONE sshd serves every listener, so keep "
                        f"the value identical on all entries."
                    )
            return base_value

        authentication = _shared("authentication")
        if authentication in ("password", "publickey", "both"):
            s["password_auth"] = authentication in ("password", "both")
            s["pubkey_auth"] = authentication in ("publickey", "both")
        elif authentication:
            raise CoreError(f"unknown ssh authentication mode '{authentication}'.")
        if not s["password_auth"] and not s["pubkey_auth"]:
            raise CoreError(
                "refusing an sshd with BOTH password AND public-key auth off — "
                "nobody (including you) could ever log in."
            )
        shell = _shared("shell")
        if shell:
            s["shell"] = str(shell)
        if _shared("sftp") is not None:
            s["sftp"] = bool(_shared("sftp"))
        if _shared("max_sessions") is not None:
            s["max_sessions"] = int(_shared("max_sessions"))
        password = _shared("password")
        if str(password or ""):
            s["default_password"] = str(password)
        banner = _shared("banner")
        if str(banner or ""):
            s["banner"] = str(banner)
        public_key = str(_shared("public_key") or "")
        if public_key:
            s["default_authorized_key"] = public_key
            # install for accounts that already exist as well
            for account in list(self._accounts.values()):
                name = self._unix_name(account)
                if await asyncio.to_thread(self._backend.user_exists, name):
                    await asyncio.to_thread(
                        self._backend.authorize_key, name, s["default_authorized_key"]
                    )

        # 3) persist the listener set (legacy 'port' mirrors the first one)
        s["listeners"] = [dict(l) for l in listeners]
        self._listeners = [dict(l) for l in listeners]
        s["port"] = listeners[0]["port"]

        # push through the same validated path the Start button uses
        how = await asyncio.to_thread(self._backend.ensure_service)
        logger.info(
            "ssh: studio document applied — %d listener%s (%s), sshd via %s",
            len(listeners), "" if len(listeners) == 1 else "s",
            ", ".join(f"{l['tag']}:{l['port']}" for l in listeners), how,
        )

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

    def _provision_credentials(self, account: UserAccount) -> None:
        """Alpha.7.2 contract: provisioning NEVER fails on a missing
        password — the panel mints a secure random one IN PLACE (the grant
        path persists it back, same contract as sing-box). The studio-set
        default password stays the intentional shared fallback (operator's
        explicit choice), so it suppresses minting."""
        if not account.settings.get("password") and not self.settings.get("default_password"):
            account.settings["password"] = secrets.token_urlsafe(18)
            logger.info("ssh: minted a random password for account '%s'.",
                        account.account_id)

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
        self._provision_credentials(account)
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
        self._provision_credentials(account)
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
        self._usage.forget(account_id)
        if account is None:
            # still try: the unix account may exist from a previous panel life
            try:
                name = sanitize_username(account_id)
            except ValueError:
                return
        else:
            name = self._unix_name(account)
        # UID lookup belongs to the optional host-transport accounting seam,
        # not the baseline SSHBackend account contract. Backends without that
        # collector must still be able to delete an account cleanly.
        uid_lookup = getattr(self._backend, "uid_of", None)
        uid = (await asyncio.to_thread(uid_lookup, name)
               if callable(uid_lookup) else None)
        await self._lock_and_kill(name)
        forget_transport = getattr(self._backend, "transport_acct_forget", None)
        if uid is not None and callable(forget_transport):
            await asyncio.to_thread(forget_transport, uid)
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
        # are no longer desired (only zg-* names are ever touched).
        # every granted account qualifies — credentials are
        # provisioned first (skipped password-less accounts, which
        # made the grant fail downstream; now nothing may fail).
        for account in accounts:
            self._provision_credentials(account)
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
    # global bandwidth identity
    # ------------------------------------------------------------------ #
    def bandwidth_identities(self) -> dict[str, dict[str, list]]:
        out: dict[str, dict[str, list]] = {}
        for account_id, account in self._accounts.items():
            uid = self._uid_of_account(account)
            out[account_id] = {
                "inner_sources": [], "uids": ([] if uid is None else [int(uid)])}
        return out

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
    # usage — real kernel accounting via iptables owner-match #
    # ------------------------------------------------------------------ #
    def _uid_of_account(self, account: UserAccount) -> int | None:
        lookup = getattr(self._backend, "uid_of", None)
        if lookup is None:
            return None
        return lookup(self._unix_name(account))

    def supports(self, capability: Capability) -> bool:
        # Environment-gated capability: the registry means this engine CAN
        # account, while status reports whether transport/SFTP collectors are
        # actually available on this host.
        if capability is Capability.USAGE_ACCOUNTING and self._acct_error:
            return False
        return super().supports(capability)

    async def get_usage(
        self, account_ids: list[str] | None = None, since: Any | None = None
    ) -> list[UsageRecord]:
        if self._acct_error:
            raise CapabilityNotSupportedError(
                self.metadata.id,
                f"usage_accounting (ssh): {self._acct_error}")
        uid_map: dict[int, str] = {}
        unresolved = 0
        for account in self._accounts.values():
            uid = await asyncio.to_thread(self._uid_of_account, account)
            if uid is not None:
                uid_map[uid] = account.account_id
            else:
                unresolved += 1
        if unresolved:
            logger.warning(
                "ssh accounting: %d account(s) have no resolvable UID "
                "(host account deleted out-of-band?) — their usage cannot "
                "be attributed this tick", unresolved)
        tunnel_counters: dict[int, tuple[int, int]] = {}
        transport_authoritative = not self._tunnel_acct_error
        if transport_authoritative:
            read_transport = getattr(self._backend, "transport_acct_read", None)
            if callable(read_transport):
                tunnel_counters = await asyncio.to_thread(read_transport)
        elif self._legacy_tunnel_acct:
            await asyncio.to_thread(self._backend.acct_sync_users, set(uid_map))
            uplink = await asyncio.to_thread(self._backend.acct_read)
            tunnel_counters = {uid: (value, 0) for uid, value in uplink.items()}

        sftp_counters: dict[int, tuple[int, int]] = {}
        # The encrypted transport already includes every SFTP/SCP byte. Use
        # the application collector only as a fallback, never double count it.
        read_sftp = getattr(self._backend, "sftp_acct_read", None)
        if (not transport_authoritative and not self._sftp_acct_error
                and callable(read_sftp)):
            sftp_counters = await asyncio.to_thread(read_sftp)

        records: list[UsageRecord] = []
        for uid, account_id in uid_map.items():
            if account_ids is not None and account_id not in account_ids:
                continue
            sftp_up, sftp_down = sftp_counters.get(uid, (0, 0))
            tunnel_up, tunnel_down = tunnel_counters.get(uid, (0, 0))
            # The accepted encrypted transport is authoritative whenever the
            # socket collector is available. SFTP counters are fallback-only,
            # so these additions never count one transfer twice.
            cumulative_up = tunnel_up + sftp_up
            cumulative_down = tunnel_down + sftp_down
            up, down = self._usage.observe(
                account_id, cumulative_up, cumulative_down)
            records.append(UsageRecord(
                core_id=self.metadata.id, account_id=account_id,
                uplink_bytes=up, downlink_bytes=down,
            ))
        return records

    # ------------------------------------------------------------------ #
    # client config + delivery (sealed delivery; one section per granted   #
    # listener — xray-style)                                               #
    # ------------------------------------------------------------------ #
    def _granted_listeners(self, account: UserAccount) -> list[dict[str, Any]]:
        """Grant-aware listener view (same convention as sing-box):
        inbound_tags whitelists, excluded_inbounds blacklists."""
        wanted = set(account.settings.get("inbound_tags") or [])
        excluded = set(account.settings.get("excluded_inbounds") or [])
        out = [l for l in self._listeners if not wanted or l["tag"] in wanted]
        return [l for l in out if l["tag"] not in excluded]

    async def describe_delivery(
        self,
        account: UserAccount,
        context: "DeliveryContext | None" = None,
    ) -> "DeliveryProfile":
        """SSH delivery: per-listener connection FIELDS — one section per
        granted inbound, exactly like xray emits one link per inbound."""
        from app.cores.delivery import (
            ArtifactKind,
            DeliveryArtifact,
            DeliveryField,
            DeliveryProfile,
            DeliverySection,
        )

        self._ensure_supported(account.protocol)
        self._ensure_credentials(account)
        s = self.settings
        from app.cores.delivery import resolve_delivery_host

        configured_host = s.get("advertise_host")
        host = (str(configured_host or "").strip() if context is None else
                resolve_delivery_host(configured_host, context))
        if not host:
            raise CoreError("no public endpoint is configured for SSH delivery")
        username = self._unix_name(account)
        password = self._account_password(account)
        sections: list[DeliverySection] = []
        for listener in self._granted_listeners(account):
            sections.append(DeliverySection(
                protocol="ssh",
                title=f"{listener['tag']} · SSH Tunnel",
                engine="ssh",
                inbound_tag=listener["tag"],
                artifacts=[
                    DeliveryArtifact(
                        kind=ArtifactKind.FIELDS,
                        label="Connection",
                        fields=(
                            DeliveryField(key="host", label="Host", value=host),
                            DeliveryField(key="port", label="Port",
                                          value=str(listener["port"])),
                            DeliveryField(key="username", label="Username",
                                          value=username),
                            DeliveryField(key="password", label="Password",
                                          value=password, secret=True),
                        ),
                    ),
                    DeliveryArtifact(
                        kind=ArtifactKind.NOTE,
                        label="How to connect",
                        note=(f"ssh -p {listener['port']} {username}@<server> — "
                              "add -D 1080 for a SOCKS proxy, or -L/-R for "
                              "port forwards. Key-based login works when a "
                              "public key is installed for your account."),
                    ),
                ],
            ))
        return DeliveryProfile(core_id=self.metadata.id, sections=sections)

    async def build_client_config(
        self, account: UserAccount, node: Any | None = None
    ) -> ClientConfig:
        self._ensure_supported(account.protocol)
        self._ensure_credentials(account)
        s = self.settings
        from app.cores.delivery import resolve_delivery_host

        configured_host = s.get("advertise_host")
        host = (str(configured_host or "").strip() if node is None else
                resolve_delivery_host(configured_host, node))
        if not host:
            raise CoreError("no public endpoint is configured for SSH delivery")
        listeners = self._granted_listeners(account)
        if not listeners:
            raise CoreError(
                f"ssh account '{account.account_id}' has no granted inbound."
            )
        return ClientConfig(
            core_id=self.metadata.id,
            protocol="ssh",
            engine="ssh",
            payload={
                "format": "ssh",
                "host": host,
                "port": int(listeners[0]["port"]),
                "username": self._unix_name(account),
                "password": self._account_password(account),
                "hint": "ssh -D 1080 (SOCKS) or ssh -L/-R port forwards",
            },
            display_name=f"SSH Tunnel · {listeners[0]['tag']}",
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
