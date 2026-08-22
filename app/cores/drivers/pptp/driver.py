"""Independent ACCEL-PPP PPTP server provider.

This driver intentionally has no dependency on SoftEther or vpncmd. PPTP is a
legacy/insecure, IPv4-only server with fixed TCP/1723 + GRE/47,
MS-CHAPv2-only authentication and mandatory MPPE128.
"""
from __future__ import annotations

import asyncio
import copy
import ipaddress
import logging
import os
import re
import secrets
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar

from app.cores.base import BaseCoreDriver
from app.cores.delivery import (
    ArtifactKind, DeliveryArtifact, DeliveryContext, DeliveryField,
    DeliveryProfile, DeliverySection, resolve_delivery_host,
)
from app.cores.drivers.pptp.accounting import PptpAccountingLedger
from app.cores.drivers.pptp.backend import LocalPptpBackend, PINNED_VERSION
from app.cores.exceptions import CoreError
from app.cores.stats import DeltaTracker
from app.cores.types import (
    Capability, ClientConfig, CoreFeatureCapability, CoreMetadata, CoreState,
    CoreStatus, DeviceSession, FeatureAvailability, HealthStatus, ListenerClaim,
    UsageRecord, UserAccount,
)

logger = logging.getLogger("zagros.cores.drivers.pptp")

_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9._@-]{1,190}$")
_ALLOWED_INBOUND_KEYS = {
    "tag", "protocol", "listen", "port", "subnet", "dns",
    "legacy_risk_ack", "internet_exposure_ack", "authentication",
    "encryption", "network", "ipv6", "security_class", "transport", "security",
}


class PptpDriver(BaseCoreDriver):
    metadata: ClassVar[CoreMetadata] = CoreMetadata(
        id="pptp",
        name="Independent PPTP Server — Legacy / Insecure",
        description=(
            "Independent ACCEL-PPP 1.14.0 PPTP server. Legacy/insecure: fixed "
            "TCP/1723 + GRE/47, MS-CHAPv2 only, mandatory MPPE128 and IPv4 only."
        ),
        protocols=["pptp"],
        capabilities={
            Capability.USER_MANAGEMENT,
            Capability.SUSPEND_RESUME,
            Capability.USAGE_ACCOUNTING,
            Capability.ONLINE_TRACKING,
            Capability.SERVICE_CONTROL,
            Capability.SELF_INSTALL,
            Capability.CLIENT_CONFIG,
            Capability.UDP_SUPPORT,
        },
        feature_capabilities={
            "inbound": CoreFeatureCapability(
                state=FeatureAvailability.SUPPORTED,
                detail="Independent ACCEL-PPP PPTP server (Legacy / Insecure)",
            ),
            "outbound": CoreFeatureCapability(
                state=FeatureAvailability.UNSUPPORTED,
                detail="PPTP outbound is not implemented",
            ),
        },
        config_schema={
            "type": "object",
            "x-security-class": "legacy_insecure",
            "x-security-label": "Legacy / Insecure",
            "properties": {
                "legacy_risk_ack": {"type": "boolean", "default": False},
                "internet_exposure_ack": {"type": "boolean", "default": False},
                "work_dir": {"type": "string"},
                "executable_path": {"type": "string"},
                "module_dir": {"type": "string"},
                "management_port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "advertise_host": {"type": "string"},
                "inbounds": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": [
                            "tag", "protocol", "listen", "port", "subnet",
                            "legacy_risk_ack", "internet_exposure_ack",
                            "authentication", "encryption", "network", "ipv6",
                        ],
                        "properties": {
                            "tag": {"type": "string", "minLength": 1},
                            "protocol": {"type": "string", "enum": ["pptp"]},
                            "listen": {"type": "string", "enum": ["0.0.0.0"]},
                            "port": {"type": "integer", "enum": [1723]},
                            "subnet": {"type": "string", "minLength": 1},
                            "dns": {"type": "string"},
                            "legacy_risk_ack": {"type": "boolean", "enum": [True]},
                            "internet_exposure_ack": {"type": "boolean", "enum": [True]},
                            "authentication": {"type": "string", "enum": ["MS-CHAPv2"]},
                            "encryption": {"type": "string", "enum": ["MPPE128"]},
                            "network": {"type": "string", "enum": ["IPv4"]},
                            "ipv6": {"type": "boolean", "enum": [False]},
                            "security_class": {"type": "string", "enum": ["legacy_insecure"]},
                        },
                    },
                },
            },
        },
        default_settings={
            "legacy_risk_ack": True,
            "internet_exposure_ack": True,
            "work_dir": "/var/lib/zagros/cores/pptp",
            "executable_path": "/opt/zagros/accel-ppp/1.14.0/sbin/accel-pppd",
            "module_dir": "/opt/zagros/accel-ppp/1.14.0/lib/accel-ppp",
            "management_port": 22001,
            "advertise_host": "",
            "inbounds": [],
        },
        driver_version="1.0.0",
        homepage="https://github.com/accel-ppp/accel-ppp",
        studio_inbounds_path="/inbounds",
        studio_max_inbounds=1,
        security_class="legacy_insecure",
        stop_when_no_inbounds=True,
    )

    def __init__(
        self, settings: dict[str, Any] | None = None, *, backend: Any | None = None,
        ledger: PptpAccountingLedger | None = None,
    ) -> None:
        super().__init__(settings)
        self.settings["inbounds"] = copy.deepcopy(self.settings.get("inbounds") or [])
        self._backend = backend or LocalPptpBackend(self.settings)
        self._accounting_path = getattr(
            self._backend, "accounting_path",
            os.path.join(str(self.settings["work_dir"]), "accounting.sqlite3"),
        )
        self._ledger: PptpAccountingLedger | None = ledger
        self._usage = DeltaTracker()
        self._accounts: dict[str, UserAccount] = {}

    # ------------------------------------------------------------------ #
    # Validation + Studio                                                #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _parse_dns(value: Any) -> list[str]:
        raw = value if isinstance(value, list) else str(value or "").split(",")
        result: list[str] = []
        for item in raw:
            text = str(item).strip()
            if not text:
                continue
            try:
                address = ipaddress.ip_address(text)
            except ValueError as exc:
                raise CoreError(f"invalid PPTP DNS address '{text}'") from exc
            if address.version != 4:
                raise CoreError("PPTP DNS servers must be IPv4")
            result.append(text)
        return result[:2]

    def _normalize_inbound(self, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise CoreError("PPTP inbound must be an object")
        unknown = sorted(set(raw) - _ALLOWED_INBOUND_KEYS)
        if unknown:
            raise CoreError(f"unsupported PPTP inbound fields: {unknown}")
        tag = str(raw.get("tag") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", tag):
            raise CoreError("PPTP inbound tag must be 1-64 safe characters")
        if raw.get("protocol") != "pptp":
            raise CoreError("independent PPTP provider only accepts protocol='pptp'")
        if raw.get("transport") not in (None, "tcp") or raw.get("security") not in (None, "none"):
            raise CoreError("PPTP transport is fixed to TCP control + GRE with no TLS layer")
        if raw.get("listen") not in (None, "0.0.0.0"):
            raise CoreError("ACCEL-PPP PPTP 1.14.0 listener is fixed to 0.0.0.0")
        if int(raw.get("port") or 0) != 1723:
            raise CoreError("PPTP control port is fixed to TCP/1723")
        if raw.get("legacy_risk_ack") is not True:
            raise CoreError("explicit Legacy/Insecure risk confirmation is required")
        if raw.get("internet_exposure_ack") is not True:
            raise CoreError("explicit Internet exposure confirmation is required")
        if raw.get("authentication") != "MS-CHAPv2":
            raise CoreError("PPTP authentication is fixed to MS-CHAPv2 only")
        if raw.get("encryption") != "MPPE128":
            raise CoreError("PPTP encryption is fixed to mandatory MPPE128")
        if raw.get("network") != "IPv4" or raw.get("ipv6") is not False:
            raise CoreError("PPTP provider is IPv4-only; IPv6 is unsupported")
        if raw.get("security_class") not in (None, "legacy_insecure"):
            raise CoreError("PPTP security_class must be legacy_insecure")
        try:
            network = ipaddress.ip_network(str(raw.get("subnet") or ""), strict=True)
        except ValueError as exc:
            raise CoreError(f"invalid PPTP IPv4 subnet: {exc}") from exc
        if network.version != 4 or not network.is_private:
            raise CoreError("PPTP subnet must be a private IPv4 network")
        if network.prefixlen < 24 or network.prefixlen > 29:
            raise CoreError("PPTP subnet prefix must be between /24 and /29")
        if network.num_addresses < 8:
            raise CoreError("PPTP subnet has insufficient addresses")
        dns = self._parse_dns(raw.get("dns") or "1.1.1.1, 8.8.8.8")
        return {
            "tag": tag, "protocol": "pptp", "listen": "0.0.0.0", "port": 1723,
            "transport": "tcp", "security": "none",
            "subnet": str(network), "dns": dns,
            "legacy_risk_ack": True, "internet_exposure_ack": True,
            "authentication": "MS-CHAPv2", "encryption": "MPPE128",
            "network": "IPv4", "ipv6": False,
            "security_class": "legacy_insecure",
        }

    def validate_studio_document(self, document: dict[str, Any]) -> list[str]:
        rows = (document or {}).get("inbounds") or []
        if not isinstance(rows, list):
            return ["PPTP inbounds must be an array"]
        if len(rows) > 1:
            return ["PPTP has one fixed TCP/1723 listener; multiple inbounds are unsupported"]
        if not rows:
            return []
        try:
            listener = self._normalize_inbound(rows[0])
            checker = getattr(self._backend, "validate_subnet", None)
            return list(checker(listener["subnet"]) or []) if callable(checker) else []
        except CoreError as exc:
            return [str(exc)]

    def export_config_document(self) -> dict[str, Any]:
        return {"inbounds": copy.deepcopy(self.settings.get("inbounds") or [])}

    async def apply_studio_document(self, document: dict[str, Any]) -> None:
        errors = self.validate_studio_document(document)
        if errors:
            raise CoreError("; ".join(errors))
        rows = (document or {}).get("inbounds") or []
        old_settings = copy.deepcopy(self.settings)
        was_running = await asyncio.to_thread(self._backend.is_running)
        old_listener = self._listener(required=False)
        try:
            if was_running:
                await asyncio.to_thread(self._backend.stop)
            self.settings["inbounds"] = (
                [self._normalize_inbound(rows[0])] if rows else []
            )
            if not rows:
                return
            await asyncio.to_thread(self._materialize)
            if was_running:
                listener = self._listener()
                await asyncio.to_thread(
                    self._backend.start, tag=listener["tag"],
                    subnet=listener["subnet"], listen=listener["listen"],
                )
        except Exception:
            self.settings.clear()
            self.settings.update(old_settings)
            try:
                await asyncio.to_thread(self._materialize)
                if was_running and old_listener:
                    await asyncio.to_thread(
                        self._backend.start, tag=old_listener["tag"],
                        subnet=old_listener["subnet"], listen=old_listener["listen"],
                    )
            except Exception as rollback_exc:
                logger.error("PPTP Studio rollback failed: %s", rollback_exc)
            raise

    def _listener(self, *, required: bool = True) -> dict[str, Any] | None:
        rows = self.settings.get("inbounds") or []
        if not rows:
            if required:
                raise CoreError("configure the PPTP inbound before starting")
            return None
        return self._normalize_inbound(rows[0])

    # ------------------------------------------------------------------ #
    # Deterministic runtime files                                        #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _pool(listener: dict[str, Any]) -> tuple[str, str, str]:
        network = ipaddress.ip_network(listener["subnet"], strict=True)
        hosts = list(network.hosts())
        return str(hosts[0]), str(hosts[1]), str(hosts[-1])

    def render_config(self, listener: dict[str, Any], management_secret: str) -> str:
        gateway, first, last = self._pool(listener)
        dns = listener.get("dns") or []
        module_dir = str(self.settings["module_dir"])
        work = str(self.settings["work_dir"])
        lines = [
            "[modules]", f"path={module_dir}", "log_file", "pptp",
            "auth_mschap_v2", "chap-secrets", "ippool", "sigchld",
            "pppd_compat", "", "[core]",
            f"log-error={work}/core.log", "thread-count=2", "", "[common]",
            "single-session=replace", "max-starting=64", "check-ip=1", "",
            "[ppp]", "verbose=0", "min-mtu=1280", "mtu=1400", "mru=1400",
            "ccp=1", "mppe=require", "ipv4=require", "ipv6=deny",
            "lcp-echo-interval=20", "lcp-echo-failure=3", "", "[auth]",
            "timeout=5", "max-failure=3", "any-login=0", "noauth=0", "",
            "[pptp]", "verbose=0", "echo-interval=30", "ip-pool=pptp",
            "ifname=zgppp%d", "", "[client-ip-range]", "0.0.0.0/0", "",
            "[ip-pool]", f"gw-ip-address={gateway}",
            f"{first}-{last},name=pptp", "", "[chap-secrets]",
            f"gw-ip-address={gateway}", f"chap-secrets={self._backend.chap_path}",
            "encrypted=0", "", "[pppd-compat]",
            f"ip-down={self._backend.hook_path}", "fork-limit=8", "verbose=0", "",
            "[log]", f"log-file={work}/accel-ppp.log",
            f"log-emerg={work}/emerg.log", f"log-fail-file={work}/auth-fail.log",
            "copy=1", "level=3", "", "[cli]", "verbose=1",
            f"tcp=127.0.0.1:{int(self.settings['management_port'])}",
            f"password={management_secret}",
            "sessions-columns=ifname,username,calling-sid,ip,type,comp,state,uptime-raw,sid,rx-bytes-raw,tx-bytes-raw",
        ]
        if dns:
            lines += ["", "[dns]", f"dns1={dns[0]}"]
            if len(dns) > 1:
                lines.append(f"dns2={dns[1]}")
        lines.append("")
        return "\n".join(lines)

    def render_chap_secrets(self) -> str:
        lines = ["# Zagros-owned ACCEL-PPP secrets. Mode 0600."]
        for account_id in sorted(self._accounts):
            account = self._accounts[account_id]
            if not account.enabled:
                continue
            self._validate_account(account)
            assigned = str(account.settings.get("assigned_ipv4") or "*")
            lines.append(
                f'"{account.account_id}" * "{account.settings["password"]}" "{assigned}"'
            )
        return "\n".join(lines) + "\n"

    def render_hook(self) -> str:
        return """#!/usr/local/bin/python3
import sys
sys.path.insert(0, "/code")
from app.cores.drivers.pptp.accounting import hook_from_environment
hook_from_environment(%r, %r, sys.argv[1] if len(sys.argv) > 1 else "")
""" % (self._backend.accounting_path, self._backend.generation_path)

    def _materialize(self) -> None:
        listener = self._listener(required=False)
        if listener is None:
            return
        secret = self._backend.ensure_management_secret()
        self._backend.configure(
            self.render_config(listener, secret), self.render_chap_secrets(),
            self.render_hook(),
        )

    # ------------------------------------------------------------------ #
    # Lifecycle                                                          #
    # ------------------------------------------------------------------ #
    def _validate_root_confirmations(self) -> None:
        requested = str(self.settings.get("release_version") or PINNED_VERSION).lstrip("v")
        if requested != PINNED_VERSION:
            raise CoreError("PPTP runtime is pinned to ACCEL-PPP 1.14.0")
        if self.settings.get("legacy_risk_ack") is not True:
            raise CoreError("PPTP install/enable requires Legacy/Insecure risk confirmation")
        if self.settings.get("internet_exposure_ack") is not True:
            raise CoreError("PPTP install/enable requires Internet exposure confirmation")

    async def install(self) -> None:
        self._validate_root_confirmations()
        await asyncio.to_thread(self._backend.verify_installation)
        await asyncio.to_thread(self._backend.ensure_management_secret)

    async def update(self, version: str | None = None) -> str:
        if version and version.lstrip("v") != PINNED_VERSION:
            raise CoreError("PPTP runtime is pinned to ACCEL-PPP 1.14.0")
        await asyncio.to_thread(self._backend.verify_installation)
        return PINNED_VERSION

    async def uninstall(self, purge: bool = False) -> None:
        if purge:
            await asyncio.to_thread(self._backend.purge)
        else:
            await asyncio.to_thread(self._backend.stop)

    async def start(self) -> None:
        self._validate_root_confirmations()
        listener = self._listener()
        self._materialize()
        await asyncio.to_thread(
            self._backend.start, tag=listener["tag"], subnet=listener["subnet"],
            listen=listener["listen"],
        )

    async def stop(self) -> None:
        await asyncio.to_thread(self._backend.stop)

    async def status(self) -> CoreStatus:
        running = await asyncio.to_thread(self._backend.is_running)
        version = await self.version()
        health = HealthStatus.UNKNOWN
        metrics = None
        message = None
        if running:
            try:
                sessions = await asyncio.to_thread(self._backend.sessions)
                metrics = await asyncio.to_thread(self._backend.metrics)
                metrics.active_sessions = len(sessions)
                metrics.active_accounts = len({session.username for session in sessions})
                health = HealthStatus.HEALTHY
            except CoreError as exc:
                health = HealthStatus.DEGRADED
                message = str(exc)
        return CoreStatus(
            core_id="pptp", state=CoreState.RUNNING if running else CoreState.STOPPED,
            health=health, core_version=version.version,
            version_reason=version.reason, metrics=metrics, message=message,
        )

    async def get_logs(self, tail: int = 200) -> AsyncIterator[str]:
        for line in await asyncio.to_thread(self._backend.logs, tail):
            yield line

    async def listener_claims(self) -> list[ListenerClaim]:
        listener = self._listener(required=False)
        if not listener:
            return []
        return [
            ListenerClaim(core_id="pptp", protocol="pptp", transport="tcp",
                          address="0.0.0.0", port=1723,
                          label="Independent PPTP control — Legacy / Insecure"),
            ListenerClaim(core_id="pptp", protocol="accel-ppp-cli", transport="tcp",
                          address="127.0.0.1", port=int(self.settings["management_port"]),
                          label="PPTP private management"),
        ]

    # ------------------------------------------------------------------ #
    # Accounts                                                           #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _validate_account(account: UserAccount) -> None:
        if account.protocol != "pptp":
            raise CoreError("PPTP core accepts only protocol='pptp'")
        if not _ACCOUNT_RE.fullmatch(account.account_id):
            raise CoreError("PPTP account id contains unsupported characters")
        password = str(account.settings.get("password") or "")
        if not password or len(password) > 256 or any(ch in password for ch in "\r\n\0\"\\"):
            raise CoreError("PPTP account password is missing or unsafe")

    @staticmethod
    def _ensure_password(account: UserAccount) -> None:
        if not account.settings.get("password"):
            account.settings["password"] = secrets.token_urlsafe(24)

    def _ensure_bandwidth_address(self, account: UserAccount) -> None:
        if account.settings.get("assigned_ipv4"):
            return
        listener = self._listener(required=False)
        if not listener:
            return
        network = ipaddress.ip_network(listener["subnet"], strict=True)
        # First host is the PPP gateway; every remaining host is a client slot.
        candidates = [str(value) for value in list(network.hosts())[1:]]
        used = {str(item.settings.get("assigned_ipv4"))
                for item in self._accounts.values()
                if item.settings.get("assigned_ipv4")}
        if not candidates:
            raise CoreError("PPTP subnet has no address available for bandwidth identity")
        start = (max(1, int(account.user_id)) - 1) % len(candidates)
        for offset in range(len(candidates)):
            value = candidates[(start + offset) % len(candidates)]
            if value not in used:
                account.settings["assigned_ipv4"] = value
                return
        raise CoreError("PPTP address pool exhausted")

    async def _publish_accounts(self) -> None:
        if not self._listener(required=False):
            return
        await asyncio.to_thread(self._materialize)
        await asyncio.to_thread(self._backend.reload)

    async def create_account(self, account: UserAccount) -> None:
        self._ensure_password(account)
        self._ensure_bandwidth_address(account)
        self._validate_account(account)
        previous = self._accounts.get(account.account_id)
        self._accounts[account.account_id] = account
        try:
            await self._publish_accounts()
        except Exception:
            if previous is None:
                self._accounts.pop(account.account_id, None)
            else:
                self._accounts[account.account_id] = previous
            await self._publish_accounts()
            raise

    async def update_account(self, account: UserAccount) -> None:
        self._ensure_password(account)
        self._ensure_bandwidth_address(account)
        self._validate_account(account)
        previous = self._accounts.get(account.account_id)
        self._accounts[account.account_id] = account
        try:
            await self._publish_accounts()
            if previous and (not account.enabled or
                             previous.settings.get("password") != account.settings.get("password")):
                await asyncio.to_thread(self._backend.terminate_account, account.account_id)
        except Exception:
            if previous is None:
                self._accounts.pop(account.account_id, None)
            else:
                self._accounts[account.account_id] = previous
            await self._publish_accounts()
            raise

    async def delete_account(self, account_id: str) -> None:
        previous = self._accounts.pop(account_id, None)
        try:
            await self._publish_accounts()
            await asyncio.to_thread(self._backend.terminate_account, account_id)
            await asyncio.to_thread(self._accounting_ledger().forget_account, account_id)
        except Exception:
            if previous is not None:
                self._accounts[account_id] = previous
                await self._publish_accounts()
            raise

    async def suspend_account(self, account_id: str) -> None:
        existing = self._accounts.get(account_id)
        if existing is None:
            return
        await self.update_account(existing.model_copy(update={"enabled": False}))

    async def resume_account(self, account: UserAccount) -> None:
        existing = self._accounts.get(account.account_id)
        if existing is not None and not account.settings:
            account = existing.model_copy(update={"enabled": True})
        else:
            account = account.model_copy(update={"enabled": True})
        await self.update_account(account)

    async def sync_accounts(self, accounts: list[UserAccount]) -> None:
        desired: dict[str, UserAccount] = {}
        for account in accounts:
            self._ensure_password(account)
            self._ensure_bandwidth_address(account)
            self._validate_account(account)
            desired[account.account_id] = account
        previous = self._accounts
        self._accounts = desired
        try:
            await self._publish_accounts()
        except Exception:
            self._accounts = previous
            await self._publish_accounts()
            raise

    # ------------------------------------------------------------------ #
    # global bandwidth identity
    # ------------------------------------------------------------------ #
    def bandwidth_identities(self) -> dict[str, dict[str, list]]:
        return {
            account_id: {
                "inner_sources": ([str(account.settings["assigned_ipv4"])]
                                  if account.settings.get("assigned_ipv4") else []),
                "uids": [],
            }
            for account_id, account in self._accounts.items()
        }

    # ------------------------------------------------------------------ #
    # Real accounting + online sessions                                  #
    # ------------------------------------------------------------------ #
    def _accounting_ledger(self) -> PptpAccountingLedger:
        if self._ledger is None:
            self._ledger = PptpAccountingLedger(self._accounting_path)
        return self._ledger

    async def get_usage(
        self, account_ids: list[str] | None = None, since: Any | None = None,
    ) -> list[UsageRecord]:
        sessions = []
        if await asyncio.to_thread(self._backend.is_running):
            sessions = await asyncio.to_thread(self._backend.sessions)
        try:
            generation = Path(self._backend.generation_path).read_text(encoding="ascii").strip()
        except OSError:
            generation = "stopped"
        totals = await asyncio.to_thread(
            self._accounting_ledger().observe, generation, sessions)
        wanted = set(account_ids) if account_ids is not None else set(totals)
        records: list[UsageRecord] = []
        for account_id in sorted(wanted):
            up, down = totals.get(account_id, (0, 0))
            delta_up, delta_down = self._usage.observe(account_id, up, down)
            records.append(UsageRecord(
                core_id="pptp", account_id=account_id,
                uplink_bytes=delta_up, downlink_bytes=delta_down,
            ))
        return records

    async def get_online_devices(
        self, account_ids: list[str] | None = None,
    ) -> list[DeviceSession]:
        wanted = set(account_ids) if account_ids is not None else None
        sessions = await asyncio.to_thread(self._backend.sessions)
        now = datetime.now(timezone.utc)
        return [
            DeviceSession(
                core_id="pptp", account_id=session.username,
                ip=session.calling_sid or None,
                connected_at=(now if not session.uptime_seconds else
                              datetime.fromtimestamp(now.timestamp() - session.uptime_seconds,
                                                     tz=timezone.utc)),
                last_activity=now,
                metadata={
                    "assigned_ipv4": session.assigned_ip,
                    "interface": session.ifname,
                    "encryption": "MPPE128" if session.compression == "mppe" else session.compression,
                    "carrier": "GRE/47", "security_class": "legacy_insecure",
                },
            )
            for session in sessions
            if session.state == "active" and (wanted is None or session.username in wanted)
        ]

    # ------------------------------------------------------------------ #
    # Sealed delivery only                                               #
    # ------------------------------------------------------------------ #
    def _delivery_values(
        self, account: UserAccount, context: DeliveryContext | None = None,
    ) -> tuple[str, dict[str, Any]]:
        self._validate_account(account)
        listener = self._listener()
        host = resolve_delivery_host(
            self.settings.get("advertise_host"), context,
            fallback=listener["listen"], allow_loopback=False,
        )
        if not host:
            raise CoreError("PPTP public advertise host is not configured")
        return host, listener

    async def build_client_config(
        self, account: UserAccount, node: Any | None = None,
    ) -> ClientConfig:
        host, listener = self._delivery_values(account)
        return ClientConfig(
            core_id="pptp", protocol="pptp", engine="pptp",
            payload={
                "server": host, "port": 1723, "username": account.account_id,
                "password": account.settings["password"],
                "authentication": "MS-CHAPv2", "encryption": "MPPE128",
                "network": "IPv4", "carrier": "GRE/47",
                "security_class": "legacy_insecure", "inbound": listener["tag"],
            },
            display_name=f"PPTP · Legacy / Insecure · {listener['tag']}",
        )

    async def describe_delivery(
        self, account: UserAccount, context: DeliveryContext | None = None,
    ) -> DeliveryProfile:
        host, listener = self._delivery_values(account, context)
        return DeliveryProfile(
            core_id="pptp",
            note=(
                "LEGACY_INSECURE: PPTP/MS-CHAPv2 has known cryptographic weaknesses. "
                "Use only when a legacy client has no modern VPN option."
            ),
            sections=[DeliverySection(
                protocol="pptp", title="PPTP — Legacy / Insecure", engine="pptp",
                inbound_tag=listener["tag"],
                note="IPv4 only · TCP/1723 + GRE/47 · MS-CHAPv2 · mandatory MPPE128",
                artifacts=[
                    DeliveryArtifact(
                        kind=ArtifactKind.FIELDS, label="Legacy PPTP credentials",
                        fields=[
                            DeliveryField(key="server", label="Server", value=host),
                            DeliveryField(key="port", label="Control port", value="1723"),
                            DeliveryField(key="carrier", label="Carrier", value="GRE/47"),
                            DeliveryField(key="username", label="Username", value=account.account_id),
                            DeliveryField(key="password", label="Password",
                                          value=str(account.settings["password"]), secret=True),
                            DeliveryField(key="authentication", label="Authentication",
                                          value="MS-CHAPv2"),
                            DeliveryField(key="encryption", label="Encryption",
                                          value="MPPE128 mandatory"),
                        ],
                    ),
                    DeliveryArtifact(
                        kind=ArtifactKind.NOTE, label="Security warning",
                        note=(
                            "Legacy / Insecure. Do not disable encryption or enable "
                            "PAP, CHAP-MD5, MS-CHAPv1, MPPE40, or IPv6."
                        ),
                    ),
                ],
            )],
        )
