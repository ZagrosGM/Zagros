"""Cross-core source-IP ceiling with timed, port-scoped bans.

Unlike the pre-v1.0.4 implementation this service NEVER changes user status
and NEVER removes an account. It observes authenticated source IPs across all
cores, keeps the earliest ``ip_limit`` addresses, and temporarily blocks only
new overflow addresses on managed VPN listeners. Dashboard/subscription HTTP
ports are not listener claims and therefore remain reachable.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import shutil
import subprocess
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, update

from app.persistence.models import IPBanModel, UserModel

logger = logging.getLogger(__name__)
SETTINGS_KEY = "ip_limits"
DEFAULT_BAN_MINUTES = 15
DEFAULT_REVIEW_SECONDS = 5
_TABLE = "zagros_ip_limit"


def load_settings(runtime) -> dict[str, int]:
    from app.platform.settings_kv import load

    raw = load(runtime.session_factory, SETTINGS_KEY, {})
    return {
        "ban_duration_minutes": max(1, min(10_080, int(
            raw.get("ban_duration_minutes") or DEFAULT_BAN_MINUTES))),
        "review_interval_seconds": max(5, min(300, int(
            raw.get("review_interval_seconds") or DEFAULT_REVIEW_SECONDS))),
    }


def save_settings(runtime, *, ban_duration_minutes: int,
                  review_interval_seconds: int) -> dict[str, int]:
    from app.platform.settings_kv import save

    if not 1 <= int(ban_duration_minutes) <= 10_080:
        raise ValueError("ban duration must be between 1 and 10080 minutes")
    if not 5 <= int(review_interval_seconds) <= 300:
        raise ValueError("review interval must be between 5 and 300 seconds")
    value = {
        "ban_duration_minutes": int(ban_duration_minutes),
        "review_interval_seconds": int(review_interval_seconds),
    }
    save(runtime.session_factory, SETTINGS_KEY, value)
    return value


async def _xray_owner_id(runtime, email: str) -> int | None:
    try:
        _legacy, username = str(email).split(".", 1)
    except ValueError:
        return None
    row = await asyncio.to_thread(runtime.users.get_user_by_username, username)
    return None if row is None else int(row.id)


def _canonical_ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


async def collect_observations(runtime) -> tuple[
    dict[int, dict[str, datetime]], set[int], list[str], int
]:
    """Collect one authenticated online poll for IP limits and Monitoring.

    This is deliberately the only cross-core/node online poll. Monitoring
    consumes the same real rows, so opening its page adds no driver, CPU or
    network sampling load. Source-IP active intervals are persisted separately
    from stable subscription HWIDs.
    """
    from app.cores.types import Capability

    owners = await asyncio.to_thread(runtime.users.account_owners)
    now = datetime.now(timezone.utc)
    settings = await asyncio.to_thread(load_settings, runtime)
    reset_after = max(15, settings["review_interval_seconds"] * 2)
    monitor_rows: list[dict[str, Any]] = []
    online_users: set[int] = set()
    failed: list[str] = []
    probed = 0

    for core_id in runtime.core_manager.list_cores():
        if not runtime.core_manager.is_enabled(core_id):
            continue
        try:
            driver = runtime.core_manager.get(core_id)
        except Exception:
            continue
        if Capability.ONLINE_TRACKING not in driver.metadata.capabilities:
            continue
        try:
            rows = await driver.get_online_devices(account_ids=None)
        except Exception as exc:  # one core cannot blind every other core
            logger.warning("IP observation failed for core %s: %s", core_id, exc)
            failed.append(core_id)
            continue
        probed += 1
        for row in rows or []:
            owner = owners.get((row.core_id, row.account_id))
            if owner is None and core_id == "xray":
                owner = await _xray_owner_id(runtime, row.account_id)
            if owner is None:
                continue
            online_users.add(int(owner))
            monitor_rows.append({
                "user_id": int(owner), "core_id": str(row.core_id),
                "account_id": str(row.account_id),
                "node_id": getattr(row, "node_id", None),
                "ip": _canonical_ip(row.ip),
                "connected_at": getattr(row, "connected_at", None),
                "last_activity": getattr(row, "last_activity", None),
                "metadata": dict(getattr(row, "metadata", {}) or {}),
            })

    try:
        from app.nodes.service import collect_node_devices
        node_rows, node_failed = await collect_node_devices(runtime)
    except Exception as exc:
        logger.debug("node IP observation unavailable: %s", exc)
        node_rows, node_failed = [], []
    observed_nodes: set[int] = set()
    for item in node_rows:
        owner = owners.get((item.get("core_id"), item.get("account_id")))
        if owner is None and item.get("core_id") == "xray":
            owner = await _xray_owner_id(runtime, str(item.get("account_id")))
        if owner is None:
            continue
        online_users.add(int(owner))
        node_id = item.get("node_id")
        if node_id is not None:
            observed_nodes.add(int(node_id))
        monitor_rows.append({
            "user_id": int(owner),
            "core_id": str(item.get("core_id") or ""),
            "account_id": str(item.get("account_id") or ""),
            "node_id": int(node_id) if node_id is not None else None,
            "ip": _canonical_ip(item.get("ip")),
            "connected_at": item.get("connected_at"),
            "last_activity": item.get("last_activity"),
            "metadata": dict(item.get("metadata") or {}),
        })
    probed += len(observed_nodes)
    failed.extend(f"node:{name}" for name in node_failed)

    first_by_ip: dict[tuple[int, str], datetime] = {}
    try:
        from app.platform.monitoring import publish_poll
        first_by_ip = await publish_poll(
            runtime, monitor_rows, now=now, failed_sources=failed,
            probed_sources=probed, reset_after_seconds=reset_after)
    except Exception as exc:  # Monitoring persistence must not disable limits
        logger.warning("Monitoring snapshot persistence failed: %s", exc)

    observed: dict[int, dict[str, datetime]] = defaultdict(dict)
    for row in monitor_rows:
        ip = row.get("ip")
        if not ip:
            continue
        owner = int(row["user_id"])
        first = first_by_ip.get((owner, ip), now)
        connected = row.get("connected_at")
        if isinstance(connected, str):
            try:
                connected = datetime.fromisoformat(connected.replace("Z", "+00:00"))
            except ValueError:
                connected = None
        if isinstance(connected, datetime):
            if connected.tzinfo is None:
                connected = connected.replace(tzinfo=timezone.utc)
            first = min(first, connected.astimezone(timezone.utc))
        observed[owner][ip] = min(observed[owner].get(ip, first), first)
    return dict(observed), online_users, sorted(failed), probed


def _expire_and_load(runtime, now: datetime) -> tuple[list[IPBanModel], int]:
    with runtime.session_factory() as session:
        result = session.execute(
            update(IPBanModel)
            .where(IPBanModel.active.is_(True), IPBanModel.expires_at <= now)
            .values(active=False)
        )
        expired = max(0, int(result.rowcount or 0))
        session.commit()
        rows = list(session.execute(
            select(IPBanModel)
            .where(IPBanModel.active.is_(True), IPBanModel.expires_at > now)
        ).scalars())
        for row in rows:
            session.expunge(row)
        return rows, expired


def _limits(runtime) -> dict[int, int]:
    with runtime.session_factory() as session:
        return {int(uid): int(limit) for uid, limit in session.execute(
            select(UserModel.id, UserModel.ip_limit)
            .where(UserModel.ip_limit.is_not(None), UserModel.ip_limit > 0)
        )}


def _insert_bans(runtime, candidates: list[tuple[int, str]], now: datetime,
                 minutes: int) -> list[IPBanModel]:
    if not candidates:
        return []
    expires = now + timedelta(minutes=minutes)
    created: list[IPBanModel] = []
    with runtime.session_factory() as session:
        for user_id, ip in candidates:
            row = IPBanModel(
                user_id=user_id, ip=ip, banned_at=now, expires_at=expires,
                reason="source IP exceeded user ip_limit", active=True,
            )
            session.add(row)
            created.append(row)
        session.commit()
        for row in created:
            session.refresh(row)
            session.expunge(row)
    return created


async def managed_ports(runtime) -> tuple[set[int], set[int]]:
    tcp: set[int] = set()
    udp: set[int] = set()
    for core_id in runtime.core_manager.list_cores():
        if not runtime.core_manager.is_enabled(core_id):
            continue
        try:
            claims = await runtime.core_manager.get(core_id).listener_claims()
        except Exception as exc:
            logger.warning("could not inspect %s listener ports for IP bans: %s",
                           core_id, exc)
            continue
        for claim in claims:
            try:
                address = ipaddress.ip_address(str(claim.address))
                if address.is_loopback:
                    continue  # management/chain listeners are not VPN ingress
            except ValueError:
                pass
            if claim.protocol == "accel-ppp-cli":
                continue
            if claim.transport.lower() == "udp":
                udp.add(int(claim.port))
            else:
                tcp.add(int(claim.port))
            # SoftEther's OpenVPN clone uses both transports despite its
            # collision claim historically being represented as TCP.
            if claim.protocol == "openvpn-clone":
                udp.add(int(claim.port))
    return tcp, udp


def _nft_script(bans: list[IPBanModel], tcp: set[int], udp: set[int],
                now: datetime) -> str:
    v4: dict[str, int] = {}
    v6: dict[str, int] = {}
    for ban in bans:
        remaining = max(1, int((ban.expires_at - now).total_seconds()))
        target = v6 if ipaddress.ip_address(ban.ip).version == 6 else v4
        target[ban.ip] = max(target.get(ban.ip, 0), remaining)
    elements = lambda rows: ", ".join(
        f"{ip} timeout {seconds}s" for ip, seconds in sorted(rows.items()))
    ports = lambda rows: ", ".join(str(port) for port in sorted(rows))

    def set_line(name: str, nft_type: str, values: str, *, timed: bool = False) -> str:
        # nft rejects ``elements = { }``. Empty address/transport families are
        # normal, so omit the elements clause until that set has members.
        flags = " flags timeout;" if timed else ""
        initial = f" elements = {{ {values} }};" if values else ""
        return f" set {name} {{ type {nft_type};{flags}{initial} }}"

    return f"""table inet {_TABLE} {{
{set_line('banned_v4', 'ipv4_addr', elements(v4), timed=True)}
{set_line('banned_v6', 'ipv6_addr', elements(v6), timed=True)}
{set_line('vpn_tcp_ports', 'inet_service', ports(tcp))}
{set_line('vpn_udp_ports', 'inet_service', ports(udp))}
 chain input {{
  type filter hook input priority -210; policy accept;
  ip saddr @banned_v4 tcp dport @vpn_tcp_ports counter drop
  ip saddr @banned_v4 udp dport @vpn_udp_ports counter drop
  ip6 saddr @banned_v6 tcp dport @vpn_tcp_ports counter drop
  ip6 saddr @banned_v6 udp dport @vpn_udp_ports counter drop
 }}
}}
"""


def apply_firewall(bans: list[IPBanModel], tcp: set[int], udp: set[int],
                   now: datetime, runner=subprocess.run) -> bool:
    nft = shutil.which("nft")
    if not nft:
        logger.error("IP limits cannot be enforced: nft is not installed")
        return False
    exists = runner([nft, "list", "table", "inet", _TABLE],
                    capture_output=True, text=True).returncode == 0
    if not bans:
        if exists:
            result = runner([nft, "delete", "table", "inet", _TABLE],
                            capture_output=True, text=True)
            return result.returncode == 0
        return True
    script = _nft_script(bans, tcp, udp, now)
    if exists:
        # The following batch is intentionally one nft transaction: no window
        # exists with the old table deleted and the new bans absent.
        script = f"delete table inet {_TABLE}\n" + script
    result = runner([nft, "-f", "-"], input=script,
                    capture_output=True, text=True)
    if result.returncode:
        logger.error("could not apply timed IP bans: %s", result.stderr.strip())
        return False
    return True


def _drop_conntrack(ip: str, tcp: set[int], udp: set[int]) -> int:
    tool = shutil.which("conntrack")
    if not tool:
        return 0
    removed = 0
    for proto, ports in (("tcp", tcp), ("udp", udp)):
        for port in ports:
            result = subprocess.run(
                [tool, "-D", "-s", ip, "-p", proto, "--dport", str(port)],
                capture_output=True, text=True)
            if result.returncode == 0:
                removed += 1
    return removed


async def _push_node_bans(runtime, bans: list[IPBanModel]) -> int:
    """Converge the same timed ban set on every paired traffic node."""
    try:
        from app.nodes.service import paired_nodes, _client
    except Exception:
        return 0
    payload = [{"ip": row.ip, "expires_at": row.expires_at.isoformat()}
               for row in bans]
    pushed = 0
    for node in paired_nodes(runtime):
        try:
            await asyncio.to_thread(_client(runtime, node).push_ip_bans, payload)
            pushed += 1
        except Exception as exc:
            logger.warning("could not push IP bans to node %s: %s", node.id, exc)
    return pushed


async def _terminate(runtime, ips: set[str], tcp: set[int], udp: set[int]) -> int:
    closed = 0
    for core_id in runtime.core_manager.list_cores():
        try:
            driver = runtime.core_manager.get(core_id)
        except Exception:
            continue
        terminate = getattr(driver, "terminate_source_ip", None)
        if not callable(terminate):
            continue
        for ip in ips:
            try:
                closed += int(await terminate(ip) or 0)
            except Exception as exc:
                logger.warning("%s could not close connections from %s: %s",
                               core_id, ip, exc)
    for ip in ips:
        closed += await asyncio.to_thread(_drop_conntrack, ip, tcp, udp)
    return closed


_LAST_RUN = 0.0
_RUN_GUARD = threading.Lock()


async def run_once(runtime, *, force: bool = False) -> dict[str, int]:
    """Collect, choose overflow addresses, persist/apply timed bans once."""
    global _LAST_RUN
    if not _RUN_GUARD.acquire(blocking=False):
        return {"observed_ips": 0, "banned": 0, "expired": 0,
                "connections_closed": 0, "skipped": 1}
    try:
        loop_now = asyncio.get_running_loop().time()
        settings = await asyncio.to_thread(load_settings, runtime)
        if not force and loop_now - _LAST_RUN < settings["review_interval_seconds"] - 0.1:
            return {"observed_ips": 0, "banned": 0, "expired": 0,
                    "connections_closed": 0, "skipped": 1}
        _LAST_RUN = loop_now
        now = datetime.now(timezone.utc)
        before, expired = await asyncio.to_thread(_expire_and_load, runtime, now)
        active_before = {(row.user_id, row.ip) for row in before}
        globally_banned = {row.ip for row in before}
        observed, online_users, failed, probed = await collect_observations(runtime)
        limits = await asyncio.to_thread(_limits, runtime)
        candidates: list[tuple[int, str]] = []
        for user_id, limit in limits.items():
            available = [(ip, first) for ip, first in observed.get(user_id, {}).items()
                         if ip not in globally_banned]
            available.sort(key=lambda item: (item[1], item[0]))
            for ip, _first in available[limit:]:
                if (user_id, ip) not in active_before:
                    candidates.append((user_id, ip))
        created = await asyncio.to_thread(
            _insert_bans, runtime, candidates, now,
            settings["ban_duration_minutes"])
        all_bans = before + created
        tcp, udp = await managed_ports(runtime)
        firewall_ok = await asyncio.to_thread(
            apply_firewall, all_bans, tcp, udp, now)
        await _push_node_bans(runtime, all_bans)
        new_ips = {row.ip for row in created}
        # Reassert termination for all active bans. If nft was temporarily
        # unavailable on the creation pass, the first successful retry still
        # kills the already-recorded overflow connections.
        banned_ips = {row.ip for row in all_bans}
        closed = await _terminate(runtime, banned_ips, tcp, udp) if firewall_ok else 0

        # Preserve the existing unified-online behavior without altering status.
        try:
            from app.platform.device_limits import publish_online_snapshot
            await publish_online_snapshot(runtime, online_users, failed, probed)
        except Exception as exc:
            logger.debug("online snapshot publish failed: %s", exc)
        stats = {
            "observed_ips": sum(len(values) for values in observed.values()),
            "banned": len(created), "expired": expired,
            "connections_closed": closed, "skipped": 0,
        }
        if created:
            logger.warning("IP limit: blocked %s for %d minute(s) on VPN ports only",
                           sorted(new_ips), settings["ban_duration_minutes"])
        return stats
    finally:
        _RUN_GUARD.release()


def list_bans(runtime, *, active_only: bool = False) -> list[dict]:
    now = datetime.now(timezone.utc)
    _active, _expired = _expire_and_load(runtime, now)
    with runtime.session_factory() as session:
        stmt = select(IPBanModel).order_by(IPBanModel.banned_at.desc())
        if active_only:
            stmt = stmt.where(IPBanModel.active.is_(True), IPBanModel.expires_at > now)
        return [{
            "id": row.id, "user_id": row.user_id, "ip": row.ip,
            "banned_at": row.banned_at.isoformat(),
            "expires_at": row.expires_at.isoformat(),
            "reason": row.reason,
            "active": bool(row.active and row.expires_at > now),
        } for row in session.execute(stmt.limit(500)).scalars()]


def revoke_ban(runtime, ban_id: int) -> bool:
    with runtime.session_factory() as session:
        row = session.get(IPBanModel, ban_id)
        if row is None:
            return False
        row.active = False
        session.commit()
        return True
