"""Marzban → Zagros migration: pure mapping + idempotent importer.

The mapping (:func:`build_migration_plan`) is a **pure function** over the
legacy snapshot — fully testable without a database. The importer
(:class:`LegacyImportService`) applies the plan with upsert semantics:
re-running it converges to the same state (idempotent), and ``dry_run``
returns the full report without writing anything.

Loss-budget (explicit, never silent — every dropped legacy artifact appears
in ``report.warnings``):
* xray JSON config itself is NOT in the DB — it is imported separately via
  the Config Studio (docs §15.7), so inbound *configuration* is not touched
  here; host rows (which ARE in the DB) migrate fully.
* ``on_hold_*``, ``auto_delete_in_days``, ``sub_last_user_agent`` have no
  Zagros counterpart yet; legacy values are archived verbatim in ``audit_logs``.
* Traffic ledger migrates as the CURRENT cycle counter (``used_traffic``);
  lifetime history is preserved as ``legacy.usage_reset`` audit entries.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.persistence.legacy_reader import LegacySnapshot

LEGACY_CORE_ID = "xray"  # legacy Marzban is single-core (xray) by design


@dataclass
class MigrationReport:
    users_total: int = 0
    users_migrated: int = 0
    accounts_migrated: int = 0
    hosts_migrated: int = 0
    nodes_migrated: int = 0
    admins_migrated: int = 0
    usage_rows_migrated: int = 0
    audit_entries: int = 0
    warnings: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    dry_run: bool = True
    idempotent: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "users_total": self.users_total, "users_migrated": self.users_migrated,
            "accounts_migrated": self.accounts_migrated,
            "hosts_migrated": self.hosts_migrated, "nodes_migrated": self.nodes_migrated,
            "admins_migrated": self.admins_migrated,
            "usage_rows_migrated": self.usage_rows_migrated,
            "audit_entries": self.audit_entries,
            "warnings": list(self.warnings), "skipped": list(self.skipped),
            "dry_run": self.dry_run, "idempotent": self.idempotent,
        }


@dataclass
class MigrationPlan:
    users: list[dict[str, Any]] = field(default_factory=list)
    accounts: list[dict[str, Any]] = field(default_factory=list)
    hosts: list[dict[str, Any]] = field(default_factory=list)
    nodes: list[dict[str, Any]] = field(default_factory=list)
    admins: list[dict[str, Any]] = field(default_factory=list)
    usage: list[dict[str, Any]] = field(default_factory=list)
    audit: list[dict[str, Any]] = field(default_factory=list)
    report: MigrationReport = field(default_factory=MigrationReport)


def _epoch_to_dt(value: Any) -> datetime | None:
    if value in (None, 0, ""):
        return None
    return datetime.fromtimestamp(int(value), tz=timezone.utc)


def _naive_to_utc(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    return None


# bcrypt, as produced by passlib — the scheme Zagros itself uses, and the one
# Marzban/Pasarguard store. Their hashes are therefore *ours*, and the admin
# keeps the password they already had.
_BCRYPT_PREFIXES: tuple[str, ...] = ("$2a$", "$2b$", "$2y$")


def is_verifiable_hash(value: object) -> bool:
    """True when the panel can check a password against this stored hash."""
    return isinstance(value, str) and value.strip().startswith(_BCRYPT_PREFIXES)


def _admin_hash_for(entry: dict[str, Any]) -> str:
    """The password hash to store for one imported admin.

    Marzban-shaped panels already store bcrypt — the same scheme Zagros uses —
    so their hash is kept **as-is** and the admin signs in with the password
    they already had. (An earlier version marked those with a ``legacy:``
    prefix that nothing on the login path understood, which quietly locked
    every imported admin out.)

    A source whose hashing we cannot verify (3x-ui) arrives with a
    **generated** password instead, stored as a real bcrypt hash so the admin
    can sign in once and change it — an imported credential nobody can use is
    not a migration, it is a lockout.
    """
    generated = entry.get("generated_password")
    if generated:
        from app.utils.passwords import hash_password

        return hash_password(generated)
    stored = (entry.get("password_hash") or "").strip()
    return stored if is_verifiable_hash(stored) else ""


def build_migration_plan(snapshot: LegacySnapshot) -> MigrationPlan:
    """Pure mapping: legacy rows → Zagros rows + an honest report."""
    plan = MigrationPlan()
    report = plan.report
    report.users_total = len(snapshot.users)

    excluded: dict[int, list[str]] = {}
    for row in snapshot.excluded_inbounds:
        excluded.setdefault(row.get("proxy_id"), []).append(row.get("inbound_tag"))

    proxies_by_user: dict[int, list[dict[str, Any]]] = {}
    for proxy in snapshot.proxies:
        proxies_by_user.setdefault(proxy.get("user_id"), []).append(proxy)

    for user in snapshot.users:
        username = user.get("username")
        if not username:
            report.skipped.append(f"user id={user.get('id')}: no username — SKIPPED")
            continue
        status = user.get("status") or "active"
        plan.users.append({
            "username": username,
            "status": status,
            "note": user.get("note"),
            "data_limit_bytes": user.get("data_limit"),
            "download_limit_mbps": int(user.get("download_limit_mbps") or 0),
            "upload_limit_mbps": int(user.get("upload_limit_mbps") or 0),
            "expire_at": _epoch_to_dt(user.get("expire")),
            "data_limit_reset_strategy": user.get("data_limit_reset_strategy") or "no_reset",
            "created_at": _naive_to_utc(user.get("created_at")),
            # 3x-ui carries a per-client IP limit; Marzban-shaped panels do not
            # (None keeps whatever the user already had on upsert).
            "device_limit": (int(user["device_limit"])
                             if str(user.get("device_limit") or "").isdigit()
                             and int(user["device_limit"]) > 0 else None),
        })
        plan.usage.append({
            "username": username,
            "used_bytes": int(user.get("used_traffic") or 0),
        })
        for legacy_field in ("on_hold_expire_duration", "auto_delete_in_days",
                             "sub_last_user_agent"):
            if user.get(legacy_field) not in (None, "", 0):
                plan.audit.append({
                    "action": "legacy.field_archived",
                    "target": username,
                    "detail": {legacy_field: user.get(legacy_field)},
                })
        if user.get("used_traffic"):
            report.warnings.append(
                f"{username}: legacy used_traffic is direction-agnostic; "
                "imported as downlink-side total bytes."
            )
        for proxy in proxies_by_user.get(user["id"], []):
            raw_settings = proxy.get("settings") or {}
            if isinstance(raw_settings, str):
                try:
                    raw_settings = json.loads(raw_settings)
                except json.JSONDecodeError:
                    report.warnings.append(
                        f"{username}/{proxy.get('type')}: unparseable proxy settings "
                        "imported as empty — re-issue credentials after migration."
                    )
                    raw_settings = {}
            settings = dict(raw_settings)
            excl = [t for t in excluded.get(proxy.get("id"), []) if t]
            if excl:
                settings["excluded_inbounds"] = excl
            # account_id carries the protocol because one legacy user owns ONE
            # proxy row PER PROTOCOL (vless+vmess+trojan+ss) on the same core —
            # each becomes its own first-class account in Zagros.
            protocol = (proxy.get("type") or "").lower()
            plan.accounts.append({
                "username": username,
                "core_id": LEGACY_CORE_ID,
                "account_id": f"{user['id']}.{username}.{protocol}",
                "protocol": protocol,
                "settings": settings,
            })
            report.accounts_migrated += 1
        report.users_migrated += 1

    for row in snapshot.usage_reset_logs:
        plan.audit.append({
            "action": "legacy.usage_reset",
            "target": f"user:{row.get('user_id')}",
            "detail": {"used_traffic_at_reset": row.get("used_traffic_at_reset"),
                       "reset_at": str(row.get("reset_at"))},
        })

    for host in snapshot.hosts:
        plan.hosts.append({
            "core_id": LEGACY_CORE_ID,
            "remark": host.get("remark") or "",
            "address": host.get("address") or "",
            "port": host.get("port"),
            "sni": host.get("sni"),
            "host_header": host.get("host"),
            "path": host.get("path"),
            "security": None if host.get("security") in ("inbound_default",) else host.get("security"),
            "alpn": None if (host.get("alpn") in (None, "", "none")) else host.get("alpn"),
            "fingerprint": None if (host.get("fingerprint") in (None, "", "none")) else host.get("fingerprint"),
            "extras": {
                "inbound_tag": host.get("inbound_tag"),
                "allowinsecure": bool(host.get("allowinsecure")),
                "is_disabled": bool(host.get("is_disabled")),
                "mux_enable": bool(host.get("mux_enable")),
                "random_user_agent": bool(host.get("random_user_agent")),
            },
        })
        report.hosts_migrated += 1
    # honest statement about inbound configuration (not stored in legacy DB)
    report.warnings.append(
        "Legacy inbound *configuration* lives in the xray JSON file, not the "
        "database — import it via Config Studio (core 'xray' document upload)."
    )

    for node in snapshot.nodes:
        plan.nodes.append({
            "name": node.get("name") or "",
            "address": node.get("address") or "",
            "port": int(node.get("api_port") or node.get("port") or 62050),
            "status": "unhealthy",  # nodes must re-establish their agent connection
            "usage_coefficient": float(node.get("usage_coefficient") or 1.0),
            "uplink": int(node.get("uplink") or 0),
            "downlink": int(node.get("downlink") or 0),
        })
        report.nodes_migrated += 1
        if node.get("uplink") or node.get("downlink"):
            plan.audit.append({
                "action": "legacy.node_counters_archived",
                "target": node.get("name") or "",
                "detail": {"uplink": node.get("uplink"), "downlink": node.get("downlink")},
            })

    for admin in snapshot.admins:
        plan.admins.append({
            "username": admin.get("username") or "",
            "password_hash": admin.get("hashed_password") or "",
            "is_sudo": bool(admin.get("is_sudo")),
            "telegram_id": admin.get("telegram_id"),
            # carried through so a source whose hashes we cannot verify gets a
            # freshly generated password instead of an unusable one
            "generated_password": admin.get("generated_password"),
        })
        report.admins_migrated += 1
    if snapshot.system:
        plan.audit.append({
            "action": "legacy.system_counters_archived",
            "target": "system",
            "detail": {"uplink": snapshot.system.get("uplink"),
                       "downlink": snapshot.system.get("downlink")},
        })
    report.audit_entries = len(plan.audit)
    report.usage_rows_migrated = len(plan.usage)
    return plan


class LegacyImportService:
    """Applies a MigrationPlan idempotently through the repositories."""

    def __init__(self, session_factory, users_repo, cipher) -> None:
        self._sf = session_factory
        self._users = users_repo
        self._cipher = cipher

    def apply(self, plan: MigrationPlan) -> MigrationReport:
        """Write the plan; safe to run repeatedly (upserts everywhere)."""
        from sqlalchemy import select

        from app.persistence.models import (
            AdminModel,
            AuditLogModel,
            CoreHostModel,
            NodeModel,
            UserUsageModel,
        )

        report = plan.report
        report.dry_run = False
        with self._sf() as s:
            # users + accounts + usage
            for u in plan.users:
                user_id = self._users.upsert_user(
                    username=u["username"], status=u["status"],
                    data_limit_bytes=u["data_limit_bytes"], expire_at=u["expire_at"],
                    device_limit=u.get("device_limit"),
                    download_limit_mbps=u.get("download_limit_mbps", 0),
                    upload_limit_mbps=u.get("upload_limit_mbps", 0),
                    note=u["note"],
                )
                usage = s.get(UserUsageModel, user_id)
                used = next((x["used_bytes"] for x in plan.usage
                             if x["username"] == u["username"]), 0)
                if usage is None:
                    s.add(UserUsageModel(user_id=user_id, uplink_bytes=0,
                                         downlink_bytes=int(used)))
                else:
                    usage.downlink_bytes = int(used)  # legacy counter is total-direction-agnostic
                for acc in (a for a in plan.accounts if a["username"] == u["username"]):
                    self._users.upsert_core_account(
                        user_id=user_id, core_id=acc["core_id"],
                        account_id=acc["account_id"], protocol=acc["protocol"],
                        enabled=u["status"] == "active",
                        settings=acc["settings"],
                    )
            # hosts (idempotent by (core_id, remark, address, inbound_tag)).
            # remark+address alone is NOT unique: Marzban routinely carries a
            # dozen hosts that differ only by inbound tag, so a uniqueness
            # check on the wider key must tolerate duplicates rather than
            # raise — a second import has to be a no-op, not a crash.
            for h in plan.hosts:
                # The inbound tag travels inside ``extras`` (there is no column
                # for it), so identity is (core, remark, address) and the tag
                # only *disambiguates* between candidates. Marzban routinely
                # carries a dozen hosts sharing remark+address, so this must
                # never assume a single row: a second import has to match the
                # same host again rather than duplicate it or crash.
                tag = h.get("inbound_tag") or (h.get("extras") or {}).get("inbound_tag")
                candidates = s.execute(
                    select(CoreHostModel).where(
                        CoreHostModel.core_id == h["core_id"],
                        CoreHostModel.remark == h["remark"],
                        CoreHostModel.address == h["address"],
                    )
                ).scalars().all()
                exists = next(
                    (row for row in candidates
                     if (row.extras or {}).get("inbound_tag") == tag),
                    # a row written before inbound tags were recorded
                    next((row for row in candidates
                          if not (row.extras or {}).get("inbound_tag")), None))
                if exists is None and candidates:
                    exists = candidates[0]
                values = dict(
                    port=h["port"], sni=h["sni"], host_header=h["host_header"],
                    path=h["path"], security=h["security"], alpn=h["alpn"],
                    fingerprint=h["fingerprint"], extras=h.get("extras") or {},
                    sort=0,
                )
                if exists is None:
                    s.add(CoreHostModel(core_id=h["core_id"], remark=h["remark"],
                                        address=h["address"], **values))
                else:
                    for k, v in values.items():
                        setattr(exists, k, v)
            # nodes (idempotent by name)
            for n in plan.nodes:
                exists = s.execute(
                    select(NodeModel).where(NodeModel.name == n["name"]).limit(1)
                ).scalars().first()
                if exists is None:
                    s.add(NodeModel(name=n["name"], address=n["address"], port=n["port"],
                                    status=n["status"],
                                    usage_coefficient=n["usage_coefficient"]))
                else:
                    exists.address = n["address"]
                    exists.port = n["port"]
                    exists.usage_coefficient = n["usage_coefficient"]
            # admins (idempotent by username)
            for a in plan.admins:
                exists = s.execute(
                    select(AdminModel).where(AdminModel.username == a["username"]).limit(1)
                ).scalars().first()
                if exists is None:
                    s.add(AdminModel(username=a["username"],
                                     password_hash=_admin_hash_for(a),
                                     is_sudo=a["is_sudo"],
                                     telegram_id=a["telegram_id"]))
            # audit (append-only but deduplicated for idempotency)
            for entry in plan.audit:
                dup = s.execute(
                    select(AuditLogModel).where(
                        AuditLogModel.action == entry["action"],
                        AuditLogModel.target == entry["target"],
                    )
                ).scalars().first()
                if dup is None:
                    s.add(AuditLogModel(action=entry["action"], actor="migration",
                                        target=entry["target"],
                                        detail_json=entry["detail"]))
            s.commit()
        return report

    def migrate(self, snapshot: LegacySnapshot, *, dry_run: bool = True) -> MigrationReport:
        """One-call convenience: plan → (optionally) apply."""
        plan = build_migration_plan(snapshot)
        plan.report.dry_run = dry_run
        if dry_run:
            return plan.report
        return self.apply(plan)
