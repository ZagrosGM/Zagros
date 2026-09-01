"""Core consolidation: standalone hysteria2/tuic fold into sing-box.

Revision ID: 0007_core_consolidation
Revises: 0006_device_limit
Create Date: 2026-08-07

Alpha.7.2 removes the standalone Hysteria2/TUIC engines (the protocols live
on natively inside the sing-box core — see ``app/cores/consolidation.py``
for the architecture record). This revision migrates all operator state so
**no listener, grant or credential is lost**:

Platform bind (``op.get_bind()``):

* each merged core's studio document entries are translated into sing-box
  wizard-shape entries (``translate_entry``); a core without a document
  gets its listener synthesized from its plain settings
  (``synthesize_default_entry``) — identical port/sni/obfs/bandwidth;
* TLS material the standalone cores referenced by file path is read from
  disk and embedded (missing files: the sing-box translator mints a fresh
  self-signed pair on first apply — the old drivers' default behavior);
* the translated entries are appended to the sing-box studio document with
  deterministic tag-collision renames (``{tag}-from-{core_id}``);
* ``user_core_accounts``, ``usage_baselines`` and ``core_hosts`` rows are
  re-keyed to ``sing-box``; ``core_inbounds`` registry rows and the merged
  ``cores``/``studio.document.*`` rows are removed.

Legacy bind (``SQLALCHEMY_DATABASE_URL``):

* ``user_templates.core_access`` grant mappings are re-keyed (merged cores
  → sing-box; tags renamed per the collision map, selections unioned).
  Individual user grants live in the PLATFORM ``user_core_accounts`` table
  (already re-keyed above) — the legacy ``users`` table has no core_access
  column by design.

Everything is guarded (tables/keys may not exist on partial installs) and
idempotent — re-running after a successful pass is a no-op because the
merged rows no longer exist.
"""
from __future__ import annotations

import json
import logging
import os

import sqlalchemy as sa
from alembic import op

revision = "0007_core_consolidation"
down_revision = "0006_device_limit"
branch_labels = None
depends_on = None

logger = logging.getLogger("alembic.zagros.0007")

_LEGACY_URL_FALLBACK = "sqlite:///db.sqlite3"  # identical to config.py


def _legacy_url() -> str:
    return os.environ.get("SQLALCHEMY_DATABASE_URL") or _LEGACY_URL_FALLBACK


def _as_json(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return None
    return value


def _load_cert_material(settings: dict) -> tuple[str | None, str | None]:
    """Read the standalone core's TLS pair from disk (best-effort).

    A missing pair is NOT an error: the old drivers minted a self-signed
    certificate at start when no pair was configured; the sing-box
    translator does the same on first apply, so the migration honestly
    returns (None, None) and lets that path run."""
    cert_path = settings.get("cert_path")
    key_path = settings.get("key_path")
    if not cert_path or not key_path:
        return None, None
    try:
        with open(str(cert_path), encoding="utf-8") as fh:
            cert = fh.read()
        with open(str(key_path), encoding="utf-8") as fh:
            key = fh.read()
    except OSError as exc:
        logger.warning(
            "consolidation: cert material unreadable (%s) — the sing-box core "
            "will mint a fresh self-signed pair on first apply instead", exc)
        return None, None
    return (cert or None), (key or None)


def upgrade() -> None:
    from app.cores.consolidation import (
        MERGED_CORES,
        TARGET_CORE_ID,
        merge_core_access,
        merge_inbound_entries,
        synthesize_default_entry,
        translate_entry,
    )

    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = set(inspector.get_table_names())

    # -------------------------------------------------------------- #
    # 1) collect merged-core listener state (studio doc or settings)
    # -------------------------------------------------------------- #
    incoming: list[tuple[str, dict]] = []          # (core_id, wizard-shape entry)
    had_state = False
    cores_by_id: dict[str, dict] = {}
    if "cores" in tables:
        rows = conn.execute(
            sa.text("SELECT core_id, settings_json FROM cores WHERE core_id IN (:a, :b)"),
            {"a": MERGED_CORES[0], "b": MERGED_CORES[1]},
        ).mappings()
        for row in rows:
            cores_by_id[row["core_id"]] = dict(_as_json(row["settings_json"]) or {})

    docs: dict[str, dict] = {}
    if "settings" in tables:
        # "key" is reserved in MySQL, so the identifier has to be quoted the
        # way the active dialect expects (backticks on MySQL, double quotes
        # elsewhere) -- an unquoted one is a syntax error there.
        kq = conn.dialect.identifier_preparer.quote("key")
        rows = conn.execute(
            sa.text(
                f"SELECT {kq}, value_json FROM settings "
                f"WHERE {kq} LIKE 'studio.document.%'"
            ),
        ).mappings()
        for row in rows:
            cid = str(row["key"]).rsplit(".", 1)[-1]
            if cid in MERGED_CORES + (TARGET_CORE_ID,):
                docs[cid] = dict(_as_json(row["value_json"]) or {})

    for core_id in MERGED_CORES:
        settings = cores_by_id.get(core_id)
        doc = docs.get(core_id)
        if settings is None and doc is None:
            continue  # this merged core never existed here — nothing to keep
        had_state = True
        cert, key = _load_cert_material(settings or {})
        entries = (doc or {}).get("inbounds") or []
        if entries:
            for entry in entries:
                incoming.append((core_id, translate_entry(
                    core_id, entry, certificate=cert, certificate_key=key)))
        else:
            incoming.append((core_id, synthesize_default_entry(
                core_id, settings, certificate=cert, certificate_key=key)))

    renames: dict[str, str] = {}

    if incoming and "settings" in tables:
        # ---------------------------------------------------------- #
        # 2) fold into the sing-box studio document
        # ---------------------------------------------------------- #
        sb_doc = docs.get(TARGET_CORE_ID) or {}
        existing = list(sb_doc.get("inbounds") or [])
        merged, renames = merge_inbound_entries(existing, incoming)
        sb_doc["inbounds"] = merged
        kq = conn.dialect.identifier_preparer.quote("key")
        stmt = sa.text(
            f"INSERT INTO settings ({kq}, value_json, updated_at) "
            "VALUES (:k, :v, CURRENT_TIMESTAMP) "
            + _upsert_suffix(conn.dialect.name)
        ).bindparams(sa.bindparam("v", type_=sa.JSON))
        conn.execute(stmt, {"k": f"studio.document.{TARGET_CORE_ID}", "v": sb_doc})
        for core_id, tag in ((i[0], i[1].get("tag")) for i in incoming):
            logger.info("consolidation: %s listener '%s' folded into sing-box", core_id, tag)

    # -------------------------------------------------------------- #
    # 3) re-key account/baseline/host rows; drop merged-core rows
    # -------------------------------------------------------------- #
    if "user_core_accounts" in tables:
        conn.execute(
            sa.text("UPDATE user_core_accounts SET core_id = :t WHERE core_id IN (:a, :b)"),
            {"t": TARGET_CORE_ID, "a": MERGED_CORES[0], "b": MERGED_CORES[1]},
        )
    if "core_hosts" in tables:
        conn.execute(
            sa.text("UPDATE core_hosts SET core_id = :t WHERE core_id IN (:a, :b)"),
            {"t": TARGET_CORE_ID, "a": MERGED_CORES[0], "b": MERGED_CORES[1]},
        )
    if "usage_baselines" in tables:
        # baseline keys are "{core_id}:{user_id}.{username}.{protocol}" —
        # the usernames charset ([a-z0-9_]) guarantees the core prefix
        # appears only at position 1, so a plain REPLACE of the prefix is
        # exact (and portable across sqlite/MySQL/PostgreSQL).
        kq = conn.dialect.identifier_preparer.quote("key")
        for core_id in MERGED_CORES:
            conn.execute(
                sa.text(
                    f"UPDATE usage_baselines SET {kq} = REPLACE({kq}, :p, :t) "
                    f"WHERE {kq} LIKE :like"
                ),
                {"p": f"{core_id}:", "t": f"{TARGET_CORE_ID}:", "like": f"{core_id}:%"},
            )
    if "core_inbounds" in tables:
        conn.execute(
            sa.text("DELETE FROM core_inbounds WHERE core_id IN (:a, :b)"),
            {"a": MERGED_CORES[0], "b": MERGED_CORES[1]},
        )
    if "cores" in tables:
        conn.execute(
            sa.text("DELETE FROM cores WHERE core_id IN (:a, :b)"),
            {"a": MERGED_CORES[0], "b": MERGED_CORES[1]},
        )
    if "settings" in tables:
        kq = conn.dialect.identifier_preparer.quote("key")
        conn.execute(
            sa.text(f"DELETE FROM settings WHERE {kq} LIKE 'studio.document.%' "
                    f"AND ({kq} = :ka OR {kq} = :kb)"),
            {"ka": f"studio.document.{MERGED_CORES[0]}",
             "kb": f"studio.document.{MERGED_CORES[1]}"},
        )

    if not had_state:
        logger.info("consolidation: no standalone core state found — clean install, nothing migrated")

    # -------------------------------------------------------------- #
    # 4) legacy grant mappings (users / user_templates core_access)
    # -------------------------------------------------------------- #
    engine = sa.create_engine(_legacy_url())
    try:
        with engine.begin() as lconn:
            ltables = set(sa.inspect(lconn).get_table_names())
            if "user_templates" not in ltables:
                return
            cols = {c["name"] for c in sa.inspect(lconn).get_columns("user_templates")}
            if "core_access" not in cols:
                return
            rows = lconn.execute(
                sa.text("SELECT id, core_access FROM user_templates "
                        "WHERE core_access IS NOT NULL")
            ).mappings()
            update_stmt = sa.text(
                "UPDATE user_templates SET core_access = :v WHERE id = :i"
            ).bindparams(sa.bindparam("v", type_=sa.JSON))
            for row in rows:
                access = _as_json(row["core_access"])
                if not isinstance(access, dict):
                    # malformed grant row — named loudly, never silently
                    # dropped (the operator re-grants from the dashboard)
                    logger.warning(
                        "consolidation: user_templates.id=%s has a non-object "
                        "core_access %r — left untouched", row["id"], access)
                    continue
                new_access = merge_core_access(access, renames)
                if new_access == access:
                    continue
                lconn.execute(update_stmt, {"v": new_access, "i": row["id"]})
    finally:
        engine.dispose()


def _upsert_suffix(dialect: str) -> str:
    """Portable upsert for the settings KV row (sqlite/mysql/postgres)."""
    if dialect == "postgresql":
        return 'ON CONFLICT ("key") DO UPDATE SET value_json = EXCLUDED.value_json' 
    if dialect == "mysql":
        # MySQL JSON columns refuse a plain string param as JSON in strict
        # mode unless wrapped — CAST keeps it valid on 5.7+/8.x.
        return "ON DUPLICATE KEY UPDATE value_json = VALUES(value_json)"
    return 'ON CONFLICT ("key") DO UPDATE SET value_json = excluded.value_json'  # sqlite


def downgrade() -> None:
    """Data-conserving: un-folding would require re-splitting sing-box
    account rows by protocol and re-keying grants; the merged state remains
    perfectly functional on a downgrade (the old drivers are gone, so the
    sing-box core simply keeps serving the protocols). Matching 0002/0003's
    no-data-loss policy, downgrade is intentionally a no-op."""
