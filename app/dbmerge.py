"""One-time merge of the legacy (Marzban-compat) database into the main one.

f-dbmerge: the panel historically ran TWO databases — the platform database
(``ZAGROS_DATABASE_URL``) and the Marzban-compat layer (``SQLALCHEMY_
DATABASE_URL``). This module merges the latter INTO the former:

* the four legacy tables whose names collide with platform tables are
  renamed (``users->legacy_users``, ``admins->legacy_admins``,
  ``nodes->legacy_nodes``, ``next_plans->legacy_next_plans`` — see
  ``app/db/models.py``); every other legacy table keeps its name;
* ``main()`` copies every legacy table across once, writes a marker row
  (``settings.key='dbmerge'`` in the MAIN database) and never touches the
  old legacy database — it stays as the rollback copy;
* ``effective_legacy_url()`` is the durable decision every engine uses:
  once the marker exists the legacy engine serves the main database;
  until then everything behaves exactly like the two-database layout.

Run via ``python3 -m app.dbmerge`` at boot (before alembic). Any failure
exits non-zero WITHOUT the marker: the panel boots on the old layout and
the next boot retries from a clean slate (targets are rebuilt).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from sqlalchemy import MetaData, Table, create_engine, inspect, text

MARKER_KEY = "dbmerge"
RENAMES = {
    "users": "legacy_users",
    "admins": "legacy_admins",
    "nodes": "legacy_nodes",
    "next_plans": "legacy_next_plans",
}
INVERSE = {new: old for old, new in RENAMES.items()}


def _load_env() -> None:
    """Pick up the panel's .env (same contract as config.py) so the
    standalone `python3 -m app.dbmerge` boot step sees the URLs."""
    try:
        from app.env_loader import load_zagros_env
        load_zagros_env()
    except Exception:  # noqa: BLE001 — degraded standalone use
        pass


def _read_marker(conn):
    for expr in ("`key`", '"key"'):
        try:
            return conn.execute(text(
                f"SELECT value_json FROM settings WHERE {expr} = '{MARKER_KEY}'"
            )).scalar()
        except Exception:  # noqa: BLE001 — try the next quoting style
            continue
    return None


def merged(main_url: str) -> bool:
    """True when the main database carries the merge marker."""
    if not main_url:
        return False
    try:
        engine = create_engine(main_url)
        try:
            with engine.connect() as conn:
                return _read_marker(conn) is not None
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 — unreachable DB: behave un-merged
        return False


def effective_legacy_url(configured: str | None) -> str | None:
    """The URL the legacy engine should serve RIGHT NOW."""
    main_url = os.environ.get("ZAGROS_DATABASE_URL") or ""
    if (configured and main_url and main_url != configured
            and merged(main_url)):
        return main_url
    return configured


def _set_marker(conn, counts: dict) -> None:
    payload = json.dumps({
        "v": 1,
        "merged_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tables": counts,
    })
    now = datetime.now(timezone.utc)
    if conn.dialect.name in ("mysql", "mariadb"):
        conn.execute(text(
            "INSERT INTO settings (`key`, value_json, updated_at) "
            "VALUES (:k, :j, :t) ON DUPLICATE KEY UPDATE "
            "value_json = VALUES(value_json), updated_at = VALUES(updated_at)"
        ), {"k": MARKER_KEY, "j": payload, "t": now})
    else:
        conn.execute(text(
            'INSERT OR REPLACE INTO settings ("key", value_json, updated_at) '
            "VALUES (:k, :j, :t)"
        ), {"k": MARKER_KEY, "j": payload, "t": now})


def main() -> int:
    _load_env()
    main_url = os.environ.get("ZAGROS_DATABASE_URL") or ""
    legacy_url = os.environ.get("SQLALCHEMY_DATABASE_URL") or ""
    if not main_url or not legacy_url:
        print("dbmerge: database URLs are not configured — skipping")
        return 0
    if main_url == legacy_url:
        print("dbmerge: a single database is already in use — nothing to do")
        return 0
    if merged(main_url):
        print("dbmerge: marker present — legacy engine serves the main database")
        return 0

    os.environ["ZAGROS_FORCE_LEGACY_RENAMES"] = "1"
    from app.db import models as legacy_models  # renamed tablenames

    src = create_engine(legacy_url, pool_pre_ping=True)
    dst = create_engine(main_url, pool_pre_ping=True)
    try:
        src_tables = set(inspect(src).get_table_names())
        has_source = bool(src_tables & set(RENAMES))
        if not has_source and not (src_tables & set(INVERSE)):
            print("dbmerge: legacy database carries no legacy tables — "
                  "nothing to merge")
            return 0

        meta = legacy_models.Base.metadata
        # clean retry: rebuild OUR target tables from the models, then copy
        meta.drop_all(dst)
        meta.create_all(dst)

        counts: dict[str, int] = {}
        src_meta = MetaData()
        copied = skipped = 0
        src_conn = src.connect()
        with dst.connect() as dconn:
            if dst.dialect.name in ("mysql", "mariadb"):
                dconn.execute(text("SET FOREIGN_KEY_CHECKS=0"))
            try:
                for table in meta.sorted_tables:
                    src_name = INVERSE.get(table.name, table.name)
                    if src_name not in src_tables:
                        skipped += 1
                        continue
                    source = Table(src_name, src_meta, autoload_with=src)
                    total = 0
                    result = src_conn.execute(source.select())
                    while True:
                        rows = result.fetchmany(1000)
                        if not rows:
                            break
                        payload = [dict(r._mapping) for r in rows]
                        dconn.execute(table.insert(), payload)
                        total += len(payload)
                    counts[table.name] = total
                    copied += 1
                _set_marker(dconn, counts)
                dconn.commit()
            except Exception:
                dconn.rollback()
                raise
            finally:
                src_conn.close()
        print(f"dbmerge: merged {copied} legacy table(s) into the main "
              f"database ({skipped} absent) — rows: {json.dumps(counts)}")
        print("dbmerge: the old legacy database was NOT modified — "
              "keep it as the rollback copy")
        return 0
    except Exception as exc:  # noqa: BLE001 — no marker → panel boots un-merged
        print(f"dbmerge: FAILED — the panel will boot on the old two-database "
              f"layout and retry next boot: {exc}")
        return 1
    finally:
        src.dispose()
        dst.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
