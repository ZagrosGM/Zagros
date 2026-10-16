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

# f-bootprobe-1: the server-database branches probe reachability through the
# same one-shot helper bootwait uses. It went missing in the consolidation
# rework, so EVERY non-sqlite deployment crashed dbmerge at boot with
# "NameError: name 'probe' is not defined" and the panel came up un-merged.
from app.bootwait import probe

MARKER_KEY = "dbmerge"
# f-dbmerge-7: v1.1.1 wrote "v": 1 markers, but on PostgreSQL the marker
# reader aborted its transaction on the MySQL-quoted first attempt and never
# saw it — installs stayed on the live legacy database while the main copy
# became a stale snapshot. v2 markers are only written AFTER a read that
# works on every dialect; a v1 marker therefore means "the engine may still
# be living in the legacy database" and triggers one final healing merge
# (fresh rows win) before the engine is allowed to switch.
MARKER_VERSION = 2
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


def _marker_quote_expr(conn) -> tuple[str, ...]:
    """Quoting styles for the settings key, DIALECT-FIRST (f-dbmerge-7).

    Guessing loops poison PostgreSQL: the first (MySQL) attempt aborts the
    transaction and the second, correct attempt dies with
    InFailedSqlTransaction. The dialect decides the first (and on real
    deployments, only) attempt; the legacy order is kept purely as a
    fallback, with a rollback before every retry.
    """
    if conn.dialect.name in ("mysql", "mariadb"):
        return ("`key`", '"key"')
    return ('"key"', "`key`")


def read_marker_value(conn) -> str | None:
    """The raw marker JSON, or None — safe on every dialect (f-dbmerge-7)."""
    for expr in _marker_quote_expr(conn):
        try:
            return conn.execute(text(
                f"SELECT value_json FROM settings WHERE {expr} = '{MARKER_KEY}'"
            )).scalar()
        except Exception:  # noqa: BLE001 — roll back and try the next quoting
            conn.rollback()
            continue
    return None


def _marker_version(payload: str | None) -> int:
    if not payload:
        return 0
    try:
        return int((json.loads(payload) or {}).get("v", 1))
    except (ValueError, TypeError):
        return 1  # a present but unreadable marker behaves like v1


def _read_marker(conn):
    return read_marker_value(conn)


def merged(main_url: str) -> bool:
    """True when the main database carries a CURRENT-version merge marker.

    A v1 marker (v1.1.1) is deliberately NOT trusted (f-dbmerge-7): on
    PostgreSQL the writing boot never actually honoured it, so the legacy
    database may hold fresher data than the main copy — the caller must
    run the healing merge once before treating the layout as merged.
    """
    if not main_url:
        return False
    try:
        engine = create_engine(main_url)
        try:
            with engine.connect() as conn:
                return _marker_version(_read_marker(conn)) >= MARKER_VERSION
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 — unreachable DB: behave un-merged
        return False


def sqlite_path(url: str) -> str | None:
    """File path of a sqlite URL, None for anything else."""
    if not url.startswith("sqlite:///"):
        return None
    path = url[len("sqlite:///"):]
    if path.startswith("/"):  # sqlite:////absolute -> '//absolute' remainder
        path = path.lstrip("/")
        return "/" + path
    return path or None


def legacy_source_exists(url: str) -> bool:
    """Whether a legacy database with real content exists RIGHT NOW.

    sqlite: the file must exist (creating it just to look would be the
    two-database bug this module exists to prevent). Server DBs: the
    server must accept a connection; an unreachable server is treated as
    "absent" so a fresh install never fabricates a legacy database.
    """
    path = sqlite_path(url or "")
    if path is not None:
        return os.path.isfile(path)
    return probe(url) is None


def remove_legacy_source(url: str) -> str:
    """Retire the merged legacy database (f-dbmerge-3).

    sqlite: the file is renamed next to itself (``<name>.merged``) — the
    database no longer exists for any engine, while the operator keeps a
    byte-identical rollback copy at zero risk. Server DBs: the legacy
    tables are dropped inside the legacy database (the server keeps other
    databases untouched). Returns a human-readable outcome.
    """
    path = sqlite_path(url or "")
    if path is not None:
        if not os.path.isfile(path):
            return "already absent"
        target = path + ".merged"
        os.replace(path, target)
        for suffix in ("-wal", "-shm"):
            side = path + suffix
            if os.path.isfile(side):
                os.remove(side)
        return f"renamed to {target}"
    engine = create_engine(url, pool_pre_ping=True)
    try:
        meta = MetaData()
        tables = [
            Table(name, meta, autoload_with=engine)
            for name in inspect(engine).get_table_names()
        ]
        with engine.begin() as conn:
            if conn.dialect.name in ("mysql", "mariadb"):
                conn.execute(text("SET FOREIGN_KEY_CHECKS=0"))
            if conn.dialect.name == "postgresql":
                # f-dbmerge-7: FK dependency order is not worth reconstructing
                # here (association tables reference users/inbounds) — CASCADE
                # drops dependents along with the referenced tables.
                for table in tables:
                    conn.execute(text(
                        f'DROP TABLE IF EXISTS "{table.name}" CASCADE'))
            else:
                for table in reversed(tables):
                    table.drop(bind=conn, checkfirst=True)
            if conn.dialect.name in ("mysql", "mariadb"):
                conn.execute(text("SET FOREIGN_KEY_CHECKS=1"))
        return f"dropped {len(tables)} legacy table(s) in place"
    finally:
        engine.dispose()


def effective_legacy_url(configured: str | None) -> str | None:
    """The URL the legacy engine should serve RIGHT NOW."""
    main_url = os.environ.get("ZAGROS_DATABASE_URL") or ""
    if (configured and main_url and main_url != configured
            and merged(main_url)):
        return main_url
    return configured


def _provision_legacy_into_main(main_url: str) -> None:
    """Create the legacy schema inside the MAIN database when it is absent.

    f-dbmerge-3 fresh-install path: there is no legacy database at all, so
    the merged layout needs the legacy tables to exist in the main database
    before the marker flips the legacy engine over. Existing tables are
    never dropped — a guarded create-only, so real operator data is
    untouchable on every path that reaches this.
    """
    os.environ["ZAGROS_FORCE_LEGACY_RENAMES"] = "1"
    from app.db import models as legacy_models  # renamed tablenames

    meta = legacy_models.Base.metadata
    dst = create_engine(main_url, pool_pre_ping=True)
    try:
        existing = set(inspect(dst).get_table_names())
        missing = [t for t in meta.tables if t not in existing]
        if not missing:
            return  # schema already provisioned (e.g. by an earlier merge)
        meta.create_all(dst, tables=[meta.tables[t] for t in missing])
    finally:
        dst.dispose()


def _set_marker(conn, counts: dict) -> None:
    # f-dbmerge-4: the marker store is the P3 `settings` table, but the boot
    # order runs dbmerge BEFORE alembic — on a truly fresh install that
    # table does not exist yet and the marker write died with
    # "no such table: settings", silently keeping the two-database layout.
    # The schema matches the platform's SettingModel exactly; alembic's
    # create_all is checkfirst and will not touch an existing table.
    # f-dbmerge-6: per-dialect DDL — PostgreSQL has no DATETIME type and no
    # INSERT OR REPLACE; MySQL/MariaDB need backtick quoting.
    if conn.dialect.name == "postgresql":
        conn.execute(text(
            'CREATE TABLE IF NOT EXISTS settings ('
            '"key" VARCHAR(128) NOT NULL PRIMARY KEY, '
            'value_json JSON, updated_at TIMESTAMPTZ)'))
    elif conn.dialect.name in ("mysql", "mariadb"):
        conn.execute(text(
            'CREATE TABLE IF NOT EXISTS settings ('
            '`key` VARCHAR(128) NOT NULL PRIMARY KEY, '
            'value_json JSON, updated_at DATETIME)'))
    else:
        conn.execute(text(
            'CREATE TABLE IF NOT EXISTS settings ('
            '"key" VARCHAR(128) NOT NULL PRIMARY KEY, '
            'value_json JSON, updated_at DATETIME)'))
    payload = json.dumps({
        "v": MARKER_VERSION,
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
    elif conn.dialect.name == "postgresql":
        conn.execute(text(
            'INSERT INTO settings ("key", value_json, updated_at) '
            "VALUES (:k, :j, :t) "
            'ON CONFLICT ("key") DO UPDATE SET '
            "value_json = EXCLUDED.value_json, updated_at = EXCLUDED.updated_at"
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
        if legacy_source_exists(legacy_url):
            # f-dbmerge-3: a merge from an earlier panel version left the
            # legacy database behind as a rollback copy; the operator asked
            # for one database, so retire it now (idempotent).
            try:
                print(f"dbmerge: retiring the legacy database — "
                      f"{remove_legacy_source(legacy_url)}")
            except Exception as exc:  # noqa: BLE001 — never block the boot
                print(f"dbmerge: legacy cleanup failed (non-fatal): {exc}")
        return 0
    path = sqlite_path(legacy_url)
    if path is not None and not os.path.isfile(path):
        # f-dbmerge-3: fresh install (or the operator removed the empty
        # legacy file). A MISSING SQLITE FILE is definitive — there is
        # nothing to migrate. Provision the legacy schema inside the main
        # database, write the marker so the legacy engine serves it from
        # this boot on, and never create a second database. Server legacy
        # databases never take this branch: an unreachable server is
        # transient and must fail the boot (below), never be declared
        # "fresh" — that would merge nothing and hide the legacy data.
        print("dbmerge: no legacy database exists — provisioning a single "
              "merged database")
        _provision_legacy_into_main(main_url)
        dst = create_engine(main_url, pool_pre_ping=True)
        try:
            with dst.begin() as dconn:
                _set_marker(dconn, {"fresh_install": True})
        finally:
            dst.dispose()
        print("dbmerge: marker written — the legacy layer serves the main "
              "database (single database)")
        return 0

    if path is None and probe(legacy_url) is not None:
        print("dbmerge: legacy server unreachable — failing this boot so it "
              "retries (never declaring a reachable-only main database merged)")
        return 1

    os.environ["ZAGROS_FORCE_LEGACY_RENAMES"] = "1"
    from app.db import models as legacy_models  # renamed tablenames

    src = create_engine(legacy_url, pool_pre_ping=True)
    dst = create_engine(main_url, pool_pre_ping=True)
    try:
        src_tables = set(inspect(src).get_table_names())
        if not src_tables:
            # f-dbmerge-3: a completely EMPTY legacy database carries no
            # operator data by definition — fold it into the single-database
            # layout instead of keeping two files forever. A database with
            # ANY table takes the full merge below, so seeded singleton rows
            # (jwt/tls/system/admin) are always copied, never dropped.
            print("dbmerge: legacy database is empty — "
                  "folding the empty file into the main database")
            src.dispose()
            dst.dispose()
            _provision_legacy_into_main(main_url)
            dst = create_engine(main_url, pool_pre_ping=True)
            try:
                with dst.begin() as dconn:
                    _set_marker(dconn, {"schema_only_legacy": True})
            finally:
                dst.dispose()
            print(f"dbmerge: marker written — retiring the legacy database: "
                  f"{remove_legacy_source(legacy_url)}")
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
        try:
            print(f"dbmerge: retiring the legacy database — "
                  f"{remove_legacy_source(legacy_url)}")
        except Exception as exc:  # noqa: BLE001 — data is already merged
            print(f"dbmerge: legacy cleanup failed (non-fatal, the merge "
                  f"itself is committed): {exc}")
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
