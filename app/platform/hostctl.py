"""Zagros host-operations entrypoint — runs INSIDE the panel container.

The host management CLI (``zagros``, from the ``zagros-scripts`` repository)
invokes this module via::

    docker compose exec -T zagros python3 -m app.platform.hostctl <command> ...

Design contract
---------------
* Ops-only bridge: it composes **existing** platform services
  (:class:`PlatformRuntime`, :class:`CoreManager`, legacy admin CRUD).
  It adds no HTTP surface and no user-facing panel feature.
* Every command prints exactly ONE JSON object line on stdout —
  ``{"ok": true, ...}`` or ``{"ok": false, "error": ..., "code": ...}`` —
  so the host CLI can parse results deterministically. Human noise never
  goes to stdout (logging stays on stderr).
* Exit codes: 0 ok · 1 error · 2 usage error · 3 panel-owned resource
  (the running panel process owns it; host CLI should restart the
  container instead) · 4 not found.
* Never starts enabled cores implicitly: ``boot()`` only *loads* saved
  core state; lifecycle actions are always explicit per command.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import traceback

# hostctl runs inside the panel container as its own process. Compose only
# MOUNTS the panel's .env (nothing is injected into the environment), so
# merge it here before ANY command reads os.environ (DB URLs, secrets, ...).
# Idempotent and override-safe — real env vars always win.
from app.env_loader import load_zagros_env  # noqa: E402

load_zagros_env()

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_PANEL_OWNED = 3
EXIT_NOT_FOUND = 4


def _emit(payload: dict) -> None:
    json.dump(payload, sys.stdout, ensure_ascii=False, default=str)
    sys.stdout.write("\n")
    sys.stdout.flush()


def _fail(exc: BaseException, *, code: str = "error", exit_code: int = EXIT_ERROR,
          debug: bool = False) -> int:
    payload = {"ok": False, "error": str(exc), "code": code,
               "exception": type(exc).__name__}
    if debug:
        payload["traceback"] = traceback.format_exc()
    _emit(payload)
    return exit_code


# --------------------------------------------------------------------- #
# async command bodies
# --------------------------------------------------------------------- #

async def _runtime():
    from app.platform.runtime import PlatformRuntime

    rt = PlatformRuntime.from_env()
    rt.verify_schema()
    await rt.core_manager.boot()  # load saved core state only — never starts cores
    return rt


async def cmd_version(_args) -> dict:
    # Resolve from the source of truth (app/__init__.py) instead of a package
    # attribute: hostctl may run through import contexts where the package
    # object is a partial/lazy proxy (tests, embedded shims) — the file is
    # always the same production file.
    import re
    from pathlib import Path

    src = (Path(__file__).resolve().parent.parent / "__init__.py").read_text(
        encoding="utf-8")
    m = re.search(r'__version__\s*=\s*"([^"]+)"', src)
    return {"panel_version": m.group(1) if m else "unknown"}


async def cmd_health(args) -> dict:
    import time

    rt = await _runtime()
    started = time.monotonic()
    db = await _db_check_payload(rt)
    states = await rt.core_state.load()
    running = sum(1 for s in states.values() if s.get("state") == "running")
    enabled = sum(1 for s in states.values() if s.get("enabled"))
    healthy = db["up_to_date"] and db["reachable"]
    return {
        "healthy": healthy,
        "db": db,
        "cores": {"installed": len(states), "enabled": enabled, "running": running},
        "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
    }


async def _db_check_payload(rt) -> dict:
    import os
    import time

    url = rt.database_url
    driver = url.split(":", 1)[0] if ":" in url else "unknown"
    started = time.monotonic()

    def _ping() -> int:
        from sqlalchemy import text

        with rt.session_factory() as s:
            s.execute(text("SELECT 1"))
        return 1

    reachable = bool(await asyncio.to_thread(_ping))

    def _alembic() -> tuple[set[str], set[str]]:
        from alembic.config import Config
        from alembic.runtime.migration import MigrationContext
        from alembic.script import ScriptDirectory

        cfg = Config(os.environ.get("ZAGROS_ALEMBIC_INI", "alembic.ini"))
        heads = set(ScriptDirectory.from_config(cfg).get_heads())
        engine = rt.session_factory.kw["bind"]
        with engine.connect() as conn:
            current = set(MigrationContext.configure(conn).get_current_heads())
        return current, heads

    try:
        current, heads = await asyncio.to_thread(_alembic)
    except Exception as exc:  # alembic table missing etc. — honest report
        return {"reachable": reachable, "up_to_date": False, "driver": driver,
                "alembic_error": str(exc),
                "latency_ms": round((time.monotonic() - started) * 1000, 2)}
    return {
        "reachable": reachable,
        "driver": driver,
        "alembic_current": sorted(current),
        "alembic_heads": sorted(heads),
        "up_to_date": reachable and current == heads,
        "latency_ms": round((time.monotonic() - started) * 1000, 2),
    }


async def cmd_db_check(_args) -> dict:
    rt = await _runtime()
    return await _db_check_payload(rt)


async def cmd_db_backup_sqlite(args) -> dict:
    """Online, crash-safe SQLite backup using the stdlib backup API."""
    import os
    import sqlite3

    # Decide from the URL itself BEFORE touching the engine: on non-sqlite
    # targets we must not even attempt a connection. Parse with SQLAlchemy
    # (robust against operator typos like 5-slash sqlite URLs, which a
    # hand-rolled split turns into a confusing sqlite "uri authority" error).
    rt_url = (args.url
              or os.environ.get("ZAGROS_DATABASE_URL")
              or os.environ.get("SQLALCHEMY_DATABASE_URL")
              or "sqlite:///zagros.db")
    from sqlalchemy.engine import make_url

    parsed_url = make_url(rt_url)
    if not parsed_url.drivername.startswith("sqlite"):
        raise RuntimeError(f"db-backup-sqlite only works for SQLite (got '{rt_url}')")
    if not parsed_url.database or parsed_url.database == ":memory:":
        raise RuntimeError(f"db-backup-sqlite needs a file database (got '{rt_url}')")
    src_path = os.path.realpath(os.path.expanduser(parsed_url.database))
    if not os.path.exists(src_path):
        raise FileNotFoundError(f"SQLite database not found at {src_path}")
    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    tmp_out = os.path.join(out_dir, ".backup-in-progress.tmp")
    if os.path.exists(tmp_out):
        os.remove(tmp_out)

    def _backup() -> int:
        src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True, timeout=30)
        try:
            dst = sqlite3.connect(tmp_out, timeout=30)
            try:
                src.backup(dst)  # hot-consistent copy, WAL-safe
            finally:
                dst.close()
        finally:
            src.close()
        return os.path.getsize(tmp_out)

    size = await asyncio.to_thread(_backup)
    os.replace(tmp_out, args.out)
    return {"database": src_path, "backup": os.path.abspath(args.out), "bytes": size}


# --------------------------------------------------------------------- #
# cores
# --------------------------------------------------------------------- #

def _core_to_json(driver, state: str, enabled: bool, status=None) -> dict:
    meta = driver.metadata
    entry = {
        "id": meta.id,
        "title": getattr(meta, "title", meta.id),
        "state": state,
        "enabled": enabled,
        "capabilities": sorted(c.value for c in meta.capabilities),
        "provides": sorted(getattr(meta, "provides", []) or []),
        "requires": sorted(getattr(meta, "requires", []) or []),
    }
    if status is not None:
        entry["health"] = getattr(getattr(status, "health", None), "value", None)
        entry["core_version"] = getattr(status, "core_version", None)
        message = getattr(status, "message", None)
        if message:
            entry["message"] = message
    return entry


async def _status_for(driver, timeout: float = 8.0):
    try:
        return await asyncio.wait_for(driver.status(), timeout=timeout)
    except Exception:
        return None


async def cmd_cores_list(args) -> dict:
    rt = await _runtime()
    states = await rt.core_state.load()
    cores = []
    for core_id in rt.core_manager.list_cores():
        driver = rt.core_manager.get(core_id)
        stored = states.get(core_id, {})
        status = None if args.no_probe else await _status_for(driver)
        cores.append(_core_to_json(
            driver,
            state=stored.get("state", "installed"),
            enabled=bool(stored.get("enabled", rt.core_manager.is_enabled(core_id))),
            status=status,
        ))
    unavailable = sorted(set(states) - set(rt.core_manager.list_cores()))
    return {"cores": cores, "stored_without_driver": unavailable}


async def cmd_cores_install(args) -> dict:
    from app.cores.registry import available_drivers

    rt = await _runtime()
    known = available_drivers()
    if args.core not in known:
        raise KeyError(
            f"Unknown core '{args.core}'. Available: {', '.join(sorted(known))}"
        )
    settings = json.loads(args.settings) if args.settings else None
    state = await rt.core_manager.install_core(
        args.core, settings, enabled=not args.disabled
    )
    return {"core": args.core, "state": state.value, "enabled": not args.disabled}


async def cmd_cores_uninstall(args) -> dict:
    rt = await _runtime()
    states = await rt.core_state.load()
    if args.core not in rt.core_manager.list_cores() and args.core not in states:
        raise KeyError(f"Core '{args.core}' is not installed.")
    report = rt.core_manager.dependency_report(args.core)
    dependents = rt.core_manager.dependents(args.core)
    if dependents and not args.force:
        _emit({
            "ok": False, "code": "HAS_DEPENDENTS", "core": args.core,
            "dependents": dependents,
            "error": f"cores {dependents} depend on '{args.core}'; pass --force",
        })
        return EXIT_ERROR
    running = states.get(args.core, {}).get("state") == "running"
    if running and not args.force:
        _emit({
            "ok": False, "core": args.core, "code": "PANEL_OWNED",
            "error": "core is running under the panel; stop it first or pass --force "
                     "(a panel restart will follow to release the process)",
        })
        return EXIT_PANEL_OWNED
    await rt.core_manager.uninstall_core(args.core, purge=args.purge, force=True)
    return {"core": args.core, "uninstalled": True, "purged": args.purge,
            "dependencies": report, "restart_required": running}


async def cmd_cores_update(args) -> dict:
    rt = await _runtime()
    if args.core not in rt.core_manager.list_cores():
        raise KeyError(f"Core '{args.core}' is not installed.")
    new_version = await rt.core_manager.update_core(args.core, args.version)
    states = await rt.core_state.load()
    running = states.get(args.core, {}).get("state") == "running"
    return {"core": args.core, "version": new_version, "restart_required": running}


async def _guarded_transition(args, action: str):
    rt = await _runtime()
    states = await rt.core_state.load()
    if args.core not in rt.core_manager.list_cores():
        _emit({"ok": False, "code": "NOT_INSTALLED",
               "error": f"Core '{args.core}' is not installed."})
        return EXIT_NOT_FOUND
    stored_state = states.get(args.core, {}).get("state", "installed")
    if stored_state == "running":
        _emit({
            "ok": False, "core": args.core, "code": "PANEL_OWNED",
            "error": f"core '{args.core}' is RUNNING under the live panel process; "
                     f"per-core hot control requires the panel — restart the service "
                     f"(`zagros reload`) or stop the panel first",
        })
        return EXIT_PANEL_OWNED
    if action == "start":
        if not states.get(args.core, {}).get("enabled", True):
            raise RuntimeError(f"core '{args.core}' is disabled; enable it first")
        status = await rt.core_manager.start_core(args.core)
    elif action == "stop":
        status = await rt.core_manager.stop_core(args.core)
    else:  # restart
        status = await rt.core_manager.restart_core(args.core)
    return {"core": args.core, "action": action, **_core_to_json(
        rt.core_manager.get(args.core),
        state=(await rt.core_state.load()).get(args.core, {}).get("state", "?"),
        enabled=True, status=status,
    )}


async def cmd_cores_start(args):
    return await _guarded_transition(args, "start")


async def cmd_cores_stop(args):
    return await _guarded_transition(args, "stop")


async def cmd_cores_restart(args):
    return await _guarded_transition(args, "restart")


async def cmd_cores_enable(args) -> dict:
    rt = await _runtime()
    await rt.core_manager.enable_core(args.core)
    return {"core": args.core, "enabled": True}


async def cmd_cores_disable(args) -> dict:
    rt = await _runtime()
    await rt.core_manager.disable_core(args.core)
    return {"core": args.core, "enabled": False}


async def cmd_cores_logs(args) -> dict:
    rt = await _runtime()
    if args.core not in rt.core_manager.list_cores():
        raise KeyError(f"Core '{args.core}' is not installed.")
    lines = []
    async for line in rt.core_manager.get(args.core).get_logs(tail=args.tail):
        lines.append(line)
    return {"core": args.core, "lines": lines[-args.tail:], "count": len(lines[-args.tail:])}


async def cmd_nodes_list(_args) -> dict:
    from app.platform.runtime import _RuntimeNodeProvider

    rt = await _runtime()
    states = await _RuntimeNodeProvider(rt.session_factory).node_states()
    return {"nodes": [s.model_dump(mode="json") for s in states]}


async def cmd_sync(args) -> dict:
    """Re-apply every stored core account through each driver's own
    ``sync_accounts`` reconciliation primitive (idempotent)."""
    rt = await _runtime()
    only = args.core
    users = await asyncio.to_thread(rt.users.list_users, limit=100000)
    summary: dict[str, dict] = {}
    for core_id in rt.core_manager.list_cores():
        if only and core_id != only:
            continue
        if not rt.core_manager.is_enabled(core_id):
            summary[core_id] = {"synced": 0, "skipped": "disabled"}
            continue
        driver = rt.core_manager.get(core_id)
        accounts = []
        skipped = 0
        for user in users:
            rows = await asyncio.to_thread(rt.users.accounts_of, user.id, decrypt=True)
            for row in rows:
                if row["core_id"] != core_id:
                    continue
                from app.cores.types import UserAccount

                accounts.append(UserAccount(
                    user_id=user.id,
                    username=user.username,
                    account_id=row["account_id"],
                    protocol=row["protocol"],
                    enabled=row["enabled"] and user.status == "active",
                    settings=row["settings"],
                ))
        try:
            await asyncio.wait_for(driver.sync_accounts(accounts), timeout=120)
            summary[core_id] = {"synced": len(accounts)}
        except Exception as exc:  # honest per-core failure, keep going
            summary[core_id] = {"synced": 0, "error": str(exc),
                                "exception": type(exc).__name__}
        summary[core_id]["skipped_accounts"] = skipped
    return {"cores": summary}


# --------------------------------------------------------------------- #
# admins (legacy CRUD — same helpers zagros-cli uses)
# --------------------------------------------------------------------- #

def _legacy_admin(args, action: str) -> dict:
    # The legacy modules are *order-dependent*: `app.db` is only safely
    # importable after the application object exists (upstream layout), so
    # warm up the fully-built app first.
    import app as _app_warm  # noqa: F401

    getattr(_app_warm, "app")

    from app.db import GetDB, crud
    from app.models.admin import AdminCreate, AdminModify

    with GetDB() as db:
        if action == "list":
            return {"admins": [{"username": a.username, "is_sudo": a.is_sudo,
                                "created_at": str(a.created_at)}
                               for a in crud.get_admins(db)]}
        if action == "create":
            if crud.get_admin(db, args.username):
                raise RuntimeError(f"Admin '{args.username}' already exists.")
            crud.create_admin(db, AdminCreate(username=args.username,
                                              password=args.password,
                                              is_sudo=args.sudo))
            return {"username": args.username, "is_sudo": args.sudo, "created": True}
        if action == "reset":
            dbadmin = crud.get_admin(db, args.username)
            if dbadmin is None:
                raise KeyError(f"Admin '{args.username}' not found.")
            crud.update_admin(db, dbadmin, AdminModify(
                password=args.password, is_sudo=dbadmin.is_sudo))
            return {"username": args.username, "password_reset": True,
                    "is_sudo": dbadmin.is_sudo}
    raise RuntimeError(f"unknown admin action {action}")


# --------------------------------------------------------------------- #
# dispatch
# --------------------------------------------------------------------- #

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hostctl",
                                description="Zagros in-container host operations bridge")
    p.add_argument("--debug", action="store_true", help="include tracebacks in error payloads")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("version")
    sub.add_parser("health")
    sub.add_parser("db-check")
    b = sub.add_parser("db-backup-sqlite")
    b.add_argument("--out", required=True)
    b.add_argument("--url", default=None,
                   help="override the database URL (e.g. the legacy stack DB); "
                        "defaults to ZAGROS_DATABASE_URL")

    c = sub.add_parser("cores-list")
    c.add_argument("--no-probe", action="store_true", help="skip live status probes")
    c = sub.add_parser("cores-install")
    c.add_argument("core")
    c.add_argument("--settings", default=None, help="JSON object of driver settings")
    c.add_argument("--disabled", action="store_true")
    c = sub.add_parser("cores-uninstall")
    c.add_argument("core")
    c.add_argument("--purge", action="store_true")
    c.add_argument("--force", action="store_true")
    c = sub.add_parser("cores-update")
    c.add_argument("core")
    c.add_argument("--version", default=None)
    for name in ("cores-start", "cores-stop", "cores-restart",
                 "cores-enable", "cores-disable"):
        c = sub.add_parser(name)
        c.add_argument("core")
    c = sub.add_parser("cores-logs")
    c.add_argument("core")
    c.add_argument("--tail", type=int, default=200)

    sub.add_parser("nodes-list")

    c = sub.add_parser("sync")
    c.add_argument("--core", default=None)

    for name, help_ in (("admin-list", None), ("admin-create", None), ("admin-reset", None)):
        c = sub.add_parser(name)
        if name != "admin-list":
            c.add_argument("--username", required=True)
            c.add_argument("--password", required=True)
            if name == "admin-create":
                c.add_argument("--sudo", action="store_true")
    return p


_SYNC_OR_DICT = object()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    name = args.command.replace("-", "_")

    async_coro = {
        "version": cmd_version,
        "health": cmd_health,
        "db_check": cmd_db_check,
        "db_backup_sqlite": cmd_db_backup_sqlite,
        "cores_list": cmd_cores_list,
        "cores_install": cmd_cores_install,
        "cores_uninstall": cmd_cores_uninstall,
        "cores_update": cmd_cores_update,
        "cores_start": cmd_cores_start,
        "cores_stop": cmd_cores_stop,
        "cores_restart": cmd_cores_restart,
        "cores_enable": cmd_cores_enable,
        "cores_disable": cmd_cores_disable,
        "cores_logs": cmd_cores_logs,
        "nodes_list": cmd_nodes_list,
        "sync": cmd_sync,
    }.get(name)

    try:
        if async_coro is not None:
            result = asyncio.run(async_coro(args))
            if isinstance(result, int):  # guarded transitions emit themselves
                return result
            _emit({"ok": True, "command": name, **result})
            return EXIT_OK
        if name in ("admin_list", "admin_create", "admin_reset"):
            _emit({"ok": True, "command": name,
                   **_legacy_admin(args, name.split("_", 1)[1])})
            return EXIT_OK
        parser.error(f"unhandled command {args.command}")
        return EXIT_USAGE
    except KeyError as exc:
        return _fail(exc, code="not_found", exit_code=EXIT_NOT_FOUND, debug=args.debug)
    except KeyboardInterrupt:
        _emit({"ok": False, "error": "interrupted", "code": "interrupted"})
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 — single JSON contract
        return _fail(exc, debug=args.debug)


if __name__ == "__main__":
    sys.exit(main())
