"""Restore a backup — our own archive, or a foreign panel's.

Two very different jobs share one API:

``zagros``
    A full archive (databases + config + data). Restored by swapping the files
    back, then asking the host agent to restart the container.
``marzban`` / ``pasarguard`` / ``3x-ui``
    Only the *data* is imported, through the migration pipeline. The archive is
    not trusted to describe our deployment, so nothing outside the database is
    touched — importing users from another panel must never rewrite this
    panel's ``.env``.

Both paths are preview-first: ``inspect()`` reports what would happen and
changes nothing.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.platform import backup_store
from app.platform import restore_formats
from app.platform import restore_sources
from app.platform.restore_errors import (  # noqa: F401  (re-exported)
    RestoreError,
    RestoreFormatError,
    RestoreSourceError,
)

RESTORE_DIR_NAME = "restore"
MAX_UPLOAD_BYTES = 4 * 1024 * 1024 * 1024  # 4 GiB — archives hold core data
RESTART_REQUEST = "panel-restart.request.json"
AGENT_CAPABILITIES = ".agent-capabilities"


# --------------------------------------------------------------------------- #
# staging
# --------------------------------------------------------------------------- #
def staging_root(data_dir: str | os.PathLike[str] | None = None) -> Path:
    base = Path(data_dir) if data_dir else Path(
        os.environ.get("ZAGROS_DATA_DIR") or "/var/lib/zagros")
    path = base / RESTORE_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:  # pragma: no cover
        pass
    return path


def save_upload(source_path: str | os.PathLike[str], name: str,
                data_dir: str | os.PathLike[str] | None = None) -> Path:
    """Move an uploaded archive into a private staging directory."""
    root = staging_root(data_dir)
    stamp = time.strftime("%Y%m%d-%H%M%SZ", time.gmtime())
    target_dir = root / f".staging-{stamp}-{os.getpid()}"
    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True, mode=0o700)
    target = target_dir / _safe_filename(name)
    shutil.move(str(source_path), str(target))
    try:
        os.chmod(target, 0o600)
    except OSError:  # pragma: no cover
        pass
    return target


def _safe_filename(name: str) -> str:
    """Keep the uploaded name, extension included.

    The extension used to be forced to ``.tar.gz``, which is how a bare
    ``x-ui.db`` or a ``db_backup.sql`` lost the only clue to what it was.
    """
    base = os.path.basename(str(name or "upload.tar.gz"))
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in base)
    return cleaned.lstrip(".") or "upload.tar.gz"


def discard(staging_file: Path) -> None:
    """Remove the staging directory that holds *staging_file*."""
    parent = Path(staging_file).parent
    if parent.is_dir() and parent.name.startswith(".staging-"):
        shutil.rmtree(parent, ignore_errors=True)


def _extract(archive: Path, dest: Path) -> list[str]:
    """Safe extraction — never writes outside *dest*, never follows links."""
    written, _skipped = restore_formats.extract(archive, dest)
    return written


def _extract_live(archive: Path, dest: Path) -> tuple[list[str], list[str]]:
    """Unpack ``data/panel-data.tar.gz`` into the **live** data directory.

    Some of those files are running right now: a core binary that is being
    executed cannot be replaced (``ETXTBSY``), and a restore that dies half way
    leaves the panel worse than before. So an in-use file is skipped and
    reported — cores are re-installable, a half-restored panel is not.
    """
    return restore_formats.extract(archive, dest, live=True)


# --------------------------------------------------------------------------- #
# reports
# --------------------------------------------------------------------------- #
@dataclass
class RestoreReport:
    source: str
    archive: str
    dry_run: bool = True
    ok: bool = True
    steps: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    credentials: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    restart: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source, "archive": self.archive, "dry_run": self.dry_run,
            "ok": self.ok, "steps": self.steps, "warnings": self.warnings,
            "counts": self.counts,
            "credentials": self.credentials,  # shown once — never logged twice
            "notes": self.notes,
            "restart": self.restart,
        }


# --------------------------------------------------------------------------- #
# inspection (no writes)
# --------------------------------------------------------------------------- #
def inspect(archive: Path, source: str, *,
            session_factory=None, cipher=None, users_repo=None) -> RestoreReport:
    """Report what a restore would do; writes nothing (except staging)."""
    report = RestoreReport(source=source, archive=Path(archive).name, dry_run=True)
    if source == "zagros":
        return _inspect_zagros(Path(archive), report)
    if source not in restore_sources.FOREIGN_SOURCES:
        raise RestoreError(f"unsupported restore source: {source}")
    return _inspect_foreign(Path(archive), source, report,
                            session_factory=session_factory, cipher=cipher,
                            users_repo=users_repo, apply=False)


def _inspect_zagros(archive: Path, report: RestoreReport) -> RestoreReport:
    try:
        meta = backup_store.meta_of(archive)
    except backup_store.BackupError as exc:
        report.ok = False
        report.warnings.append(str(exc))
        return report
    if meta.get("kind") != backup_store.BACKUP_KIND:
        report.warnings.append(
            f"archive declares kind={meta.get('kind')!r} — expected "
            f"{backup_store.BACKUP_KIND!r}; restore it as a foreign source instead.")
    verification = backup_store.verify(archive)
    report.steps.append(f"archive verified ({verification['files']} files)")
    if not verification["ok"]:
        report.ok = False
        report.warnings.extend(verification["problems"][:10])
    names = backup_store.archive_names(archive)
    for member, note in (("db/zagros.sqlite3", "platform database"),
                         ("data/panel-data.tar.gz", "panel data"),
                         ("config/.env", "deployment configuration")):
        report.steps.append(
            f"{member}: {'present' if member in names else 'absent'}"
            + ("" if member in names else f" — {note} not restored"))
        if member not in names:
            report.warnings.append(f"{member} missing from the archive")
    report.counts = {"files": verification["files"]}
    report.restart = {"required": True, "method": "host-agent"}
    return report


# --------------------------------------------------------------------------- #
# foreign restore / import
# --------------------------------------------------------------------------- #
def _resolve_database(archive: Path, source: str,
                      report: RestoreReport) -> Path:
    """Find (or build) the SQLite database an upload carries.

    Three very different uploads reach this function: a bare ``x-ui.db``, a
    Marzban backup whose database is a **MySQL dump**, and a proper archive
    that holds a database file. Each is turned into something readable.
    """
    kind = restore_formats.classify(archive)
    if kind == "database":
        report.steps.append(f"{archive.name}: SQLite database")
        return archive
    if kind == "sqldump":
        built = restore_formats.materialize_database(archive, archive.parent)
        report.steps.append(f"{archive.name}: SQL dump replayed into {built.name}")
        return built

    staging = archive.parent / ".extract"
    if staging.exists():
        shutil.rmtree(staging)
    _extract(archive, staging)
    report.steps.append(f"unpacked {archive.name} ({restore_formats.classify(archive)})")

    databases = restore_sources.find_databases(staging)
    if databases:
        chosen = restore_sources.pick_database(staging, source)
        report.steps.append(f"database: {chosen.name}")
        return chosen

    dumps = restore_sources.find_dumps(staging)
    if dumps:
        chosen_dump = max(dumps, key=lambda item: item.stat().st_size)
        built = restore_formats.materialize_database(chosen_dump, staging)
        report.steps.append(f"database: replayed SQL dump {chosen_dump.name}")
        return built

    names = sorted(item.name for item in staging.rglob("*") if item.is_file())[:10]
    raise RestoreSourceError(
        f"no database or SQL dump found in {archive.name}"
        + (f" (the archive holds: {', '.join(names)})" if names else "")
        + ". Accepted uploads: a Zagros/Marzban/3x-ui archive, an SQLite file, "
          "or a .sql dump.")


def _read_with_fallback(db_path: Path, source: str, report: RestoreReport):
    """Read *db_path* as *source*, retrying as the panel it looks like.

    Picking the wrong source in the UI is easy and the cost used to be silent:
    a 3x-ui database read as Marzban imports nothing and reports success. When
    our own reading of the selected source finds no users but the file clearly
    belongs to another panel, that panel wins and the report says so.
    """
    detected = restore_sources.identify_database(db_path)
    if (detected.get("source") and detected["source"] != source
            and detected.get("confidence", 0) >= 0.6):
        report.warnings.append(
            f"this database looks like {detected['source']}, not {source} "
            f"(evidence: {', '.join(detected['evidence'][:5])}). "
            "Continuing with the source you selected.")

    snapshot, notes = restore_sources.read_snapshot(source, db_path)
    if not snapshot.users and detected.get("source") and detected["source"] != source:
        other = detected["source"]
        retry, retry_notes = restore_sources.read_snapshot(other, db_path)
        if retry.users:
            report.warnings.append(
                f"reading it as {source} found no users — imported as {other} instead.")
            return retry, retry_notes, other
    return snapshot, notes, source


def _inspect_foreign(archive: Path, source: str, report: RestoreReport, *,
                     session_factory=None, cipher=None, users_repo=None,
                     apply: bool = False) -> RestoreReport:
    staging = archive.parent / ".extract"
    try:
        db_path = _resolve_database(archive, source, report)
        snapshot, notes, used_source = _read_with_fallback(db_path, source, report)
        report.source = used_source
        report.steps.append(f"read {db_path.name} as {used_source}")
        report.counts = {"users": len(snapshot.users), "hosts": len(snapshot.hosts),
                         "admins": len(snapshot.admins), "nodes": len(snapshot.nodes)}

        if session_factory is None or cipher is None or users_repo is None:
            report.warnings.append("preview only — the importer is not wired to a session")
            return report

        from app.persistence.migration import LegacyImportService

        service = LegacyImportService(session_factory, users_repo, cipher)
        migration = service.migrate(snapshot, dry_run=not apply)
        report.counts.update({k: v for k, v in migration.as_dict().items()
                              if isinstance(v, int)})
        report.warnings.extend(migration.warnings[:20])
        report.notes.extend(getattr(migration, "notes", [])[:10])
        report.steps.append("import applied" if apply else "import previewed (dry run)")
        if apply:
            report.credentials = dict(notes.get("generated_admin_passwords") or {})
            if report.credentials:
                report.warnings.append(
                    "These admins were imported with a NEW password (the source "
                    "hash could not be verified). Save it now — it is shown once.")
        report.dry_run = not apply
        return report
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def restore_foreign(archive: Path, source: str, *, session_factory, cipher,
                    users_repo) -> RestoreReport:
    report = RestoreReport(source=source, archive=Path(archive).name, dry_run=False)
    result = _inspect_foreign(Path(archive), source, report, session_factory=session_factory,
                              cipher=cipher, users_repo=users_repo, apply=True)
    result.restart = {"required": False,
                      "reason": "an import changes rows, not the deployment"}
    return result


# --------------------------------------------------------------------------- #
# zagros restore
# --------------------------------------------------------------------------- #
def restore_zagros(archive: Path, *, data_dir: str | os.PathLike[str],
                   database_url: str | None, legacy_database_url: str | None = None,
                   config_dir: str | os.PathLike[str] | None = None,
                   allow_config: bool = True,
                   session_factory=None, cipher=None, users_repo=None) -> RestoreReport:
    """Restore our own archive and request a restart to pick it up.

    The fast path swaps the database files back. That only works when this
    panel runs the same engine the archive was taken from — a panel on MySQL
    cannot adopt a SQLite file, so there the rows are imported through the
    migration pipeline instead (and the report says which happened).
    """
    archive = Path(archive)
    report = RestoreReport(source="zagros", archive=archive.name, dry_run=False)
    data_root = Path(data_dir)
    staging = archive.parent / ".extract"
    if staging.exists():
        shutil.rmtree(staging)

    try:
        _extract(archive, staging)

        # 1. verify before touching anything
        verification = backup_store.verify(archive)
        if not verification["ok"]:
            report.warnings.extend(verification["problems"][:10])
        report.steps.append(f"verified {verification['files']} files")

        # 2. panel data (certificates, keys, core configs, templates, ...)
        inner = staging / "data" / "panel-data.tar.gz"
        if inner.is_file():
            written, skipped = _extract_live(inner, data_root)
            report.steps.append(f"restored {len(written)} panel-data paths")
            report.counts["data_paths"] = len(written)
            for item in skipped[:5]:
                report.warnings.append(f"skipped {item} — reinstall the core "
                                       "from Core Management if you need it")
        else:
            report.warnings.append("no data/panel-data.tar.gz — data not restored")

        # 3. databases
        engines_match = _engine_of(database_url) == "sqlite"
        if engines_match:
            for member, url in (("db/zagros.sqlite3", database_url),
                                ("db/legacy.sqlite3", legacy_database_url)):
                dumped = staging / member
                if not dumped.is_file() or not url:
                    continue
                target = _target_of(url)
                if target is None:
                    report.warnings.append(f"{member}: non-SQLite database URL — not restored")
                    continue
                _swap_database(dumped, target)
                report.steps.append(f"restored database → {target}")
        else:
            imported = _import_rows(staging, report, session_factory=session_factory,
                                    cipher=cipher, users_repo=users_repo)
            if not imported:
                report.warnings.append(
                    f"this panel runs {_engine_of(database_url) or 'a non-SQLite engine'}, "
                    "so the archive's database file cannot be copied into place and the "
                    "row-level import was not available — the databases were left untouched.")

        # 4. deployment configuration (only when it came from this archive)
        if allow_config:
            env_src = staging / "config" / ".env"
            if env_src.is_file():
                target = _env_target(config_dir, data_root)
                if target:
                    shutil.copy2(env_src, target)
                    report.steps.append(f"restored {target}")
                else:
                    report.warnings.append(
                        "config/.env present in the archive but no deployment "
                        "directory is reachable from the container — copy it manually.")
            else:
                report.warnings.append("no config/.env in the archive — "
                                       "deployment settings left untouched")

        # 5. ask the host agent to restart us
        report.restart = request_restart(data_root)
        report.steps.append(report.restart.get("detail", "restart requested"))
        if not report.restart.get("accepted"):
            report.warnings.append(
                "Run `sudo zagros restart` on the host to finish the restore.")
        return report
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _engine_of(url: str | None) -> str | None:
    """``sqlite`` / ``mysql`` / ``postgresql`` — or None when unknown."""
    if not url:
        return None
    lowered = url.lower()
    for engine in ("sqlite", "mysql", "mariadb", "postgresql", "postgres"):
        if lowered.startswith(engine):
            return "mysql" if engine == "mariadb" else (
                "postgresql" if engine == "postgres" else engine)
    return None


def _import_rows(staging: Path, report: RestoreReport, *, session_factory,
                 cipher, users_repo) -> bool:
    """Import the archive's rows instead of copying its database file.

    This is the MySQL-panel path (and the safety net whenever a database file
    cannot be swapped in): users, their usage, admins and hosts are read from
    the archive and written through the repositories, so the engine on this
    side does not matter.
    """
    if session_factory is None or cipher is None or users_repo is None:
        return False

    from app.persistence.migration import LegacyImportService

    service = LegacyImportService(session_factory, users_repo, cipher)
    imported_any = False
    for member in ("db/zagros.sqlite3", "db/legacy.sqlite3"):
        dumped = staging / member
        if not dumped.is_file():
            continue
        source = "zagros" if member.endswith("zagros.sqlite3") else "marzban"
        try:
            snapshot, notes = restore_sources.read_snapshot(source, dumped)
        except RestoreError as exc:
            report.warnings.append(f"{member}: {exc}")
            continue
        if not (snapshot.users or snapshot.admins):
            continue
        migration = service.migrate(snapshot, dry_run=False)
        report.counts.update({k: v for k, v in migration.as_dict().items()
                              if isinstance(v, int)})
        report.credentials.update(notes.get("generated_admin_passwords") or {})
        report.warnings.extend(migration.warnings[:10])
        report.steps.append(
            f"imported rows from {member} into this panel's database "
            f"({len(snapshot.users)} users)")
        imported_any = True
    return imported_any


def _target_of(url: str) -> Path | None:
    return backup_store.sqlite_path(url)


def _swap_database(dumped: Path, target: Path) -> None:
    """Replace a live SQLite file (and drop stale WAL/SHM sidecars)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".restore-tmp")
    shutil.copy2(dumped, tmp)
    os.replace(tmp, target)
    for suffix in ("-wal", "-shm"):
        sidecar = target.with_name(target.name + suffix)
        if sidecar.exists():
            try:
                sidecar.unlink()
            except OSError:  # pragma: no cover
                pass
    # sanity: the restored file must be a readable SQLite database
    con = sqlite3.connect(f"file:{target}?mode=ro", uri=True, timeout=10)
    try:
        con.execute("SELECT count(*) FROM sqlite_master").fetchone()
    finally:
        con.close()


def _env_target(config_dir: str | os.PathLike[str] | None, data_root: Path) -> Path | None:
    candidates: list[Path] = []
    if config_dir:
        candidates.append(Path(config_dir))
    env_home = os.environ.get("ZAGROS_HOME")
    if env_home:
        candidates.append(Path(env_home))
    candidates += [Path("/opt/zagros"), data_root.parent / "zagros"]
    for candidate in candidates:
        if (candidate / ".env").is_file() and os.access(candidate, os.W_OK):
            return candidate / ".env"
    return None


# --------------------------------------------------------------------------- #
# restart
# --------------------------------------------------------------------------- #
def agent_supports_restart(data_dir: str | os.PathLike[str]) -> bool:
    """True when the installed host agent understands restart requests."""
    root = Path(data_dir) / "host-actions"
    caps = root / AGENT_CAPABILITIES
    if not caps.is_file():
        return False  # agent predates the capability file → unknown/older
    try:
        payload = json.loads(caps.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    actions = payload.get("actions") or []
    return "restart-panel" in actions


def request_restart(data_dir: str | os.PathLike[str]) -> dict[str, Any]:
    """Ask the host agent to recreate the container.

    The panel cannot restart itself (it would be killing its own process), so
    the request is dropped where the privileged host agent watches for it.
    """
    root = Path(data_dir) / "host-actions"
    if not (root / ".agent-ready").is_file():
        return {"accepted": False, "reason": "host agent not installed",
                "detail": "run `sudo zagros advanced install-host-agent`, then restart",
                "required": True}
    if not agent_supports_restart(data_dir):
        return {"accepted": False, "reason": "host agent too old for restart requests",
                "detail": "update the agent: sudo zagros advanced install-host-agent",
                "required": True}
    root.mkdir(parents=True, exist_ok=True)
    payload = {"version": 1, "action": "restart-panel",
               "requested_at": int(time.time()),
               "reason": "restore completed"}
    path = root / RESTART_REQUEST
    part = path.with_suffix(".part")
    part.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(part, 0o600)
    os.replace(part, path)
    return {"accepted": True, "status": "pending", "required": True,
            "detail": "restart requested — the host agent will recreate the container"}
