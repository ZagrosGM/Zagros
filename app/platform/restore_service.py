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
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.platform import backup_store
from app.platform import restore_sources

RESTORE_DIR_NAME = "restore"
MAX_UPLOAD_BYTES = 4 * 1024 * 1024 * 1024  # 4 GiB — archives hold core data
RESTART_REQUEST = "panel-restart.request.json"
AGENT_CAPABILITIES = ".agent-capabilities"


class RestoreError(RuntimeError):
    """Raised when a restore cannot be carried out safely."""


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
    base = os.path.basename(str(name or "upload.tar.gz"))
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in base)
    cleaned = cleaned.lstrip(".") or "upload.tar.gz"
    if not cleaned.endswith((".tar.gz", ".tgz", ".tar")):
        cleaned += ".tar.gz"
    return cleaned


def discard(staging_file: Path) -> None:
    """Remove the staging directory that holds *staging_file*."""
    parent = Path(staging_file).parent
    if parent.is_dir() and parent.name.startswith(".staging-"):
        shutil.rmtree(parent, ignore_errors=True)


def _extract(archive: Path, dest: Path) -> list[str]:
    """Safe extraction — never writes outside *dest*, never follows links."""
    dest.mkdir(parents=True, exist_ok=True)
    extracted: list[str] = []
    with tarfile.open(archive, "r:gz") as tar:
        try:
            tar.extractall(dest, filter="data")  # py3.12+: no traversal, no links
        except TypeError:  # pragma: no cover - older Python
            tar.extractall(dest)
        extracted = tar.getnames()
    return extracted


def _extract_inner_tar(inner: Path, dest: Path) -> list[str]:
    """Unpack ``data/panel-data.tar.gz`` into the live data directory."""
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(inner, "r:gz") as tar:
        try:
            tar.extractall(dest, filter="data")
        except TypeError:  # pragma: no cover
            tar.extractall(dest)
        return tar.getnames()


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
    restart: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source, "archive": self.archive, "dry_run": self.dry_run,
            "ok": self.ok, "steps": self.steps, "warnings": self.warnings,
            "counts": self.counts,
            "credentials": self.credentials,  # shown once — never logged twice
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
    with tarfile.open(archive, "r:gz") as tar:
        names = set(tar.getnames())
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
def _inspect_foreign(archive: Path, source: str, report: RestoreReport, *,
                     session_factory=None, cipher=None, users_repo=None,
                     apply: bool = False) -> RestoreReport:
    staging = archive.parent / ".extract"
    if staging.exists():
        shutil.rmtree(staging)
    try:
        _extract(archive, staging)
        db_path = restore_sources.pick_database(staging, source)
        detected = restore_sources.identify_database(db_path)
        if detected["source"] and detected["source"] != source and detected["confidence"] >= 0.6:
            report.warnings.append(
                f"this database looks like {detected['source']}, not {source} "
                f"(evidence: {', '.join(detected['evidence'][:5])}). "
                "Continuing with the source you selected.")
        snapshot, notes = restore_sources.read_snapshot(source, db_path)
        report.steps.append(f"read {db_path.name} as {source}")
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
                   allow_config: bool = True) -> RestoreReport:
    """Restore our own archive and request a restart to pick it up."""
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
            restored = _extract_inner_tar(inner, data_root)
            report.steps.append(f"restored {len(restored)} panel-data paths")
            report.counts["data_paths"] = len(restored)
        else:
            report.warnings.append("no data/panel-data.tar.gz — data not restored")

        # 3. databases — swap the file, then let the restart reopen it
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
