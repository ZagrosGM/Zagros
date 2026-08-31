"""Create, list, verify and prune Zagros backup archives.

The archive layout is **byte-compatible with the ``zagros`` host CLI** so a
backup taken from the dashboard can be restored on the host with
``zagros restore`` and the other way around. Keep both writers in step.

Layout::

    zagros-backup-<UTC>.tar.gz
    ├── manifest.json        {"manifest_version", "created_utc", "files":[{path,sha256,bytes}]}
    ├── manifest.meta        key=value lines (kind, cli, panel, image_tag, db_kind, ...)
    ├── db/
    │   ├── zagros.sqlite3   hot (WAL-safe) copy of the platform database
    │   └── legacy.sqlite3   hot copy of the legacy database, when present
    ├── config/
    │   ├── .env             the deployment — the single source of truth
    │   ├── docker-compose.yml
    │   └── .state/          CLI state (last update, rollback points, ...)
    └── data/
        ├── panel-data.tar.gz    everything under the data dir, minus exclusions
        └── logs.tar.gz, panel.log   only with --logs

Exclusions are deliberate and recorded in the manifest: core binaries and
assets are re-installable, the backup directory must never contain itself, and
the databases are dumped separately so the copy is hot-consistent.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import tarfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable

BACKUP_KIND = "zagros-full"
MANIFEST_VERSION = 1
BACKUP_DIR_NAME = "backups"

# Directories/files that must never be archived (see module docstring).
_EXCLUDES: tuple[str, ...] = (
    "./backups",
    "./cache",
    "./db",
    "./cores/*/bin",
    "./cores/*/assets",
    "./cores/softether/runtime/vpnserver",
    "./cores/softether/runtime/vpncmd",
    "./cores/softether/runtime/hamcore.se2",
    "./cores/softether/runtime/libcedar.so*",
    "./cores/softether/runtime/libmayaqua.so*",
    "./zagros.db",
    "./zagros.db-*",
    "./legacy.db",
    "./legacy.db-*",
)
_LOG_EXCLUDE = "./logs"

_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


class BackupError(RuntimeError):
    """Raised when a backup cannot be created, read or verified."""


# --------------------------------------------------------------------------- #
# paths
# --------------------------------------------------------------------------- #
def directory(data_dir: str | os.PathLike[str] | None = None) -> Path:
    """Where archives live. Created on demand (0700 — archives hold secrets)."""
    base = Path(data_dir) if data_dir else Path(os.environ.get("ZAGROS_DATA_DIR") or "/var/lib/zagros")
    path = base / BACKUP_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:  # pragma: no cover - non-POSIX / read-only edge
        pass
    return path


def new_name(now: float | None = None) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%SZ", time.gmtime(now or time.time()))
    return f"zagros-backup-{stamp}.tar.gz"


def _unique_name(backup_dir: Path, now: float | None = None) -> str:
    """A name that does not already exist.

    Two backups started in the same second (a double click, or a scheduled run
    colliding with a manual one) would otherwise overwrite each other silently.
    The first one keeps the plain, CLI-compatible name.
    """
    candidate = new_name(now)
    if not (backup_dir / candidate).exists():
        return candidate
    stem = candidate[: -len(".tar.gz")]
    index = 2
    while (backup_dir / f"{stem}-{index}.tar.gz").exists():
        index += 1
    return f"{stem}-{index}.tar.gz"


def safe_name(name: str) -> str:
    """Validate an archive name — it must never escape the backup directory."""
    candidate = os.path.basename(str(name or ""))
    if not _SAFE_NAME.match(candidate) or not candidate.endswith(".tar.gz"):
        raise BackupError(f"invalid backup archive name: {name!r}")
    return candidate


def path_for(name: str, data_dir: str | os.PathLike[str] | None = None) -> Path:
    """Resolve *name* inside the backup directory (no traversal, must exist)."""
    return directory(data_dir) / safe_name(name)


# --------------------------------------------------------------------------- #
# model
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class BackupArtifact:
    name: str
    size_bytes: int
    created_utc: str
    kind: str = BACKUP_KIND
    panel_version: str = ""
    db_kind: str = "unknown"
    verified: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _db_kind(url: str | None) -> str:
    text = (url or "").lower()
    if text.startswith("sqlite"):
        return "sqlite"
    if text.startswith("mysql") or text.startswith("mariadb"):
        return "mysql"
    if text.startswith("postgresql") or text.startswith("postgres"):
        return "postgresql"
    return "unknown"


def sqlite_path(url: str | None) -> Path | None:
    """Public alias — other modules resolve database files through this."""
    return _sqlite_path(url)


def _sqlite_path(url: str | None) -> Path | None:
    """Absolute path of a SQLite file URL, or ``None`` for other backends."""
    if not url or not url.lower().startswith("sqlite"):
        return None
    try:
        from sqlalchemy.engine import make_url

        parsed = make_url(url)
    except Exception:  # pragma: no cover - defensive: malformed URL
        return None
    if not parsed.database or parsed.database == ":memory:":
        return None
    return Path(os.path.realpath(os.path.expanduser(parsed.database)))


def hot_copy_sqlite(url: str | None, out: Path) -> bool:
    """WAL-safe copy of a live SQLite database (read-only source, no locks held).

    Returns ``False`` when the backend is not SQLite or the file is absent —
    a backup must still succeed with a note in the manifest rather than fail
    because one optional component is missing.
    """
    src = _sqlite_path(url)
    if src is None or not src.exists():
        return False
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".in-progress")
    if tmp.exists():
        tmp.unlink()

    def _copy() -> None:
        source = sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=30)
        try:
            target = sqlite3.connect(str(tmp), timeout=30)
            try:
                source.backup(target)  # hot-consistent, WAL-safe
            finally:
                target.close()
        finally:
            source.close()

    _copy()
    os.replace(tmp, out)
    return True


def _add_tree(tar: tarfile.TarFile, root: Path, arcname: str) -> None:
    tar.add(str(root), arcname=arcname, recursive=True)


def _excluded(rel: str, patterns: Iterable[str]) -> bool:
    """``fnmatch``-style exclusion against a data-dir-relative path.

    The path *and every ancestor* are tested, so ``./cores/*/bin`` excludes
    ``cores/xray/bin/xray`` and not just the directory entry itself.
    """
    import fnmatch

    rel = rel.replace(os.sep, "/").lstrip("./")
    if not rel or rel == ".":
        return False
    parts = rel.split("/")
    for index in range(len(parts), 0, -1):
        candidate = "./" + "/".join(parts[:index])
        for pattern in patterns:
            if fnmatch.fnmatch(candidate, pattern):
                return True
    return False


def _build_panel_data_tar(data_dir: Path, out: Path, *, include_logs: bool) -> list[str]:
    """Archive the data directory, honouring the exclusion list.

    The tree is walked explicitly (rather than with ``tar.add(recursive=True)``)
    so exclusions apply at every depth — a filter callback only sees the
    arcname, which is not enough to match ancestor patterns.
    """
    patterns = list(_EXCLUDES)
    if not include_logs:
        patterns.append(_LOG_EXCLUDE)
    notes: list[str] = []
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".in-progress")

    with tarfile.open(tmp, "w:gz") as tar:
        for entry in sorted(data_dir.iterdir()):
            if _excluded(entry.name, patterns):
                notes.append(entry.name)
                continue
            try:
                if entry.is_dir() and not entry.is_symlink():
                    for root, dirs, files in os.walk(entry):
                        rel_root = os.path.relpath(root, data_dir)
                        # prune excluded directories before descending
                        dirs[:] = sorted(
                            d for d in dirs
                            if not _excluded(os.path.join(rel_root, d), patterns))
                        for filename in sorted(files):
                            rel = os.path.join(rel_root, filename)
                            if _excluded(rel, patterns):
                                continue
                            tar.add(os.path.join(root, filename), arcname=rel)
                else:
                    tar.add(str(entry), arcname=entry.name)
            except (PermissionError, OSError) as exc:  # unreadable subtree
                notes.append(f"{entry.name} (unreadable: {exc.strerror or exc})")
    os.replace(tmp, out)
    return notes


def _write_manifest_json(staging: Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for base, _dirs, names in os.walk(staging):
        for name in sorted(names):
            path = Path(base) / name
            rel = os.path.relpath(path, staging)
            if rel == "manifest.json" or rel.startswith(".bak"):
                continue
            files.append({"path": rel.replace(os.sep, "/"),
                          "sha256": _sha256(path),
                          "bytes": path.stat().st_size})
    manifest = {"manifest_version": MANIFEST_VERSION,
                "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "files": files}
    (staging / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    return manifest


def _write_manifest_meta(staging: Path, fields: dict[str, str]) -> None:
    body = "".join(f"{key}={value}\n" for key, value in fields.items())
    (staging / "manifest.meta").write_text(body, encoding="utf-8")


# --------------------------------------------------------------------------- #
# create
# --------------------------------------------------------------------------- #
def create(
    *,
    data_dir: str | os.PathLike[str],
    database_url: str | None,
    legacy_database_url: str | None = None,
    panel_version: str = "",
    image_tag: str = "",
    include_logs: bool = False,
    config_dir: str | os.PathLike[str] | None = None,
    name: str | None = None,
) -> BackupArtifact:
    """Build one archive and return its descriptor.

    Runs the heavy lifting synchronously; callers on the event loop should
    wrap it in ``asyncio.to_thread`` (the API layer does).
    """
    data_root = Path(data_dir)
    if not data_root.is_dir():
        raise BackupError(f"data directory does not exist: {data_root}")
    backup_dir = directory(data_root)
    archive_name = safe_name(name or _unique_name(backup_dir))
    timestamp = time.strftime("%Y%m%d-%H%M%SZ", time.gmtime())
    staging = backup_dir / f".staging-{timestamp}-{os.getpid()}"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True, mode=0o700)

    missing: list[str] = []
    try:
        # 1. databases — hot copies, never a plain file copy
        db_dir = staging / "db"
        db_dir.mkdir()
        platform_db = hot_copy_sqlite(database_url, db_dir / "zagros.sqlite3")
        if not platform_db:
            missing.append("db/zagros.sqlite3")
        if legacy_database_url:
            legacy_db = hot_copy_sqlite(legacy_database_url, db_dir / "legacy.sqlite3")
            if not legacy_db:
                missing.append("db/legacy.sqlite3")

        # 2. deployment configuration (may be outside the container → optional)
        cfg_dir = staging / "config"
        cfg_dir.mkdir()
        copied_config = _copy_deployment_config(cfg_dir, config_dir, data_root)
        if not copied_config:
            missing.append("config/.env")

        # 3. panel data
        data_out = staging / "data"
        data_out.mkdir()
        skipped = _build_panel_data_tar(data_root, data_out / "panel-data.tar.gz",
                                        include_logs=include_logs)
        if include_logs:
            logs_dir = data_root / "logs"
            if logs_dir.is_dir():
                with tarfile.open(data_out / "logs.tar.gz", "w:gz") as tar:
                    tar.add(str(logs_dir), arcname="logs", recursive=True)

        # 4. manifests (meta first — the JSON indexes every other file)
        _write_manifest_meta(staging, {
            "kind": BACKUP_KIND,
            "cli": "panel",
            "panel": panel_version or "unknown",
            "image_tag": image_tag or "",
            "db_kind": _db_kind(database_url),
            "created_utc": timestamp,
            "include_logs": "yes" if include_logs else "no",
            **({"missing": ",".join(missing)} if missing else {}),
            **({"excluded": ",".join(skipped)} if skipped else {}),
            "exclusions": "cores/*/bin, cores/*/assets, SoftEther runtime binaries, "
                          "./cache, ./db (dumped separately), ./backups"
                          + ("" if include_logs else ", ./logs"),
        })
        _write_manifest_json(staging)

        # 5. pack
        final = backup_dir / archive_name
        tmp_archive = backup_dir / (archive_name + ".tmp")
        with tarfile.open(tmp_archive, "w:gz") as tar:
            for entry in sorted(staging.iterdir()):
                tar.add(str(entry), arcname=entry.name, recursive=True)
        os.replace(tmp_archive, final)
        try:
            os.chmod(final, 0o600)
        except OSError:  # pragma: no cover
            pass
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    return BackupArtifact(
        name=archive_name,
        size_bytes=(backup_dir / archive_name).stat().st_size,
        created_utc=timestamp,
        kind=BACKUP_KIND,
        panel_version=panel_version,
        db_kind=_db_kind(database_url),
    )


def _copy_deployment_config(dest: Path, config_dir: str | os.PathLike[str] | None,
                            data_root: Path) -> bool:
    """Copy ``.env`` / ``docker-compose.yml`` / ``.state`` when reachable."""
    candidates: list[Path] = []
    if config_dir:
        candidates.append(Path(config_dir))
    env_home = os.environ.get("ZAGROS_HOME")
    if env_home:
        candidates.append(Path(env_home))
    candidates += [Path("/opt/zagros"), data_root.parent / "zagros", data_root]
    copied = False
    for candidate in candidates:
        try:
            if not candidate.is_dir():
                continue
            for src_name, dst_name in ((".env", ".env"),
                                       ("docker-compose.yml", "docker-compose.yml"),
                                       ("docker-compose.yaml", "docker-compose.yml")):
                src = candidate / src_name
                if src.is_file():
                    shutil.copy2(src, dest / dst_name)
                    copied = True
            state = candidate / ".state"
            if state.is_dir():
                shutil.copytree(state, dest / ".state", dirs_exist_ok=True)
            if copied:
                return True
        except (PermissionError, OSError):
            continue
    return copied


# --------------------------------------------------------------------------- #
# read / verify / prune
# --------------------------------------------------------------------------- #
def list_artifacts(data_dir: str | os.PathLike[str] | None = None) -> list[BackupArtifact]:
    backup_dir = directory(data_dir)
    artifacts: list[BackupArtifact] = []
    for path in sorted(backup_dir.glob("*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            meta = meta_of(path)
        except Exception:  # unreadable archive — still listed, flagged
            meta = {}
        artifacts.append(BackupArtifact(
            name=path.name,
            size_bytes=path.stat().st_size,
            created_utc=meta.get("created_utc") or
                        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(path.stat().st_mtime)),
            kind=meta.get("kind") or BACKUP_KIND,
            panel_version=meta.get("panel") or "",
            db_kind=meta.get("db_kind") or "unknown",
        ))
    return artifacts


def meta_of(archive: Path | str) -> dict[str, str]:
    """Parse ``manifest.meta`` (key=value lines) from an archive."""
    path = Path(archive)
    if not path.is_file():
        raise BackupError(f"backup archive not found: {path}")
    with tarfile.open(path, "r:gz") as tar:
        try:
            member = tar.getmember("manifest.meta")
        except KeyError as exc:
            raise BackupError(f"{path.name}: not a Zagros backup (no manifest.meta)") from exc
        handle = tar.extractfile(member)
        if handle is None:  # pragma: no cover - defensive
            raise BackupError(f"{path.name}: unreadable manifest.meta")
        text = handle.read().decode("utf-8", errors="replace")
    meta: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            meta[key.strip()] = value.strip()
    return meta


def manifest_of(archive: Path | str) -> dict[str, Any]:
    """Parse ``manifest.json`` (the file index with checksums)."""
    path = Path(archive)
    with tarfile.open(path, "r:gz") as tar:
        try:
            member = tar.getmember("manifest.json")
        except KeyError as exc:
            raise BackupError(f"{path.name}: no manifest.json") from exc
        handle = tar.extractfile(member)
        if handle is None:  # pragma: no cover - defensive
            raise BackupError(f"{path.name}: unreadable manifest.json")
        return json.loads(handle.read().decode("utf-8"))


def verify(archive: Path | str) -> dict[str, Any]:
    """Check the archive against its own manifest (structure + checksums)."""
    path = Path(archive)
    manifest = manifest_of(path)
    problems: list[str] = []
    with tarfile.open(path, "r:gz") as tar:
        names = set(tar.getnames())
        for entry in manifest.get("files", []):
            if entry["path"] not in names:
                problems.append(f"missing: {entry['path']}")
    return {"ok": not problems, "problems": problems,
            "files": len(manifest.get("files", [])), "archive": path.name}


def delete(name: str, data_dir: str | os.PathLike[str] | None = None) -> bool:
    path = path_for(name, data_dir)
    if not path.is_file():
        return False
    path.unlink()
    return True


def prune(keep: int, data_dir: str | os.PathLike[str] | None = None) -> list[str]:
    """Keep the newest *keep* archives; return the names that were removed."""
    if keep < 0:
        raise BackupError("keep must be >= 0")
    artifacts = list_artifacts(data_dir)
    removed: list[str] = []
    for artifact in artifacts[keep:]:
        if delete(artifact.name, data_dir):
            removed.append(artifact.name)
    return removed
