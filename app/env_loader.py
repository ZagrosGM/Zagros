"""Zagros ``.env`` discovery, legacy migration and deterministic loading.

Configuration contract (single source of truth):

* The panel reads its settings from a ``.env`` file. The resolved location is:

  1. ``$ZAGROS_ENV_FILE`` (explicit override, e.g. tests), else
  2. ``<project-root>/.env`` — the directory containing this package's
     parent (``/code/.env`` inside the container image, the repository
     root in development). This is independent of the process CWD.

* Legacy deployments shipped with ``zagros.env`` instead. When that file
  exists and ``.env`` does not, it is migrated automatically
  (copied to ``.env`` with secure permissions; the legacy file is kept as
  ``zagros.env.migrated`` for audit).

* Precedence (highest first): real process environment variables (only set
  by tests/CI/operators explicitly), then the ``.env`` file, then built-in
  defaults. In a docker deployment *nothing* is injected into the container
  environment — compose only mounts the file — so the file is effectively
  the sole source of truth and editing it + restarting the container is
  guaranteed to apply every change.

The loader merges the file into ``os.environ`` *without overriding* real
variables. It is idempotent and deliberately avoids importing ``config``
(or anything heavier) so it can run at the very top of the config module,
Alembic's env.py, the platform runtime and the in-container host tooling.
"""
from __future__ import annotations

import logging
import os
import shutil

logger = logging.getLogger("uvicorn.error")

ENV_OVERRIDE_VAR = "ZAGROS_ENV_FILE"
ENV_BASENAME = ".env"
LEGACY_BASENAME = "zagros.env"
MIGRATED_SUFFIX = ".migrated"

_loaded_path: str | None = None


def default_env_path() -> str:
    """``<project-root>/.env`` derived from this file's location (CWD-free)."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(project_root, ENV_BASENAME)


def resolve_env_path() -> str:
    override = os.environ.get(ENV_OVERRIDE_VAR, "").strip()
    return override or default_env_path()


def migrate_legacy_env(path: str | None = None) -> str | None:
    """Migrate a legacy ``zagros.env`` next to *path* to ``.env``.

    Returns the migrated file path when a migration happened, else None.
    Idempotent: if ``.env`` already exists nothing is touched and both
    files are left alone (the ``.env`` file wins, as documented).
    """
    path = path or resolve_env_path()
    legacy = os.path.join(os.path.dirname(path), LEGACY_BASENAME)
    if os.path.exists(path) or not os.path.isfile(legacy):
        return None
    shutil.copy2(legacy, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    migrated = legacy + MIGRATED_SUFFIX
    shutil.move(legacy, migrated)
    logger.warning(
        "configuration migrated: %s → %s (legacy kept as %s). "
        "Edit .env from now on (e.g. `zagros config edit`).",
        legacy, path, migrated,
    )
    return path


def load_zagros_env(path: str | None = None) -> str | None:
    """Merge the resolved ``.env`` into ``os.environ`` (no overrides).

    Returns the path actually loaded (or the migrated one), None when no
    file exists. Calling it repeatedly is a no-op.
    """
    global _loaded_path
    if _loaded_path is not None:
        return _loaded_path

    path = path or resolve_env_path()
    try:
        migrated = migrate_legacy_env(path)
    except OSError as exc:
        migrated = None
        logger.warning("legacy zagros.env migration failed (%s) — continuing", exc)

    if not os.path.isfile(path):
        _loaded_path = migrated or ""
        return migrated or None

    from dotenv import load_dotenv

    load_dotenv(path, override=False)
    _loaded_path = path
    return path
