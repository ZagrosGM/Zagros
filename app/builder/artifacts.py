"""Immutable on-disk store for build artifacts and final logs.

Layout (relative to the store root)::

    applications/{app}/releases/{version}+{build}/{platform}-{arch}/{file}
    applications/{app}/build-logs/{build_public_id}/{platform}-{arch}.log

Writes are atomic (temp file + ``os.replace``) and immutable (refusing
to overwrite), checksummed before they become visible, and confined to
the root (every path resolves + containment-checked, so ``..`` in a
worker-supplied filename can never escape).
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from uuid import uuid4

from app.builder.errors import BuildConflict, BuildValidationFailed

MAX_FINAL_LOG_BYTES = 5 * 1024 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_API_LOG_BYTES = 1024 * 1024

_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@+-]{0,255}$")


def _segment(value: str, *, what: str) -> str:
    if not isinstance(value, str) or not _SAFE_SEGMENT.match(value):
        raise BuildValidationFailed(f"unsafe {what} '{value}'")
    if value in (".", ".."):
        raise BuildValidationFailed(f"unsafe {what} '{value}'")
    return value


class FileArtifactStore:
    def __init__(self, root: str | os.PathLike[str]) -> None:
        # No directories are created here: the runtime is constructed in
        # unprivileged contexts (tests, boot probes) where the production
        # root may not be writable. Layout materializes lazily on write.
        self._root = Path(root)

    @classmethod
    def from_env(cls, root: str | os.PathLike[str] | None = None,
                 ) -> "FileArtifactStore":
        return cls(root or os.environ.get(
            "ZAGROS_BUILD_ARTIFACT_DIR",
            "/var/lib/zagros/build-artifacts"))

    @property
    def root(self) -> Path:
        return self._root

    # ---------------------------------------------------------- #
    # paths
    # ---------------------------------------------------------- #
    def artifact_rel_path(self, *, app_public_id: str, version: str,
                          build_number: int, platform: str, arch: str,
                          filename: str) -> str:
        app = _segment(app_public_id, what="application id")
        release = _segment(f"{version}+{int(build_number)}", what="release")
        target = _segment(f"{platform}-{arch}", what="target")
        name = _segment(filename, what="filename")
        if name.startswith("."):
            raise BuildValidationFailed(
                f"unsafe filename '{filename}'")
        return (f"applications/{app}/releases/{release}/{target}/{name}")

    def log_rel_path(self, *, app_public_id: str, build_public_id: str,
                     platform: str, arch: str,
                     artifact: str = "apk") -> str:
        app = _segment(app_public_id, what="application id")
        build = _segment(build_public_id, what="build id")
        suffix = "-aab" if artifact == "aab" else ""
        target = _segment(f"{platform}-{arch}{suffix}", what="target")
        return f"applications/{app}/build-logs/{build}/{target}.log"

    def _resolve(self, rel_path: str) -> Path:
        candidate = (self._root / rel_path).resolve()
        root = self._root.resolve()
        if candidate != root and root not in candidate.parents:
            raise BuildValidationFailed("path escapes the artifact store")
        return candidate

    # ---------------------------------------------------------- #
    # writes (atomic + immutable + checksummed)
    # ---------------------------------------------------------- #
    def stage_upload(self) -> Path:
        staging = self._root / ".staging"
        staging.mkdir(parents=True, exist_ok=True)
        path = staging / f"{uuid4().hex}.part"
        path.touch(mode=0o600)
        return path

    def discard_staged(self, staged: Path) -> None:
        try:
            Path(staged).unlink(missing_ok=True)
        except OSError:
            pass

    @staticmethod
    def sha256_of(path: Path) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def finalize(self, staged: str | os.PathLike[str], *, rel_path: str,
                 expected_sha256: str, expected_size: int) -> tuple[str, int]:
        staged_path = Path(staged)
        if not staged_path.is_file():
            raise BuildValidationFailed("staged upload is missing")
        if int(expected_size) < 0 or int(expected_size) > MAX_ARTIFACT_BYTES:
            raise BuildValidationFailed("artifact size out of bounds")
        actual_size = staged_path.stat().st_size
        if actual_size != int(expected_size):
            raise BuildValidationFailed(
                f"artifact size mismatch (declared {expected_size}, "
                f"received {actual_size})")
        actual_sha = self.sha256_of(staged_path)
        if actual_sha != (expected_sha256 or "").strip().lower():
            raise BuildValidationFailed("artifact checksum mismatch")
        dest = self._resolve(rel_path)
        if dest.exists():
            raise BuildConflict(
                "artifact already recorded (releases are immutable)")
        dest.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staged_path, dest)
        dest.chmod(0o644)
        return rel_path, actual_size

    def write_final_log(self, rel_path: str, content: bytes) -> str:
        if len(content) > MAX_FINAL_LOG_BYTES:
            raise BuildValidationFailed(
                f"final log exceeds {MAX_FINAL_LOG_BYTES} bytes")
        dest = self._resolve(rel_path)
        if dest.exists():
            raise BuildConflict(
                "final log already recorded (releases are immutable)")
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.parent / f".{dest.name}.{uuid4().hex}.tmp"
        tmp.write_bytes(content)
        os.replace(tmp, dest)
        dest.chmod(0o644)
        return rel_path

    # ---------------------------------------------------------- #
    # reads
    # ---------------------------------------------------------- #
    def open_for_download(self, rel_path: str) -> Path:
        path = self._resolve(rel_path)
        if not path.is_file():
            raise BuildValidationFailed("stored file is missing")
        return path

    def read_log(self, rel_path: str) -> tuple[bytes, bool]:
        path = self._resolve(rel_path)
        if not path.is_file():
            return b"", False
        size = path.stat().st_size
        if size <= MAX_API_LOG_BYTES:
            return path.read_bytes(), False
        with open(path, "rb") as handle:
            handle.seek(size - MAX_API_LOG_BYTES)
            return handle.read(), True
