"""Shared GitHub-release binary installer for self-installing drivers.

Factored out of the sing-box driver (DRY) and reused by every driver whose
core ships release binaries on GitHub (sing-box, hysteria, tuic).

Handles: latest-release resolution, OS/arch asset matching, tar.gz / zip /
raw-binary payloads, atomic install with exec permissions, version reporting.
"""
from __future__ import annotations

import io
import json
import os
import platform
import tarfile
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable

from app.cores.exceptions import CoreError

_RELEASES_API = "https://api.github.com/repos/{repo}/releases/latest"
#: direct-download endpoints — work without the (rate-limited) REST API
_DIRECT_DL = "https://github.com/{repo}/releases/latest/download/{asset}"
_PINNED_DL = "https://github.com/{repo}/releases/download/{tag}/{asset}"
_UA = {"User-Agent": "zagros-panel"}

_SYSTEM = {"Linux": "linux", "Darwin": "darwin", "Windows": "windows"}
_ARCH = {
    "x86_64": "amd64", "AMD64": "amd64",
    "aarch64": "arm64", "armv7l": "armv7", "i386": "386", "i686": "386",
}
#: rust-style arch triplets (tuic and some older projects use these)
_RUST_ARCH = {
    "x86_64": "x86_64", "AMD64": "x86_64",
    "aarch64": "aarch64", "armv7l": "armv7",
}


def host_os() -> str:
    try:
        return _SYSTEM[platform.system()]
    except KeyError:
        raise CoreError(f"unsupported host OS: {platform.system()}") from None


def host_arch(*, rust: bool = False) -> str:
    table = _RUST_ARCH if rust else _ARCH
    machine = platform.machine()
    try:
        return table[machine]
    except KeyError:
        raise CoreError(f"unsupported host architecture: {machine!r}") from None


def _open(url: str, *, timeout: float):
    """urlopen with a proper User-Agent; honors GITHUB_TOKEN (60→5000 req/h)."""
    req = urllib.request.Request(url, headers=dict(_UA))
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    return urllib.request.urlopen(req, timeout=timeout)


def fetch_latest_release(repo: str, *, timeout: float = 30.0) -> dict:
    try:
        with _open(_RELEASES_API.format(repo=repo), timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise CoreError(f"cannot resolve latest release of {repo}: {exc}") from exc


_RELEASE_LIST_API = "https://api.github.com/repos/{repo}/releases?per_page={limit}"


def fetch_recent_releases(repo: str, *, limit: int = 10, timeout: float = 20.0) -> list[dict]:
    """Last N release tags of a repo (newest first, non-draft)."""
    limit = max(1, min(limit, 30))
    try:
        with _open(_RELEASE_LIST_API.format(repo=repo, limit=limit),
                   timeout=timeout) as resp:
            releases = json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise CoreError(f"cannot list releases of {repo}: {exc}") from exc
    out = []
    for rel in releases:
        if rel.get("draft"):
            continue
        out.append({
            "tag": rel.get("tag_name"),
            "name": rel.get("name") or "",
            "prerelease": bool(rel.get("prerelease")),
            "published_at": rel.get("published_at"),
        })
        if len(out) >= limit:
            break
    return out


def _download_asset(repo: str, name: str, url: str | None, *,
                    member_match: Callable[[str], bool] | None,
                    extra_members: dict | None = None,
                    timeout: float,
                    sha256: str | None = None) -> tuple[bytes, str]:
    """Fetch one asset (zip/tar.gz/raw) and return (binary bytes, filename).

    ``extra_members``: archive member name → absolute target path; every
    listed member is also extracted and installed with mode 0644.
    ``sha256``: optional expected digest of the RAW downloaded payload
    (the archive itself, verified before any extraction) — hard supply-chain
    check for vendored binaries; mismatch raises, never installs.
    """
    try:
        with _open(url or _DIRECT_DL.format(repo=repo, asset=name), timeout=timeout) as resp:
            blob = resp.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        raise CoreError(f"download of {name} failed: {exc}") from exc

    if sha256 is not None:
        import hashlib

        actual = hashlib.sha256(blob).hexdigest()
        if actual.lower() != sha256.lower():
            raise CoreError(
                f"checksum mismatch for {name}: expected sha256 {sha256}, "
                f"got {actual} — refusing to install a payload whose integrity "
                f"could not be verified."
            )

    def extras_from(namelist, read):
        for member, target in (extra_members or {}).items():
            hit = next((n for n in namelist() if n.rsplit("/", 1)[-1] == member), None)
            if hit is None:
                raise CoreError(f"extra member {member} not found inside {name}.")
            _install_bytes(read(hit), target, mode=0o644)

    if name.endswith((".tar.gz", ".tgz")):
        if member_match is None:
            raise CoreError(f"{name}: archive asset requires a member_match predicate.")
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
            member = next((m for m in archive.getnames() if member_match(m)), None)
            if member is None:
                raise CoreError(f"binary not found inside {name}.")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise CoreError(f"cannot extract {member} from {name}.")
            data = extracted.read()
            extras_from(lambda: archive.getnames(),
                        lambda m: archive.extractfile(m).read())
            return data, name
    if name.endswith(".zip"):
        if member_match is None:
            raise CoreError(f"{name}: archive asset requires a member_match predicate.")
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            member = next((m for m in archive.namelist() if member_match(m)), None)
            if member is None:
                raise CoreError(f"binary not found inside {name}.")
            data = archive.read(member)
            extras_from(lambda: archive.namelist(), lambda m: archive.read(m))
            return data, name
    if extra_members:
        raise CoreError(f"{name}: extra_members require an archive asset.")
    return blob, name  # raw-binary asset (hysteria / tuic / geoip.dat style)


def install_from_github(
    *,
    repo: str,
    target_executable: str,
    asset_match: Callable[[str], bool],
    member_match: Callable[[str], bool] | None = None,
    direct_asset: str | None = None,
    pinned: tuple[str, str] | None = None,
    extra_members: dict | None = None,
    timeout: float = 180.0,
    sha256: str | None = None,
) -> str:
    """Download the matching asset of *repo*'s latest release and install it.

    ``asset_match``: predicate over asset names (os/arch check lives here).
    ``member_match``: for archives, predicate picking the binary inside the
    archive; omit for raw-binary assets (downloaded file IS the binary).
    ``direct_asset``: exact asset filename used as a fallback through
    ``/releases/latest/download/`` when the REST API is unavailable
    (rate-limit / offline metadata) — anonymous GitHub API is limited to
    60 requests/hour per IP, so production installs must not hard-depend on
    it. Set ``GITHUB_TOKEN`` to raise the limit.
    ``pinned``: optional ``(tag, asset_name)`` for reproducible installs
    from an exact release (``/releases/download/<tag>/<asset>``), skipping
    the REST API entirely — preferred in production.
    ``extra_members``: optional mapping of additional archive member names
    (e.g. ``geoip.dat``) to absolute target paths, installed alongside the
    main binary from the same archive with mode 0644.
    ``sha256``: optional expected digest of the downloaded payload, verified
    before extraction (used for Zagros-vendored binaries whose checksums are
    published in the same vendor release).

    Returns the release tag (e.g. "v1.11.4", or "latest-direct" when the
    fallback path was used and the exact tag is unknown). Raises CoreError
    on any gap — honestly, never silently skipping an install.
    """
    if pinned is not None:
        tag, name = pinned
        data, _ = _download_asset(
            repo, name, _PINNED_DL.format(repo=repo, tag=tag, asset=name),
            member_match=member_match, extra_members=extra_members,
            timeout=timeout, sha256=sha256)
        _install_bytes(data, target_executable)
        return tag
    tag: str | None = None
    name: str | None = None
    url: str | None = None
    try:
        release = fetch_latest_release(repo)
        tag = str(release.get("tag_name", "unknown"))
        asset = next(
            (a for a in release.get("assets", []) if asset_match(str(a.get("name", "")))),
            None,
        )
        if asset is None:
            names = [str(a.get("name", "")) for a in release.get("assets", [])]
            raise CoreError(
                f"no matching release asset in {repo}@{tag} "
                f"(available: {', '.join(names) or 'none'})"
            )
        name = str(asset.get("name", ""))
        url = str(asset.get("browser_download_url"))
    except CoreError:
        if direct_asset is None:
            raise
        tag, name, url = "latest-direct", direct_asset, None

    data, _ = _download_asset(repo, name, url, member_match=member_match,
                              extra_members=extra_members, timeout=timeout,
                              sha256=sha256)
    _install_bytes(data, target_executable)
    return tag


def _install_bytes(data: bytes, target_executable: str, mode: int = 0o755) -> None:
    os.makedirs(os.path.dirname(target_executable) or ".", exist_ok=True)
    tmp = f"{target_executable}.tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, target_executable)


def download_raw_asset(
    *,
    repo: str,
    asset_name: str,
    target_path: str,
    timeout: float = 180.0,
) -> str:
    """Install a raw (non-executable) data asset — e.g. geoip.dat / dlc.dat.

    Tries the deterministic ``/releases/latest/download/<asset>`` URL first
    (no REST API quota), falls back to the API to locate a matching asset.
    Returns the installed path; mode 0644 (it is data, not a binary).
    """
    try:
        data, _ = _download_asset(repo, asset_name, None, member_match=None, timeout=timeout)
    except CoreError:
        release = fetch_latest_release(repo)
        asset = next(
            (a for a in release.get("assets", []) if str(a.get("name", "")) == asset_name),
            None,
        )
        if asset is None:
            raise CoreError(f"asset {asset_name} not found in latest release of {repo}.") from None
        data, _ = _download_asset(repo, asset_name, str(asset["browser_download_url"]),
                                  member_match=None, timeout=timeout)
    _install_bytes(data, target_path, mode=0o644)
    return target_path


