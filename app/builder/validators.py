"""Build-request validation, secret rejection and log redaction.

Two different mechanisms, often confused:

* *validation* rejects secrets in ``build_config`` UP FRONT (a config is
  not a vault — anything secret-shaped fails the request with 422);
* *redaction* is the last-writer safety net for free-form text the panel
  did not author (worker logs, failure messages). Redaction is
  best-effort BY DESIGN — document the patterns, test them, never claim
  completeness.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

from app.builder.errors import BuildValidationFailed

# platform -> allowed arch slugs (flutter/toolchain canonical names)
PLATFORM_ARCHES: dict[str, frozenset[str]] = {
    "android": frozenset({"armeabi-v7a", "arm64-v8a", "x86_64"}),
    "ios": frozenset({"arm64"}),
    "windows": frozenset({"x64", "arm64"}),
    "linux": frozenset({"x64", "arm64"}),
    "macos": frozenset({"arm64", "x64"}),
}

# platform -> RQ queue label (workers subscribe per native pool)
QUEUE_FOR_PLATFORM: dict[str, str] = {
    "android": "builder:linux",
    "ios": "builder:macos",
    "windows": "builder:windows",
    "linux": "builder:linux",
    "macos": "builder:macos",
}


# artifact kind per target (Phase 17). Default "apk" everywhere: old
# requests without the key keep working byte-for-byte. "aab" is
# android-only and always the full multi-ABI bundle.
ARTIFACTS: tuple[str, ...] = ("apk", "aab")

# platform -> artifact bundle kinds the contract script stages for it
# (white_label_build.expected_artifact_name is the source of truth:
# android apk/aab, windows zip of the exe bundle, linux/macos tar.gz,
# ios ipa).
PLATFORM_ARTIFACTS: dict[str, tuple[str, ...]] = {
    "android": ("apk", "aab"),
    "windows": ("zip",),
    "linux": ("tar.gz",),
    "macos": ("tar.gz",),
    "ios": ("ipa",),
}

DEFAULT_SOURCE_ALLOWLIST: tuple[str, ...] = (
    "https://github.com/ZagrosGM/Zagros-VPN.git",
    "https://github.com/ZagrosGM/Zagros-VPN",
)

# Phase 14: the client build needs the SDK checkout as a sibling of the
# app checkout, so every build pins a second source. Separate allowlist
# on purpose (least privilege: app mirrors and SDK mirrors are governed
# independently).
DEFAULT_SDK_ALLOWLIST: tuple[str, ...] = (
    "https://github.com/ZagrosGM/Zagros-VPN-SDK.git",
    "https://github.com/ZagrosGM/Zagros-VPN-SDK",
)

MAX_TARGETS = 8
MAX_CONFIG_BYTES = 64 * 1024
MAX_CONFIG_DEPTH = 4

_SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")

# key-name fragments that mark a build_config entry as secret-shaped.
# Compared case-insensitively against every dict key at every depth.
# NOTE: there is deliberately no bare "signing" fragment — white-label
# configs legitimately carry the PUBLIC signing_key_id/signing_public_key
# identifiers, and a fragment would false-positive on them. Secret-shaped
# signing material is caught by the precise fragments + exact names below
# (and by "password"/"private_key" for keystore/password variants).
_SECRET_KEY_FRAGMENTS = (
    "password", "passwd", "secret", "token", "private_key", "privatekey",
    "api_key", "apikey", "credential", "passphrase",
    "client_secret", "auth_key", "keystore", "key_password",
    "sign_password",
)

# Full key names that are secret-shaped even though no fragment matches
# (exact match, so public identifiers like signing_key_id still pass).
_SECRET_KEY_EXACT = frozenset({"signing_key", "signing_secret"})

_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL)

# labeled assignments: password=..., "token": "...", api-key: '...'
_LABELED_SECRET = re.compile(
    r"(?i)(password|passwd|secret|token|private[_-]?key|api[_-]?key|"
    r"passphrase|credential|client[_-]?secret|auth[_-]?key|authorization)"
    r"(['\"]?\s*[:=]\s*['\"]?)((?:[Bb]earer\s+)?[^\s'\";,}]+)")

_TOKEN_PREFIXES = re.compile(
    r"\b(ghp_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|"
    r"glpat-[A-Za-z0-9_-]+|xox[bap]-[A-Za-z0-9-]+|"
    r"sk-[A-Za-z0-9]{8,}|rk-[A-Za-z0-9]{8,})\b")

_BEARER = re.compile(r"(?i)\b(Bearer)\s+([A-Za-z0-9._~+/-]+)")

_URL_USERINFO = re.compile(r"(https?://[^/\s:]+:)([^@\s/]+)(@)")

REDACTED = "***REDACTED***"


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_version(version: object) -> str:
    if not isinstance(version, str):
        raise BuildValidationFailed("version must be a string")
    cleaned = version.strip()
    if not cleaned or len(cleaned) > 32 or not _SEMVER.match(cleaned):
        raise BuildValidationFailed(
            "version must be semver (MAJOR.MINOR.PATCH with optional "
            "-prerelease/+build), max 32 characters")
    return cleaned


def _normalize_repo(url: str) -> str:
    cleaned = url.strip().rstrip("/")
    if urlsplit(cleaned).scheme.lower() == "https":
        # Hosts + GitHub paths compare case-insensitively; file:// mirror
        # paths keep their exact case (filesystems may be case-sensitive).
        cleaned = cleaned.lower()
        if cleaned.endswith(".git"):
            cleaned = cleaned[:-4]
    return cleaned


def validate_source_repo(repo: object,
                         allowlist: tuple[str, ...] | list[str], *,
                         field: str = "source_repo") -> str:
    if not isinstance(repo, str):
        raise BuildValidationFailed(f"{field} must be a string")
    cleaned = repo.strip()
    if not cleaned or len(cleaned) > 512:
        raise BuildValidationFailed(f"{field} is required (max 512 chars)")
    parsed = urlsplit(cleaned)
    if parsed.scheme == "https":
        if not parsed.hostname:
            raise BuildValidationFailed(
                f"{field} must be an https URL or a file:// mirror")
    elif parsed.scheme == "file":
        # On-prem mirror support: absolute local paths only, still
        # allowlist-governed below.
        if parsed.netloc not in ("", "localhost") or not parsed.path.startswith("/"):
            raise BuildValidationFailed(
                f"file:// {field} must be an absolute path")
    else:
        raise BuildValidationFailed(
            f"{field} must be an https URL or a file:// mirror")
    allowed = {_normalize_repo(entry) for entry in allowlist}
    if _normalize_repo(cleaned) not in allowed:
        raise BuildValidationFailed(
            f"{field} is not on the build source allowlist")
    return cleaned


def validate_source_revision(revision: object) -> str:
    if not isinstance(revision, str):
        raise BuildValidationFailed("source_revision must be a string")
    cleaned = revision.strip().lower()
    if not _HEX40.match(cleaned):
        raise BuildValidationFailed(
            "source_revision must be a pinned 40-hex commit SHA "
            "(branches/tags are never built)")
    return cleaned


def validate_targets(targets: object) -> list[dict[str, str]]:
    if not isinstance(targets, list) or not targets:
        raise BuildValidationFailed(
            "targets must be a non-empty list of {platform, arch}")
    if len(targets) > MAX_TARGETS:
        raise BuildValidationFailed(
            f"at most {MAX_TARGETS} targets per build")
    cleaned: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in targets:
        if not isinstance(entry, dict):
            raise BuildValidationFailed(
                "each target must be {platform, arch}")
        platform = entry.get("platform")
        arch = entry.get("arch")
        if not isinstance(platform, str) or not isinstance(arch, str):
            raise BuildValidationFailed(
                "each target must be {platform, arch} strings")
        platform, arch = platform.strip().lower(), arch.strip().lower()
        default_artifact = PLATFORM_ARTIFACTS.get(platform, ("apk",))[0]
        artifact = entry.get("artifact", default_artifact)
        if not isinstance(artifact, str):
            raise BuildValidationFailed(
                "each target artifact must be a string")
        artifact = artifact.strip().lower()
        allowed_artifacts = PLATFORM_ARTIFACTS.get(platform, ("apk",))
        if artifact not in allowed_artifacts:
            raise BuildValidationFailed(
                f"unsupported artifact '{artifact}' for '{platform}' "
                f"(supported: {', '.join(allowed_artifacts)})")
        arches = PLATFORM_ARCHES.get(platform)
        if arches is None:
            raise BuildValidationFailed(
                f"unsupported platform '{platform}' "
                f"(supported: {', '.join(sorted(PLATFORM_ARCHES))})")
        if arch not in arches:
            raise BuildValidationFailed(
                f"unsupported arch '{arch}' for platform '{platform}' "
                f"(supported: {', '.join(sorted(arches))})")
        if artifact == "aab" and platform != "android":
            raise BuildValidationFailed(
                f"artifact 'aab' is only supported for android, "
                f"not '{platform}'")
        if (platform, arch, artifact) in seen:
            suffix = f"/{artifact}" if artifact != "apk" else ""
            raise BuildValidationFailed(
                f"duplicate target {platform}/{arch}{suffix}")
        seen.add((platform, arch, artifact))
        cleaned.append({"platform": platform, "arch": arch,
                        "artifact": artifact})
    return cleaned


def _secret_key_name(key: object) -> str | None:
    if not isinstance(key, str):
        return "non-string key"
    lowered = key.lower()
    if lowered in _SECRET_KEY_EXACT:
        return key
    for fragment in _SECRET_KEY_FRAGMENTS:
        if fragment in lowered:
            return key
    return None


def _walk_config(value: object, depth: int, path: str) -> None:
    if depth > MAX_CONFIG_DEPTH:
        raise BuildValidationFailed(
            f"build_config exceeds max depth {MAX_CONFIG_DEPTH} at {path}")
    if isinstance(value, dict):
        for key, item in value.items():
            hit = _secret_key_name(key)
            if hit is not None:
                raise BuildValidationFailed(
                    f"build_config['{path + str(key)}'] looks like a secret "
                    f"('{hit}'): configs are stored in cleartext and shipped "
                    f"to workers — pass secrets as build credentials instead")
            if isinstance(key, str) and len(key) > 128:
                raise BuildValidationFailed(
                    f"build_config key too long at {path}")
            _walk_config(item, depth + 1, f"{path}{key}.")
    elif isinstance(value, list):
        if len(value) > 256:
            raise BuildValidationFailed(
                f"build_config list too long at {path}")
        for index, item in enumerate(value):
            _walk_config(item, depth + 1, f"{path}{index}.")
    elif isinstance(value, str):
        if len(value) > 8192:
            raise BuildValidationFailed(
                f"build_config string too long at {path}")
        if "PRIVATE KEY-----" in value:
            raise BuildValidationFailed(
                f"build_config at {path} contains private-key material: "
                f"use build credentials instead")
    elif not isinstance(value, (int, float, bool)) and value is not None:
        raise BuildValidationFailed(
            f"build_config has unsupported type at {path}")


def validate_build_config(config: object) -> tuple[dict, str]:
    """Validate + canonicalize; returns (config, sha256 digest)."""
    if not isinstance(config, dict):
        raise BuildValidationFailed("build_config must be a JSON object")
    try:
        raw = canonical_json(config)
    except (TypeError, ValueError) as exc:
        raise BuildValidationFailed(
            f"build_config is not JSON-serializable: {exc}") from exc
    if len(raw.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise BuildValidationFailed(
            f"build_config exceeds {MAX_CONFIG_BYTES} bytes")
    _walk_config(config, 0, "")
    display = config.get("display_name")
    if not isinstance(display, str) or not display.strip():
        raise BuildValidationFailed(
            "build_config.display_name is required (non-empty string)")
    if len(display.strip()) > 64:
        raise BuildValidationFailed(
            "build_config.display_name is too long (max 64)")
    canonical = json.loads(raw)
    return canonical, sha256_hex(raw.encode("utf-8"))


def redact_text(text: object, *, max_bytes: int = 1024 * 1024) -> str:
    """Best-effort redaction for worker-authored free text. Never complete."""
    if not isinstance(text, str):
        text = str(text)
    raw = text.encode("utf-8", "replace")
    truncated = len(raw) > max_bytes
    if truncated:
        text = raw[:max_bytes].decode("utf-8", "replace")
    text = _PRIVATE_KEY_BLOCK.sub(REDACTED, text)
    text = _LABELED_SECRET.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", text)
    text = _TOKEN_PREFIXES.sub(REDACTED, text)
    text = _BEARER.sub(lambda match: f"{match.group(1)} {REDACTED}", text)
    text = _URL_USERINFO.sub(
        lambda match: f"{match.group(1)}{REDACTED}{match.group(3)}", text)
    if truncated:
        text += f"\n…[truncated to {max_bytes} bytes]"
    return text


def redact_mapping(value: object) -> object:
    if isinstance(value, dict):
        out: dict = {}
        for key, item in value.items():
            if _secret_key_name(key) is not None:
                out[key] = REDACTED
            else:
                out[key] = redact_mapping(item)
        return out
    if isinstance(value, list):
        return [redact_mapping(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
