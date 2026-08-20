"""Credential-safe persistence and API views for outbound profiles.

``admin.outbounds.v1`` historically stored a raw list of ``Outbound`` JSON,
including passwords/private keys.  The version-2 envelope keeps public profile
settings in the existing KV row and seals credential material with the
platform AES-256-GCM ``SecretsCipher``.  No SQL schema migration is required.

The codec deliberately supports *reading* the legacy list so upgrades do not
lose desired state.  Any successful save/deploy writes only the encrypted v2
shape.  Public views expose boolean secret state, never plaintext/ciphertext.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from app.cores.outbounds.model import Outbound, OutboundKind
from app.persistence.cipher import SecretsCipher

_ENVELOPE_VERSION = 2

# Public certificates/peer public keys are intentionally absent.  Exact names
# cover every current schema; suffix/prefix checks below are defense-in-depth
# for future providers so a newly named credential does not silently land in
# plaintext.
_SECRET_EXACT = frozenset({
    "password", "ipsec_psk", "private_key", "preshared_key", "key_pem",
    "ovpn_content", "obfs_password", "seed", "uuid", "token", "api_token",
    "client_secret", "secret", "auth_token",
})
_PUBLIC_EXACT = frozenset({
    "peer_public_key", "public_key", "reality_public_key", "server_cert",
    "ca_pem", "probe_ca_pem", "cert_pem", "host_key", "tls_server_name",
})


def is_secret_setting(key: str) -> bool:
    lowered = str(key).strip().lower()
    if lowered in _PUBLIC_EXACT:
        return False
    if lowered in _SECRET_EXACT:
        return True
    return (
        lowered.endswith(("_password", "_private_key", "_preshared_key",
                          "_secret", "_token"))
        or lowered.startswith(("password_", "secret_", "token_"))
    )


def split_settings(settings: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    public: dict[str, Any] = {}
    credentials: dict[str, Any] = {}
    for key, value in dict(settings or {}).items():
        (credentials if is_secret_setting(key) else public)[key] = value
    return public, credentials


class OutboundWrite(BaseModel):
    """API write DTO that can omit already-stored secrets.

    ``Outbound`` itself remains the strict runtime type.  This looser boundary
    first merges omitted credentials from the matching stored name+kind, then
    validates the complete result as ``Outbound``.  Explicit clear requests are
    separate from empty form values to prevent an accidental secret wipe.
    """

    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9\-_.]{1,63}$")
    kind: OutboundKind
    settings: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    secret_state: dict[str, bool] = Field(default_factory=dict)
    clear_secret_keys: list[str] = Field(default_factory=list)
    sealed_credentials: str | None = None


class OutboundSecretCodec:
    def __init__(self, cipher: SecretsCipher | None) -> None:
        self._cipher = cipher

    @staticmethod
    def _aad(name: str, kind: OutboundKind | str) -> str:
        value = kind.value if isinstance(kind, OutboundKind) else str(kind)
        return f"outbound:{name}:{value}"

    @staticmethod
    def _import_aad(kind: OutboundKind | str) -> str:
        value = kind.value if isinstance(kind, OutboundKind) else str(kind)
        return f"outbound-import:{value}"

    def seal_import_credentials(
        self, kind: OutboundKind | str, credentials: dict[str, Any],
    ) -> str | None:
        if not credentials:
            return None
        invalid = sorted(key for key in credentials if not is_secret_setting(key))
        if invalid:
            raise ValueError(f"cannot seal public outbound fields as credentials: {invalid}")
        if self._cipher is None:
            raise ValueError("a SecretsCipher is required to seal imported credentials")
        return self._cipher.encrypt_json(credentials, aad=self._import_aad(kind))

    def _open_import_credentials(
        self, kind: OutboundKind | str, blob: str,
    ) -> dict[str, Any]:
        if self._cipher is None:
            raise ValueError("a SecretsCipher is required to open imported credentials")
        credentials = self._cipher.decrypt_json(blob, aad=self._import_aad(kind))
        invalid = sorted(key for key in credentials if not is_secret_setting(key))
        if invalid:
            raise ValueError(f"sealed import contains public setting keys {invalid}")
        return credentials

    @staticmethod
    def _safe_validate(data: dict[str, Any], *, name: str) -> Outbound:
        try:
            return Outbound.model_validate(data)
        except ValidationError as exc:
            details = []
            for error in exc.errors(include_input=False, include_context=False):
                location = ".".join(str(item) for item in error.get("loc") or ())
                message = str(error.get("msg") or "invalid value")
                details.append(f"{location}: {message}" if location else message)
            raise ValueError(
                f"outbound '{name}' is invalid: " + "; ".join(details)
            ) from None

    def decode(self, raw: Any) -> list[Outbound]:
        if not raw:
            return []
        if isinstance(raw, list):
            # Legacy plaintext compatibility is read-only.  The next successful
            # write/deploy atomically replaces it with the v2 envelope.
            result: list[Outbound] = []
            for item in raw:
                if not isinstance(item, dict):
                    raise ValueError("legacy outbound profile must be an object")
                result.append(self._safe_validate(
                    item, name=str(item.get("name") or "")))
            return result
        if not isinstance(raw, dict) or raw.get("version") != _ENVELOPE_VERSION:
            raise ValueError("unsupported outbound persistence format")
        profiles = raw.get("profiles")
        if not isinstance(profiles, list):
            raise ValueError("outbound persistence profiles must be an array")
        result: list[Outbound] = []
        for stored in profiles:
            if not isinstance(stored, dict):
                raise ValueError("outbound persistence profile must be an object")
            name = str(stored.get("name") or "")
            kind = OutboundKind(stored.get("kind"))
            public = dict(stored.get("settings") or {})
            leaked = sorted(key for key in public if is_secret_setting(key))
            if leaked:
                raise ValueError(
                    f"outbound '{name}' encrypted envelope leaked credential keys {leaked}")
            credentials: dict[str, Any] = {}
            encrypted = stored.get("credentials_enc")
            if encrypted:
                if not isinstance(encrypted, str):
                    raise ValueError(f"outbound '{name}' credentials ciphertext is invalid")
                if self._cipher is None:
                    raise ValueError("a SecretsCipher is required to read outbound credentials")
                credentials = self._cipher.decrypt_json(
                    encrypted, aad=self._aad(name, kind))
                invalid = sorted(key for key in credentials if not is_secret_setting(key))
                if invalid:
                    raise ValueError(
                        f"outbound '{name}' ciphertext contains public setting keys {invalid}")
            result.append(self._safe_validate({
                "name": name,
                "kind": kind,
                "enabled": bool(stored.get("enabled", True)),
                "settings": {**public, **credentials},
            }, name=name))
        return result

    def encode(self, outbounds: Iterable[Outbound]) -> dict[str, Any]:
        profiles: list[dict[str, Any]] = []
        for outbound in outbounds:
            public, credentials = split_settings(outbound.settings)
            stored: dict[str, Any] = {
                "name": outbound.name,
                "kind": outbound.kind.value,
                "enabled": outbound.enabled,
                "settings": public,
            }
            if credentials:
                if self._cipher is None:
                    raise ValueError("a SecretsCipher is required to store outbound credentials")
                stored["credentials_enc"] = self._cipher.encrypt_json(
                    credentials, aad=self._aad(outbound.name, outbound.kind))
            profiles.append(stored)
        return {"version": _ENVELOPE_VERSION, "profiles": profiles}

    @staticmethod
    def public_view(outbound: Outbound) -> dict[str, Any]:
        public, credentials = split_settings(outbound.settings)
        return {
            "name": outbound.name,
            "kind": outbound.kind.value,
            "enabled": outbound.enabled,
            "settings": public,
            "secret_state": {
                key: value not in (None, "") for key, value in sorted(credentials.items())
            },
        }

    def merge_writes(
        self, writes: Iterable[OutboundWrite], existing: Iterable[Outbound],
    ) -> list[Outbound]:
        previous = {item.name: item for item in existing}
        result: list[Outbound] = []
        for write in writes:
            old = previous.get(write.name)
            settings = dict(write.settings)
            if write.sealed_credentials:
                sealed = self._open_import_credentials(
                    write.kind, write.sealed_credentials)
                # Explicit form values win when an importer supplies both.
                settings = {**sealed, **settings}
            internal = sorted(key for key in settings if str(key).startswith("_policy_"))
            if internal:
                raise ValueError(
                    f"outbound '{write.name}': deployment-only settings are not writable: {internal}")

            old_secrets: dict[str, Any] = {}
            if old is not None and old.kind is write.kind:
                _public, old_secrets = split_settings(old.settings)
            clear = set(write.clear_secret_keys)
            invalid_clear = sorted(key for key in clear if not is_secret_setting(key))
            if invalid_clear:
                raise ValueError(
                    f"outbound '{write.name}': clear_secret_keys contains non-secret keys "
                    f"{invalid_clear}")
            incoming_secret_keys = {key for key in settings if is_secret_setting(key)}
            for key in incoming_secret_keys:
                value = settings[key]
                # Empty UI password controls mean "leave unchanged".  An
                # intentional deletion must use clear_secret_keys.
                if value in (None, ""):
                    settings.pop(key)
                    if key not in clear and key in old_secrets:
                        settings[key] = old_secrets[key]
            for key, value in old_secrets.items():
                if key not in settings and key not in clear:
                    settings[key] = value
            for key in clear:
                settings.pop(key, None)
            result.append(OutboundSecretCodec._safe_validate({
                "name": write.name,
                "kind": write.kind,
                "settings": settings,
                "enabled": write.enabled,
            }, name=write.name))
        return result
