"""Registration and signed-request security for Zagros Node Agent."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path

from app.persistence.cipher import SecretsCipher


class NodeSecurityError(ValueError):
    pass


class NodeIdentityStore:
    """Sealed signer identity; bootstrap token is stored as a hash only."""

    def __init__(self, root: str, registration_hash: str | None = None) -> None:
        self.root = Path(root)
        self.path = self.root / "identity.json"
        self.key_path = self.root / "identity.key"
        self.audit_path = self.root / "audit.jsonl"
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        if not self.key_path.exists():
            part = self.key_path.with_suffix(".part")
            part.write_bytes(os.urandom(32))
            os.chmod(part, 0o600)
            os.replace(part, self.key_path)
        local_key = self.key_path.read_bytes()
        if len(local_key) != 32:
            raise NodeSecurityError("identity.key must contain exactly 32 bytes")
        os.chmod(self.key_path, 0o600)
        self._cipher = SecretsCipher(local_key)
        self._lock = threading.RLock()
        if not self.path.exists():
            payload = {
                "node_id": secrets.token_hex(16),
                "registration_token_hash": registration_hash or "",
                "signing_key_enc": None,
                "registered_panel": None,
            }
            self._write(payload)
        else:
            # One-time migration from the early alpha root-private plaintext
            # signer. Remove it immediately after sealing; never wait for a
            # later registration/lifecycle action.
            payload = json.loads(self.path.read_text())
            legacy = payload.pop("signing_key", None)
            if legacy:
                payload["signing_key_enc"] = self._seal_signing_key(
                    base64.b64decode(legacy), str(payload["node_id"]))
            else:
                payload.setdefault("signing_key_enc", None)
            self._write(payload)

    def _read(self) -> dict:
        return json.loads(self.path.read_text())

    def _seal_signing_key(self, key: bytes, node_id: str) -> str:
        return self._cipher.encrypt_json(
            {"key": base64.b64encode(key).decode("ascii")},
            aad=f"node-signing:{node_id}")

    def _write(self, payload: dict) -> None:
        part = self.path.with_suffix(".part")
        part.write_text(json.dumps(payload, sort_keys=True) + "\n")
        os.chmod(part, 0o600)
        os.replace(part, self.path)

    @property
    def node_id(self) -> str:
        return str(self._read()["node_id"])

    def signing_key(self) -> bytes | None:
        state = self._read()
        value = state.get("signing_key_enc")
        if not value:
            return None
        try:
            unsealed = self._cipher.decrypt_json(
                str(value), aad=f"node-signing:{state['node_id']}")
            key = base64.b64decode(unsealed["key"])
        except Exception as exc:  # noqa: BLE001 - fail closed on any tamper/key loss
            raise NodeSecurityError("node signing key cannot be unsealed") from exc
        if len(key) != 32:
            raise NodeSecurityError("node signing key has invalid length")
        return key

    def register(self, token: str, panel_id: str) -> bytes:
        with self._lock:
            state = self._read()
            expected = str(state.get("registration_token_hash") or "")
            actual = hashlib.sha256(token.encode("utf-8")).hexdigest()
            if not expected or not hmac.compare_digest(expected, actual):
                raise NodeSecurityError("invalid or already-consumed registration token")
            key = secrets.token_bytes(32)
            state["registration_token_hash"] = ""  # burn one-time token
            state["signing_key_enc"] = self._seal_signing_key(
                key, str(state["node_id"]))
            state.pop("signing_key", None)
            state["registered_panel"] = panel_id
            self._write(state)
            self.audit("node.register", {"panel_id": panel_id})
            return key

    def revoke(self) -> None:
        with self._lock:
            state = self._read()
            state["signing_key_enc"] = None
            state.pop("signing_key", None)
            state["registered_panel"] = None
            self._write(state)
            self.audit("node.revoke", {})

    def audit(self, action: str, detail: dict) -> None:
        row = {"ts": int(time.time()), "action": action,
               "detail": detail}
        with open(self.audit_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
        os.chmod(self.audit_path, 0o600)


class ReplayGuard:
    """Bounded nonce cache that survives an agent process restart."""

    def __init__(self, root: str | None = None, *, window_seconds: int = 300) -> None:
        self.window = window_seconds
        self._path = Path(root) / "replay.json" if root else None
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()
        if self._path and self._path.exists():
            try:
                value = json.loads(self._path.read_text())
                self._seen = {str(key): int(ts) for key, ts in value.items()}
            except (OSError, ValueError, TypeError):
                # Corrupt replay state must fail closed rather than forgetting
                # potentially live nonces inside the acceptance window.
                raise NodeSecurityError("node replay cache is invalid") from None

    def _write(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        part = self._path.with_suffix(".part")
        part.write_text(json.dumps(self._seen, sort_keys=True) + "\n")
        os.chmod(part, 0o600)
        os.replace(part, self._path)

    def accept(self, nonce: str, timestamp: int, *, now: int | None = None) -> None:
        now = int(time.time()) if now is None else now
        if abs(now - timestamp) > self.window:
            raise NodeSecurityError("request timestamp is outside the replay window")
        if not (16 <= len(nonce) <= 128 and nonce.isalnum()):
            raise NodeSecurityError("invalid request nonce")
        with self._lock:
            self._seen = {key: ts for key, ts in self._seen.items()
                          if now - ts <= self.window}
            if nonce in self._seen:
                raise NodeSecurityError("replayed request nonce")
            self._seen[nonce] = timestamp
            self._write()


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical_request(method: str, path: str, timestamp: str,
                      nonce: str, body: bytes) -> bytes:
    return "\n".join((method.upper(), path, timestamp, nonce,
                       body_hash(body))).encode("utf-8")


def signature(key: bytes, method: str, path: str, timestamp: str,
              nonce: str, body: bytes) -> str:
    return hmac.new(
        key, canonical_request(method, path, timestamp, nonce, body),
        hashlib.sha256).hexdigest()


def verify_signature(key: bytes, provided: str, method: str, path: str,
                     timestamp: str, nonce: str, body: bytes) -> None:
    expected = signature(key, method, path, timestamp, nonce, body)
    if not hmac.compare_digest(expected, provided):
        raise NodeSecurityError("invalid request signature")
