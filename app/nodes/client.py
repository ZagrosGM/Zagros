"""Certificate-pinned, HMAC-signed client for Zagros Node Agent."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import socket
import ssl
import tempfile
import time
from pathlib import Path
from typing import Any

import requests

from app.node_agent.security import signature


class NodeClientError(RuntimeError):
    pass


def _normalize_fingerprint(value: str) -> str:
    return "".join(char for char in value.lower() if char in "0123456789abcdef")


def fetch_pinned_certificate(address: str, port: int,
                             expected_fingerprint: str) -> tuple[str, str]:
    """Fetch TLS leaf cert only after matching the operator-provided SHA-256."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # trust comes from explicit pin below
    try:
        with socket.create_connection((address, port), timeout=8) as raw:
            with context.wrap_socket(raw, server_hostname=address) as tls:
                der = tls.getpeercert(binary_form=True)
    except OSError as exc:
        raise NodeClientError(f"cannot connect to node TLS listener: {exc}") from exc
    actual = hashlib.sha256(der).hexdigest()
    if not secrets.compare_digest(
            actual, _normalize_fingerprint(expected_fingerprint)):
        raise NodeClientError(
            f"node certificate fingerprint mismatch (observed {actual})")
    return ssl.DER_cert_to_PEM_cert(der), actual


class ZagrosNodeClient:
    def __init__(self, address: str, port: int, node_id: str | None,
                 signing_key: bytes | None, certificate_pem: str) -> None:
        self.address = address
        self.port = int(port)
        self.node_id = node_id
        self.signing_key = signing_key
        self.certificate_pem = certificate_pem

    @property
    def base_url(self) -> str:
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"https://{host}:{self.port}"

    def _certificate_file(self) -> str:
        handle = tempfile.NamedTemporaryFile(
            mode="w", prefix="zagros-node-ca-", suffix=".pem", delete=False)
        handle.write(self.certificate_pem); handle.close()
        os.chmod(handle.name, 0o600)
        return handle.name

    def _request(self, method: str, path: str, *, payload: dict | None = None,
                 timeout: float = 30.0, signed: bool = True) -> dict:
        body = (json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
                if payload is not None else b"")
        headers = {"Content-Type": "application/json"}
        if signed:
            if self.node_id is None or self.signing_key is None:
                raise NodeClientError("node client is not registered")
            timestamp = str(int(time.time()))
            nonce = secrets.token_hex(16)
            headers.update({
                "X-Zagros-Node": self.node_id,
                "X-Zagros-Timestamp": timestamp,
                "X-Zagros-Nonce": nonce,
                "X-Zagros-Signature": signature(
                    self.signing_key, method, path.partition("?")[0],
                    timestamp, nonce, body),
            })
        certfile = self._certificate_file()
        try:
            response = requests.request(
                method, self.base_url + path, data=body or None,
                headers=headers, verify=certfile, timeout=timeout)
        except requests.RequestException as exc:
            raise NodeClientError(f"node request failed: {exc}") from exc
        finally:
            Path(certfile).unlink(missing_ok=True)
        try:
            value = response.json()
        except ValueError:
            value = {"detail": response.text[:500]}
        if response.status_code >= 400:
            detail = value.get("detail") if isinstance(value, dict) else value
            raise NodeClientError(f"node HTTP {response.status_code}: {detail}")
        if not isinstance(value, dict):
            raise NodeClientError("node returned a non-object response")
        return value

    def register(self, panel_id: str, registration_token: str) -> dict:
        return self._request("POST", "/v1/register", payload={
            "panel_id": panel_id, "registration_token": registration_token,
        }, signed=False)

    def heartbeat(self) -> dict:
        return self._request("GET", "/v1/heartbeat")

    def health(self) -> dict:
        return self._request("GET", "/v1/health")

    def revoke(self) -> dict:
        return self._request("POST", "/v1/revoke")

    def cores(self) -> dict:
        return self._request("GET", "/v1/cores")

    def core_status(self, core_id: str) -> dict:
        return self._request("GET", f"/v1/cores/{core_id}")

    def core_version(self, core_id: str) -> dict:
        return self._request("GET", f"/v1/cores/{core_id}/version")

    def core_logs(self, core_id: str, tail: int = 200) -> dict:
        return self._request("GET", f"/v1/cores/{core_id}/logs?tail={int(tail)}")

    def lifecycle(self, core_id: str, action: str, *,
                  settings: dict | None = None, purge: bool = False,
                  force: bool = False) -> dict:
        return self._request(
            "POST", f"/v1/cores/{core_id}/lifecycle",
            payload={"action": action, "settings": settings or {},
                     "purge": purge, "force": force},
            timeout=920 if action in ("install", "uninstall") else 120,
        )

    def provision_account(self, core_id: str, account_id: str, *, user_id: int,
                          username: str, protocol: str, enabled: bool,
                          settings: dict, create: bool) -> dict:
        from urllib.parse import quote

        path = f"/v1/cores/{quote(core_id, safe='')}/accounts/{quote(account_id, safe='')}"
        return self._request("PUT", path, payload={
            "user_id": user_id, "username": username,
            "protocol": protocol, "enabled": enabled,
            "settings": settings, "create": create,
        }, timeout=150)

    def set_account_enabled(self, core_id: str, account_id: str, *,
                            enabled: bool, user_id: int, username: str,
                            protocol: str, settings: dict) -> dict:
        from urllib.parse import quote

        path = (f"/v1/cores/{quote(core_id, safe='')}/accounts/"
                f"{quote(account_id, safe='')}/state")
        return self._request("PUT", path, payload={
            "enabled": enabled, "user_id": user_id, "username": username,
            "protocol": protocol, "settings": settings,
        }, timeout=150)

    def delete_account(self, core_id: str, account_id: str) -> dict:
        from urllib.parse import quote

        path = f"/v1/cores/{quote(core_id, safe='')}/accounts/{quote(account_id, safe='')}"
        return self._request("DELETE", path, timeout=150)

    def apply_inbounds(self, core_id: str, document: dict) -> dict:
        return self._request(
            "PUT", f"/v1/cores/{core_id}/inbounds",
            payload={"document": document}, timeout=120)
