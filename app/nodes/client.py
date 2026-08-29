"""Certificate-pinned, HMAC-signed client for the Zagros node agent.

Two channels, two trust levels:

* **info port (``api_port``)** — plain HTTP, read-only, no credentials. Used
  once, to discover a node's identity and fetch the certificate we then pin.
  Everything it returns is public by definition; see
  ``node_agent/info_api.py`` in the zagros-node repository.
* **control plane (``port``)** — HTTPS with the pinned leaf certificate, plus
  an HMAC-SHA256 signature over every request. This is the only channel that
  can change anything.

Long operations (install/uninstall) are submitted as jobs and polled here,
so a slow core download can never be cut in half by an idle proxy timeout.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import ssl
import tempfile
import time
from pathlib import Path
import requests

# Kept byte-identical to node_agent/security.py — this is the wire contract.
from app.nodes.signing import signature

DEFAULT_TIMEOUT = 30.0
_JOB_TIMEOUTS = {"install": 1200.0, "uninstall": 600.0, "update": 1200.0}
_TERMINAL = ("succeeded", "failed", "cancelled")


class NodeClientError(RuntimeError):
    """Any transport-, auth- or node-side failure talking to a node."""


def _normalize_fingerprint(value: str) -> str:
    return "".join(char for char in (value or "").lower() if char in "0123456789abcdef")


def fetch_pinned_certificate(address: str, port: int,
                             expected_fingerprint: str) -> tuple[str, str]:
    """Fetch the node's TLS leaf, but only after it matches the operator's pin.

    This is the trust anchor of the whole design: the certificate is self-
    signed, so the SHA-256 the operator verified (printed by the installer)
    is the only thing that makes it trustworthy.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # trust comes from the explicit pin
    try:
        with socket.create_connection((address, port), timeout=8) as raw:
            with context.wrap_socket(raw, server_hostname=address) as tls:
                der = tls.getpeercert(binary_form=True)
    except OSError as exc:
        raise NodeClientError(f"cannot connect to node TLS listener: {exc}") from exc
    actual = hashlib.sha256(der).hexdigest()
    if not secrets.compare_digest(actual, _normalize_fingerprint(expected_fingerprint)):
        raise NodeClientError(
            f"node certificate fingerprint mismatch (observed {actual})")
    return ssl.DER_cert_to_PEM_cert(der), actual


def fetch_node_info(address: str, api_port: int, *, timeout: float = 8.0) -> dict:
    """Read a node's public bootstrap document (info port, unauthenticated)."""
    host = f"[{address}]" if ":" in address and not address.startswith("[") else address
    url = f"http://{host}:{api_port}/info"
    try:
        response = requests.get(url, timeout=timeout)
    except requests.RequestException as exc:
        raise NodeClientError(f"node info endpoint unreachable: {exc}") from exc
    if response.status_code >= 400:
        raise NodeClientError(
            f"node info endpoint returned HTTP {response.status_code}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise NodeClientError("node info endpoint returned invalid JSON") from exc
    if not isinstance(payload, dict) or not payload.get("certificate_pem"):
        raise NodeClientError("node info endpoint returned an incomplete document")
    return payload


class ZagrosNodeClient:
    """Signed commands against one node."""

    def __init__(self, address: str, port: int, node_id: str | None,
                 signing_key: bytes | None, certificate_pem: str,
                 *, api_port: int | None = None) -> None:
        self.address = address
        self.port = int(port)
        self.api_port = int(api_port) if api_port else None
        self.node_id = node_id
        self.signing_key = signing_key
        self.certificate_pem = certificate_pem

    # ------------------------------------------------------------------ #
    @property
    def base_url(self) -> str:
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"https://{host}:{self.port}"

    def _certificate_file(self) -> str:
        handle = tempfile.NamedTemporaryFile(
            mode="w", prefix="zagros-node-pin-", suffix=".pem", delete=False)
        handle.write(self.certificate_pem)
        handle.close()
        os.chmod(handle.name, 0o600)
        return handle.name

    def _request(self, method: str, path: str, *, payload: dict | None = None,
                 timeout: float = DEFAULT_TIMEOUT, signed: bool = True) -> dict:
        body = (json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
                if payload is not None else b"")
        headers = {"Content-Type": "application/json"}
        route = path.partition("?")[0]
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
                    self.signing_key, method, route, timestamp, nonce, body),
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

    # ------------------------------------------------------------------ #
    # pairing
    # ------------------------------------------------------------------ #
    def register(self, panel_id: str, registration_token: str) -> dict:
        return self._request("POST", "/v1/register", payload={
            "panel_id": panel_id, "registration_token": registration_token,
        }, signed=False)

    def revoke(self) -> dict:
        return self._request("POST", "/v1/revoke")

    # ------------------------------------------------------------------ #
    # node state
    # ------------------------------------------------------------------ #
    def heartbeat(self) -> dict:
        return self._request("GET", "/v1/heartbeat")

    def health(self) -> dict:
        return self._request("GET", "/v1/health")

    def info(self) -> dict:
        return self._request("GET", "/v1/info")

    def audit(self, limit: int = 100) -> dict:
        return self._request("GET", f"/v1/audit?limit={max(1, min(limit, 500))}")

    # ------------------------------------------------------------------ #
    # cores
    # ------------------------------------------------------------------ #
    def cores(self) -> dict:
        return self._request("GET", "/v1/cores")

    def core_status(self, core_id: str) -> dict:
        return self._request("GET", f"/v1/cores/{core_id}")

    def core_version(self, core_id: str) -> dict:
        return self._request("GET", f"/v1/cores/{core_id}/version")

    def core_logs(self, core_id: str, tail: int = 200) -> dict:
        return self._request("GET", f"/v1/cores/{core_id}/logs?tail={int(tail)}")

    def core_settings(self, core_id: str) -> dict:
        return self._request("GET", f"/v1/cores/{core_id}/settings")

    def apply_settings(self, core_id: str, settings: dict) -> dict:
        """Patch a core's settings on the node (validated by its driver)."""
        return self._request("PUT", f"/v1/cores/{core_id}/settings",
                             payload={"settings": settings}, timeout=60)

    def apply_accounts(self, core_id: str, accounts: list[dict],
                       *, replace: bool = True) -> dict:
        """Converge a core's accounts on the node to the panel's state."""
        return self._request("PUT", f"/v1/cores/{core_id}/accounts",
                             payload={"accounts": accounts, "replace": replace},
                             timeout=300)

    def apply_identity(self, core_id: str, material: dict[str, str]) -> dict:
        """Hand the master's SERVER identity to a node.

        Secret material (a CA, a WireGuard private key, an IPsec PSK) — sent
        only over the mutually authenticated control plane, to a node whose
        certificate the panel pinned at pairing time.
        """
        return self._request("PUT", f"/v1/cores/{core_id}/identity",
                             payload={"material": material}, timeout=300)

    def apply_inbounds(self, core_id: str, document: dict) -> dict:
        return self._request(
            "PUT", f"/v1/cores/{core_id}/inbounds",
            payload={"document": document}, timeout=120)

    # ------------------------------------------------------------------ #
    # lifecycle (job-based)
    # ------------------------------------------------------------------ #
    def job(self, job_id: str) -> dict:
        return self._request("GET", f"/v1/jobs/{job_id}")

    def lifecycle(self, core_id: str, action: str, *,
                  settings: dict | None = None, purge: bool = False,
                  force: bool = False, wait: float = 15.0,
                  poll_interval: float = 1.0) -> dict:
        """Submit a lifecycle action and follow its job to a terminal state.

        ``wait`` is passed to the node so fast actions (start/stop/restart)
        finish in a single round-trip; slow ones keep being polled here until
        the action's own timeout elapses.
        """
        budget = _JOB_TIMEOUTS.get(action, 120.0)
        submitted = self._request(
            "POST", f"/v1/cores/{core_id}/lifecycle?wait={max(0.0, float(wait))}",
            payload={"action": action, "settings": settings or {},
                     "purge": purge, "force": force},
            timeout=min(budget + 30.0, wait + 60.0),
        )
        job = dict(submitted)
        state = str(job.get("state") or "")
        if state in _TERMINAL:
            return _finish(job)

        deadline = time.time() + budget
        while time.time() < deadline:
            time.sleep(poll_interval)
            job = self.job(str(job.get("job_id")))
            state = str(job.get("state") or "")
            if state in _TERMINAL:
                return _finish(job)
        raise NodeClientError(
            f"'{action}' on '{core_id}' is still {state or 'running'} after "
            f"{budget:.0f}s — the node continues it in the background "
            f"(job {job.get('job_id')})")


def _finish(job: dict) -> dict:
    if job.get("state") == "failed":
        raise NodeClientError(
            f"{job.get('action')} failed on the node: "
            f"{job.get('error') or job.get('error_type') or 'unknown error'}")
    if job.get("state") == "cancelled":
        raise NodeClientError(f"{job.get('action')} was cancelled on the node")
    return job
