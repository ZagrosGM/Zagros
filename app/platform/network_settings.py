"""Validated Panel Network desired state and host-action handoff.

The panel container cannot safely restart its own Docker/host-network binding.
It therefore persists desired state in SQL and writes one private, atomic
request under the mounted data directory.  The Zagros host agent (installed by
zagros-scripts) applies the host .env and panel binding, health-checks the new
URL and rolls back on failure.  No Docker socket is exposed to the web process.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class PanelNetworkSettings(BaseModel):
    domain: str | None = None
    port: int = Field(default=8000, ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    bind_address: str = "0.0.0.0"
    trusted_proxies: list[str] = Field(default_factory=list)
    hsts: bool = False
    redirect_http_to_https: bool = False
    tls_certificate_id: str | None = None

    @field_validator("bind_address")
    @classmethod
    def valid_bind(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("bind_address must be an IPv4/IPv6 address") from exc
        return value

    @field_validator("trusted_proxies")
    @classmethod
    def valid_proxies(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            try:
                normalized.append(str(ipaddress.ip_network(value, strict=False)))
            except ValueError as exc:
                raise ValueError(f"invalid trusted proxy CIDR '{value}'") from exc
        return sorted(set(normalized))

    @model_validator(mode="after")
    def coherent(self) -> "PanelNetworkSettings":
        domain = (self.domain or "").strip().strip(".") or None
        if domain and not re.fullmatch(
            r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", domain
        ):
            raise ValueError("domain is not a valid hostname")
        if self.scheme == "http" and (self.hsts or self.redirect_http_to_https):
            raise ValueError("HSTS/HTTP→HTTPS require scheme=https")
        if self.scheme == "https" and not self.tls_certificate_id:
            raise ValueError("HTTPS requires a managed TLS certificate selection")
        object.__setattr__(self, "domain", domain)
        return self

    def public_url(self) -> str:
        host = self.domain or self.bind_address
        if not self.domain and host in ("0.0.0.0", "::"):
            host = "127.0.0.1"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        default = 443 if self.scheme == "https" else 80
        suffix = "" if self.port == default else f":{self.port}"
        return f"{self.scheme}://{host}{suffix}"


class HostNetworkRequest:
    def __init__(self, root: str = "/var/lib/zagros/host-actions") -> None:
        self.root = Path(root)

    def agent_ready(self) -> bool:
        return (self.root / ".agent-ready").is_file()

    def request(self, settings: PanelNetworkSettings) -> dict:
        if not self.agent_ready():
            raise RuntimeError(
                "Zagros host network agent is not installed; desired state can be saved/tested, "
                "but Apply is disabled because the panel container cannot safely restart itself")
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        operation = secrets.token_hex(16)
        payload = {
            "version": 1,
            "operation_id": operation,
            "requested_at": int(time.time()),
            "settings": settings.model_dump(mode="json"),
        }
        path = self.root / "panel-network.request.json"
        part = path.with_suffix(".part")
        part.write_text(json.dumps(payload, sort_keys=True) + "\n")
        os.chmod(part, 0o600)
        os.replace(part, path)
        return {"accepted": True, "operation_id": operation,
                "status": "pending", "public_url": settings.public_url()}

    def status(self, operation_id: str | None = None) -> dict:
        path = self.root / "panel-network.result.json"
        if not path.exists():
            return {"status": "idle" if not operation_id else "pending",
                    "operation_id": operation_id}
        try:
            result = json.loads(path.read_text())
        except (OSError, ValueError):
            return {"status": "invalid-result", "operation_id": operation_id}
        if operation_id and result.get("operation_id") != operation_id:
            return {"status": "pending", "operation_id": operation_id}
        # The host result contract is intentionally secret-free.
        return result
