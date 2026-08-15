"""Standalone Xray backend for the native Zagros Node Agent.

Unlike :class:`LegacyXrayBackend`, this adapter has no imports from the panel's
legacy database, singleton config, node fan-out, or host table. It owns one
Xray process and one atomic JSON document rooted in the node's configured data
path. The regular panel deliberately keeps using its legacy bridge until that
migration is performed separately.
"""
from __future__ import annotations

import copy
import json
import os
import re
import socket
import subprocess
import threading
import time
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from app.cores.exceptions import CoreError
from app.cores.types import CoreMetrics
from app.cores.drivers.xray.backend import XrayUsageStat


class StandaloneXrayBackend:
    def __init__(self, settings: dict[str, Any]):
        self._settings = settings
        self._executable = Path(str(settings["executable_path"]))
        self._assets = Path(str(settings["assets_path"]))
        self._config = Path(str(settings["config_path"]))
        self._runtime_config = self._config.with_suffix(".runtime.json")
        self._process: subprocess.Popen[str] | None = None
        self._logs: deque[str] = deque(maxlen=2000)
        self._lock = threading.RLock()
        self._api_port = self._free_port()
        self._counters: dict[str, tuple[int, int]] = {}
        self._managed_outbound_tags: set[str] = set()

    @staticmethod
    def _free_port() -> int:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def executable_path(self) -> str:
        return str(self._executable)

    @staticmethod
    def _seed() -> dict[str, Any]:
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [],
            "outbounds": [
                {"protocol": "freedom", "tag": "DIRECT"},
                {"protocol": "blackhole", "tag": "BLOCK"},
            ],
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": []},
        }

    def _read(self) -> dict[str, Any]:
        if not self._config.exists():
            return self._seed()
        try:
            value = json.loads(self._config.read_text())
        except (OSError, ValueError) as exc:
            raise CoreError(f"cannot read standalone xray config: {exc}") from exc
        if not isinstance(value, dict):
            raise CoreError("standalone xray config must be a JSON object")
        return value

    @staticmethod
    def _validate(document: dict[str, Any], *, require_inbound: bool = False) -> None:
        inbounds = document.get("inbounds")
        outbounds = document.get("outbounds")
        if not isinstance(inbounds, list) or (require_inbound and not inbounds):
            raise CoreError("standalone xray config requires a non-empty inbounds list")
        if not isinstance(outbounds, list) or not outbounds:
            raise CoreError("standalone xray config requires a non-empty outbounds list")
        for label, rows in (("inbound", inbounds), ("outbound", outbounds)):
            tags = [str(row.get("tag") or "") for row in rows if isinstance(row, dict)]
            if len(tags) != len(rows) or any(not tag or "," in tag for tag in tags):
                raise CoreError(f"every xray {label} needs a valid non-empty tag")
            if len(set(tags)) != len(tags):
                raise CoreError(f"xray {label} tags must be unique")

    def _write(self, document: dict[str, Any]) -> None:
        self._validate(document)
        self._config.parent.mkdir(parents=True, exist_ok=True)
        part = self._config.with_suffix(self._config.suffix + ".part")
        part.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n")
        os.chmod(part, 0o600)
        os.replace(part, self._config)

    def _runtime_document(self) -> dict[str, Any]:
        document = copy.deepcopy(self._read())
        self._validate(document, require_inbound=True)
        document["api"] = {
            "tag": "API",
            "services": ["HandlerService", "StatsService", "LoggerService"],
        }
        document.setdefault("stats", {})
        policy = document.setdefault("policy", {})
        levels = policy.setdefault("levels", {}).setdefault("0", {})
        levels.update({"statsUserUplink": True, "statsUserDownlink": True})
        api_inbound = {
            "listen": "127.0.0.1", "port": self._api_port,
            "protocol": "dokodemo-door", "tag": "API_INBOUND",
            "settings": {"address": "127.0.0.1"},
        }
        document["inbounds"] = [
            row for row in document["inbounds"]
            if row.get("tag") != "API_INBOUND"
        ]
        document["inbounds"].insert(0, api_inbound)
        routing = document.setdefault("routing", {})
        rules = [
            row for row in routing.setdefault("rules", [])
            if row.get("inboundTag") != ["API_INBOUND"]
        ]
        rules.insert(0, {"type": "field", "inboundTag": ["API_INBOUND"],
                         "outboundTag": "API"})
        routing["rules"] = rules
        return document

    def _write_runtime(self) -> None:
        self._runtime_config.parent.mkdir(parents=True, exist_ok=True)
        part = self._runtime_config.with_suffix(".part")
        part.write_text(json.dumps(self._runtime_document(), ensure_ascii=False) + "\n")
        os.chmod(part, 0o600)
        os.replace(part, self._runtime_config)

    def _capture(self, process: subprocess.Popen[str]) -> None:
        assert process.stdout is not None
        for line in process.stdout:
            self._logs.append(line.rstrip())

    def start(self) -> None:
        with self._lock:
            if self.is_running():
                raise CoreError("standalone xray is already running")
            if not self._executable.is_file() or not os.access(self._executable, os.X_OK):
                raise CoreError(f"xray binary is not executable: {self._executable}")
            self._write_runtime()
            env = dict(os.environ)
            env["XRAY_LOCATION_ASSET"] = str(self._assets)
            self._process = subprocess.Popen(
                [str(self._executable), "run", "-config", str(self._runtime_config)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                env=env, start_new_session=True,
            )
            threading.Thread(target=self._capture, args=(self._process,),
                             daemon=True).start()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if self._process.poll() is not None:
                    tail = "\n".join(self.logs(20))
                    self._process = None
                    raise CoreError(f"standalone xray exited during start: {tail[-2000:]}")
                time.sleep(0.05)
            if not self.is_running():
                raise CoreError("standalone xray did not remain running")

    def stop(self) -> None:
        with self._lock:
            process = self._process
            if process is None or process.poll() is not None:
                self._process = None
                return
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            self._process = None

    def restart(self) -> None:
        self.stop()
        self.start()

    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def version(self) -> str | None:
        if not self._executable.is_file():
            return None
        try:
            proc = subprocess.run([str(self._executable), "version"],
                                  capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            return None
        match = re.search(r"^Xray\s+([^\s]+)",
                          (proc.stdout or "") + (proc.stderr or ""), re.MULTILINE)
        return match.group(1) if match else None

    def metrics(self) -> CoreMetrics:
        metrics = CoreMetrics()
        if not self.is_running() or self._process is None:
            return metrics
        try:
            import psutil
            process = psutil.Process(self._process.pid)
            metrics.cpu_percent = process.cpu_percent(interval=None)
            metrics.memory_bytes = process.memory_info().rss
        except Exception:  # noqa: BLE001 - telemetry is best effort
            pass
        return metrics

    def logs(self, tail: int = 200) -> Sequence[str]:
        return list(self._logs)[-max(1, tail):]

    def inbounds(self) -> Mapping[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for row in self._read().get("inbounds", []):
            stream = row.get("streamSettings") or {}
            result[str(row["tag"])] = {
                "tag": row["tag"], "protocol": row.get("protocol"),
                "port": row.get("port"), "network": stream.get("network", "tcp"),
                "tls": stream.get("security", "none"),
                "host": [], "sni": [], "path": "", "header_type": "",
            }
        return result

    def host_options(self, tag: str) -> Sequence[dict[str, Any]]:
        return []

    def _mutate(self, operation) -> None:
        with self._lock:
            document = self._read()
            operation(document)
            self._write(document)
            if self.is_running():
                self.restart()

    def apply_config_document(self, document: dict[str, Any]) -> None:
        with self._lock:
            candidate = copy.deepcopy(document)
            self._validate(candidate, require_inbound=True)
            self._write(candidate)
            if self.is_running():
                self.restart()

    def add_user(self, tag: str, protocol: str, email: str,
                 settings: dict[str, Any]) -> None:
        def add(document: dict[str, Any]) -> None:
            inbound = next((row for row in document["inbounds"]
                            if row.get("tag") == tag), None)
            if inbound is None or inbound.get("protocol") != protocol:
                raise CoreError(f"xray inbound '{tag}' does not serve {protocol}")
            clients = inbound.setdefault("settings", {}).setdefault("clients", [])
            clients[:] = [row for row in clients if row.get("email") != email]
            clients.append({**settings, "email": email})
        self._mutate(add)

    def remove_user(self, tag: str, email: str) -> None:
        def remove(document: dict[str, Any]) -> None:
            inbound = next((row for row in document["inbounds"]
                            if row.get("tag") == tag), None)
            if inbound is None:
                return
            clients = inbound.setdefault("settings", {}).setdefault("clients", [])
            clients[:] = [row for row in clients if row.get("email") != email]
        self._mutate(remove)

    def _stats(self, reset: bool) -> dict[str, tuple[int, int]]:
        if not self.is_running():
            return {}
        try:
            from xray_api import XRay
            rows = XRay("127.0.0.1", self._api_port).get_users_stats(
                reset=reset, timeout=10)
        except Exception:  # noqa: BLE001 - a failed read must not invent traffic
            return {}
        totals: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for row in rows:
            totals[row.name][0 if row.link == "uplink" else 1] += int(row.value)
        return {name: (value[0], value[1]) for name, value in totals.items()}

    def usage(self, reset: bool = False) -> list[XrayUsageStat]:
        return [XrayUsageStat(email=name, uplink=value[0], downlink=value[1])
                for name, value in self._stats(reset).items()]

    def online_accounts(self) -> list[str]:
        current = self._stats(False)
        online = [name for name, totals in current.items()
                  if name in self._counters and sum(totals) > sum(self._counters[name])]
        self._counters = current
        return online

    def set_routing_rules(self, rules: list[dict[str, Any]]) -> None:
        def update(document: dict[str, Any]) -> None:
            routing = document.setdefault("routing", {})
            routing["rules"] = copy.deepcopy(rules)
            routing.setdefault("domainStrategy", "IPIfNonMatch")
        self._mutate(update)

    def set_outbounds(self, outbounds: list[dict[str, Any]]) -> None:
        tags = [str(row.get("tag") or "") for row in outbounds]
        if any(not tag for tag in tags) or len(tags) != len(set(tags)):
            raise CoreError("xray outbound deployment contains invalid or duplicate tags")
        def update(document: dict[str, Any]) -> None:
            existing = [row for row in document.get("outbounds", [])
                        if row.get("tag") not in self._managed_outbound_tags
                        and not str(row.get("tag") or "").startswith("zg-")]
            document["outbounds"] = existing + copy.deepcopy(outbounds)
            self._managed_outbound_tags = set(tags)
        self._mutate(update)

    def ensure_listener(self, protocol: str, port: int) -> None:
        tag = f"zg-chain-{protocol}-{port}"
        def update(document: dict[str, Any]) -> None:
            if any(row.get("tag") == tag for row in document["inbounds"]):
                return
            settings = {"auth": "noauth", "udp": False} if protocol == "socks" else {}
            document["inbounds"].append({
                "listen": "127.0.0.1", "port": port,
                "protocol": protocol, "tag": tag, "settings": settings,
            })
        self._mutate(update)
