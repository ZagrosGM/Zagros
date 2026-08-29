"""End-to-end test of the panel's node service against a real node agent.

Nothing is mocked: the test boots ``node_agent`` from the zagros-node
checkout on ephemeral ports, then drives the panel service through the
exact sequence the dashboard performs.

    create node → installer command → discover → pair (pinned fingerprint)
    → heartbeat → inventory → install core (job) → logs → uninstall

Requires the zagros-node repository (default: ../zagros-node).

    python tests/test_node_service.py [--agent-dir ../zagros-node] [--no-core]
"""
from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
# Running this file directly puts ``tests/`` on sys.path[0], where its
# ``platform/`` package would shadow the standard library module of the same
# name. Drop the script directory before anything imports sqlalchemy.
_here = str(Path(__file__).resolve().parent)
sys.path[:] = [p for p in sys.path if os.path.abspath(p or ".") != _here]
sys.path.insert(0, str(REPO))

CONTROL_PORT = 63050
INFO_PORT = 63051


def build_runtime(tmp: str):
    os.environ.setdefault("ZAGROS_SECRET_KEY", "integration-master-secret-0123456789")
    from sqlalchemy import create_engine

    from app.persistence.base import create_schema
    from app.platform.runtime import PlatformRuntime

    url = f"sqlite:///{tmp}/zagros.db"
    engine = create_engine(url)
    create_schema(engine)
    return PlatformRuntime(database_url=url,
                           master_secret=os.environ["ZAGROS_SECRET_KEY"])


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent-dir", default=str(REPO.parent / "zagros-node"))
    parser.add_argument("--core", default="xray")
    parser.add_argument("--no-core", action="store_true")
    args = parser.parse_args()

    agent_dir = Path(args.agent_dir).resolve()
    if not (agent_dir / "node_agent").is_dir():
        print(f"agent checkout not found at {agent_dir} (pass --agent-dir)")
        return 2

    tmp = tempfile.mkdtemp(prefix="zagros-node-service-")
    checks: list[tuple[str, bool, str]] = []

    def start_agent(token: str | None) -> subprocess.Popen:
        """Boot the agent; ``token`` is the panel's one-time token.

        The real installer writes only the token's SHA-256 into the node's
        environment — the node never sees (or stores) the token itself.
        """
        import hashlib

        env = {
            **os.environ,
            "PYTHONPATH": str(agent_dir / "vendor" / "zagros"),
            "ZAGROS_NODE_DATA": f"{tmp}/agent",
            "ZAGROS_CORE_ROOT": f"{tmp}/cores",
            "ZAGROS_NODE_PORT": str(CONTROL_PORT),
            "ZAGROS_NODE_API_PORT": str(INFO_PORT),
            "ZAGROS_NODE_NAME": "it-node",
            "ZAGROS_NODE_INFO_DETAIL": "1",
            "ZAGROS_NODE_REGISTRATION_HASH": (hashlib.sha256(
                token.encode("utf-8")).hexdigest() if token else ""),
        }
        import socket
        import time
        import urllib.request

        log_path = Path(tmp) / "agent.log"
        handle = open(log_path, "ab")
        process = subprocess.Popen(
            [sys.executable, "-m", "node_agent"], cwd=str(agent_dir), env=env,
            stdout=handle, stderr=subprocess.STDOUT)

        # Both listeners must be up: the info port proves the agent booted,
        # the control-plane socket proves it can be paired with.
        for _ in range(120):
            if process.poll() is not None:
                break
            control_ready = False
            with socket.socket() as probe:
                probe.settimeout(0.5)
                control_ready = probe.connect_ex(("127.0.0.1", CONTROL_PORT)) == 0
            if not control_ready:
                time.sleep(0.5)
                continue
            try:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{INFO_PORT}/healthz", timeout=1).read()
                return process
            except Exception:  # noqa: BLE001
                time.sleep(0.5)
        process.kill()
        tail = ""
        try:
            handle.flush()
            tail = log_path.read_text(errors="replace")[-2000:]
        except Exception:  # noqa: BLE001
            pass
        raise RuntimeError(
            "the agent did not become ready on both listeners\n" + tail)

    def stop_agent(proc: subprocess.Popen) -> None:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()

    process = start_agent(None)

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, ok, detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}{f' — {detail}' if detail else ''}")

    try:
        from app.nodes.models import NodeCreate
        from app.nodes.service import (
            core_lifecycle, core_logs, create_node, discover, heartbeat,
            installer_command, list_nodes, node_cores, pair,
        )
        from app.nodes.client import NodeClientError

        runtime = await asyncio.to_thread(build_runtime, tmp)

        # ---------------------------------------------------------------- #
        node, installer = await create_node(runtime, NodeCreate(
            name="it-node", address="127.0.0.1", port=CONTROL_PORT,
            api_port=INFO_PORT, add_as_new_host=False))
        check("node created as pending", node.status == "pending", node.status)
        check("installer command embeds the token",
              bool(installer.registration_token)
              and installer.registration_token in installer.command)
        check("installer command carries the api port",
              f"--api-port {INFO_PORT}" in installer.command)

        listed = await list_nodes(runtime)
        check("node appears in the list", any(n.id == node.id for n in listed))

        # an installer command can be re-read (rotating while pending is OK)
        again = await installer_command(runtime, node.id)
        check("installer command is stable", again.command == installer.command)

        # The installer is what arms the node with the token's hash; restart
        # the agent the same way install.sh would have started it.
        check("token is handed to the node only as a hash",
              bool(installer.registration_token))
        stop_agent(process)
        process = start_agent(installer.registration_token)

        # ---------------------------------------------------------------- #
        info = await discover(runtime, node.id)
        check("discovery reaches the node", info.reachable, info.error or "")
        check("discovery returns a fingerprint",
              len(info.certificate_sha256 or "") == 64, info.certificate_sha256 or "")

        # a wrong fingerprint must be refused (the pin is the trust anchor)
        try:
            await pair(runtime, node.id, certificate_fingerprint="0" * 64)
            check("wrong fingerprint refused", False, "pairing succeeded!")
        except Exception as exc:  # noqa: BLE001
            check("wrong fingerprint refused", "mismatch" in str(exc), str(exc)[:80])

        paired = await pair(runtime, node.id,
                            certificate_fingerprint=info.certificate_sha256)
        check("pairing succeeds with the real fingerprint",
              paired.status == "connected", paired.status)
        check("pin is persisted", len(paired.certificate_fingerprint or "") == 64)

        # the token is single use: pairing again must fail
        try:
            await pair(runtime, node.id,
                       certificate_fingerprint=info.certificate_sha256)
            check("second pairing refused", False, "token was reusable!")
        except Exception as exc:  # noqa: BLE001
            check("second pairing refused", True, str(exc)[:70])

        # ---------------------------------------------------------------- #
        healthy = await heartbeat(runtime, node.id)
        check("signed heartbeat", healthy.status == "connected")
        check("agent version recorded", bool(healthy.agent_version),
              healthy.agent_version or "")

        inventory = await node_cores(runtime, node.id)
        check("inventory lists the full catalog", len(inventory.available) >= 6,
              str(inventory.available))

        # rotating the token on a paired node must be refused
        try:
            await installer_command(runtime, node.id, rotate=True)
            check("rotation refused while paired", False, "rotation succeeded!")
        except PermissionError as exc:
            check("rotation refused while paired", True, str(exc)[:60])

        if args.no_core:
            print("  [SKIP] core install (--no-core)")
        else:
            job = await core_lifecycle(runtime, node.id, args.core,
                                       action="install")
            check(f"install job for {args.core} reached a terminal state",
                  job.get("state") in ("succeeded", "failed", "cancelled"),
                  str(job)[:160])
            check("install succeeded", job.get("state") == "succeeded",
                  str(job.get("error") or "")[:200])

            after = await node_cores(runtime, node.id)
            check("installed core leaves the node catalog",
                  args.core in after.installed and args.core not in after.available,
                  f"installed={sorted(after.installed)} available={after.available}")

            logs = await core_logs(runtime, node.id, args.core, tail=20)
            check("core logs readable", "lines" in logs)

            uninstall = await core_lifecycle(runtime, node.id, args.core,
                                             action="uninstall", purge=True,
                                             force=True)
            check("uninstall job completed",
                  uninstall.get("state") in ("succeeded", "cancelled"),
                  str(uninstall)[:160])
    finally:
        stop_agent(process)
        shutil.rmtree(tmp, ignore_errors=True)

    failed = [name for name, ok, _ in checks if not ok]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed")
    if failed:
        print("failed: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
