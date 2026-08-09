"""SSH per-UID accounting — the kernel-side rule lifecycle, for real
(alpha.7.5 item 13).

`test_ssh_driver.py` covers the driver↔usage-record flow with a stub
backend; THIS file exercises the REAL `LocalSystemSSHBackend.acct_*` code
against a stateful `iptables` stand-in that reproduces the kernel
semantics that matter for the field bug class:

  * `-A` APPENDS DUPLICATES (netfilter does not dedupe rules) — two racing
    usage ticks used to leave two owner-match rules for one userid, and
    every packet was counted twice;
  * `-C` answers exact-rule existence (rc 0/1);
  * `-D` removes exactly ONE instance;
  * `-L -n -v -x` prints exact per-rule byte counters.

Pins: repeated+concurrent syncs end with exactly one rule per UID, past
duplicate/stale damage is drained, and counters read back through the
real code path.

Run: pytest tests/cores/test_ssh_acct.py -q
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

from app.cores.drivers.ssh.sshtool import ACCT_CHAIN  # noqa: E402

FAKE_IPTABLES = r'''#!/usr/bin/env python3
"""Stateful iptables stand-in (see test module docstring).

State lives in the JSON file named by $FAKE_IPTABLES_STATE and every
mutation is serialized with flock — the same per-table serialization the
kernel gives netfilter updates."""
import fcntl
import json
import os
import sys

STATE = os.environ["FAKE_IPTABLES_STATE"]


def _load(fh):
    fh.seek(0)
    raw = fh.read()
    if not raw.strip():
        return {"chains": {"OUTPUT": []}, "counters": {}}
    return json.loads(raw)


def _store(fh, st):
    fh.seek(0)
    fh.truncate()
    json.dump(st, fh)


def main(argv):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    if not os.path.exists(STATE):
        with open(STATE, "w") as fh:
            json.dump({"chains": {"OUTPUT": []}, "counters": {}}, fh)
    with open(STATE, "r+") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        st = _load(fh)
        rc, out = _apply(st, argv[1:])
        _store(fh, st)
        fcntl.flock(fh, fcntl.LOCK_UN)
    if out:
        sys.stdout.write(out)
    return rc


def _apply(st, args):  # noqa: C901 — small table-driven dispatcher
    chains = st.setdefault("chains", {"OUTPUT": []})
    counters = st.setdefault("counters", {})
    if not args:
        return 2, ""
    cmd = args[0]
    if cmd == "-N":
        name = args[1]
        if name in chains:
            return 1, ""
        chains[name] = []
        return 0, ""
    if cmd == "-S":
        name = args[1] if len(args) > 1 else None
        if name is not None and name not in chains:
            return 1, ""
        out = []
        for cname, rules in chains.items():
            if name and cname != name:
                continue
            out.append(f"-P {cname} ACCEPT" if cname == "OUTPUT" else f"-N {cname}")
            out.extend(f"-A {cname} {r}" for r in rules)
        return 0, "\n".join(out) + "\n"
    if cmd == "-I":
        _, cname, _idx, *rule = args
        chains.setdefault(cname, []).insert(0, " ".join(rule))
        return 0, ""
    if cmd == "-A":
        _, cname, *rule = args
        chains.setdefault(cname, []).append(" ".join(rule))
        return 0, ""
    if cmd == "-C":
        _, cname, *rule = args
        return (0 if " ".join(rule) in chains.get(cname, []) else 1), ""
    if cmd == "-D":
        _, cname, *rule = args
        rules = chains.get(cname, [])
        try:
            rules.remove(" ".join(rule))
        except ValueError:
            return 1, ""
        return 0, ""
    if cmd == "-F":
        chains[args[1]] = []
        return 0, ""
    if cmd == "-X":
        chains.pop(args[1], None)
        return 0, ""
    if cmd == "-L":
        cname = args[1]
        if cname not in chains:
            return 1, "iptables: No chain/target/match by that name.\n"
        lines = [f"Chain {cname} (0 references)",
                 " pkts bytes target prot opt in out source destination"]
        for rule in chains[cname]:
            toks = rule.split()
            uid = toks[toks.index("--uid-owner") + 1] if "--uid-owner" in toks else ""
            byts = counters.get(f"{cname}|{uid}", 0)
            lines.append(
                f"   17 {byts} RETURN all -- * * 0.0.0.0/0 0.0.0.0/0"
                f" owner UID match {uid}")
        return 0, "\n".join(lines) + "\n"
    return 2, f"fake-iptables: unsupported {args!r}\n"


sys.exit(main(sys.argv))
'''


def _backend(tmp_path, monkeypatch):
    """REAL LocalSystemSSHBackend whose `_iptables()` resolves to the fake."""
    state = tmp_path / "iptables-state.json"
    fake = tmp_path / "iptables"
    fake.write_text(FAKE_IPTABLES)
    fake.chmod(0o755)
    monkeypatch.setenv("FAKE_IPTABLES_STATE", str(state))

    from app.cores.drivers.ssh.backend import LocalSystemSSHBackend

    backend = LocalSystemSSHBackend({})
    monkeypatch.setattr(backend, "_iptables", lambda: str(fake))
    return backend, state


def _uid_rules(state: Path, uid: int) -> list[str]:
    st = json.loads(state.read_text())
    needle = f"--uid-owner {uid}"
    return [r for r in st["chains"].get(ACCT_CHAIN, []) if needle in r]


def _seed(state: Path, chains: dict[str, list[str]]) -> None:
    st = {"chains": {"OUTPUT": [f"-j {ACCT_CHAIN}"], **chains}, "counters": {}}
    state.write_text(json.dumps(st))


def test_repeated_sync_leaves_exactly_one_rule_per_uid(tmp_path, monkeypatch):
    backend, state = _backend(tmp_path, monkeypatch)
    backend.acct_sync_users({1000, 1001})
    backend.acct_sync_users({1000, 1001})
    backend.acct_sync_users({1000, 1001, 1002})
    assert len(_uid_rules(state, 1000)) == 1
    assert len(_uid_rules(state, 1001)) == 1
    assert len(_uid_rules(state, 1002)) == 1


def test_sync_drains_past_duplicate_and_stale_damage(tmp_path, monkeypatch):
    backend, state = _backend(tmp_path, monkeypatch)
    rule = lambda uid: f"-m owner --uid-owner {uid} -j RETURN"
    _seed(state, {ACCT_CHAIN: [rule(1000), rule(1000), rule(1001), rule(1001)]})
    backend.acct_sync_users({1000})
    assert len(_uid_rules(state, 1000)) == 1  # drained duplicate, kept one
    assert len(_uid_rules(state, 1001)) == 0  # every stale instance gone


def test_concurrent_syncs_converge_to_a_single_rule(tmp_path, monkeypatch):
    backend, state = _backend(tmp_path, monkeypatch)
    errors: list[BaseException] = []

    def hammer():
        try:
            for _ in range(5):
                backend.acct_sync_users({1077})
        except BaseException as exc:  # noqa: BLE001 — collected, asserted
            errors.append(exc)

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # double counting source eliminated: exactly one owner-match rule
    assert len(_uid_rules(state, 1077)) == 1


def test_acct_read_reports_kernel_counters(tmp_path, monkeypatch):
    backend, state = _backend(tmp_path, monkeypatch)
    backend.acct_sync_users({1042})
    st = json.loads(state.read_text())
    st["counters"][f"{ACCT_CHAIN}|1042"] = 987654321
    state.write_text(json.dumps(st))
    assert backend.acct_read() == {1042: 987654321}


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
