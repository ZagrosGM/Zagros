"""Sealed delivery envelope tests (X25519 + HKDF-SHA256 + AES-256-GCM).

Run: pytest tests/crypto/test_seal.py  OR  python tests/crypto/test_seal.py
"""
from __future__ import annotations

import secrets as _secrets
import sys
import traceback
import types as _types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.crypto.seal import (  # noqa: E402
    SEAL_ALGORITHM,
    SealedEnvelope,
    SealError,
    open_envelope,
    seal,
)
from app.crypto.x25519 import generate_keypair  # noqa: E402


def test_seal_roundtrip() -> None:
    priv, pub = generate_keypair()
    payload = _secrets.token_bytes(600)  # larger than one GCM block, realistic config size
    env = seal(payload, pub)
    assert env.v == 1 and env.alg == SEAL_ALGORITHM
    assert open_envelope(env, priv) == payload


def test_envelopes_are_unique() -> None:
    priv, pub = generate_keypair()
    a, b = seal(b"same", pub), seal(b"same", pub)
    assert a.eph != b.eph and a.ct != b.ct, "ephemeral keys/nonces must differ per seal"
    assert open_envelope(a, priv) == open_envelope(b, priv) == b"same"


def test_json_wire_format() -> None:
    priv, pub = generate_keypair()
    env = seal(b"wire", pub)
    text = env.to_json()
    restored = SealedEnvelope.from_json(text)
    assert open_envelope(restored, priv) == b"wire"


def test_tamper_rejected() -> None:
    priv, pub = generate_keypair()
    env = seal(b"classified", pub)

    def _mutate_first(value: str, preferred: str) -> str:
        """Replace the first char with one that is actually different.

        A blind ``"A" + value[1:]`` is a no-op when value already starts with
        "A" (~1/64 of the time for base64), which used to make this test flaky.
        """
        replacement = preferred if not value.startswith(preferred) else ("B" if preferred != "B" else "C")
        return replacement + value[1:]

    variants = [
        env.model_copy(update={"ct": env.ct[:-2] + ("xx" if not env.ct.endswith("xx") else "yy")}),
        env.model_copy(update={"eph": _mutate_first(env.eph, "A")}),
        env.model_copy(update={"nonce": _mutate_first(env.nonce, "B")}),
        env.model_copy(update={"v": 2}),
        env.model_copy(update={"alg": "none"}),
    ]
    for i, bad in enumerate(variants):
        try:
            open_envelope(bad, priv)
            raise AssertionError(f"tamper variant #{i} accepted")
        except (SealError, ValueError):
            pass


def test_wrong_recipient_rejected() -> None:
    _, pub = generate_keypair()
    other_priv, _ = generate_keypair()
    env = seal(b"for someone else", pub)
    try:
        open_envelope(env, other_priv)
        raise AssertionError("wrong recipient opened envelope")
    except SealError:
        pass


def test_malformed_json_rejected() -> None:
    priv, _ = generate_keypair()
    for bad in ("not json", "{}", '{"v": 1}', '{"v": 1, "eph": "!!!"}'):
        try:
            env = SealedEnvelope.from_json(bad)
            open_envelope(env, priv)
            raise AssertionError(f"malformed envelope accepted: {bad}")
        except (SealError, ValueError):
            pass


if __name__ == "__main__":
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
