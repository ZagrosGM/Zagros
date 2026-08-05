"""X25519 (RFC 7748) conformance tests.

Golden vectors: RFC 7748 §5.2 test vectors (including the non-canonical
u-coordinate case that requires MSB masking), the 1-iteration value, plus
deterministic key agreement cases cross-checked at development time against
the reference `cryptography` library.

Run: pytest tests/crypto/test_x25519.py  OR  python tests/crypto/test_x25519.py
"""
from __future__ import annotations

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

from app.crypto.x25519 import (  # noqa: E402
    X25519_KEY_SIZE,
    generate_keypair,
    public_from_private,
    x25519,
)

_RFC_VECTORS = [
    ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
     "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
     "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
    # u-coordinate has the MSB set -> exercises the mandatory RFC 7748 masking
    ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
     "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
     "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
]

# Deterministic pairs derived from sha256 seeds; shared secrets verified
# against the `cryptography` library at development time.
_GOLDEN_PAIRS = [
    {"priv": "0181eaa8e884866c468dadb6d7c4ad6f9186a675de9bb2fa7629fc40baf51bf6",
     "pub": "71c6450afa11358e2aa10596ff91e8a80a88067b94db8dc728e4a1300c5bbb34",
     "peer": "318ec5a39b0b81f17dfed8f855de2deba8cce24a37a400980fdd7e3f4897586f",
     "shared": "7b333eca7f75ca4f721ddbd072280321e69f0f516969eac963d15f95e329cc6f"},
    {"priv": "c9402343160eb4e7b8fedf2759b4219be3263c4fb8581d1a017e174811d60375",
     "pub": "59c6711077ae70d22c9bc3f501f5cacdf9d4e1efe4b71842c7bbf91fb4df8b67",
     "peer": "92f8d25bd8587b0fee74f738eece608879caff6760d2ebf6771df02d422e4ca3",
     "shared": "60f769e4d0330b4969c6aa8465c3ae3cd4a2a0fb9880fc47dccd1b7821fd5869"},
    {"priv": "d1d401d738b916eeb8213341cb12390ddac8c858bb9d37fa9360ecfaef8e591e",
     "pub": "68e1ed5ea1e8db3152bc295a9d5c42896148d85c30aeb36c96018fa49563b179",
     "peer": "bd30e0bd15da0f9079de82ef3480cbbbc2f922a6f367ca2b60069ae39e932d61",
     "shared": "e365a7cc518e32b3d61bfcf1d27182133bdb0669ccdc91444f629b424dd46368"},
    {"priv": "b2e18ab83d6a30056252abcae5335185914a6ca8b7ad7e7b6d8ab9b2af0d71e8",
     "pub": "ac9ffef9cc556a5a469d59ee592782e97505bf61c6aec0e994175c8e977cc15a",
     "peer": "cb24cd961ecdecdba972bdeb7b8f98337ddd740fca111dbce8ac3c6831e7a92c",
     "shared": "ba3e2cfa3f5b83a6907f1ca34486b3acd7e581779fd745bf87c1980a94b11a7b"},
]


def test_rfc7748_vectors() -> None:
    for scalar_hex, u_hex, out_hex in _RFC_VECTORS:
        got = x25519(bytes.fromhex(scalar_hex), bytes.fromhex(u_hex))
        assert got.hex() == out_hex, f"RFC 7748 vector failed: {got.hex()}"


def test_rfc7748_single_iteration() -> None:
    # RFC 7748 §5.2: after ONE iteration with k=u=9 the value must be:
    got = x25519((9).to_bytes(32, "little"), (9).to_bytes(32, "little"))
    assert got.hex() == "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"


def test_public_key_derivation_golden() -> None:
    for pair in _GOLDEN_PAIRS:
        got = public_from_private(bytes.fromhex(pair["priv"]))
        assert got.hex() == pair["pub"], f"public key mismatch: {got.hex()}"


def test_key_agreement_golden() -> None:
    for pair in _GOLDEN_PAIRS:
        priv, peer = bytes.fromhex(pair["priv"]), bytes.fromhex(pair["peer"])
        peer_pub = public_from_private(peer)
        mine = x25519(priv, peer_pub)
        theirs = x25519(peer, bytes.fromhex(pair["pub"]))
        assert mine.hex() == pair["shared"]
        assert mine == theirs, "agreement asymmetry"


def test_roundtrip_random() -> None:
    for _ in range(8):
        a_priv, a_pub = generate_keypair()
        b_priv, b_pub = generate_keypair()
        assert x25519(a_priv, b_pub) == x25519(b_priv, a_pub)
        assert len(a_pub) == X25519_KEY_SIZE


def test_non_contributory_key_rejected() -> None:
    priv, _ = generate_keypair()
    try:
        x25519(priv, b"\x00" * 32)  # low-order point -> all-zero shared secret
        raise AssertionError("non-contributory key accepted")
    except ValueError:
        pass
    try:
        x25519(priv, b"\x01" + b"\x00" * 31)
        raise AssertionError("low-order point accepted")
    except ValueError:
        pass


def test_input_validation() -> None:
    priv, pub = generate_keypair()
    for bad_scalar in (b"", b"\x00" * 31, b"\x00" * 33):
        try:
            x25519(bad_scalar, pub)
            raise AssertionError("bad scalar accepted")
        except ValueError:
            pass
    try:
        x25519(priv, b"\x00" * 31)
        raise AssertionError("bad public key size accepted")
    except ValueError:
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
