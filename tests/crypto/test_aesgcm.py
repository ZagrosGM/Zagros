"""AES (FIPS-197) + GCM (SP 800-38D) conformance tests.

Golden vectors: FIPS-197/SP 800-38A known answers, plus deterministic
AES-GCM cases cross-checked at development time against the reference
`cryptography` library (dev-time only; runtime & tests are dependency-free).

Run: pytest tests/crypto/test_aesgcm.py  OR  python tests/crypto/test_aesgcm.py
"""
from __future__ import annotations

import os
import pytest
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

from app.crypto.aesgcm import (  # noqa: E402
    AesGcmError,
    _AesCipher,
    _aes_gcm_decrypt_pure,
    _aes_gcm_encrypt_pure,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
)

# ------------------------------------------------------------------ #
# FIPS-197 known answers (key, plaintext, ciphertext) for 128/192/256
# ------------------------------------------------------------------ #
_ECB_KATS = [
    ("000102030405060708090a0b0c0d0e0f",
     "00112233445566778899aabbccddeeff",
     "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("000102030405060708090a0b0c0d0e0f1011121314151617",
     "00112233445566778899aabbccddeeff",
     "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "00112233445566778899aabbccddeeff",
     "8ea2b7ca516745bfeafc49904b496089"),
]

# Deterministic GCM vectors — parameters derived from sha256 seeds so they
# are reproducible anywhere; `ref` values verified against `cryptography`.
_GCM_VECTORS = [
    {"key": "c23305641184d90ef0849138d4f16cdd", "nonce": "9ebb0db651591827dacae1b0",
     "pt": "", "aad": "",
     "ref": "ecf77bffb248a07fe82a3db80e1c5a3e"},
    {"key": "c26ec02cc8dc5591d1285a7079c020b3", "nonce": "c48099cc06c8da9bd2d7f8ee",
     "pt": "291eb81095746efe3b3ddb295bf31e90", "aad": "",
     "ref": "36d5d2aa03b2dc67086b7c4b3269e123b072340d27cb936ee0127d8512e16aca"},
    {"key": "3e016b8ee8e30c7cbe7db23e42c055212c9076640d1cc44d3e447b42c7bad252",
     "nonce": "8e9a1c3b67ca4876e4b6622d",
     "pt": "fe1ce05be4a297f46aaaa24e985b756e89b36c050c5bf2da3d8d7ded87818501"
           "fe1ce05be4a297f46aaaa24e985b756e89b36c050c5bf2da3d8d7ded87818501",
     "aad": "359ae6890822bec2a8aebea26c",
     "ref": "979faa493b5a3da90be47664b48fff4288a038e60554b4f3b94b0b56aaa55ad4319f00"
           "ab8e64e1f188de9ce4b53788d7964aa6a241301276676a427467799148068ad420db0d"
           "e6876dd7ca7fd992302f"},
    {"key": "0889ce2aa05ab1640922ff3242d0ae0b280b90a1adcd84c1549cedd49a90388f",
     "nonce": "ef69d99795af1f9340506a0e",
     "pt": "fcee0e075bd03aeb01811ebb09c101574d9988a52d12b01e69c4667015502e27"
           "fcee0e075bd03aeb01811ebb09c101574d9988a52d12b01e69c4667015502e27",
     "aad": "",
     "ref": "6b469104f0276b3dbb855638c21baefbbb68cc8acebe5cda3e15aa040820d414"
           "0e7d5691a36daf86daeb848d9fa12fa2cf2b4774ec43ec5c105f74238cac966b"
           "d422d4889931c61f39e77ae34571bf0d"},
    {"key": "a8c2c1869b1679c79de0ef7e9a20922d02ae587fa68e5859",
     "nonce": "bdf41cf12709253a532602e3",
     "pt": "44122197d0bdec0cced6c171da4341b77a7df083eb6a7dd2d37f418d2742fa2ca2",
     "aad": "8766508c5c6fdf",
     "ref": "ed5063361f362027086d37db4f6eeba5477007233c1cf75fef7a9f69b2d1de"
           "8e1fbea8b513ca6da7e2cca26b60077fb27c"},
    {"key": "629dbbae2d84d3262cdb666499af362d", "nonce": "8fa88d3ec4b18fbd5d8f0ae9",
     "pt": "87f8f42e775b655b0c84b3c55e114cecb82f68d26996a6989619fa74cc8a881a"
           "87f8f42e775b655b0c84b3c55e114cecb82f68d26996a6989619fa74cc8a881a"
           "87f8f42e775b655b0c84b3c55e114cecb82f68d26996a6989619fa74cc8a881a"
           "be3eac034527f93ab9b870f68dfef77b0e378e024ca0cd",
     "aad": "43d4e33ba0cdbf41c95d62aad753d4e2",
     "ref": "c840ae73b12891ec0008bf9eff02443e7c01460385f7589a01ac17b534de92"
           "c2216444bd43de951093dadda9ca4151c2809a072f7b11fb2306cd821a058a"
           "d3a351aea922584125cf06712f81249c69276116712c46ca427b2679688ba4"
           "51d0eea5955a909a5d9075be2a8eb8cccb32c08159b10f2a7e1df285e54e54"
           "419540cdba46e817a6141a"},
]


def test_aes_ecb_known_answers() -> None:
    for key_hex, pt_hex, ct_hex in _ECB_KATS:
        got = _AesCipher(bytes.fromhex(key_hex)).encrypt_block(bytes.fromhex(pt_hex))
        assert got.hex() == ct_hex, f"AES-{len(bytes.fromhex(key_hex)) * 8} KAT failed: {got.hex()}"


def test_gcm_golden_vectors() -> None:
    for i, vec in enumerate(_GCM_VECTORS):
        key, nonce = bytes.fromhex(vec["key"]), bytes.fromhex(vec["nonce"])
        pt, aad, ref = bytes.fromhex(vec["pt"]), bytes.fromhex(vec["aad"]), vec["ref"]
        got = aes_gcm_encrypt(key, nonce, pt, aad)
        assert got.hex() == ref, f"GCM vector #{i} mismatch:\n{got.hex()}\n{ref}"
        assert aes_gcm_decrypt(key, nonce, got, aad) == pt


def test_gcm_roundtrip_random_sizes() -> None:
    for size in (0, 1, 15, 16, 17, 31, 64, 255):
        key, nonce = os.urandom(32), os.urandom(12)
        pt, aad = os.urandom(size), os.urandom(size % 20)
        ct = aes_gcm_encrypt(key, nonce, pt, aad)
        assert len(ct) == size + 16
        assert aes_gcm_decrypt(key, nonce, ct, aad) == pt


def test_gcm_tamper_detection() -> None:
    key, nonce, aad = os.urandom(32), os.urandom(12), b"hdr"
    ct = aes_gcm_encrypt(key, nonce, b"secret-message", aad)
    for mutated in (
        ct[:-17] + bytes([ct[-17] ^ 1]) + ct[-16:],  # flip ciphertext bit
        ct[:-1] + bytes([ct[-1] ^ 1]),               # flip tag bit
    ):
        try:
            aes_gcm_decrypt(key, nonce, mutated, aad)
            raise AssertionError("tampered ciphertext accepted")
        except AesGcmError:
            pass
    try:
        aes_gcm_decrypt(key, nonce, ct, b"other-aad")
        raise AssertionError("wrong AAD accepted")
    except AesGcmError:
        pass
    try:
        aes_gcm_decrypt(os.urandom(32), nonce, ct, aad)
        raise AssertionError("wrong key accepted")
    except AesGcmError:
        pass


def test_gcm_rejects_bad_nonce_and_short_input() -> None:
    key = os.urandom(32)
    for bad_nonce in (b"", os.urandom(8), os.urandom(16)):
        try:
            aes_gcm_encrypt(key, bad_nonce, b"x")
            raise AssertionError("non-96-bit nonce accepted")
        except ValueError:
            pass
    try:
        aes_gcm_decrypt(key, os.urandom(12), b"too-short")
        raise AssertionError("short ciphertext accepted")
    except AesGcmError:
        pass


def test_aes_rejects_bad_key_and_block_sizes() -> None:
    for bad in (b"", b"\x00" * 15, b"\x00" * 33):
        try:
            _AesCipher(bad)
            raise AssertionError("bad key size accepted")
        except ValueError:
            pass
    try:
        _AesCipher(b"\x00" * 16).encrypt_block(b"\x00" * 15)
        raise AssertionError("bad block size accepted")
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


# ---------------------------------------------------------------------- #
# dual-backend guarantee: pure-Python and library implementations must be
# bit-identical on the golden KAT set (dispatch must never drift).
# ---------------------------------------------------------------------- #

def test_pure_python_backend_matches_dispatch_on_kats() -> None:
    for vec in _GCM_VECTORS:
        key, nonce = bytes.fromhex(vec["key"]), bytes.fromhex(vec["nonce"])
        pt, aad = bytes.fromhex(vec["pt"]), bytes.fromhex(vec["aad"])
        pure_ct = _aes_gcm_encrypt_pure(key, nonce, pt, aad)
        assert aes_gcm_encrypt(key, nonce, pt, aad) == pure_ct
        assert _aes_gcm_decrypt_pure(key, nonce, pure_ct, aad) == pt


def test_pure_python_backend_rejects_tampering() -> None:
    vec = _GCM_VECTORS[0]
    key, nonce = bytes.fromhex(vec["key"]), bytes.fromhex(vec["nonce"])
    pt, aad = bytes.fromhex(vec["pt"]), bytes.fromhex(vec["aad"])
    blob = bytearray(_aes_gcm_encrypt_pure(key, nonce, pt, aad))
    blob[-1] ^= 1
    with pytest.raises(AesGcmError):
        _aes_gcm_decrypt_pure(key, nonce, bytes(blob), aad)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
