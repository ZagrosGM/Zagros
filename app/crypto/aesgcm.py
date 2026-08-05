"""AES block cipher (FIPS-197) and GCM authenticated encryption (SP 800-38D).

Pure-Python, dependency-free implementation used for:

* encrypting ``user_core_accounts.credentials`` at rest (AES-256-GCM),
* sealing client connection payloads delivered to the Zagros app.

Only the *forward* AES direction is implemented because GCM is a CTR-mode
construction (encryption and decryption both use the block-encrypt function).
The implementation processes one 16-byte block per call — it is constant in
behaviour, intentionally simple and audit-friendly. Throughput is ample for
credential-sized payloads (a few hundred bytes).

Correctness is pinned by golden vectors in ``tests/crypto/test_aesgcm.py``:

* FIPS-197 / NIST SP 800-38A known-answer tests for AES-128/192/256 ECB, and
* NIST GCM test cases plus cross-library digests generated at development
  time with the reference ``cryptography`` package.
"""
from __future__ import annotations

import hmac

# --------------------------------------------------------------------- #
# AES (FIPS-197) — forward direction only
# --------------------------------------------------------------------- #

_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

_BLOCK = 16


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) modulo the AES polynomial."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


class _AesCipher:
    """Forward-only AES with 128/192/256-bit keys."""

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        nk = len(key) // 4
        self._rounds = nk + 6
        self._round_keys = self._expand_key(key, nk)

    @staticmethod
    def _expand_key(key: bytes, nk: int) -> list[list[int]]:
        words = [list(key[4 * i: 4 * i + 4]) for i in range(nk)]
        total = 4 * (nk + 7)
        for i in range(nk, total):
            temp = list(words[i - 1])
            if i % nk == 0:
                temp.append(temp.pop(0))                      # RotWord
                temp = [_SBOX[b] for b in temp]               # SubWord
                temp[0] ^= _RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                temp = [_SBOX[b] for b in temp]
            words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
        # flatten into round keys (16 bytes each)
        return [
            [b for w in words[4 * r: 4 * r + 4] for b in w]
            for r in range(nk + 7)
        ]

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != _BLOCK:
            raise ValueError("AES operates on 16-byte blocks")
        state = list(block)

        def add_round_key(r: int) -> None:
            rk = self._round_keys[r]
            for i in range(16):
                state[i] ^= rk[i]

        def sub_bytes() -> None:
            for i in range(16):
                state[i] = _SBOX[state[i]]

        def shift_rows() -> None:
            # state is column-major: state[row + 4*col]
            for row in range(1, 4):
                tmp = [state[row + 4 * c] for c in range(4)]
                for c in range(4):
                    state[row + 4 * c] = tmp[(c + row) % 4]

        def mix_columns() -> None:
            for c in range(4):
                col = state[4 * c: 4 * c + 4]
                state[4 * c + 0] = _mul(col[0], 2) ^ _mul(col[1], 3) ^ col[2] ^ col[3]
                state[4 * c + 1] = col[0] ^ _mul(col[1], 2) ^ _mul(col[2], 3) ^ col[3]
                state[4 * c + 2] = col[0] ^ col[1] ^ _mul(col[2], 2) ^ _mul(col[3], 3)
                state[4 * c + 3] = _mul(col[0], 3) ^ col[1] ^ col[2] ^ _mul(col[3], 2)

        add_round_key(0)
        for rnd in range(1, self._rounds):
            sub_bytes()
            shift_rows()
            mix_columns()
            add_round_key(rnd)
        sub_bytes()
        shift_rows()
        add_round_key(self._rounds)
        return bytes(state)


# --------------------------------------------------------------------- #
# GCM (NIST SP 800-38D)
# --------------------------------------------------------------------- #

_GCM_TAG_SIZE = 16


def _gf128_mul(x: int, y: int) -> int:
    """Multiply in GF(2^128) with the GCM polynomial (bit-reflected)."""
    r = 0xE1000000000000000000000000000000
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ r
        else:
            v >>= 1
    return z


def _ghash(h: int, data: bytes) -> int:
    y = 0
    for off in range(0, len(data), 16):
        chunk = data[off: off + 16]
        if len(chunk) < 16:
            chunk = chunk + b"\x00" * (16 - len(chunk))
        y = _gf128_mul(y ^ int.from_bytes(chunk, "big"), h)
    return y


def _gctr(cipher: _AesCipher, icb: int, data: bytes) -> bytes:
    if not data:
        return b""
    out = bytearray()
    counter = icb
    for off in range(0, len(data), 16):
        keystream = cipher.encrypt_block(counter.to_bytes(16, "big"))
        chunk = data[off: off + 16]
        out.extend(bytes(a ^ b for a, b in zip(chunk, keystream)))
        counter = (counter & ~0xFFFFFFFF) | ((counter + 1) & 0xFFFFFFFF)
    return bytes(out)


class AesGcmError(ValueError):
    """Raised when AEAD decryption fails (bad key, tampered data, wrong AAD)."""


def _aes_gcm_encrypt_pure(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> bytes:
    """Encrypt and authenticate; returns ``ciphertext || 16-byte tag``.

    ``nonce`` must be exactly 12 bytes (96-bit GCM IVs keep the J0=IV||1
    construction, which is the only form this module supports — non-96-bit
    IVs are rejected instead of silently using GHASH-derived J0).
    """
    if len(nonce) != 12:
        raise ValueError("GCM nonce must be 12 bytes")
    cipher = _AesCipher(key)
    h = int.from_bytes(cipher.encrypt_block(b"\x00" * 16), "big")
    j0 = int.from_bytes(nonce + b"\x00\x00\x00\x01", "big")
    ciphertext = _gctr(cipher, j0 + 1, plaintext)
    # assemble GHASH input: A || pad || C || pad || len(A) || len(C)
    ghash_input = (
        aad
        + b"\x00" * ((-len(aad)) % 16)
        + ciphertext
        + b"\x00" * ((-len(ciphertext)) % 16)
        + (len(aad) * 8).to_bytes(8, "big")
        + (len(ciphertext) * 8).to_bytes(8, "big")
    )
    s = _ghash(h, ghash_input)
    tag_block = _gctr(cipher, j0, s.to_bytes(16, "big"))
    return ciphertext + tag_block[:_GCM_TAG_SIZE]


def _aes_gcm_decrypt_pure(
    key: bytes,
    nonce: bytes,
    data: bytes,
    aad: bytes = b"",
) -> bytes:
    """Verify and decrypt ``ciphertext || tag``; raises :class:`AesGcmError`."""
    if len(nonce) != 12:
        raise ValueError("GCM nonce must be 12 bytes")
    if len(data) < _GCM_TAG_SIZE:
        raise AesGcmError("ciphertext too short")
    ciphertext, tag = data[:-_GCM_TAG_SIZE], data[-_GCM_TAG_SIZE:]
    cipher = _AesCipher(key)
    h = int.from_bytes(cipher.encrypt_block(b"\x00" * 16), "big")
    j0 = int.from_bytes(nonce + b"\x00\x00\x00\x01", "big")
    ghash_input = (
        aad
        + b"\x00" * ((-len(aad)) % 16)
        + ciphertext
        + b"\x00" * ((-len(ciphertext)) % 16)
        + (len(aad) * 8).to_bytes(8, "big")
        + (len(ciphertext) * 8).to_bytes(8, "big")
    )
    s = _ghash(h, ghash_input)
    expected = _gctr(cipher, j0, s.to_bytes(16, "big"))[:_GCM_TAG_SIZE]
    if not hmac.compare_digest(expected, tag):
        raise AesGcmError("authentication failed")
    return _gctr(cipher, j0 + 1, ciphertext)


# ---------------------------------------------------------------------- #
# backend dispatch: prefer the audited C backend (`cryptography` — already
# a hard dependency); keep the verified pure-Python implementation as the
# bootstrap fallback. Both paths are pinned to the same FIPS/SP800-38D
# golden vectors in tests, so they are bit-identical by contract.
# ---------------------------------------------------------------------- #
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _LibAesGcm

    _HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - minimal bootstrap only
    _HAS_CRYPTOGRAPHY = False
    _LibAesGcm = None

if _HAS_CRYPTOGRAPHY:

    def aes_gcm_encrypt(key, nonce, plaintext, aad=b""):
        if len(nonce) != 12:
            raise ValueError("GCM nonce must be 12 bytes")
        return _LibAesGcm(key).encrypt(nonce, plaintext, aad)

    def aes_gcm_decrypt(key, nonce, data, aad=b""):
        if len(nonce) != 12:
            raise ValueError("GCM nonce must be 12 bytes")
        if len(data) < _GCM_TAG_SIZE:
            raise AesGcmError("ciphertext too short")
        try:
            return _LibAesGcm(key).decrypt(nonce, data, aad)
        except Exception as exc:  # InvalidTag and friends
            raise AesGcmError("authentication failed") from exc

else:  # pragma: no cover - exercised when cryptography is absent

    aes_gcm_encrypt = _aes_gcm_encrypt_pure
    aes_gcm_decrypt = _aes_gcm_decrypt_pure
