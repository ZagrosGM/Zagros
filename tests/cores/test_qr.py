"""QR encoder tests — ISO/IEC 18004 conformance.

Golden vectors were generated once with the independent, battle-tested
`python-qrcode` library (dev-time only; the runtime and tests are
dependency-free). They cover: single/multi-block, interleaving, alignment
patterns, version-info (v7+), 8/16-bit length fields, binary payloads.

Run: pytest tests/cores/test_qr.py -v   OR   python tests/cores/test_qr.py
"""
from __future__ import annotations

import hashlib
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

from app.cores.qr import (  # noqa: E402
    EccLevel,
    QrError,
    _GF_EXP,
    _gf_mul,
    _rs_generator,
    _rs_remainder,
    data_codewords,
    encode_matrix,
    to_ascii,
    to_svg,
)

# --- golden fixture: "HELLO WORLD", version 1, level M, mask 2 ------------ #
_GOLDEN_V1_M2 = (
    "111111100000101111111",
    "100000100101001000001",
    "101110101110101011101",
    "101110101010101011101",
    "101110101010101011101",
    "100000101101001000001",
    "111111101010101111111",
    "000000001010000000000",
    "101111100011001111100",
    "011000010111111101100",
    "101100110000111001110",
    "011101001111110011100",
    "100010110110110000101",
    "000000001110100001000",
    "111111100101001000110",
    "100000101110010101111",
    "101110101001000100101",
    "101110101000111111000",
    "101110101100100100100",
    "100000100010110011100",
    "111111101011100010110",
)
_GOLDEN_V3_M5_SHA = "8501b7d0b2822eb218acbb9121e375be550a9c8c6fe5054feb3d295e89ac92cb"
_GOLDEN_V10_M4_SHA = "318bd79f1de34ac730209209b6ad31e7af6d2c1188478731295976a850488f9e"
_GOLDEN_V36_L7_SHA = "a28c775c431d4fc22bcdc2f0df1011ec557ccb1b1dbf94e7ac57acfdefeafbc6"


def _matrix_bits(matrix: list[list[bool]]) -> str:
    return "".join("1" if cell else "0" for row in matrix for cell in row)


def _digest(matrix: list[list[bool]]) -> str:
    return hashlib.sha256(_matrix_bits(matrix).encode()).hexdigest()


# ---------------------------------------------------------------------- #
# tests                                                                  #
# ---------------------------------------------------------------------- #

def test_golden_v1_full_matrix() -> None:
    """Bit-exact match for the full 21x21 reference matrix."""
    matrix = encode_matrix("HELLO WORLD", level=EccLevel.MEDIUM, version=1, mask=2)
    assert len(matrix) == 21 and all(len(row) == 21 for row in matrix)
    got = tuple(_matrix_bits(matrix)[i * 21:(i + 1) * 21] for i in range(21))
    assert got == _GOLDEN_V1_M2, "matrix differs from the python-qrcode golden vector"


def test_golden_multi_version_digests() -> None:
    """Larger versions interleave ECC blocks and add alignment/version info."""
    m3 = encode_matrix("Zagros/WireGuard peer cfg #1.alice",
                       level=EccLevel.MEDIUM, version=3, mask=5)
    assert _digest(m3) == _GOLDEN_V3_M5_SHA
    m10 = encode_matrix(b"y" * 200, level=EccLevel.MEDIUM, version=10, mask=4)
    assert _digest(m10) == _GOLDEN_V10_M4_SHA
    m36 = encode_matrix(b"B" * 1500, level=EccLevel.LOW, version=36, mask=7)
    assert _digest(m36) == _GOLDEN_V36_L7_SHA


def test_gf_arithmetic_identity() -> None:
    """GF(256): exp/log tables consistent; a · a⁻¹ = 1 for every element."""
    from app.cores.qr import _GF_LOG

    assert _GF_EXP[255] == _GF_EXP[0]
    for a in range(1, 256):
        assert _gf_mul(a, 1) == a
        inverse = _GF_EXP[255 - _GF_LOG[a]]
        assert _gf_mul(a, inverse) == 1, f"GF inverse check failed for {a:#04x}"


def test_rs_remainder_is_divisible() -> None:
    """message·x^deg - remainder must be divisible by the generator."""
    degree = 10
    gen = _rs_generator(degree)
    assert len(gen) == degree + 1 and gen[0] == 1
    data = [64, 180, 132, 84, 196, 196, 242, 5, 116, 245, 36, 196, 64, 236, 17, 236]
    rem = _rs_remainder(data, gen)
    combined = data + rem
    # evaluating `combined` as coefficients must leave remainder zero
    check = _rs_remainder(combined, gen)
    assert all(b == 0 for b in check)


def test_function_patterns_invariants() -> None:
    matrix = encode_matrix("invariants", level=EccLevel.MEDIUM, version=2, mask=0)
    size = len(matrix)
    assert size == 25  # 4*2+17

    def finder_ok(ox: int, oy: int) -> bool:
        for dy in range(7):
            for dx in range(7):
                border = dx in (0, 6) or dy in (0, 6)
                inner = 2 <= dx <= 4 and 2 <= dy <= 4
                if matrix[oy + dy][ox + dx] != (border or inner):
                    return False
        return True

    assert finder_ok(0, 0) and finder_ok(size - 7, 0) and finder_ok(0, size - 7)
    for i in range(8, size - 8):  # timing alternates, starts dark
        assert matrix[6][i] == (i % 2 == 0)
        assert matrix[i][6] == (i % 2 == 0)
    assert matrix[size - 8][8] is True  # dark module


def test_format_info_golden_constant() -> None:
    """(M, mask 0) format info is the well-known ISO constant 0x5412."""
    matrix = encode_matrix("fmt", level=EccLevel.MEDIUM, version=1, mask=0)
    bits = 0
    for i in range(6):
        bits |= int(matrix[i][8]) << i
    bits |= int(matrix[7][8]) << 6
    bits |= int(matrix[8][8]) << 7
    bits |= int(matrix[8][7]) << 8
    for i in range(9, 15):
        bits |= int(matrix[8][14 - i]) << i
    assert bits == 0x5412, f"format info {bits:#06x} != 0x5412"


def test_capacity_selection_and_fallback() -> None:
    # auto version grows with payload size, falls back to level L
    small = encode_matrix("hello")
    assert len(small) == 21  # v1-M fits 14 bytes
    medium = encode_matrix("x" * 100)
    assert len(medium) > 21
    big = encode_matrix("w" * 1000)  # needs level L fallback
    assert len(big) >= 4 * 19 + 17

    max_bytes = data_codewords(40, EccLevel.LOW) - 3
    try:
        encode_matrix(b"z" * (max_bytes + 4))
        raise AssertionError("oversized payload must raise QrError")
    except QrError:
        pass


def test_deterministic_and_renderers() -> None:
    payload = "wireguard://peer/1.alice"
    a = encode_matrix(payload)
    b = encode_matrix(payload)
    assert a == b, "encoder must be deterministic"

    svg = to_svg(a)
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    assert "viewBox=" in svg and "</svg>" in svg and "#000000" in svg

    ascii_art = to_ascii(a)
    lines = ascii_art.splitlines()
    assert len(lines) == len(a) + 4  # border=2 rows top/bottom
    assert all(len(line) == (len(a) + 4) * 2 for line in lines)


# ---------------------------------------------------------------------- #
# standalone + pytest runner                                             #
# ---------------------------------------------------------------------- #

def _run_standalone() -> int:
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    passed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
            passed += 1
        except Exception:
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} tests passed")
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    sys.exit(_run_standalone())
