"""Pure-Python QR Code generator (ISO/IEC 18004) — dependency-free.

Why: WireGuard/SSR/Trojan/... share-links are most conveniently delivered as
QR codes, but the platform must not pull an imaging dependency for that.

Deliberate scope (honest, documented):
  * **byte mode only** — optimal universal encoding for config payloads/URIs
  * ECC levels **L** and **M** (auto-fallback L→capacity for long payloads)
  * versions 1..40 auto-selected, mask auto-selected by ISO penalty scoring
  * outputs: boolean matrix, SVG string, ASCII preview

Correctness anchors (enforced by unit tests):
  * GF(256) arithmetic self-checks (tables, generator polynomial roots)
  * RS remainder divisibility checks
  * function-pattern invariants (finder/timing/alignment/dark module)
  * golden matrices generated once with the independent `segno` library
    (dev-time only — the runtime has zero third-party dependencies)
"""
from __future__ import annotations

from enum import Enum


class QrError(ValueError):
    """Payload cannot be represented as a QR code (too large / invalid)."""


class EccLevel(Enum):
    LOW = "L"
    MEDIUM = "M"

    @property
    def format_bits(self) -> int:  # ISO table: L=01, M=00
        return 1 if self is EccLevel.LOW else 0


# ---------------------------------------------------------------------- #
# Spec tables (ISO/IEC 18004, Table 9 + Annex D) — levels L and M only   #
# ---------------------------------------------------------------------- #

#: total codewords per version (1..40)
_TOTAL_CODEWORDS = (
    26, 44, 70, 100, 134, 172, 196, 242, 292, 346,
    404, 466, 532, 581, 655, 733, 815, 901, 991, 1085,
    1156, 1258, 1364, 1474, 1588, 1706, 1828, 1921, 2051, 2185,
    2323, 2465, 2611, 2761, 2876, 3034, 3196, 3362, 3462, 3606,
)

#: ECC codewords per block, per version (1..40)
_ECC_PER_BLOCK = {
    EccLevel.LOW: (
        7, 10, 15, 20, 26, 18, 20, 24, 30, 18,
        20, 24, 26, 30, 22, 24, 28, 30, 28, 28,
        28, 28, 30, 30, 26, 28, 30, 30, 30, 30,
        30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ),
    EccLevel.MEDIUM: (
        10, 16, 26, 18, 24, 16, 18, 22, 22, 26,
        30, 22, 22, 24, 24, 28, 24, 28, 28, 26,
        28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
        28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    ),
}

#: number of error-correction blocks per version (1..40)
_NUM_BLOCKS = {
    EccLevel.LOW: (
        1, 1, 1, 1, 1, 2, 2, 2, 2, 4,
        4, 4, 4, 4, 6, 6, 6, 6, 7, 8,
        8, 9, 9, 10, 12, 12, 12, 13, 14, 15,
        16, 17, 18, 19, 19, 20, 21, 22, 24, 25,
    ),
    EccLevel.MEDIUM: (
        1, 1, 1, 2, 2, 4, 4, 4, 5, 5,
        5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
        17, 17, 18, 20, 21, 23, 25, 26, 28, 29,
        31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
    ),
}

#: alignment-pattern center coordinates per version (1..40)
_ALIGNMENT_POS = (
    (), (6, 18), (6, 22), (6, 26), (6, 30),
    (6, 34), (6, 22, 38), (6, 24, 42), (6, 26, 46), (6, 28, 50),
    (6, 30, 54), (6, 32, 58), (6, 34, 62), (6, 26, 46, 66),
    (6, 26, 48, 70), (6, 26, 50, 74), (6, 30, 54, 78), (6, 30, 56, 82),
    (6, 30, 58, 86), (6, 34, 62, 90), (6, 28, 50, 72, 94),
    (6, 26, 50, 74, 98), (6, 30, 54, 78, 102), (6, 28, 54, 80, 106),
    (6, 32, 58, 84, 110), (6, 30, 58, 86, 114), (6, 34, 62, 90, 118),
    (6, 26, 50, 74, 98, 122), (6, 30, 54, 78, 102, 126),
    (6, 26, 52, 78, 104, 130), (6, 30, 56, 82, 108, 134),
    (6, 34, 60, 86, 112, 138), (6, 30, 58, 86, 114, 142),
    (6, 34, 62, 90, 118, 146), (6, 30, 54, 78, 102, 126, 150),
    (6, 24, 50, 76, 102, 128, 154), (6, 28, 54, 80, 106, 132, 158),
    (6, 32, 58, 84, 110, 136, 162), (6, 26, 54, 82, 110, 138, 166),
    (6, 30, 58, 86, 114, 142, 170),
)

_MODE_BYTE = 0b0100
_PAD_BYTES = (0xEC, 0x11)


# ---------------------------------------------------------------------- #
# GF(256) arithmetic — primitive polynomial x^8+x^4+x^3+x^2+1 (0x11D)   #
# ---------------------------------------------------------------------- #

def _build_gf_tables() -> tuple[list[int], list[int]]:
    exp = [0] * 512
    log = [0] * 256
    value = 1
    for i in range(255):
        exp[i] = value
        log[value] = i
        value <<= 1
        if value & 0x100:
            value ^= 0x11D
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


_GF_EXP, _GF_LOG = _build_gf_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _rs_generator(degree: int) -> list[int]:
    """(x - α^0)·(x - α^1)·...·(x - α^(degree-1)) in coefficient form."""
    gen = [1]
    for i in range(degree):
        root = _GF_EXP[i]
        nxt = [0] * (len(gen) + 1)
        for j, coef in enumerate(gen):
            nxt[j] ^= coef                    # coef · x term
            nxt[j + 1] ^= _gf_mul(coef, root)  # coef · (x - α^i) constant term
        gen = nxt
    return gen


def _rs_remainder(data: list[int], generator: list[int]) -> list[int]:
    """Polynomial division remainder: data·x^deg mod generator over GF(256)."""
    result = [0] * (len(generator) - 1)
    for byte in data:
        factor = byte ^ result.pop(0)
        result.append(0)
        if factor != 0:
            for i, coef in enumerate(generator[1:]):
                result[i] ^= _gf_mul(coef, factor)
    return result


# ---------------------------------------------------------------------- #
# Capacity / version selection                                           #
# ---------------------------------------------------------------------- #

def data_codewords(version: int, level: EccLevel) -> int:
    idx = version - 1
    return _TOTAL_CODEWORDS[idx] - _ECC_PER_BLOCK[level][idx] * _NUM_BLOCKS[level][idx]


def _count_bits(version: int) -> int:
    return 8 if version <= 9 else 16


def _fits(version: int, level: EccLevel, nbytes: int) -> bool:
    needed = 4 + _count_bits(version) + 8 * nbytes
    return needed <= data_codewords(version, level) * 8


def _select_version(level: EccLevel, nbytes: int) -> int:
    for version in range(1, 41):
        if _fits(version, level, nbytes):
            return version
    raise QrError(
        f"payload too large for level {level.value} "
        f"({nbytes} bytes > {data_codewords(40, level)} max)"
    )


# ---------------------------------------------------------------------- #
# Data encoding + ECC + interleaving                                     #
# ---------------------------------------------------------------------- #

class _BitBuffer:
    def __init__(self) -> None:
        self.bits: list[int] = []

    def put(self, value: int, width: int) -> None:
        for i in range(width - 1, -1, -1):
            self.bits.append((value >> i) & 1)

    def to_bytes(self) -> list[int]:
        assert len(self.bits) % 8 == 0
        return [
            sum(self.bits[i + j] << (7 - j) for j in range(8))
            for i in range(0, len(self.bits), 8)
        ]


def _encode_data(payload: bytes, version: int, level: EccLevel) -> list[int]:
    capacity = data_codewords(version, level)
    buffer = _BitBuffer()
    buffer.put(_MODE_BYTE, 4)
    buffer.put(len(payload), _count_bits(version))
    for byte in payload:
        buffer.put(byte, 8)
    # terminator: up to 4 zero bits, then pad to byte boundary
    buffer.put(0, min(4, capacity * 8 - len(buffer.bits)))
    while len(buffer.bits) % 8:
        buffer.bits.append(0)
    data = buffer.to_bytes()
    for i in range(capacity - len(data)):
        data.append(_PAD_BYTES[i % 2])
    return data


def _add_ecc_and_interleave(data: list[int], version: int, level: EccLevel) -> list[int]:
    idx = version - 1
    num_blocks = _NUM_BLOCKS[level][idx]
    ecc_len = _ECC_PER_BLOCK[level][idx]
    raw_total = _TOTAL_CODEWORDS[idx]
    data_len = raw_total - ecc_len * num_blocks
    assert len(data) == data_len

    short_len = data_len // num_blocks
    num_short = num_blocks - data_len % num_blocks
    generator = _rs_generator(ecc_len)

    blocks: list[list[int]] = []
    eccs: list[list[int]] = []
    pos = 0
    for i in range(num_blocks):
        take = short_len + (0 if i < num_short else 1)
        block = data[pos:pos + take]
        pos += take
        blocks.append(block)
        eccs.append(_rs_remainder(block, generator))
    assert pos == data_len

    result: list[int] = []
    for i in range(short_len + 1):
        for j, block in enumerate(blocks):
            if i < short_len or j >= num_short:
                if i < len(block):
                    result.append(block[i])
    for i in range(ecc_len):
        for ecc in eccs:
            result.append(ecc[i])
    assert len(result) == raw_total
    return result


# ---------------------------------------------------------------------- #
# Matrix construction                                                    #
# ---------------------------------------------------------------------- #

_FORMAT_MASK = 0b101010000010010  # 0x5412 = (M, mask 0) golden constant


def _format_bits(level: EccLevel, mask: int) -> int:
    data = (level.format_bits << 3) | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ (0b10100110111 if (rem >> 9) & 1 else 0)
    return ((data << 10) | (rem & 0x3FF)) ^ _FORMAT_MASK


def _version_bits(version: int) -> int:
    rem = version
    for _ in range(12):
        rem = (rem << 1) ^ (0b1111100100101 if (rem >> 11) & 1 else 0)
    return (version << 12) | (rem & 0xFFF)


_MASK_FNS = (
    lambda r, c: (r + c) % 2 == 0,
    lambda r, c: r % 2 == 0,
    lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
)


class _MatrixBuilder:
    def __init__(self, version: int) -> None:
        self.version = version
        self.size = 4 * version + 17
        self.modules: list[list[bool]] = [[False] * self.size for _ in range(self.size)]
        self.is_function: list[list[bool]] = [[False] * self.size for _ in range(self.size)]
        self._draw_function_patterns()

    # -- low level ---------------------------------------------------- #
    def _set_function(self, x: int, y: int, dark: bool) -> None:
        self.modules[y][x] = dark
        self.is_function[y][x] = True

    # -- fixed patterns ----------------------------------------------- #
    def _draw_function_patterns(self) -> None:
        size = self.size
        for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
            self._draw_finder(cx, cy)
        # timing
        for i in range(8, size - 8):
            self._set_function(i, 6, i % 2 == 0)
            self._set_function(6, i, i % 2 == 0)
        # alignment
        positions = _ALIGNMENT_POS[self.version - 1]
        for x in positions:
            for y in positions:
                # skip only the three positions overlapping finder patterns
                top_left = x <= 8 and y <= 8
                top_right = x >= size - 9 and y <= 8
                bottom_left = x <= 8 and y >= size - 9
                if top_left or top_right or bottom_left:
                    continue
                self._draw_alignment(x, y)
        # reserve format info areas (values filled after masking)
        self._draw_format(EccLevel.LOW, 0)
        if self.version >= 7:
            self._draw_version()

    def _draw_finder(self, cx: int, cy: int) -> None:
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                x, y = cx + dx, cy + dy
                if 0 <= x < self.size and 0 <= y < self.size:
                    dist = max(abs(dx), abs(dy))
                    self._set_function(x, y, dist != 2 and dist != 4)

    def _draw_alignment(self, cx: int, cy: int) -> None:
        for dy in range(-2, 3):
            for dx in range(-2, 3):
                self._set_function(cx + dx, cy + dy, max(abs(dx), abs(dy)) != 1)

    def _draw_format(self, level: EccLevel, mask: int) -> None:
        bits = _format_bits(level, mask)
        size = self.size
        for i in range(6):
            self._set_function(8, i, (bits >> i) & 1 != 0)
        self._set_function(8, 7, (bits >> 6) & 1 != 0)
        self._set_function(8, 8, (bits >> 7) & 1 != 0)
        self._set_function(7, 8, (bits >> 8) & 1 != 0)
        for i in range(9, 15):
            self._set_function(14 - i, 8, (bits >> i) & 1 != 0)
        for i in range(8):
            self._set_function(size - 1 - i, 8, (bits >> i) & 1 != 0)
        for i in range(8, 15):
            self._set_function(8, size - 15 + i, (bits >> i) & 1 != 0)
        self._set_function(8, size - 8, True)  # dark module

    def _draw_version(self) -> None:
        bits = _version_bits(self.version)
        size = self.size
        for i in range(18):
            bit = (bits >> i) & 1 != 0
            a, b = size - 11 + i % 3, i // 3
            self._set_function(a, b, bit)
            self._set_function(b, a, bit)

    # -- data + masking ------------------------------------------------ #
    def draw_data(self, codewords: list[int], mask: int) -> None:
        size = self.size
        mask_fn = _MASK_FNS[mask]
        bit_index = 0
        total_bits = len(codewords) * 8
        right = size - 1
        while right >= 1:
            if right == 6:
                right = 5
            for vert in range(size):
                for j in range(2):
                    x = right - j
                    upward = ((right + 1) & 2) == 0
                    y = (size - 1 - vert) if upward else vert
                    if not self.is_function[y][x]:
                        dark = False
                        if bit_index < total_bits:
                            dark = ((codewords[bit_index >> 3] >> (7 - (bit_index & 7))) & 1) != 0
                            bit_index += 1
                        if mask_fn(y, x):
                            dark = not dark
                        self.modules[y][x] = dark
            right -= 2
        if right == 6:  # pragma: no cover - unreachable by construction
            raise AssertionError("column 6 must be skipped")


# ---------------------------------------------------------------------- #
# Penalty scoring (ISO/IEC 18004 §8.8.2)                                 #
# ---------------------------------------------------------------------- #

def _penalty(modules: list[list[bool]]) -> int:
    size = len(modules)
    penalty = 0

    def line_penalty(line: list[bool]) -> int:
        score = 0
        run_color = line[0]
        run_len = 1
        history = [run_len]
        for color in line[1:]:
            if color == run_color:
                run_len += 1
            else:
                history.append(run_len)
                run_color = color
                run_len = 1
        history.append(run_len)
        # N1: runs of 5+
        for length in history:
            if length >= 5:
                score += 3 + (length - 5)
        # N3: finder-like 1:1:3:1:1 with a 4-module light guard either side
        # dark/light run signature: 1,1,3,1,1 starting dark
        for i in range(len(history) - 4):
            window = history[i:i + 5]
            if window[0] == 1 and window[1] == 1 and window[2] == 3 and \
                    window[3] == 1 and window[4] == 1:
                starts_dark = (i % 2 == 0) == (line[0] is True)
                if not starts_dark:
                    continue
                before = history[i - 1] if i > 0 else (size if i == 0 and line[0] is False else 0)
                after = history[i + 5] if i + 5 < len(history) else (
                    size if i + 5 == len(history) else 0)
                # guard may be the quiet zone (edge of matrix) only when the
                # pattern sits flush against the edge
                guard = 0
                if i > 0 and history[i - 1] >= 4 and not (line[0] is True and i % 2 == 1):
                    guard += 1
                if i + 5 < len(history) and history[i + 5] >= 4:
                    guard += 1
                # edge cases: pattern at very edge with light run against border
                if i == 0 and line[0] is False:
                    guard += 1
                if i + 5 >= len(history):
                    guard += 1
                score += guard * 40
        return score

    rows = modules
    cols = [[modules[y][x] for y in range(size)] for x in range(size)]
    penalty += sum(line_penalty(line) for line in rows)
    penalty += sum(line_penalty(line) for line in cols)

    # N2: 2x2 same-colour blocks
    for y in range(size - 1):
        for x in range(size - 1):
            color = modules[y][x]
            if modules[y][x + 1] == color and modules[y + 1][x] == color and \
                    modules[y + 1][x + 1] == color:
                penalty += 3

    # N4: dark-module balance
    dark = sum(1 for row in modules for v in row if v)
    total = size * size
    k = abs(dark * 20 - total * 10) // total
    penalty += k * 10
    return penalty


# ---------------------------------------------------------------------- #
# Public API                                                             #
# ---------------------------------------------------------------------- #

def encode_matrix(
    payload: bytes | str,
    *,
    level: EccLevel = EccLevel.MEDIUM,
    version: int | None = None,
    mask: int | None = None,
) -> list[list[bool]]:
    """Encode *payload* into a QR module matrix (True = dark).

    ``version``/``mask`` are normally left ``None`` (auto); they are exposed
    for golden-vector tests and deterministic rendering.
    """
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    if not payload:
        raise QrError("empty payload")

    if version is None:
        try:
            version = _select_version(level, len(payload))
        except QrError:
            level = EccLevel.LOW  # capacity fallback
            version = _select_version(level, len(payload))
    else:
        if not _fits(version, level, len(payload)):
            raise QrError(
                f"payload of {len(payload)} bytes does not fit version {version} "
                f"level {level.value} ({data_codewords(version, level)} data codewords)"
            )

    data = _encode_data(payload, version, level)
    codewords = _add_ecc_and_interleave(data, version, level)

    if mask is not None:
        builder = _MatrixBuilder(version)
        builder.draw_data(codewords, mask)
        builder._draw_format(level, mask)
        return builder.modules

    best: tuple[int, list[list[bool]]] | None = None
    for candidate in range(8):
        builder = _MatrixBuilder(version)
        builder.draw_data(codewords, candidate)
        builder._draw_format(level, candidate)
        score = _penalty(builder.modules)
        if best is None or score < best[0]:
            best = (score, builder.modules)
    assert best is not None
    return best[1]


def to_svg(matrix: list[list[bool]], *, border: int = 4, module_px: int = 8) -> str:
    """Render the matrix as a compact standalone SVG (quiet zone included)."""
    size = len(matrix)
    full = size + border * 2
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {full} {full}" '
        f'width="{full * module_px}" height="{full * module_px}" '
        f'shape-rendering="crispEdges">',
        f'<rect width="{full}" height="{full}" fill="#ffffff"/>',
        '<path fill="#000000" d="',
    ]
    path = []
    for y, row in enumerate(matrix):
        for x, dark in enumerate(row):
            if dark:
                path.append(f"M{x + border} {y + border}h1v1h-1z")
    parts.append("".join(path))
    parts.append('"/></svg>')
    return "".join(parts)


def to_ascii(matrix: list[list[bool]], *, border: int = 2) -> str:
    """Terminal preview using full-block glyphs (for logs/debugging only)."""
    dark_glyph, light_glyph = "██", "  "
    size = len(matrix)
    pad = light_glyph * (size + border * 2)
    lines = [pad] * border
    for row in matrix:
        lines.append(
            light_glyph * border
            + "".join(dark_glyph if cell else light_glyph for cell in row)
            + light_glyph * border
        )
    lines += [pad] * border
    return "\n".join(lines)
