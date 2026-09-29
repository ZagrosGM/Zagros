"""Launcher-icon storage for white-label Applications.

Icons live as files under ``<data_dir>/app_icons/<public_id>.png`` (the data
dir is the persisted host volume, so icons survive redeploys) while the
``branding["icon"]`` document on the application row carries the verified
metadata (sha256, bytes, dimensions).

Build consumption: every upload also renders a deterministic 5-density
Android pack (``<id>.android.zip``) which the worker fetches over its
job-token-authenticated ``.../jobs/.../icon`` endpoint and the contract
script stages into the res tree. iOS packs are still a follow-up.
"""

from __future__ import annotations

import hashlib
import os
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

ICON_SUBDIR = "app_icons"
MAX_BYTES = 1024 * 1024  # 1 MiB — launcher art, not a photo library
MIN_SIDE = 48
MAX_SIDE = 2048
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
MIME = "image/png"

# Android launcher densities the worker stages into the res tree. Rendered
# here (the panel guarantees Pillow) so neither the worker host nor the
# stdlib-only contract script needs an imaging library.
ANDROID_DENSITIES: tuple[tuple[str, int], ...] = (
    ("mipmap-mdpi", 48),
    ("mipmap-hdpi", 72),
    ("mipmap-xhdpi", 96),
    ("mipmap-xxhdpi", 144),
    ("mipmap-xxxhdpi", 192),
)
ANDROID_ICON_ENTRY = "ic_launcher.png"


class IconValidationError(ValueError):
    """The upload is not a usable square PNG launcher icon."""


def validate_icon_png(data: bytes) -> tuple[int, int]:
    """Return (width, height) or raise [IconValidationError]."""
    if len(data) > MAX_BYTES:
        raise IconValidationError(
            f"icon exceeds {MAX_BYTES // 1024} KiB ({len(data)} bytes)")
    if len(data) < 8 or data[:8] != PNG_MAGIC:
        raise IconValidationError("icon must be a PNG file")
    try:
        from PIL import Image
    except ImportError as exc:  # pragma: no cover — Pillow is required
        raise IconValidationError(
            "icon validation needs Pillow on the panel") from exc
    try:
        with Image.open(BytesIO(data)) as img:
            img.load()
            width, height = img.size
            image_format = img.format
    except Exception as exc:
        raise IconValidationError(f"icon is not a readable image: {exc}")
    if image_format != "PNG":
        raise IconValidationError("icon must be a PNG file")
    if width != height:
        raise IconValidationError(
            f"icon must be square (got {width}x{height})")
    if not (MIN_SIDE <= width <= MAX_SIDE):
        raise IconValidationError(
            f"icon side must be {MIN_SIDE}..{MAX_SIDE}px (got {width})")
    return width, height


def icon_file_path(data_dir: str, public_id: str) -> Path:
    """Filesystem path for one application's icon (name-sanitized)."""
    safe = "".join(
        c for c in public_id if c.isalnum() or c in "-_") or "icon"
    return Path(data_dir) / ICON_SUBDIR / f"{safe}.png"


def pack_file_path(data_dir: str, public_id: str) -> Path:
    """Filesystem path for the rendered Android density pack (zip)."""
    safe = "".join(
        c for c in public_id if c.isalnum() or c in "-_") or "icon"
    return Path(data_dir) / ICON_SUBDIR / f"{safe}.android.zip"


def render_android_pack(data: bytes) -> bytes:
    """Render the 5-density launcher pack from validated icon bytes.

    Deterministic (fixed zip timestamps) so re-renders compare equal.
    The caller must have run [validate_icon_png] first.
    """
    from PIL import Image

    with Image.open(BytesIO(data)) as img:
        img.load()
        base = img.convert("RGBA")
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for density, side in ANDROID_DENSITIES:
            frame = (base if base.size == (side, side)
                     else base.resize((side, side), Image.LANCZOS))
            cell = BytesIO()
            frame.save(cell, format="PNG", optimize=True)
            entry = zipfile.ZipInfo(
                f"{density}/{ANDROID_ICON_ENTRY}",
                date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(entry, cell.getvalue())
    return buf.getvalue()


def store_icon(data_dir: str, public_id: str, data: bytes) -> dict:
    """Validate + atomically store; return the branding metadata document."""
    width, height = validate_icon_png(data)
    pack = render_android_pack(data)
    path = icon_file_path(data_dir, public_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    for dest, blob in ((path, data),
                       (pack_file_path(data_dir, public_id), pack)):
        tmp_path = dest.with_name(dest.name + ".tmp")
        tmp_path.write_bytes(blob)
        os.replace(tmp_path, dest)
        os.chmod(dest, 0o644)
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "width": width,
        "height": height,
        "mime": MIME,
        "android_pack_sha256": hashlib.sha256(pack).hexdigest(),
        "android_pack_bytes": len(pack),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def delete_icon_file(data_dir: str, public_id: str) -> bool:
    """Remove the stored files; True when the icon itself existed."""
    try:
        icon_file_path(data_dir, public_id).unlink()
    except FileNotFoundError:
        return False
    try:
        pack_file_path(data_dir, public_id).unlink()
    except FileNotFoundError:
        pass
    return True
