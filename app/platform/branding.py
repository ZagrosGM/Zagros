"""Operator white-labeling of the admin dashboard (f-branding-1, installer FR).

Every screen used to hard-code the Zagros name/logo — resellers presented
the software vendor's brand instead of the operator's, and the only escape
was patching built files inside the container (lost on every update).

One settings row (``branding``), edited in Settings → General (sudo),
applied at runtime by the dashboard via the PUBLIC read endpoint
``GET /api/zagros/branding`` (the login page needs it pre-auth):

  panel_name / panel_tagline   sidebar + login + tab title
  name_fa/name_en etc.         per-language overrides (null = inherit)
  logo_url / favicon_url       https(s) URL or data:image/* (≤ 256 KB)
  accent_color                 #rrggbb — swaps the --brand token family
  show_powered_by              optional "Powered by Zagros" footer

NULL everywhere = stock Zagros: the defaults reproduce current behaviour
exactly, and an invalid value is rejected server-side, never half-applied.
"""
from __future__ import annotations

import logging
import re

from pydantic import BaseModel, ConfigDict, field_validator

logger = logging.getLogger(__name__)

KEY = "branding"
MAX_ASSET_CHARS = 400_000  # ~256 KB base64 data URI / long URL guard
_NAME_RE = re.compile(r"^.{1,64}$", re.S)
_TAGLINE_RE = re.compile(r"^.{0,160}$", re.S)
_HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
_ASSET_RE = re.compile(r"^(https?://|data:image/(png|jpeg|webp|svg\+xml);)", re.I)


class Branding(BaseModel):
    panel_name: str | None = None
    panel_tagline: str | None = None
    name_fa: str | None = None
    name_en: str | None = None
    tagline_fa: str | None = None
    tagline_en: str | None = None
    logo_url: str | None = None
    favicon_url: str | None = None
    accent_color: str | None = None
    show_powered_by: bool | None = None

    model_config = ConfigDict(extra="forbid")

    @field_validator("panel_name", "name_fa", "name_en")
    @classmethod
    def _name_ok(cls, v):
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if not _NAME_RE.match(v):
            raise ValueError("name must be 1-64 characters")
        return v

    @field_validator("panel_tagline", "tagline_fa", "tagline_en")
    @classmethod
    def _tagline_ok(cls, v):
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if not _TAGLINE_RE.match(v):
            raise ValueError("tagline must be at most 160 characters")
        return v

    @field_validator("logo_url", "favicon_url")
    @classmethod
    def _asset_ok(cls, v):
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if len(v) > MAX_ASSET_CHARS or not _ASSET_RE.match(v):
            raise ValueError(
                "asset must be an http(s) URL or a data:image/* URI (<=256KB)")
        # javascript: and friends cannot pass _ASSET_RE — be explicit anyway
        if v.lower().startswith(("javascript:", "vbscript:", "file:")):
            raise ValueError("asset scheme not allowed")
        return v

    @field_validator("accent_color")
    @classmethod
    def _accent_ok(cls, v):
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if not _HEX_RE.match(v):
            raise ValueError("accent_color must be #rrggbb")
        return v.lower()

    def public_dict(self) -> dict:
        """The unauthenticated view: everything the UI may render."""
        return self.model_dump(mode="json")


def load(session_factory) -> Branding:
    """Current branding (defaults where unset). Never raises."""
    from app.platform import settings_kv

    raw = settings_kv.load(session_factory, KEY, {}) or {}
    try:
        return Branding.model_validate(raw)
    except Exception as exc:  # noqa: BLE001 — a bad row must not 500 the UI
        logger.warning("branding row invalid, serving defaults: %s", exc)
        return Branding()


def save(session_factory, branding: Branding) -> Branding:
    from app.platform import settings_kv

    # None fields are dropped so the row stores only overrides
    settings_kv.save(session_factory, KEY,
                     {k: v for k, v in branding.model_dump().items()
                      if v is not None})
    return branding
