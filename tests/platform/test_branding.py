"""f-branding-1 — operator white-labeling: validation, defaults, public view."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

from app.platform import branding  # noqa: E402
from app.platform.settings_kv import load as kv_load, save as kv_save  # noqa: E402


class _FakeSF:
    """Minimal session_factory double backed by a dict."""

    def __init__(self):
        self.store: dict = {}

    def __call__(self):
        return _FakeSession(self.store)


class _FakeSession:
    def __init__(self, store):
        self._store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get(self, model, key):
        return self._store.get(key)

    def add(self, row):
        self._store[row.key] = row

    def commit(self):
        pass


class _Row:
    def __init__(self, key, value_json):
        self.key = key
        self.value_json = value_json


def test_branding_defaults_are_stock_zagros():
    sf = _FakeSF()
    out = branding.load(sf)
    assert out.public_dict() == {
        "panel_name": None, "panel_tagline": None,
        "name_fa": None, "name_en": None,
        "tagline_fa": None, "tagline_en": None,
        "logo_url": None, "favicon_url": None,
        "accent_color": None, "show_powered_by": None,
    }


def test_branding_roundtrip_and_partial_override():
    sf = _FakeSF()
    branding.save(sf, branding.Branding(panel_name="Nova VPN",
                                        accent_color="#0aBcDe",
                                        show_powered_by=False))
    out = branding.load(sf)
    assert out.panel_name == "Nova VPN"
    assert out.show_powered_by is False
    assert kv_load(sf, branding.KEY)["panel_name"] == "Nova VPN"


def test_branding_rejects_bad_values():
    # empty = unset (None), NOT an error — the UI sends empties freely
    assert branding.Branding(panel_name="").panel_name is None
    with pytest.raises(ValueError):
        branding.Branding(accent_color="red")           # not #rrggbb
    with pytest.raises(ValueError):
        branding.Branding(logo_url="javascript:alert(1)")
    with pytest.raises(ValueError):
        branding.Branding(logo_url="ftp://x/y.png")
    with pytest.raises(ValueError):
        branding.Branding(panel_name="x" * 65)
    # a data URI logo IS fine
    branding.Branding(logo_url="data:image/svg+xml;base64,PHN2Zy8+")


def test_branding_invalid_row_serves_defaults(monkeypatch):
    sf = _FakeSF()
    sf.store["branding"] = _Row("branding", "not-a-dict")
    out = branding.load(sf)
    assert out.panel_name is None, "bad storage must never break the UI"


def test_public_branding_served_on_both_paths():
    """rc4 regression — the dashboard api client prefixes "/api", so the public
    view must answer on /api/zagros/branding (not only on /branding)."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.platform.routers import zagros_router

    app = FastAPI()
    app.include_router(zagros_router)
    client = TestClient(app, raise_server_exceptions=False)

    for path in ("/branding", "/api/zagros/branding"):
        r = client.get(path)
        assert r.status_code == 200, path
        assert r.json() == {}  # no runtime attached -> stock, no crash
