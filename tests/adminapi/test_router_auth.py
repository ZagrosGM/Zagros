"""Router-level auth guarantees (security review, Alpha).

Every ``/api/zagros/*`` endpoint MUST require a sudo admin. Without an
authentication stack the dependency fails closed (503), never open.
The client/portal endpoints deliberately stay public (their own token
schemes); this test proves that distinction is wired correctly.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
except ImportError:  # pragma: no cover
    pytest.skip("fastapi not installed (transient dev dep)", allow_module_level=True)

from app.platform.routers import zagros_admin_router, zagros_router  # noqa: E402

ADMIN_ROUTES = [
    ("get", "/api/zagros/dashboard/snapshot"),
    ("get", "/api/zagros/studio/xray/raw"),
    ("post", "/api/zagros/studio/xray/preview"),
    ("post", "/api/zagros/studio/xray/apply"),
    ("post", "/api/zagros/studio/xray/wizard/inbound"),
    ("get", "/api/zagros/settings/portal"),
    ("put", "/api/zagros/settings/portal"),
    ("post", "/api/zagros/users/1/subscription-token"),
    ("post", "/api/zagros/users/1/app-credentials"),
    ("post", "/api/zagros/migrate/legacy"),
]


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(zagros_router)
    app.include_router(zagros_admin_router)
    return TestClient(app)


def test_admin_routes_never_open_anonymously(client: TestClient) -> None:
    """No admin endpoint may answer 2xx/404-not-found-but-reached-handler —
    the auth dependency must bite first (401/403 with the legacy stack,
    503 without it)."""
    for method, path in ADMIN_ROUTES:
        call = getattr(client, method)
        resp = call(path) if method == "get" else call(path, json={})
        assert resp.status_code in (401, 403, 503), (
            f"{method.upper()} {path} answered {resp.status_code} without auth!")


def test_client_and_portal_routes_remain_public(client: TestClient) -> None:
    """The app-login flow is public by design (its own rate-limited auth)."""
    resp = client.post("/client/v1/auth/login",
                       json={"username": "nobody", "password": "wrong"})
    # The legacy /client/v1 API is permanently closed with 410 (the signed
    # Application API replaced it) and the subscription portal answers 410
    # pages for unknown/expired tickets. Either way the request must NOT be
    # 401/403 — i.e. the ADMIN guard never bites on public/retired routes.
    assert resp.status_code == 410
    resp = client.get("/zagros/sub/whatever")
    # 410 with a runtime attached (ticketed portal); 503 when the runtime
    # is absent (the bare test app) — either way NOT admin-guarded.
    assert resp.status_code in (410, 503)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
