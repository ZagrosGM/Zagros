from __future__ import annotations

import asyncio
import json
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.platform.admin_api import _forward_ticket_to_bot, DEFAULT_SUPPORT_BOT_URL, DEFAULT_SUPPORT_INTEGRATION_SECRET


@pytest.mark.asyncio
async def test_support_ticket_privacy_and_forwarding(tmp_path):
    # Test that _forward_ticket_to_bot sends ONLY ticket_type, subject, message, attachment
    captured_requests = []

    class MockResponse:
        status_code = 200
        def json(self):
            return {"ok": True, "ticket_id": "TCK-TEST-123"}

    class MockAsyncClient:
        def __init__(self, *args, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def post(self, url, data=None, files=None, headers=None):
            captured_requests.append({
                "url": url, "data": data, "files": files, "headers": headers
            })
            return MockResponse()

    import httpx
    httpx.AsyncClient = MockAsyncClient

    secret = "integration_secret_test_456"
    bot_url = "http://127.0.0.1:8080/support-bot/api.php"

    res = await _forward_ticket_to_bot(
        bot_url=bot_url, secret=secret,
        ticket_type="bug",
        subject="Sample Bug Subject",
        message="Sample Bug Message Detail",
        file_bytes=b"hello log file", file_name="log.txt", mime_type="text/plain",
    )

    assert res["ok"] is True
    assert res["ticket_id"] == "TCK-TEST-123"

    req = captured_requests[0]
    assert req["url"] == bot_url
    assert req["data"] == {
        "type": "bug",
        "subject": "Sample Bug Subject",
        "message": "Sample Bug Message Detail",
    }
    # Verify PRIVACY: Assert NO sensitive panel keys, user lists or secrets were passed
    payload_str = json.dumps(req["data"])
    for forbidden in ["password", "token", "secret_key", "users", "database", "109.248."]:
        assert forbidden not in payload_str

    # Verify signature and timestamp headers present
    assert "X-Zagros-Signature" in req["headers"]
    assert "X-Zagros-Timestamp" in req["headers"]
    assert len(req["headers"]["X-Zagros-Signature"]) == 64  # HMAC-SHA256 hex length


@pytest.mark.asyncio
async def test_support_ticket_endpoints_and_multipart():
    # Verify support ticket endpoint with multipart form data (Test 1, 2, 3, 4)
    from app.platform.routers import zagros_admin_router, get_runtime
    from app.platform.admin_api import _forward_ticket_to_bot
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    async def mock_forward(*args, **kwargs):
        return {"ok": True, "ticket_id": f"TCK-MOCK-{kwargs.get('ticket_type', 'bug').upper()}"}

    with patch("app.platform.admin_api._forward_ticket_to_bot", side_effect=mock_forward):
        app = FastAPI()
        app.include_router(zagros_admin_router)

        class MockKV:
            async def get_value(self, key):
                return {"bot_url": "http://127.0.0.1:8080/support-bot/api.php", "integration_secret": "test_secret"}

        class MockRuntime:
            kv = MockKV()

        app.dependency_overrides[get_runtime] = lambda: MockRuntime()
        for dep in zagros_admin_router.dependencies:
            app.dependency_overrides[dep.dependency] = lambda: None

        client = TestClient(app)

        # Test 1 — Bug Report without attachment
        res1 = client.post(
            "/api/zagros/support/ticket",
            data={
                "ticket_type": "bug",
                "subject": "WireGuard connection dropped",
                "message": "When connecting via WireGuard, the tunnel drops after 5 minutes.",
            }
        )
        assert res1.status_code == 200, res1.text
        data1 = res1.json()
        assert data1["ok"] is True
        assert "ticket_id" in data1
        assert "TCK-MOCK-BUG" in data1["ticket_id"]

        # Test 2 — Feature Request without attachment
        res2 = client.post(
            "/api/zagros/support/ticket",
            data={
                "ticket_type": "feature",
                "subject": "Add Dark Mode toggle to User Portal",
                "message": "It would be great to have an explicit dark mode toggle on subscription page.",
            }
        )
        assert res2.status_code == 200, res2.text
        data2 = res2.json()
        assert data2["ok"] is True
        assert "ticket_id" in data2
        assert "TCK-MOCK-FEATURE" in data2["ticket_id"]

        # Test 3 — Attachment (Bug Report with File)
        res3 = client.post(
            "/api/zagros/support/ticket",
            data={
                "ticket_type": "bug",
                "subject": "Error log attached",
                "message": "See attached log for details.",
            },
            files={
                "attachment": ("debug.log", b"sample error log content", "text/plain")
            }
        )
        assert res3.status_code == 200, res3.text
        data3 = res3.json()
        assert data3["ok"] is True
        assert "ticket_id" in data3

        # Test 4 — Validation (Invalid ticket_type -> 422)
        res4_type = client.post(
            "/api/zagros/support/ticket",
            data={
                "ticket_type": "invalid_type",
                "subject": "Valid Subject",
                "message": "Valid Message",
            }
        )
        assert res4_type.status_code == 422

        # Test 4 — Validation (Missing subject -> 422)
        res4_subj = client.post(
            "/api/zagros/support/ticket",
            data={
                "ticket_type": "bug",
                "subject": "   ",
                "message": "Valid Message",
            }
        )
        assert res4_subj.status_code == 422

        # Test 4 — Validation (Attachment > 10MB -> 413)
        big_file = b"X" * (10 * 1024 * 1024 + 100)
        res4_big = client.post(
            "/api/zagros/support/ticket",
            data={
                "ticket_type": "bug",
                "subject": "Big File Test",
                "message": "Sending huge file",
            },
            files={
                "attachment": ("huge.bin", big_file, "application/octet-stream")
            }
        )
        assert res4_big.status_code == 413
