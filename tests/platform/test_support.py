from __future__ import annotations

import asyncio
import json
import pytest
from app.platform.admin_api import _forward_ticket_to_bot


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
