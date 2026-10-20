from __future__ import annotations

import asyncio
import json
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.platform.admin_api import (
    _forward_ticket_to_bot,
    _support_target_urls,
    DEFAULT_SUPPORT_BOT_URL,
    DEFAULT_SUPPORT_INTEGRATION_SECRET,
)


def test_support_endpoint_resolution_prefers_worker_and_honours_explicit_urls():
    assert _support_target_urls("https://support.example") == [
        "https://support.example/api/ticket",
        "https://support.example/api.php",
    ]
    assert _support_target_urls("https://support.example/api/ticket") == [
        "https://support.example/api/ticket"]
    assert _support_target_urls("https://legacy.example/api.php") == [
        "https://legacy.example/api.php"]


@pytest.mark.asyncio
async def test_support_ticket_privacy_and_forwarding(tmp_path, monkeypatch):
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
    monkeypatch.setattr(httpx, "AsyncClient", MockAsyncClient)

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


# --------------------------------------------------------------------------- #
# the bot's answers become actionable HTTP errors (bug list item 5)
# --------------------------------------------------------------------------- #

class _BotAnswer:
    def __init__(self, status_code: int, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def _client_answering(monkeypatch, answer):
    import httpx

    class _Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def post(self, url, data=None, files=None, headers=None):
            if isinstance(answer, Exception):
                raise answer
            return answer

    monkeypatch.setattr(httpx, "AsyncClient", _Client)


@pytest.mark.asyncio
@pytest.mark.parametrize("status, body, expect_status, expect_text", [
    # PHP refused the upload before api.php ran (upload_max_filesize = 2M on
    # the bot host) — what a 2.2 MB screenshot produced on the live panel
    (422, {"ok": False, "error": "Attachment error: Upload error code: 1"}, 413,
     "larger than the bot server accepts"),
    (422, {"ok": False, "error": "Attachment error: Upload error code: 2"}, 413,
     "larger than the bot server accepts"),
    (401, {"ok": False, "error": "bad signature"}, 401, "integration secret does not match"),
    (500, {"ok": False, "error": "db down"}, 500, "answered HTTP 500: db down"),
    (200, {"ok": False, "error": "flood"}, 200, "did not accept the ticket: flood"),
    (502, ValueError("not json"), 502, "answered HTTP 502"),
])
async def test_bot_refusals_are_named(monkeypatch, status, body, expect_status, expect_text):
    from app.platform.admin_api import SupportBotError

    _client_answering(monkeypatch, _BotAnswer(status, body))
    with pytest.raises(SupportBotError) as info:
        await _forward_ticket_to_bot(
            bot_url="http://bot.test", secret="s", ticket_type="bug",
            subject="s", message="m",
            file_bytes=b"x" * 2048, file_name="shot.png", mime_type="image/png")
    assert info.value.status == expect_status
    assert expect_text in str(info.value)


@pytest.mark.asyncio
async def test_worker_404_falls_back_to_legacy_php_once(monkeypatch):
    import httpx

    seen = []

    class _Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def post(self, url, data=None, files=None, headers=None):
            seen.append(url)
            if url.endswith("/api/ticket"):
                return _BotAnswer(404, {"ok": False, "error": "not found"})
            return _BotAnswer(200, {"ok": True, "ticket_id": "TCK-PHP"})

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    result = await _forward_ticket_to_bot(
        bot_url="https://legacy.example", secret="s", ticket_type="bug",
        subject="s", message="m")
    assert result["ticket_id"] == "TCK-PHP"
    assert seen == ["https://legacy.example/api/ticket",
                    "https://legacy.example/api.php"]


@pytest.mark.asyncio
async def test_upload_error_without_a_file_is_not_a_size_problem(monkeypatch):
    """No attachment was sent → 'Upload error code: 1' cannot be about size."""
    from app.platform.admin_api import SupportBotError

    _client_answering(monkeypatch, _BotAnswer(
        422, {"ok": False, "error": "Attachment error: Upload error code: 1"}))
    with pytest.raises(SupportBotError) as info:
        await _forward_ticket_to_bot(bot_url="http://bot.test", secret="s",
                                     ticket_type="bug", subject="s", message="m")
    assert info.value.status == 422
    assert "answered HTTP 422" in str(info.value)


@pytest.mark.asyncio
async def test_unreachable_bot_names_the_url(monkeypatch):
    import httpx
    from app.platform.admin_api import SupportBotError

    _client_answering(monkeypatch, httpx.ConnectError("refused"))
    with pytest.raises(SupportBotError) as info:
        await _forward_ticket_to_bot(bot_url="http://bot.test", secret="s",
                                     ticket_type="bug", subject="s", message="m")
    assert info.value.status is None
    assert "http://bot.test/api/ticket is unreachable (ConnectError)" in str(info.value)


def test_ticket_endpoint_maps_bot_answers_to_status_codes(monkeypatch):
    from fastapi import FastAPI
    from app.platform.admin_api import SupportBotError
    from app.platform.routers import get_runtime, zagros_admin_router

    answers = iter([
        SupportBotError("the support bot refused the attachment (2252 KB): it is larger "
                        "than the bot server accepts", status=413),
        SupportBotError("the support bot rejected this panel's signature", status=401),
        SupportBotError("the support bot at http://x/api.php is unreachable (ConnectError)",
                        status=None),
        RuntimeError("boom"),
    ])

    async def fake_forward(*args, **kwargs):
        raise next(answers)

    class MockKV:
        async def get_value(self, key):
            return {}

    class MockRuntime:
        kv = MockKV()

    with patch("app.platform.admin_api._forward_ticket_to_bot", side_effect=fake_forward):
        app = FastAPI()
        app.include_router(zagros_admin_router)
        app.dependency_overrides[get_runtime] = lambda: MockRuntime()
        for dep in zagros_admin_router.dependencies:
            app.dependency_overrides[dep.dependency] = lambda: None
        client = TestClient(app)
        form = {"ticket_type": "bug", "subject": "s", "message": "m"}

        r = client.post("/api/zagros/support/ticket", data=form,
                        files={"attachment": ("shot.png", b"x" * 10, "image/png")})
        assert r.status_code == 413, r.text
        assert "larger than the bot server accepts" in r.json()["detail"]
        r = client.post("/api/zagros/support/ticket", data=form)
        assert r.status_code == 502 and "signature" in r.json()["detail"]
        r = client.post("/api/zagros/support/ticket", data=form)
        assert r.status_code == 502 and "unreachable" in r.json()["detail"]
        r = client.post("/api/zagros/support/ticket", data=form)
        assert r.status_code == 502
        assert r.json()["detail"] == "Support service is temporarily unavailable."
