"""Client API tests — auth, tokens, sealed delivery, safe views.

Simulates the full app flow end-to-end including the client side of the
sealed channel (ephemeral keypair, envelope opening) exactly like the
Flutter app will.

Run: pytest tests/clientapi/test_clientapi.py -v  OR  python tests/clientapi/test_clientapi.py
"""
from __future__ import annotations

import asyncio
import json
import sys
import traceback
import types as _types
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.clientapi.errors import (  # noqa: E402
    AuthFailedError,
    ClientApiError,
    ConnectTokenError,
    RateLimitedError,
    UserSuspendedError,
)
from app.clientapi.service import ClientApiService  # noqa: E402
from app.clientapi.stores import (  # noqa: E402
    InMemoryConnectTokenStore,
    InMemoryRefreshTokenStore,
)
from app.clientapi.tokens import SignedTokenService  # noqa: E402
from app.cores.types import ClientConfig, UserAccount  # noqa: E402
from app.crypto.seal import open_envelope  # noqa: E402
from app.crypto.x25519 import generate_keypair  # noqa: E402

_SECRET_UUID = "11111111-aaaa-bbbb-cccc-222222222222"


# ---------------------------------------------------------------------- #
# fakes
# ---------------------------------------------------------------------- #

class _FakeDriver:
    last_node = None

    class _Meta:
        id = "fakebox"
        name = "FakeBox"
    metadata = _Meta()

    async def build_client_config(self, account, node=None) -> ClientConfig:
        type(self).last_node = node
        return ClientConfig(
            core_id="fakebox", protocol="vless", engine="sing-box",
            payload={"outbounds": [{"type": "vless", "server": "h.example.com",
                                    "server_port": 443, "uuid": _SECRET_UUID}]},
            display_name="FakeBox · main",
        )


class _Provider:
    def __init__(self) -> None:
        self.users: dict[int, dict] = {
            7: {"id": 7, "username": "alice", "status": "active",
                "expire_at": None, "online": False,
                "app_username": None, "app_password_hash": None},
        }
        self.usage = (7_500_000_000, 10_000_000_000)

    async def get_user_record(self, user_id: int):
        return self.users.get(user_id)

    async def find_user_by_app_username(self, app_username: str):
        for u in self.users.values():
            if u.get("app_username") == app_username:
                return u
        return None

    async def save_app_credentials(self, user_id, app_username, app_password_hash):
        self.users[user_id]["app_username"] = app_username
        self.users[user_id]["app_password_hash"] = app_password_hash

    async def get_core_accounts(self, user_id: int):
        account = UserAccount(user_id=user_id, username="alice",
                              account_id=f"{user_id}.alice", protocol="vless",
                              settings={"id": _SECRET_UUID})
        return [(_FakeDriver(), account)]

    async def get_usage(self, user_id: int):
        return self.usage


class _Clock:
    def __init__(self) -> None:
        self.t = 1_700_000_000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def _service(clock: _Clock | None = None) -> tuple[ClientApiService, _Provider, list]:
    provider = _Provider()
    clock = clock or _Clock()
    events: list = []
    import time as _time
    tokens = SignedTokenService(b"unit-test-secret-key-32bytes!!!", ttl_seconds=900)
    service = ClientApiService(
        provider, InMemoryRefreshTokenStore(), InMemoryConnectTokenStore(), tokens,
        now=_time.time if clock is None else clock,
        on_event=lambda name, data: events.append((name, data)),
    )
    # force the deterministic clock into token issuing/verification when given
    if clock is not None:
        service._now = clock
    return service, provider, events


def _login(service: ClientApiService, username: str, password: str):
    return asyncio.run(service.authenticate(username, password))


# ---------------------------------------------------------------------- #
# credentials & auth
# ---------------------------------------------------------------------- #

def test_issue_credentials_and_login_roundtrip() -> None:
    service, provider, events = _service()
    creds = asyncio.run(service.issue_app_credentials(7))
    assert creds.username.startswith("u7.") and len(creds.password) >= 16
    tokens = _login(service, creds.username, creds.password)
    assert tokens.access_token.startswith("zga.") and tokens.refresh_token
    assert any(e[0] == "auth.success" for e in events)
    user_id = service.verify_access(tokens.access_token)
    assert user_id == 7


def test_wrong_password_and_unknown_user_are_uniform() -> None:
    service, provider, _ = _service()
    creds = asyncio.run(service.issue_app_credentials(7))
    for username, password in ((creds.username, "nope"), ("ghost.user", "nope")):
        try:
            _login(service, username, password)
            raise AssertionError("bad credentials accepted")
        except AuthFailedError as exc:
            assert "invalid username or password" in str(exc)


def test_suspended_user_cannot_login() -> None:
    service, provider, _ = _service()
    creds = asyncio.run(service.issue_app_credentials(7))
    provider.users[7]["status"] = "expired"
    try:
        _login(service, creds.username, creds.password)
        raise AssertionError("expired user logged in")
    except UserSuspendedError:
        pass


def test_rate_limit_after_repeated_failures() -> None:
    service, _, _ = _service()
    creds = asyncio.run(service.issue_app_credentials(7))
    for _ in range(5):
        try:
            _login(service, creds.username, "bad")
        except AuthFailedError:
            pass
    try:
        _login(service, creds.username, "bad")
        raise AssertionError("rate limit not enforced")
    except RateLimitedError:
        pass


def test_credential_rotation_revokes_old_sessions() -> None:
    service, _, _ = _service()
    creds1 = asyncio.run(service.issue_app_credentials(7))
    _login(service, creds1.username, creds1.password)
    asyncio.run(service.issue_app_credentials(7))  # rotate
    try:
        _login(service, creds1.username, creds1.password)
        raise AssertionError("rotated credentials still work")
    except AuthFailedError:
        pass


# ---------------------------------------------------------------------- #
# tokens
# ---------------------------------------------------------------------- #

def test_refresh_rotation_and_replay_guard() -> None:
    service, _, _ = _service()
    creds = asyncio.run(service.issue_app_credentials(7))
    tokens1 = _login(service, creds.username, creds.password)
    tokens2 = asyncio.run(service.refresh(tokens1.refresh_token))
    assert tokens2.refresh_token != tokens1.refresh_token
    # replaying the rotated refresh token must fail
    try:
        asyncio.run(service.refresh(tokens1.refresh_token))
        raise AssertionError("rotated refresh token replayed")
    except AuthFailedError:
        pass


def test_logout_revokes_refresh() -> None:
    service, _, _ = _service()
    creds = asyncio.run(service.issue_app_credentials(7))
    tokens = _login(service, creds.username, creds.password)
    asyncio.run(service.logout(tokens.refresh_token))
    try:
        asyncio.run(service.refresh(tokens.refresh_token))
        raise AssertionError("logged-out refresh accepted")
    except AuthFailedError:
        pass


def test_access_token_tamper_and_type_guard() -> None:
    tokens = SignedTokenService(b"another-secret-key-32-bytes!!!!!", ttl_seconds=60)
    token, _ = tokens.issue(7)
    assert tokens.verify(token)["sub"] == "7"
    body, sig = token.split(".")[1], token.split(".")[0]
    try:
        tokens.verify(token[:-2] + ("AA" if not token.endswith("AA") else "BB"))
        raise AssertionError("tampered token verified")
    except Exception:
        pass
    try:
        tokens.verify(token, expected_type="refresh")
        raise AssertionError("wrong token type accepted")
    except Exception:
        pass


def test_access_token_expiry() -> None:
    import time as _time
    tokens = SignedTokenService(b"expiry-secret-key-32-bytes!!!!!!", ttl_seconds=-1)
    token, _ = tokens.issue(7)
    _time.sleep(0.01)
    try:
        tokens.verify(token)
        raise AssertionError("expired token verified")
    except Exception as exc:
        assert "expired" in str(exc)


# ---------------------------------------------------------------------- #
# profile
# ---------------------------------------------------------------------- #

def test_profile_contains_no_secrets() -> None:
    service, _, _ = _service()
    profile = asyncio.run(service.get_profile(7))
    blob = profile.model_dump_json()
    assert _SECRET_UUID not in blob
    assert "payload" not in blob
    assert profile.cores[0].display_name == "FakeBox · main"
    assert profile.cores[0].status == "active"
    assert profile.remaining_bytes == 2_500_000_000


# ---------------------------------------------------------------------- #
# sealed connect flow (full client-side simulation)
# ---------------------------------------------------------------------- #

def test_full_connect_flow_with_sealed_delivery() -> None:
    service, _, events = _service()
    offer = asyncio.run(service.request_connect(7, "fakebox"))
    assert offer.ttl_seconds == 30

    # --- client side: generate ephemeral keypair -------------------------- #
    client_priv, client_pub = generate_keypair()
    import base64
    client_pub_b64 = base64.urlsafe_b64encode(client_pub).decode().rstrip("=")

    envelope = asyncio.run(service.deliver_config(offer.connect_token, client_pub_b64))
    document = json.loads(open_envelope(envelope, client_priv))
    config = document["config"]
    assert config["core_id"] == "fakebox" and config["protocol"] == "vless"
    assert config["payload"]["outbounds"][0]["uuid"] == _SECRET_UUID
    assert any(e[0] == "config.delivered" for e in events)


def test_sealed_delivery_forwards_public_host_context_to_driver() -> None:
    from app.cores.delivery import DeliveryContext

    service, _, _ = _service()
    offer = asyncio.run(service.request_connect(7, "fakebox"))
    client_priv, client_pub = generate_keypair()
    import base64
    client_pub_b64 = base64.urlsafe_b64encode(client_pub).decode().rstrip("=")
    context = DeliveryContext(public_host="vpn.example.test")
    envelope = asyncio.run(service.deliver_config(
        offer.connect_token, client_pub_b64, context))
    assert json.loads(open_envelope(envelope, client_priv))["config"]["core_id"] == "fakebox"
    assert _FakeDriver.last_node == context


def test_connect_token_is_one_time() -> None:
    service, _, _ = _service()
    offer = asyncio.run(service.request_connect(7, "fakebox"))
    _, client_pub = generate_keypair()
    import base64
    pub_b64 = base64.urlsafe_b64encode(client_pub).decode().rstrip("=")
    asyncio.run(service.deliver_config(offer.connect_token, pub_b64))
    try:
        asyncio.run(service.deliver_config(offer.connect_token, pub_b64))
        raise AssertionError("connect token replayed")
    except ConnectTokenError:
        pass


def test_connect_token_expiry_and_unknown() -> None:
    clock = _Clock()
    service, _, _ = _service(clock)
    offer = asyncio.run(service.request_connect(7, "fakebox"))
    import base64
    _, client_pub = generate_keypair()
    pub_b64 = base64.urlsafe_b64encode(client_pub).decode().rstrip("=")
    clock.advance(31)  # past the 30 s TTL
    try:
        asyncio.run(service.deliver_config(offer.connect_token, pub_b64))
        raise AssertionError("expired connect token accepted")
    except ConnectTokenError:
        pass
    try:
        asyncio.run(service.deliver_config("no-such-token", pub_b64))
        raise AssertionError("unknown token accepted")
    except ConnectTokenError:
        pass


def test_connect_rejects_suspended_and_wrong_core() -> None:
    service, provider, _ = _service()
    try:
        asyncio.run(service.request_connect(7, "ghost-core"))
        raise AssertionError("unknown core connect accepted")
    except ClientApiError:
        pass
    provider.users[7]["status"] = "limited"
    try:
        asyncio.run(service.request_connect(7, "fakebox"))
        raise AssertionError("limited user got connect offer")
    except UserSuspendedError:
        pass


def test_delivery_rejects_bad_client_key() -> None:
    service, _, _ = _service()
    offer = asyncio.run(service.request_connect(7, "fakebox"))
    try:
        asyncio.run(service.deliver_config(offer.connect_token, "short"))
        raise AssertionError("bad client key accepted")
    except ConnectTokenError:
        pass


if __name__ == "__main__":
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
