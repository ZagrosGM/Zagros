from __future__ import annotations

import pytest
from datetime import datetime, timezone
from app.db import GetDB, crud
from app.models.user import UserCreate, UserModify, UserStatus, UserStatusCreate, ProxyTypes
from app.platform.admin_api import DEFAULT_SUPPORT_BOT_URL, DEFAULT_SUPPORT_INTEGRATION_SECRET


def test_support_defaults():
    assert DEFAULT_SUPPORT_BOT_URL == "https://support.zagrosgm.site"
    assert DEFAULT_SUPPORT_INTEGRATION_SECRET == "6b3f42e6569ab1184fafe7ed3e60879ba5cb74ce855371d92274d36987ebd6dc"


def test_user_edit_preserves_proxy_credentials():
    with GetDB() as db:
        username = "test_edit_user_proxy_1"
        existing = crud.get_user(db, username)
        if existing:
            crud.remove_user(db, existing)

        # Create a user with Shadowsocks proxy
        uc = UserCreate(
            username=username,
            status=UserStatusCreate.active,
            proxies={"shadowsocks": {}},
            inbounds={},
        )
        user = crud.create_user(db, uc)
        ss_proxy = next(p for p in user.proxies if p.type == ProxyTypes.Shadowsocks)
        original_pass = ss_proxy.settings.get("password")
        original_method = ss_proxy.settings.get("method")
        assert original_pass is not None

        # Modify user bandwidth limit only (passing empty proxy dict as frontend does)
        um = UserModify(
            download_limit_mbps=100,
            upload_limit_mbps=50,
            proxies={"shadowsocks": {}},
        )
        updated = crud.update_user(db, user, um)
        updated_ss_proxy = next(p for p in updated.proxies if p.type == ProxyTypes.Shadowsocks)

        # PRESERVATION ASSERTION: Password and method MUST NOT change!
        assert updated_ss_proxy.settings.get("password") == original_pass
        assert updated_ss_proxy.settings.get("method") == original_method
        assert updated.download_limit_mbps == 100
        assert updated.upload_limit_mbps == 50

        # Cleanup
        crud.remove_user(db, updated)


def test_online_at_utc_serialization():
    from app.models.user import UserResponse
    dt = datetime(2026, 8, 23, 12, 0, 0)
    with GetDB() as db:
        username = "test_online_at_user"
        existing = crud.get_user(db, username)
        if existing:
            crud.remove_user(db, existing)

        uc = UserCreate(
            username=username,
            status=UserStatusCreate.active,
            proxies={"vless": {}},
            inbounds={},
        )
        user = crud.create_user(db, uc)
        user.online_at = dt
        db.commit()

        resp = UserResponse.model_validate(user)
        dump = resp.model_dump(mode="json")
        assert "online_at" in dump
        assert dump["online_at"].endswith("Z") or "+00:00" in dump["online_at"]

        crud.remove_user(db, user)
