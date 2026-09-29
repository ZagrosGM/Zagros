import time
import jwt
from base64 import b64decode, b64encode
from datetime import datetime, timedelta
from functools import lru_cache
from hashlib import sha256
from math import ceil
from typing import Union


from config import JWT_ACCESS_TOKEN_EXPIRE_MINUTES


@lru_cache(maxsize=None)
def get_secret_key():
    from app.db import GetDB, get_jwt_secret_key

    with GetDB() as db:
        secret = get_jwt_secret_key(db)
    if not secret:
        # The init_jwt_table migration seeds this row. Inventing a secret
        # here would silently invalidate every token already issued, so the
        # honest move is to say what is wrong and how to fix it.
        raise RuntimeError(
            "JWT secret is missing from the database — run the migrations "
            "(revision 'init_jwt_table' seeds it) before issuing or "
            "verifying tokens")
    return secret


def _effective_expire_minutes() -> int:
    """Token lifetime: the database override wins over the environment.

    Settings -> Security can change this without editing ``.env`` (which would
    need a restart). The override lives in the *platform* database, so this
    resolves the running runtime exactly like the scheduler jobs do; if the
    runtime is not up yet, the environment value applies.
    """
    try:
        import app as _app

        runtime = getattr(getattr(_app, "app", None), "state", None)
        runtime = getattr(runtime, "zagros", None)
        if runtime is not None:
            from app.platform.settings_kv import load

            with runtime.session_factory() as session:
                override = load(session, "security", {}).get("token_expire_minutes")
            if override is not None:
                return int(override)
    except Exception:  # noqa: BLE001 - never break token creation
        pass
    return int(JWT_ACCESS_TOKEN_EXPIRE_MINUTES)


def create_admin_token(username: str, is_sudo=False) -> str:
    data = {"sub": username, "access": "sudo" if is_sudo else "admin", "iat": datetime.utcnow()}
    minutes = _effective_expire_minutes()
    if minutes > 0:
        expire = datetime.utcnow() + timedelta(minutes=minutes)
        data["exp"] = expire
    encoded_jwt = jwt.encode(data, get_secret_key(), algorithm="HS256")
    return encoded_jwt


def get_admin_payload(token: str) -> Union[dict, None]:
    try:
        payload = jwt.decode(token, get_secret_key(), algorithms=["HS256"])
        username: str = payload.get("sub")
        access: str = payload.get("access")
        if not username or access not in ('admin', 'sudo'):
            return
        try:
            created_at = datetime.utcfromtimestamp(payload['iat'])
        except KeyError:
            created_at = None

        return {"username": username, "is_sudo": access == "sudo", "created_at": created_at}
    except jwt.exceptions.PyJWTError:
        return


def _sub_signing_secrets() -> list[str]:
    """Primary secret first, then the source panels' secrets accepted for
    OLD subscription links (f-import-links)."""
    try:
        candidates = [get_secret_key()]
    except Exception:  # noqa: BLE001 - missing primary: fallbacks still work
        candidates = []
    candidates.extend(_imported_sub_secrets())
    return candidates


@lru_cache(maxsize=1)
def _imported_sub_secrets() -> tuple[str, ...]:
    """Secrets of MIGRATED source panels (Marzban/Pasarguard ``jwt.secret_key``).

    A migration must not break the subscription URLs users already have
    saved in their clients. Those URLs are signed with the SOURCE panel's
    JWT secret, so after a restore the source's secret is installed ALONGSIDE
    ours (never instead of it) — old links validate against it while every
    new link keeps being signed with this panel's own secret.
    """
    try:
        import app as _app

        runtime = getattr(getattr(_app, "app", None), "state", None)
        runtime = getattr(runtime, "zagros", None)
        if runtime is None:
            return ()
        from app.platform.settings_kv import load

        stored = load(runtime.session_factory, "security", {}).get(
            "imported_sub_secrets")
        if not isinstance(stored, list):
            return ()
        return tuple(str(s) for s in stored if isinstance(s, str) and s)
    except Exception:  # noqa: BLE001 - fallbacks are best-effort
        return ()


def invalidate_imported_sub_secrets() -> None:
    _imported_sub_secrets.cache_clear()


def install_imported_sub_secret(secret: str) -> bool:
    """Accept *secret* for old-link validation. Idempotent; True if added."""
    secret = str(secret or "").strip()
    if len(secret) < 16:
        return False
    try:
        if secret == get_secret_key():
            return False
    except Exception:  # noqa: BLE001 - store it even without a primary yet
        pass
    import app as _app

    runtime = getattr(getattr(_app, "app", None), "state", None)
    runtime = getattr(runtime, "zagros", None)
    if runtime is None:
        return False
    from app.platform.settings_kv import load, save

    doc = load(runtime.session_factory, "security", {})
    if not isinstance(doc, dict):
        doc = {}
    stored = [str(s) for s in (doc.get("imported_sub_secrets") or [])
              if isinstance(s, str) and s]
    if secret in stored:
        invalidate_imported_sub_secrets()
        return False
    stored.append(secret)
    doc["imported_sub_secrets"] = stored[-5:]
    save(runtime.session_factory, "security", doc)
    invalidate_imported_sub_secrets()
    return True


def create_subscription_token(username: str) -> str:
    data = username + ',' + str(ceil(time.time()))
    data_b64_str = b64encode(data.encode('utf-8'), altchars=b'-_').decode('utf-8').rstrip('=')
    data_b64_sign = b64encode(
        sha256(
            (data_b64_str+get_secret_key()).encode('utf-8')
        ).digest(),
        altchars=b'-_'
    ).decode('utf-8')[:10]
    data_final = data_b64_str + data_b64_sign
    return data_final


def get_subscription_payload(token: str) -> Union[dict, None]:
    try:
        if len(token) < 15:
            return

        if token.startswith("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."):
            for secret in _sub_signing_secrets():
                try:
                    payload = jwt.decode(token, secret, algorithms=["HS256"])
                except jwt.exceptions.PyJWTError:
                    continue
                if payload.get("access") == "subscription":
                    return {"username": payload['sub'], "created_at": datetime.utcfromtimestamp(payload['iat'])}
            return
        else:
            u_token = token[:-10]
            u_signature = token[-10:]
            try:
                u_token_dec = b64decode(
                    (u_token.encode('utf-8') + b'=' * (-len(u_token.encode('utf-8')) % 4)),
                    altchars=b'-_', validate=True)
                u_token_dec_str = u_token_dec.decode('utf-8')
            except:
                return
            for secret in _sub_signing_secrets():
                u_token_resign = b64encode(sha256((u_token+secret).encode('utf-8')
                                                  ).digest(), altchars=b'-_').decode('utf-8')[:10]
                if u_signature == u_token_resign:
                    u_username = u_token_dec_str.split(',')[0]
                    u_created_at = int(u_token_dec_str.split(',')[1])
                    return {"username": u_username, "created_at": datetime.utcfromtimestamp(u_created_at)}
            return
    except jwt.exceptions.PyJWTError:
        return
