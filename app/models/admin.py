from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, ConfigDict, field_validator

from app.db import Session, crud, get_db
from app.utils.jwt import get_admin_payload
from app.utils.passwords import pwd_context  # noqa: F401  (re-exported)
from config import SUDOERS
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/admin/token")  # Admin view url


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class Admin(BaseModel):
    username: str
    is_sudo: bool
    telegram_id: Optional[int] = None
    discord_webhook: Optional[str] = None
    users_usage: Optional[int] = None
    created_at: Optional[datetime] = None
    # --------------------------------------------------------- #
    # Admin governance. None = unlimited / no expiry.
    #   * max_users — hard cap on owned users
    #   * expire_at — admin account expiry (login + API both die)
    #   * traffic_alloc_limit — cap on SUM(users' data_limit)
    #   * traffic_consume_limit — cap on SUM(users' lifetime traffic)
    # The last two are computed aggregates (list endpoint only).
    # --------------------------------------------------------- #
    max_users: Optional[int] = None
    expire_at: Optional[datetime] = None
    traffic_alloc_limit: Optional[int] = None
    traffic_consume_limit: Optional[int] = None
    users_count: Optional[int] = None
    users_lifetime_usage: Optional[int] = None
    users_allocated_traffic: Optional[int] = None
    model_config = ConfigDict(from_attributes=True)

    @property
    def is_expired(self) -> bool:
        if self.expire_at is None:
            return False
        expiry = self.expire_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return expiry <= datetime.now(timezone.utc)

    @field_validator("users_usage",  mode='before')
    def cast_to_int(cls, v):
        if v is None:  # Allow None values
            return v
        if isinstance(v, float):  # Allow float to int conversion
            return int(v)
        if isinstance(v, int):  # Allow integers directly
            return v
        raise ValueError("must be an integer or a float, not a string")  # Reject strings

    @classmethod
    def get_admin(cls, token: str, db: Session):
        payload = get_admin_payload(token)
        if not payload:
            return

        if payload['username'] in SUDOERS and payload['is_sudo'] is True:
            return cls(username=payload['username'], is_sudo=True)

        dbadmin = crud.get_admin(db, payload['username'])
        if not dbadmin:
            return

        if dbadmin.password_reset_at:
            if not payload.get("created_at"):
                return
            # ``iat`` is whole seconds (floored) while the reset stamp keeps
            # sub-second precision — and MySQL DATETIME(0) *rounds* it up.
            # A token issued in the same second as the reset must survive,
            # otherwise a sign-in right after ``zagros reset-admin`` (or a
            # password change in Settings) is bounced as "session expired".
            if dbadmin.password_reset_at > payload["created_at"] + timedelta(seconds=1):
                return

        # Admin governance: an expired admin's token is dead. Login,
        # creating users, editing — everything goes through this gate, so
        # expiring the account suspends ALL of the admin's powers at once.
        if crud.admin_is_expired(dbadmin):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin account expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return cls.model_validate(dbadmin)

    @classmethod
    def get_current(cls,
                    db: Session = Depends(get_db),
                    token: str = Depends(oauth2_scheme)):
        admin = cls.get_admin(token, db)
        if not admin:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return admin

    @classmethod
    def check_sudo_admin(cls,
                         db: Session = Depends(get_db),
                         token: str = Depends(oauth2_scheme)):
        admin = cls.get_admin(token, db)
        if not admin:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not admin.is_sudo:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You're not allowed"
            )
        return admin


class AdminCreate(Admin):
    password: str
    telegram_id: Optional[int] = None
    discord_webhook: Optional[str] = None

    @property
    def hashed_password(self):
        return pwd_context.hash(self.password)

    @field_validator("discord_webhook")
    @classmethod
    def validate_discord_webhook(cls, value):
        if value and not value.startswith("https://discord.com"):
            raise ValueError("Discord webhook must start with 'https://discord.com'")
        return value


class AdminModify(BaseModel):
    password: Optional[str] = None
    is_sudo: bool
    telegram_id: Optional[int] = None
    discord_webhook: Optional[str] = None
    # Governance fields. Presence is tracked via model_fields_set so the
    # CRUD layer can distinguish "keep the current value" (field absent)
    # from "clear the limit" (field present with null/0).
    max_users: Optional[int] = None
    expire_at: Optional[datetime] = None
    traffic_alloc_limit: Optional[int] = None
    traffic_consume_limit: Optional[int] = None

    @property
    def hashed_password(self):
        if self.password:
            return pwd_context.hash(self.password)

    @field_validator("discord_webhook")
    @classmethod
    def validate_discord_webhook(cls, value):
        if value and not value.startswith("https://discord.com"):
            raise ValueError("Discord webhook must start with 'https://discord.com'")
        return value


class AdminPartialModify(AdminModify):
    """PATCH-style variant: every field optional (absent = keep current).

    Fields are redeclared with ``None`` defaults — merely re-annotating
    them ``Optional`` would still leave them REQUIRED to pydantic, which
    previously forced callers to pass every key explicitly.
    """
    password: Optional[str] = None
    is_sudo: Optional[bool] = None
    telegram_id: Optional[int] = None
    discord_webhook: Optional[str] = None
    max_users: Optional[int] = None
    expire_at: Optional[datetime] = None
    traffic_alloc_limit: Optional[int] = None
    traffic_consume_limit: Optional[int] = None


class AdminInDB(Admin):
    username: str
    hashed_password: str

    def verify_password(self, plain_password):
        return pwd_context.verify(plain_password, self.hashed_password)


class AdminValidationResult(BaseModel):
    username: str
    is_sudo: bool
