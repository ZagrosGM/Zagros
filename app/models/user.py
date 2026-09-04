import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union, TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator, model_validator

from app import xray
if TYPE_CHECKING:
    from app.models.admin import Admin
from app.models.proxy import ProxySettings, ProxyTypes
from app.subscription.share import generate_v2ray_links
from app.utils.jwt import create_subscription_token

USERNAME_REGEXP = re.compile(r"^(?=\w{3,32}\b)[a-zA-Z0-9-_@.]+(?:_[a-zA-Z0-9-_@.]+)*$")


class ReminderType(str, Enum):
    expiration_date = "expiration_date"
    data_usage = "data_usage"


class UserStatus(str, Enum):
    active = "active"
    disabled = "disabled"
    limited = "limited"
    expired = "expired"
    on_hold = "on_hold"


class UserStatusModify(str, Enum):
    active = "active"
    disabled = "disabled"
    on_hold = "on_hold"


class UserStatusCreate(str, Enum):
    active = "active"
    on_hold = "on_hold"


class UserDataLimitResetStrategy(str, Enum):
    no_reset = "no_reset"
    day = "day"
    week = "week"
    month = "month"
    year = "year"


class NextPlanModel(BaseModel):
    data_limit: Optional[int] = None
    expire: Optional[int] = None
    add_remaining_traffic: bool = False
    fire_on_either: bool = True
    model_config = ConfigDict(from_attributes=True)


class User(BaseModel):
    proxies: Dict[ProxyTypes, ProxySettings] = {}
    expire: Optional[int] = Field(None, nullable=True)
    data_limit: Optional[int] = Field(
        ge=0, default=None, description="data_limit can be 0 or greater"
    )
    data_limit_reset_strategy: UserDataLimitResetStrategy = (
        UserDataLimitResetStrategy.no_reset
    )
    # Global device limit — ALL cores combined (distinct IPs; cores without
    # a per-IP view count as one online presence each). None/0 = unlimited.
    device_limit: Optional[int] = Field(
        None, ge=0,
        description="max simultaneous devices across every core; 0/None = unlimited")
    # Aggregate across every core/connection for this user. Strict integers
    # reject NaN, booleans, strings and fractional values at the API boundary.
    download_limit_mbps: int = Field(
        0, strict=True, ge=0, le=100_000,
        description="aggregate download ceiling in Mbps; 0 = unlimited")
    upload_limit_mbps: int = Field(
        0, strict=True, ge=0, le=100_000,
        description="aggregate upload ceiling in Mbps; 0 = unlimited")
    inbounds: Dict[ProxyTypes, List[str]] = {}
    note: Optional[str] = Field(None, nullable=True)
    sub_updated_at: Optional[datetime] = Field(None, nullable=True)
    sub_last_user_agent: Optional[str] = Field(None, nullable=True)
    online_at: Optional[datetime] = Field(None, nullable=True)

    @field_serializer("online_at", mode="plain", check_fields=False)
    def serialize_online_at(self, dt: datetime | None) -> str | None:
        if dt is None:
            return None
        if isinstance(dt, datetime):
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        return str(dt)
    on_hold_expire_duration: Optional[int] = Field(None, nullable=True)
    on_hold_timeout: Optional[Union[datetime, None]] = Field(None, nullable=True)

    auto_delete_in_days: Optional[int] = Field(None, nullable=True)

    next_plan: Optional[NextPlanModel] = Field(None, nullable=True)

    # Multi-core access grants (Zagros): core_id → selected inbound tags.
    # One dashboard user may hold protocols from MANY cores (vless on xray,
    # hysteria2 on sing-box, wireguard, openvpn, ...). Absent (None) keeps the
    # current grants; an explicit mapping applies a diff per listed core.
    core_access: Optional[Dict[str, List[str]]] = Field(
        None, description="per-core inbound grants: {core_id: [tag, ...]}")

    @field_validator("core_access", mode="before")
    def validate_core_access(cls, v):
        if v is None:
            return v
        if not isinstance(v, dict):
            raise ValueError("core_access must be an object {core_id: [tags]}")
        out: dict[str, list[str]] = {}
        for core_id, tags in v.items():
            if not isinstance(core_id, str) or not core_id:
                raise ValueError("core_access keys must be core ids")
            if not isinstance(tags, (list, tuple)):
                raise ValueError(f"core_access['{core_id}'] must be a list of inbound tags")
            out[core_id] = [str(t) for t in tags]
        return out

    @field_validator('data_limit', mode='before')
    def cast_to_int(cls, v):
        if v is None:  # Allow None values
            return v
        if isinstance(v, float):  # Allow float to int conversion
            return int(v)
        if isinstance(v, int):  # Allow integers directly
            return v
        raise ValueError("data_limit must be an integer or a float, not a string")  # Reject strings

    @field_validator("proxies", mode="before")
    def validate_proxies(cls, v, values, **kwargs):
        """Normalize legacy Xray proxies without deciding user validity.

        A Zagros user may be intentionally non-Xray (WireGuard/OpenVPN/SSH/
        SoftEther/sing-box only). Creation validity therefore belongs to
        ``UserCreate`` where both proxies and ``core_access`` are visible;
        enforcing non-empty proxies here made template-only users fail 422
        before the API could provision their real core grants.
        """
        v = v or {}
        return {
            proxy_type: ProxySettings.from_dict(
                proxy_type, v.get(proxy_type, {}))
            for proxy_type in v
        }

    @field_validator("username", check_fields=False)
    @classmethod
    def validate_username(cls, v):
        if not USERNAME_REGEXP.match(v):
            raise ValueError(
                "Username only can be 3 to 32 characters and contain a-z, 0-9, and underscores in between."
            )
        return v

    @field_validator("note", check_fields=False)
    @classmethod
    def validate_note(cls, v):
        if v and len(v) > 500:
            raise ValueError("User's note can be a maximum of 500 character")
        return v

    @field_validator("on_hold_expire_duration", "on_hold_timeout", mode="before")
    def validate_timeout(cls, v, values):
        # Check if expire is 0 or None and timeout is not 0 or None
        if (v in (0, None)):
            return None
        return v


class UserCreate(User):
    username: str
    status: UserStatusCreate = None
    # Marzban parity fix (pydantic-v2 migration regression): in v1 the
    # inbounds validator ran with ``always=True``, so an omitted ``inbounds``
    # meant "include every inbound of the selected protocols". In v2
    # validators never run for defaulted (missing) fields — without
    # validate_default=True a fresh API-created user silently ended up with
    # EVERY inbound excluded (empty subscription!). UserModify is left
    # untouched on purpose: there the omission must mean "no change".
    inbounds: Dict[ProxyTypes, List[str]] = Field(default={}, validate_default=True)

    @model_validator(mode="after")
    def validate_has_real_access(self):
        """A new user needs Xray proxies OR at least one real core grant.

        ``UserModify`` must stay partial, so this creation-only invariant
        cannot live on the shared base model.
        """
        has_core_access = any(bool(tags) for tags in (self.core_access or {}).values())
        if not self.proxies and not has_core_access:
            raise ValueError(
                "Each user needs at least one Xray proxy or one core_access inbound"
            )
        return self

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "username": "user1234",
            "proxies": {
                "vmess": {"id": "35e4e39c-7d5c-4f4b-8b71-558e4f37ff53"},
                "vless": {},
            },
            "inbounds": {
                "vmess": ["VMess TCP", "VMess Websocket"],
                "vless": ["VLESS TCP REALITY", "VLESS GRPC REALITY"],
            },
            "next_plan": {
                "data_limit": 0,
                "expire": 0,
                "add_remaining_traffic": False,
                "fire_on_either": True
            },
            "expire": 0,
            "data_limit": 0,
            "data_limit_reset_strategy": "no_reset",
            "status": "active",
            "note": "",
            "on_hold_timeout": "2023-11-03T20:30:00",
            "on_hold_expire_duration": 0,
        }
    })

    @property
    def excluded_inbounds(self):
        excluded = {}
        for proxy_type in self.proxies:
            excluded[proxy_type] = []
            for inbound in xray.config.inbounds_by_protocol.get(proxy_type, []):
                if not inbound["tag"] in self.inbounds.get(proxy_type, []):
                    excluded[proxy_type].append(inbound["tag"])

        return excluded

    @field_validator("inbounds", mode="before")
    def validate_inbounds(cls, inbounds, values, **kwargs):
        proxies = values.data.get("proxies", [])

        # delete inbounds that are for protocols not activated
        for proxy_type in inbounds.copy():
            if proxy_type not in proxies:
                del inbounds[proxy_type]

        # check by proxies to ensure that every protocol has inbounds set
        for proxy_type in proxies:
            tags = inbounds.get(proxy_type)

            if tags:
                for tag in tags:
                    if tag not in xray.config.inbounds_by_tag:
                        raise ValueError(f"Inbound {tag} doesn't exist")

            # elif isinstance(tags, list) and not tags:
            #     raise ValueError(f"{proxy_type} inbounds cannot be empty")

            else:
                inbounds[proxy_type] = [
                    i["tag"]
                    for i in xray.config.inbounds_by_protocol.get(proxy_type, [])
                ]

        return inbounds

    @field_validator("status", mode="before")
    def validate_status(cls, status, values):
        on_hold_expire = values.data.get("on_hold_expire_duration")
        expire = values.data.get("expire")
        if status == UserStatusCreate.on_hold:
            if (on_hold_expire == 0 or on_hold_expire is None):
                raise ValueError("User cannot be on hold without a valid on_hold_expire_duration.")
            if expire:
                raise ValueError("User cannot be on hold with specified expire.")
        return status


class UserModify(User):
    status: UserStatusModify = None
    data_limit_reset_strategy: UserDataLimitResetStrategy = None
    # PATCH semantics: omitted keeps current; explicit 0 removes the limit.
    download_limit_mbps: Optional[int] = Field(
        None, strict=True, ge=0, le=100_000)
    upload_limit_mbps: Optional[int] = Field(
        None, strict=True, ge=0, le=100_000)
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "proxies": {
                "vmess": {"id": "35e4e39c-7d5c-4f4b-8b71-558e4f37ff53"},
                "vless": {},
            },
            "inbounds": {
                "vmess": ["VMess TCP", "VMess Websocket"],
                "vless": ["VLESS TCP REALITY", "VLESS GRPC REALITY"],
            },
            "next_plan": {
                "data_limit": 0,
                "expire": 0,
                "add_remaining_traffic": False,
                "fire_on_either": True
            },
            "expire": 0,
            "data_limit": 0,
            "data_limit_reset_strategy": "no_reset",
            "status": "active",
            "note": "",
            "on_hold_timeout": "2023-11-03T20:30:00",
            "on_hold_expire_duration": 0,
        }
    })

    @property
    def excluded_inbounds(self):
        excluded = {}
        for proxy_type in self.inbounds:
            excluded[proxy_type] = []
            for inbound in xray.config.inbounds_by_protocol.get(proxy_type, []):
                if not inbound["tag"] in self.inbounds.get(proxy_type, []):
                    excluded[proxy_type].append(inbound["tag"])

        return excluded

    @field_validator("inbounds", mode="before")
    def validate_inbounds(cls, inbounds, values, **kwargs):
        # check with inbounds, "proxies" is optional on modifying
        # so inbounds particularly can be modified
        if inbounds:
            for proxy_type, tags in inbounds.items():

                # if not tags:
                #     raise ValueError(f"{proxy_type} inbounds cannot be empty")

                for tag in tags:
                    if tag not in xray.config.inbounds_by_tag:
                        raise ValueError(f"Inbound {tag} doesn't exist")

        return inbounds

    @field_validator("proxies", mode="before")
    def validate_proxies(cls, v):
        return {
            proxy_type: ProxySettings.from_dict(
                proxy_type, v.get(proxy_type, {}))
            for proxy_type in v
        }

    @field_validator("status", mode="before")
    def validate_status(cls, status, values):
        on_hold_expire = values.data.get("on_hold_expire_duration")
        expire = values.data.get("expire")
        if status == UserStatusCreate.on_hold:
            if (on_hold_expire == 0 or on_hold_expire is None):
                raise ValueError("User cannot be on hold without a valid on_hold_expire_duration.")
            if expire:
                raise ValueError("User cannot be on hold with specified expire.")
        return status


class UserResponse(User):
    username: str
    status: UserStatus
    used_traffic: int
    lifetime_used_traffic: int = 0
    created_at: datetime
    links: List[str] = []
    subscription_url: str = ""
    proxies: dict
    excluded_inbounds: Dict[ProxyTypes, List[str]] = {}

    admin: Optional[Any] = None
    model_config = ConfigDict(from_attributes=True)

    @field_serializer("admin", mode="plain", check_fields=False)
    def serialize_admin(self, admin_obj: Any) -> dict | None:
        if admin_obj is None:
            return None
        if hasattr(admin_obj, "username"):
            return {
                "id": getattr(admin_obj, "id", None),
                "username": getattr(admin_obj, "username", None),
                "is_sudo": getattr(admin_obj, "is_sudo", False),
            }
        return admin_obj if isinstance(admin_obj, dict) else None

    @model_validator(mode="after")
    def validate_links(self):
        if not self.links:
            self.links = generate_v2ray_links(
                self.proxies, self.inbounds, extra_data=self.model_dump(), reverse=False,
            )
        return self

    @model_validator(mode="after")
    def validate_subscription_url(self):
        if not self.subscription_url:
            # The public link shape comes from the dashboard's Subscription
            # settings (public domain/scheme/port + path) with the environment
            # (SUBSCRIPTION_URL_PREFIX / PANEL_BASE_URL) as the fallback — the
            # same recipe the Users page uses for copy/QR, so a bot reading
            # this field (Mirza, scripts) hands out the same link the panel
            # shows. /zagros/sub/<token> remains a server-side legacy alias
            # only; no newly generated URL carries the old namespace.
            from app.platform.subscription_links import subscription_url

            self.subscription_url = subscription_url(create_subscription_token(self.username))
        return self

    @field_validator("proxies", mode="before")
    def validate_proxies(cls, v, values, **kwargs):
        if isinstance(v, list):
            v = {p.type: p.settings for p in v}
        return super().validate_proxies(v, values, **kwargs)

    @field_validator("used_traffic", "lifetime_used_traffic", mode='before')
    def cast_to_int(cls, v):
        if v is None:  # Allow None values
            return v
        if isinstance(v, float):  # Allow float to int conversion
            return int(v)
        if isinstance(v, int):  # Allow integers directly
            return v
        raise ValueError("must be an integer or a float, not a string")  # Reject strings


class SubscriptionUserResponse(UserResponse):
    admin: Any | None = Field(default=None, exclude=True)
    excluded_inbounds: Dict[ProxyTypes, List[str]] | None = Field(None, exclude=True)
    note: str | None = Field(None, exclude=True)
    inbounds: Dict[ProxyTypes, List[str]] | None = Field(None, exclude=True)
    auto_delete_in_days: int | None = Field(None, exclude=True)
    model_config = ConfigDict(from_attributes=True)


class UsersResponse(BaseModel):
    users: List[UserResponse]
    total: int


class UserUsageResponse(BaseModel):
    node_id: Union[int, None] = None
    node_name: str
    used_traffic: int

    @field_validator("used_traffic",  mode='before')
    def cast_to_int(cls, v):
        if v is None:  # Allow None values
            return v
        if isinstance(v, float):  # Allow float to int conversion
            return int(v)
        if isinstance(v, int):  # Allow integers directly
            return v
        raise ValueError("must be an integer or a float, not a string")  # Reject strings


class UserUsagesResponse(BaseModel):
    username: str
    usages: List[UserUsageResponse]


class UsersUsagesResponse(BaseModel):
    usages: List[UserUsageResponse]
