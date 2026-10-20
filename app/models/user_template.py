from typing import Dict, List, Optional

from pydantic import field_validator, ConfigDict, BaseModel, Field

from app import xray
from app.models.proxy import ProxyTypes


def _normalize_inbounds(value) -> Dict[str, List[str]]:
    """Normalize an xray selection to ``{protocol(value): [tags]}``.

    Accepts the wire dict (any-case protocol keys, ``[]`` = wildcard) and —
    for pre-0028 rows — the ``template_inbounds_association`` object list.
    """
    if isinstance(value, dict):
        final: Dict[str, List[str]] = {}
        for key, tags in value.items():
            try:
                proto = key.value if isinstance(key, ProxyTypes) else str(key)
            except Exception:  # noqa: BLE001 — never fail a read on a key
                continue
            final[proto.lower()] = [str(t) for t in (tags or [])]
        return final
    # legacy association rows: map tags through the LIVE xray registry
    inbound_tags = [i.tag for i in (value or [])]
    final = {}
    for protocol, inbounds in xray.config.inbounds_by_protocol.items():
        for inbound in inbounds:
            if inbound["tag"] in inbound_tags:
                name = str(protocol.value if isinstance(protocol, ProxyTypes)
                           else protocol).lower()
                final.setdefault(name, []).append(inbound["tag"])
    return final


class UserTemplate(BaseModel):
    name: Optional[str] = Field(None, nullable=True)
    data_limit: Optional[int] = Field(
        ge=0, default=None, description="data_limit can be 0 or greater"
    )
    expire_duration: Optional[int] = Field(
        ge=0, default=None, description="expire_duration can be 0 or greater in seconds"
    )
    username_prefix: Optional[str] = Field(max_length=20, min_length=1, default=None)
    username_suffix: Optional[str] = Field(max_length=20, min_length=1, default=None)

    inbounds: Dict[ProxyTypes, List[str]] = {}

    # Multi-core access grants (Zagros): core_id → inbound tags selected
    # from that core (e.g. {"sing-box": ["hy2-in"], "wireguard": ["wg0"]}).
    core_access: Optional[Dict[str, List[str]]] = Field(None, nullable=True)


class UserTemplateCreate(UserTemplate):
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "name": "my template 1",
            "username_prefix": None,
            "username_suffix": None,
            "inbounds": {"vmess": ["VMESS_INBOUND"], "vless": ["VLESS_INBOUND"]},
            "data_limit": 0,
            "expire_duration": 0,
        }
    })


class UserTemplateModify(UserTemplate):
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "name": "my template 1",
            "username_prefix": None,
            "username_suffix": None,
            "inbounds": {"vmess": ["VMESS_INBOUND"], "vless": ["VLESS_INBOUND"]},
            "data_limit": 0,
            "expire_duration": 0,
        }
    })


class UserTemplateResponse(UserTemplate):
    id: int
    # f-templink-1 (v1.1.3 bugfix 2): how many users were created from this
    # template — the Templates editor asks whether to sync them on save.
    users_count: int = 0

    @field_validator("inbounds", mode="before")
    @classmethod
    def validate_inbounds(cls, v):
        return _normalize_inbounds(v)

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def of(cls, dbtemplate, users_count: int | None = None) -> "UserTemplateResponse":
        """Build the response from an ORM row, preferring the verbatim JSON.

        f-tplsel-1: ``inbounds`` used to be re-derived from the association
        × live xray registry, which zeroed every template on panels whose
        xray core was down. The ``inbounds_json`` column (0028) is the
        source of truth; rows stored before 0028 keep the association
        fallback until they are saved again. ``users_count`` (bugfix 2) is
        filled by the caller from its session (one grouped query for the
        list endpoint); 0 when the caller cannot count.
        """
        stored = getattr(dbtemplate, "inbounds_json", None)
        inbounds: Dict[str, List[str]] = (
            _normalize_inbounds(stored) if stored is not None
            else _normalize_inbounds(dbtemplate.inbounds))
        if users_count is None:
            try:
                from app.db.models import User as LegacyUser
                from app.db import GetDB
                from sqlalchemy import func

                with GetDB() as db:
                    users_count = int(db.query(func.count(LegacyUser.id))
                                      .filter(LegacyUser.template_id == dbtemplate.id)
                                      .scalar() or 0)
            except Exception:  # noqa: BLE001 — the count is informational
                users_count = 0
        return cls(
            id=dbtemplate.id,
            name=dbtemplate.name,
            data_limit=dbtemplate.data_limit,
            expire_duration=dbtemplate.expire_duration,
            username_prefix=dbtemplate.username_prefix,
            username_suffix=dbtemplate.username_suffix,
            inbounds=inbounds,
            core_access=dbtemplate.core_access,
            users_count=int(users_count or 0),
        )
