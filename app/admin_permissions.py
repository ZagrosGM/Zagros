"""Admin permission matrix (f-panel-5).

A permission document lives on ``admins.permissions`` (JSON/TEXT, nullable):

    {"v": 1,
     "sections": {"users": "edit", "templates": "hidden", ...},
     "inbounds": ["VLESS TCP REALITY", ...] | null}

Semantics:
  * NULL document            -> the historical default: EVERY section at
                                "edit" for non-sudo admins (sudo-only admin
                                management is NOT part of the matrix and
                                stays gated by ``check_sudo_admin``).
  * is_sudo=True             -> the matrix is bypassed entirely.
  * section level            -> "hidden" < "view" < "edit".
  * a section MISSING from a stored document -> "edit" (backward compatible).
  * inbounds list            -> the only inbound tags the admin may grant
                                (null = unrestricted). Enforced on the
                                inbound catalog and on user create/modify.

This module is framework-light: the only FastAPI surface is
``fastapi_dep(section, level)`` so routers can declare
``Depends(fastapi_dep("users", "edit"))``.
"""
from __future__ import annotations

SECTIONS = (
    "overview", "users", "templates", "subscriptions", "applications",
    "nodes", "cores", "routing", "outbounds", "inbounds", "hosts", "dns",
    "certificates", "monitoring", "statistics", "support", "settings",
    "advanced",
)

_LEVELS = {"hidden": 0, "view": 1, "edit": 2}

# /api/zagros path prefix -> section. Longest prefix wins; GET/HEAD need the
# section at "view", every other method at "edit".
_PATH_SECTIONS = (
    ("/settings/portal", "subscriptions"),
    ("/subscription", "templates"),
    ("/applications", "applications"),
    ("/build-credentials", "applications"),
    ("/builder", "applications"),
    ("/builds", "applications"),
    ("/inbounds", "inbounds"),
    ("/studio", "inbounds"),
    ("/monitoring", "monitoring"),
    ("/client-sessions", "monitoring"),
    ("/sessions", "monitoring"),
    ("/devices", "monitoring"),
    ("/certificates", "certificates"),
    ("/statistics", "statistics"),
    ("/dashboard", "overview"),
    ("/panel", "overview"),
    ("/outbounds", "outbounds"),
    ("/routing", "routing"),
    ("/settings", "settings"),
    ("/backup", "settings"),
    ("/restore", "settings"),
    ("/security", "settings"),
    ("/support", "support"),
    ("/migrate", "advanced"),
    ("/bandwidth", "advanced"),
    ("/utils", "users"),
    ("/users", "users"),
    ("/cores", "cores"),
    ("/nodes", "nodes"),
    ("/hosts", "hosts"),
)


def default_permissions() -> dict:
    """The NULL-document default: every section editable, no inbound limit."""
    return {"v": 1, "sections": {s: "edit" for s in SECTIONS},
            "inbounds": None}


def normalize(raw) -> dict:
    """Validate/repair a stored document; never raise (bad shape = default)."""
    if not isinstance(raw, dict):
        return default_permissions()
    sections_in = raw.get("sections")
    sections: dict[str, str] = {}
    if isinstance(sections_in, dict):
        for key, value in sections_in.items():
            if key in SECTIONS and value in _LEVELS:
                sections[key] = value
    inbounds = raw.get("inbounds")
    if isinstance(inbounds, list):
        inbounds = [str(t) for t in inbounds if str(t).strip()]
    else:
        inbounds = None
    return {"v": 1, "sections": sections, "inbounds": inbounds}


def allowed_inbounds(raw) -> list[str] | None:
    """Inbound tags this admin may grant; None = unrestricted."""
    return normalize(raw).get("inbounds")


def allows(raw, section: str, need: str) -> bool:
    """True when the document permits ``need`` on ``section``."""
    if need not in _LEVELS:
        return False
    doc = normalize(raw)
    level = doc["sections"].get(section, "edit")  # missing = historical full
    return _LEVELS[level] >= _LEVELS[need]


def classify_request(path: str, method: str) -> tuple[str | None, str | None]:
    """Map an /api/zagros request to (section, required level)."""
    prefix = "/api/zagros"
    rel = path[len(prefix):] if path.startswith(prefix) else path
    rel = "/" + rel.lstrip("/")
    best: tuple[str, int] | None = None
    for stem, section in _PATH_SECTIONS:
        if rel == stem or rel.startswith(stem + "/") or rel.startswith(stem + "?"):
            if best is None or len(stem) > best[1]:
                best = (section, len(stem))
    if best is None:
        return None, None
    return best[0], ("view" if method.upper() in ("GET", "HEAD", "OPTIONS")
                     else "edit")


def fastapi_dep(section: str, level: str):
    """Dependency factory: current admin must hold ``level`` on ``section``."""
    from fastapi import Depends, HTTPException

    import app.db  # noqa: F401  — must precede the model import (cycle)
    from app.models.admin import Admin

    def _dep(admin: Admin = Depends(Admin.get_current)):
        if admin.is_sudo:
            return admin
        if not allows(admin.permissions, section, level):
            raise HTTPException(status_code=403, detail="You're not allowed")
        return admin

    return _dep
