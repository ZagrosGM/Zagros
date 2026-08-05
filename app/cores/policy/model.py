"""Global policy model — constraints that apply to a user across ALL cores.

One profile, one source of truth: volume and expiry are global (a byte used on
OpenVPN depletes the same quota the xray driver sees), device slots are global,
and geo/hours/IP limits are defined once and enforced everywhere possible.
"""
from __future__ import annotations

import re
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, field_validator

_HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


class Violation(str, Enum):
    EXPIRED = "EXPIRED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    DEVICE_LIMIT_REACHED = "DEVICE_LIMIT_REACHED"
    IP_LIMIT_REACHED = "IP_LIMIT_REACHED"
    OUTSIDE_ALLOWED_HOURS = "OUTSIDE_ALLOWED_HOURS"
    COUNTRY_NOT_ALLOWED = "COUNTRY_NOT_ALLOWED"
    COUNTRY_BLOCKED = "COUNTRY_BLOCKED"
    ASN_NOT_ALLOWED = "ASN_NOT_ALLOWED"
    ASN_BLOCKED = "ASN_BLOCKED"


class HourWindow(BaseModel):
    """Allowed usage window; ``days`` uses weekday numbers (Mon=0, Sun=6).
    Overnight windows (start > end) wrap past midnight."""

    days: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4, 5, 6])
    start: str = "00:00"
    end: str = "23:59"

    @field_validator("days")
    @classmethod
    def _valid_days(cls, v: list[int]) -> list[int]:
        if not v or any(d < 0 or d > 6 for d in v):
            raise ValueError("days must be weekday numbers in [0..6].")
        return sorted(set(v))

    @field_validator("start", "end")
    @classmethod
    def _valid_hhmm(cls, v: str) -> str:
        if not _HHMM.match(v):
            raise ValueError(f"bad HH:MM value: {v!r}")
        return v

    def contains(self, moment: datetime) -> bool:
        start = int(self.start[:2]) * 60 + int(self.start[3:])
        end = int(self.end[:2]) * 60 + int(self.end[3:])
        minute = moment.hour * 60 + moment.minute
        day = moment.weekday()
        if start <= end:                                   # same-day window
            return day in self.days and start <= minute <= end
        # overnight window, e.g. 22:00 -> 06:00
        prev_day = (day - 1) % 7
        if minute >= start:
            return day in self.days
        return prev_day in self.days and minute <= end


class PolicyProfile(BaseModel):
    """One global constraint set per user (applies simultaneously on all cores)."""

    # quota & time (panel-enforced, always global)
    data_limit_bytes: int | None = None        # None = unlimited
    expire_at: datetime | None = None
    device_limit: int | None = None            # None = unlimited
    # network constraints
    speed_limit_kbps: int | None = None        # native where the core allows
    max_ips: int | None = None
    max_session_seconds: int | None = None
    # schedule & geo
    allowed_hours: list[HourWindow] = Field(default_factory=list)   # empty = always
    allowed_countries: list[str] | None = None                      # None = all allowed
    blocked_countries: list[str] = Field(default_factory=list)
    allowed_asns: list[int] | None = None
    blocked_asns: list[int] = Field(default_factory=list)

    def active_constraints(self) -> list[str]:
        fields = [
            "data_limit_bytes", "expire_at", "device_limit", "speed_limit_kbps",
            "max_ips", "max_session_seconds",
        ]
        active = [f for f in fields if getattr(self, f) is not None]
        if self.allowed_hours:
            active.append("allowed_hours")
        if self.allowed_countries is not None or self.blocked_countries:
            active.append("country_lock")
        if self.allowed_asns is not None or self.blocked_asns:
            active.append("asn_lock")
        return active


class AdmissionContext(BaseModel):
    """Everything the engine needs to decide one connection admission."""

    now: datetime
    device_uid: str
    used_bytes: int = 0
    active_device_uids: list[str] = Field(default_factory=list)
    active_ips: list[str] = Field(default_factory=list)
    client_ip: str | None = None
    country: str | None = None
    asn: int | None = None


class PolicyDecision(BaseModel):
    allowed: bool
    violations: list[Violation] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
