"""Secret-free public models for Application connections and usage."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class ConnectionStartBody(BaseModel):
    # Selector returned by the immediately preceding GET /configs call.
    config_id: str = Field(min_length=36, max_length=64)


class ConnectionView(BaseModel):
    connection_id: str
    config_id: str | None = None
    core_id: str
    protocol: str
    desired_status: str
    observed_status: str
    target: Literal["local", "node"]
    teardown_capability: Literal["targeted", "authorization_only"]
    not_after: datetime
    renewed_at: datetime | None = None
    last_observed_at: datetime | None = None
    error: str | None = None


class ConnectionStatusList(BaseModel):
    connections: list[ConnectionView] = Field(default_factory=list)


class UsageSummary(BaseModel):
    used_bytes: int
    uplink_bytes: int
    downlink_bytes: int
    data_limit_bytes: int | None = None
    remaining_bytes: int | None = None
    expire_at: datetime | None = None
    active_connections: int = 0
    as_of: datetime


class UsageHistoryBucket(BaseModel):
    start: datetime
    end: datetime
    uplink_bytes: int
    downlink_bytes: int
    total_bytes: int


class UsageHistoryPage(BaseModel):
    granularity: Literal["hour", "day"]
    from_time: datetime
    to_time: datetime
    items: list[UsageHistoryBucket] = Field(default_factory=list)
    next_cursor: str | None = None
