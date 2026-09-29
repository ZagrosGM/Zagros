"""Pydantic contracts for the build-system HTTP APIs.

Admin responses never carry secrets (no tokens, no hashes, no material).
The single exception is the worker job document (``JobFetchResult``),
which exists precisely to deliver decrypted build credentials to an
authenticated worker over TLS — and the one-time token echoes, which are
returned exactly once at issuance.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class BuildTargetBody(BaseModel):
    platform: str
    arch: str
    artifact: str = "apk"


class BuildCreateBody(BaseModel):
    # None resolves to the calling (sudo) admin; explicit ids stay supported
    # so service/CLI callers keep working unchanged.
    owner_admin_id: int | None = Field(default=None, gt=0)
    version: str
    source_repo: str
    source_revision: str
    sdk_source_repo: str
    sdk_source_revision: str
    build_config: dict[str, Any] = Field(default_factory=dict)
    targets: list[BuildTargetBody]
    credential_ids: list[str] = Field(default_factory=list)


class ApplicationRef(BaseModel):
    public_id: str
    name: str


class JobPublic(BaseModel):
    platform: str
    arch: str
    artifact: str = "apk"
    queue: str
    queue_job_id: str | None = None
    status: str
    worker_id: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    failure_code: str | None = None
    failure_message: str | None = None
    log_ref: str | None = None


class ArtifactPublic(BaseModel):
    platform: str
    arch: str
    artifact: str = "apk"
    filename: str
    rel_path: str
    sha256: str
    size_bytes: int
    signature_ref: str | None = None
    sbom_ref: str | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None


class BuildPublic(BaseModel):
    public_id: str
    application: ApplicationRef | None = None
    version: str
    build_number: int
    source_repo: str
    source_revision: str
    # None only on legacy (pre-Phase-14) rows, which predate SDK pinning.
    sdk_source_repo: str | None = None
    sdk_source_revision: str | None = None
    build_config: dict[str, Any] = Field(default_factory=dict)
    config_digest: str
    requested_platforms: list[dict[str, str]] = Field(default_factory=list)
    credential_ids: list[str] = Field(default_factory=list)
    status: str
    progress: int
    failure_code: str | None = None
    failure_message: str | None = None
    created_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    targets: list[JobPublic] = Field(default_factory=list)
    artifacts: list[ArtifactPublic] = Field(default_factory=list)


class BuildListResult(BaseModel):
    items: list[BuildPublic]
    total: int


class QueueCancelEntry(BaseModel):
    queue: str
    job_id: str
    removed_from_queue: bool


class CancelResult(BaseModel):
    build: BuildPublic
    queue_cancel: list[QueueCancelEntry] = Field(default_factory=list)


class LogEntry(BaseModel):
    id: str
    text: str


class LogReadResult(BaseModel):
    terminal: bool
    truncated: bool = False
    entries: list[LogEntry] = Field(default_factory=list)
    next_cursor: str


class WorkerCreateBody(BaseModel):
    worker_id: str
    display_name: str
    platform_labels: list[str]


class WorkerPublic(BaseModel):
    worker_id: str
    display_name: str
    platform_labels: list[str]
    status: str
    last_seen_at: datetime | None = None
    created_at: datetime | None = None


class RegisterTokenBody(BaseModel):
    ttl_seconds: int = 3600


class RegisterTokenResult(BaseModel):
    register_token: str
    expires_at: datetime


class WorkerRegisterBody(BaseModel):
    worker_id: str
    register_token: str


class WorkerEnrolledResult(WorkerPublic):
    api_token: str


class HeartbeatResult(WorkerPublic):
    queue_depths: dict[str, int | None] = Field(default_factory=dict)


class CredentialCreateBody(BaseModel):
    scope: str
    owner_ref: str
    kind: str
    label: str
    material: dict[str, Any]


class CredentialPublic(BaseModel):
    public_id: str
    scope: str
    owner_ref: str
    kind: str
    label: str
    envelope_digest: str
    created_at: datetime | None = None
    rotated_at: datetime | None = None
    revoked: bool = False
    revoked_at: datetime | None = None


class CredentialRotateBody(BaseModel):
    material: dict[str, Any]


class ClaimBody(BaseModel):
    worker_id: str
    worker_token: str


class StatusReportBody(BaseModel):
    status: Literal["success", "failed"]
    failure_code: str | None = None
    failure_message: str | None = None
    final_log: str | None = None


class JobSource(BaseModel):
    repo: str
    revision: str


class AttachedCredential(BaseModel):
    public_id: str
    kind: str
    label: str
    material: dict[str, Any]


class JobIconRef(BaseModel):
    """Launcher-pack advertisement (worker downloads + verifies by sha256).

    Absent/``present=False`` on legacy rows and pack-less applications;
    the worker then builds with the stock icons.
    """
    present: bool = False
    sha256: str | None = None
    size_bytes: int | None = None
    width: int | None = None
    height: int | None = None


class ExternalHostProbeBody(BaseModel):
    """Wizard 'test external build host' request. Never stored."""
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(default="", max_length=256)
    private_key: str = Field(default="", max_length=8192)


class ExternalHostProbeResult(BaseModel):
    reachable: bool = False
    host_key_pin: str | None = None
    os_pretty: str | None = None
    cores: int | None = None
    mem_avail_mb: int | None = None
    mem_total_mb: int | None = None
    swap_total_mb: int | None = None
    disk_free_mb: int | None = None
    is_root: bool = False
    toolchain: dict[str, bool] = Field(default_factory=dict)
    message: str | None = None


class ResolvedSourceResult(BaseModel):
    source: JobSource
    sdk_source: JobSource


class JobFetchResult(BaseModel):
    v: int
    build_public_id: str
    application: ApplicationRef | None = None
    version: str
    build_number: int
    platform: str
    arch: str
    artifact: str = "apk"
    source: JobSource
    # None only on legacy (pre-Phase-14) rows; the v2 worker refuses a
    # job document without a pinned SDK source.
    sdk_source: JobSource | None = None
    build_config: dict[str, Any] = Field(default_factory=dict)
    config_digest: str
    icon: JobIconRef = Field(default_factory=JobIconRef)
    credentials: list[AttachedCredential] = Field(default_factory=list)
    log_stream: str
