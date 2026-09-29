"""SQL repository for builds, workers and build credentials.

Synchronous by design (routers run it via ``asyncio.to_thread``). Returns
plain JSON-safe dicts — datetimes included; pydantic serializes them at
the HTTP boundary. Worker/job tokens only ever persist as SHA-256 hashes;
credential material only ever persists inside a SecretsCipher envelope.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.builder.errors import (
    BuildConflict,
    BuildError,
    BuildForbidden,
    BuildNotFound,
    BuildValidationFailed,
    CredentialNotFound,
    CredentialRevoked,
    WorkerAuthFailed,
    WorkerConflict,
    WorkerNotFound,
)
from app.builder.validators import QUEUE_FOR_PLATFORM, redact_text
from app.persistence.cipher import SecretsCipher
from app.persistence.models import (
    AppBuildArtifactModel,
    AppBuildModel,
    ApplicationModel,
    BuildCredentialModel,
    BuildPlatformJobModel,
    BuildWorkerModel,
)

TERMINAL_JOB = frozenset({"success", "failed", "cancelled"})
TERMINAL_BUILD = frozenset({"success", "failed", "cancelled"})

WORKER_LABELS = frozenset({"linux", "windows", "macos"})
WORKER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-_]{1,127}$")

CREDENTIAL_SCOPES = frozenset({"worker", "application", "global"})
CREDENTIAL_KINDS = frozenset(
    {"ssh_password", "ssh_key", "signing_key", "api_token"})


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _safe_compare(presented: str, stored_hex: str | None) -> bool:
    if not stored_hex:
        return False
    try:
        expected = bytes.fromhex(stored_hex)
    except ValueError:
        return False
    return hmac.compare_digest(
        hashlib.sha256(presented.encode("utf-8")).digest(), expected)


def _build_dict(build: AppBuildModel, jobs: list[BuildPlatformJobModel],
                artifacts: list[AppBuildArtifactModel],
                application: ApplicationModel | None) -> dict[str, Any]:
    return {
        "public_id": build.public_id,
        "application": ({
            "public_id": application.public_id,
            "name": application.name,
        } if application is not None else None),
        "version": build.version,
        "build_number": build.build_number,
        "source_repo": build.source_repo,
        "source_revision": build.source_revision,
        "sdk_source_repo": build.sdk_source_repo,
        "sdk_source_revision": build.sdk_source_revision,
        "build_config": build.build_config,
        "config_digest": build.config_digest,
        "requested_platforms": build.requested_platforms,
        "credential_ids": build.credential_ids,
        "status": build.status,
        "progress": build.progress,
        "failure_code": build.failure_code,
        "failure_message": build.failure_message,
        "created_at": build.created_at,
        "started_at": build.started_at,
        "finished_at": build.finished_at,
        "targets": [_job_dict(job) for job in jobs],
        "artifacts": [_artifact_dict(row) for row in artifacts],
    }


def _job_dict(job: BuildPlatformJobModel) -> dict[str, Any]:
    return {
        "platform": job.platform,
        "arch": job.arch,
        "artifact": job.artifact,
        "queue": job.queue_name,
        "queue_job_id": job.queue_job_id,
        "status": job.status,
        "worker_id": job.worker_id,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "failure_code": job.failure_code,
        "failure_message": job.failure_message,
        "log_ref": job.log_ref,
    }


def _artifact_dict(row: AppBuildArtifactModel) -> dict[str, Any]:
    return {
        "platform": row.platform,
        "arch": row.arch,
        "artifact": row.artifact,
        "filename": row.filename,
        "rel_path": row.rel_path,
        "sha256": row.sha256,
        "size_bytes": row.size_bytes,
        "signature_ref": row.signature_ref,
        "sbom_ref": row.sbom_ref,
        "provenance": row.provenance,
        "created_at": row.created_at,
    }


def _worker_dict(row: BuildWorkerModel) -> dict[str, Any]:
    return {
        "worker_id": row.worker_id,
        "display_name": row.display_name,
        "platform_labels": row.platform_labels,
        "status": row.status,
        "last_seen_at": row.last_seen_at,
        "created_at": row.created_at,
    }


def _credential_dict(row: BuildCredentialModel) -> dict[str, Any]:
    return {
        "public_id": row.public_id,
        "scope": row.scope,
        "owner_ref": row.owner_ref,
        "kind": row.kind,
        "label": row.label,
        "envelope_digest": row.envelope_digest,
        "created_at": row.created_at,
        "rotated_at": row.rotated_at,
        "revoked": row.revoked,
        "revoked_at": row.revoked_at,
    }


class BuildRepository:
    def __init__(self, session_factory,
                 cipher: SecretsCipher) -> None:
        self._sf = session_factory
        self._cipher = cipher

    # ---------------------------------------------------------- #
    # applications (read-only seam into the Application domain)
    # ---------------------------------------------------------- #
    def get_application(self, public_id: str) -> dict[str, Any]:
        with self._sf() as session:
            row = session.scalars(select(ApplicationModel).where(
                ApplicationModel.public_id == public_id)).one_or_none()
            if row is None:
                raise BuildNotFound(
                    f"application '{public_id}' does not exist")
            return {
                "id": row.id,
                "public_id": row.public_id,
                "owner_admin_id": row.owner_admin_id,
                "name": row.name,
                "status": row.status,
            }

    # ---------------------------------------------------------- #
    # builds
    # ---------------------------------------------------------- #
    def create_build(self, *, owner_admin_id: int, application_id: int,
                     version: str, source_repo: str, source_revision: str,
                     sdk_source_repo: str, sdk_source_revision: str,
                     build_config: dict, config_digest: str,
                     targets: list[dict[str, str]],
                     credential_ids: list[str] | None = None,
                     ) -> dict[str, Any]:
        with self._sf() as session:
            peak = session.scalar(select(func.max(AppBuildModel.build_number)).where(
                AppBuildModel.application_id == application_id)) or 0
            build = AppBuildModel(
                public_id=str(uuid4()), application_id=application_id,
                owner_admin_id=owner_admin_id, version=version,
                build_number=peak + 1, source_repo=source_repo,
                source_revision=source_revision,
                sdk_source_repo=sdk_source_repo,
                sdk_source_revision=sdk_source_revision,
                build_config=build_config,
                config_digest=config_digest,
                requested_platforms=[
                    {"platform": t["platform"], "arch": t["arch"],
                     "artifact": t["artifact"]}
                    for t in targets],
                credential_ids=list(credential_ids or []),
                status="queued", progress=0)
            session.add(build)
            session.flush()
            for target in targets:
                session.add(BuildPlatformJobModel(
                    build_id=build.id, platform=target["platform"],
                    arch=target["arch"], artifact=target["artifact"],
                    queue_name=QUEUE_FOR_PLATFORM[target["platform"]],
                    status="queued", job_token_valid=False))
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise BuildConflict(
                    "build number collided — retry the request") from exc
            jobs = _jobs_of(session, build.id)
            artifacts: list[AppBuildArtifactModel] = []
            application = session.get(ApplicationModel, application_id)
            return _build_dict(build, jobs, artifacts, application)

    def get_build(self, public_id: str) -> dict[str, Any]:
        with self._sf() as session:
            build = _build_by_public_id(session, public_id)
            jobs = _jobs_of(session, build.id)
            artifacts = _artifacts_of(session, build.id)
            application = session.get(ApplicationModel, build.application_id)
            return _build_dict(build, jobs, artifacts, application)

    def list_builds(self, *, limit: int = 50, offset: int = 0,
                    status: str | None = None,
                    application_public_id: str | None = None,
                    owner_admin_id: int | None = None,
                    ) -> tuple[list[dict[str, Any]], int]:
        limit = min(max(int(limit), 1), 200)
        offset = max(int(offset), 0)
        with self._sf() as session:
            query = select(AppBuildModel)
            if status is not None:
                query = query.where(AppBuildModel.status == status)
            if application_public_id is not None:
                app_id = session.scalar(select(ApplicationModel.id).where(
                    ApplicationModel.public_id == application_public_id))
                if app_id is None:
                    return [], 0
                query = query.where(AppBuildModel.application_id == app_id)
            if owner_admin_id is not None:
                query = query.where(
                    AppBuildModel.owner_admin_id == owner_admin_id)
            total = session.scalar(select(func.count()).select_from(
                query.subquery())) or 0
            rows = list(session.scalars(query.order_by(
                AppBuildModel.id.desc()).limit(limit).offset(offset)))
            items = []
            for build in rows:
                jobs = _jobs_of(session, build.id)
                application = session.get(
                    ApplicationModel, build.application_id)
                items.append(_build_dict(build, jobs, [], application))
            return items, total

    def attach_queue_job(self, *, build_public_id: str, platform: str,
                         arch: str, artifact: str = "apk",
                         queue_job_id: str) -> None:
        with self._sf() as session:
            _, job = _job_by_ref(session, build_public_id, platform, arch,
                                 artifact)
            job.queue_job_id = queue_job_id
            session.commit()

    def issue_job_token(self, *, build_public_id: str, platform: str,
                        arch: str, artifact: str = "apk") -> str:
        token = secrets.token_urlsafe(32)
        with self._sf() as session:
            _, job = _job_by_ref(session, build_public_id, platform, arch,
                                 artifact)
            if job.status in TERMINAL_JOB:
                raise BuildConflict("job is already terminal")
            job.job_token_hash = _token_hash(token)
            job.job_token_valid = True
            session.commit()
        return token

    def verify_job_token(self, *, build_public_id: str, platform: str,
                         arch: str, artifact: str = "apk",
                         token: str) -> dict[str, Any]:
        """Return the verified (build, job) pair or raise 401/404."""
        with self._sf() as session:
            build, job = _job_by_ref(session, build_public_id, platform,
                                     arch, artifact)
            if (not job.job_token_valid
                    or not _safe_compare(token, job.job_token_hash)):
                raise WorkerAuthFailed("invalid or expired job token")
            application = session.get(ApplicationModel, build.application_id)
            return {
                "build": _build_dict(
                    build, _jobs_of(session, build.id),
                    _artifacts_of(session, build.id), application),
                "job": _job_dict(job),
                "job_id": job.id,
                "build_id": build.id,
            }

    def job_icon_ref(self, build_public_id: str) -> dict | None:
        """Launcher-pack reference for a build, or None when pack-less.

        Present requires the rendered pack marker in the application's
        branding icon document; the worker still verifies the downloaded
        bytes against ``sha256``/``size_bytes``.
        """
        with self._sf() as session:
            build = session.execute(select(AppBuildModel).where(
                AppBuildModel.public_id == build_public_id,
            )).scalar_one_or_none()
            if build is None:
                return None
            app = session.get(ApplicationModel, build.application_id)
            if app is None:
                return None
            meta = (app.branding or {}).get("icon") or {}
            if not meta.get("android_pack_sha256"):
                return None
            return {
                "public_id": app.public_id,
                "sha256": meta["android_pack_sha256"],
                "size_bytes": meta.get("android_pack_bytes"),
                "width": meta.get("width"),
                "height": meta.get("height"),
            }

    def claim_job(self, *, build_public_id: str, platform: str, arch: str,
                  artifact: str = "apk", token: str, worker_id: str,
                  ) -> dict[str, Any]:
        with self._sf() as session:
            build, job = _job_by_ref(session, build_public_id, platform,
                                     arch, artifact)
            if (not job.job_token_valid
                    or not _safe_compare(token, job.job_token_hash)):
                raise WorkerAuthFailed("invalid or expired job token")
            if job.status in TERMINAL_JOB:
                raise WorkerAuthFailed("job is already terminal")
            if job.status == "running" and job.worker_id != worker_id:
                raise BuildConflict(
                    f"job already claimed by worker '{job.worker_id}'")
            now = _utcnow()
            job.status = "running"
            job.worker_id = worker_id
            if job.started_at is None:
                job.started_at = now
            if build.status == "queued":
                build.status = "running"
                build.started_at = now
            _recompute_progress(session, build)
            session.commit()
            return _job_dict(job)

    def report_job(self, *, build_public_id: str, platform: str, arch: str,
                   artifact: str = "apk", token: str, success: bool,
                   failure_code: str | None = None,
                   failure_message: str | None = None,
                   log_ref: str | None = None) -> dict[str, Any]:
        message = (redact_text(failure_message, max_bytes=2000)
                   if failure_message else None)
        if message is not None and len(message) > 500:
            message = message[:497] + "…"
        code = (failure_code or "").strip()[:64] or None
        allowed_codes = {
            None, "clone_failed", "checkout_failed", "config_invalid",
            "toolchain_missing", "build_failed", "artifact_invalid",
            "artifact_upload_failed", "no_artifacts", "worker_error",
            "cancelled", "timeout", "panel_error", "credential_revoked",
            # f-panel-1 resource guard + auto-provision codes
            "resources_insufficient", "provision_failed",
            "provision_unsupported",
        }
        if code not in allowed_codes:
            code = "worker_error"
        with self._sf() as session:
            build, job = _job_by_ref(session, build_public_id, platform,
                                     arch, artifact)
            if (not job.job_token_valid
                    or not _safe_compare(token, job.job_token_hash)):
                raise WorkerAuthFailed("invalid or expired job token")
            if job.status in TERMINAL_JOB:
                raise BuildConflict("job is already terminal")
            if job.status not in ("queued", "running"):
                raise BuildConflict(f"cannot report from state '{job.status}'")
            now = _utcnow()
            if success:
                produced = session.scalar(select(func.count()).select_from(
                    AppBuildArtifactModel).where(
                        AppBuildArtifactModel.build_id == build.id,
                        AppBuildArtifactModel.platform == platform,
                        AppBuildArtifactModel.arch == arch,
                        AppBuildArtifactModel.artifact == artifact)) or 0
                if produced == 0:
                    success, code = False, "no_artifacts"
                    message = ("worker reported success without uploading "
                               "any artifact")
            job.status = "success" if success else "failed"
            job.failure_code = None if success else (code or "worker_error")
            job.failure_message = None if success else message
            job.finished_at = now
            job.job_token_valid = False
            job.job_token_hash = None
            if log_ref is not None:
                job.log_ref = log_ref
            _aggregate_build(session, build)
            session.commit()
            jobs = _jobs_of(session, build.id)
            application = session.get(ApplicationModel, build.application_id)
            return _build_dict(
                build, jobs, _artifacts_of(session, build.id), application)

    def cancel_build(self, public_id: str
                     ) -> tuple[dict[str, Any], list[tuple[str, str]]]:
        """Mark terminal + invalidate tokens; returns live RQ jobs to drop."""
        with self._sf() as session:
            build = _build_by_public_id(session, public_id)
            if build.status in TERMINAL_BUILD:
                raise BuildConflict(
                    f"build is already {build.status}")
            now = _utcnow()
            live: list[tuple[str, str]] = []
            for job in _jobs_of(session, build.id):
                if job.status in TERMINAL_JOB:
                    continue
                job.status = "cancelled"
                job.failure_code = "cancelled"
                job.finished_at = now
                job.job_token_valid = False
                job.job_token_hash = None
                if job.queue_job_id:
                    live.append((job.queue_name, job.queue_job_id))
            build.status = "cancelled"
            build.finished_at = now
            _recompute_progress(session, build)
            session.commit()
            jobs = _jobs_of(session, build.id)
            application = session.get(ApplicationModel, build.application_id)
            return (_build_dict(
                build, jobs, _artifacts_of(session, build.id), application),
                live)

    def fail_build(self, public_id: str, *, code: str,
                   message: str) -> dict[str, Any]:
        """Panel-side failure (dispatch failed, operator abort pre-claim).

        Marks the build and every non-terminal job failed and invalidates
        all job tokens. Only reachable while no job has produced terminal
        output semantics the worker owns — terminal jobs keep their state.
        """
        with self._sf() as session:
            build = _build_by_public_id(session, public_id)
            if build.status in TERMINAL_BUILD:
                raise BuildConflict(
                    f"build is already {build.status}")
            now = _utcnow()
            for job in _jobs_of(session, build.id):
                if job.status in TERMINAL_JOB:
                    continue
                job.status = "failed"
                job.failure_code = (code or "panel_error")[:64]
                job.failure_message = redact_text(
                    message, max_bytes=2000)[:500]
                job.finished_at = now
                job.job_token_valid = False
                job.job_token_hash = None
            _aggregate_build(session, build)
            # _aggregate_build derives failure from the jobs; keep the
            # panel-supplied reason (identical content, explicit source).
            build.failure_code = (code or "panel_error")[:64]
            build.failure_message = redact_text(message, max_bytes=2000)[:500]
            session.commit()
            jobs = _jobs_of(session, build.id)
            application = session.get(ApplicationModel, build.application_id)
            return _build_dict(
                build, jobs, _artifacts_of(session, build.id), application)

    def record_artifact(self, *, job_id: int, filename: str, rel_path: str,
                        sha256: str, size_bytes: int,
                        signature_ref: str | None = None,
                        sbom_ref: str | None = None,
                        provenance: dict | None = None) -> dict[str, Any]:
        with self._sf() as session:
            job = session.get(BuildPlatformJobModel, job_id)
            if job is None:
                raise BuildNotFound("platform job does not exist")
            if job.status != "running":
                raise BuildConflict(
                    f"artifacts are only accepted while running "
                    f"(job is {job.status})")
            row = AppBuildArtifactModel(
                build_id=job.build_id, platform=job.platform, arch=job.arch,
                artifact=job.artifact,
                filename=filename, rel_path=rel_path, sha256=sha256,
                size_bytes=size_bytes, signature_ref=signature_ref,
                sbom_ref=sbom_ref, provenance=provenance or {})
            session.add(row)
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise BuildConflict(
                    f"artifact '{filename}' already recorded for "
                    f"{job.platform}/{job.arch}") from exc
            return _artifact_dict(row)

    # ---------------------------------------------------------- #
    # workers
    # ---------------------------------------------------------- #
    def create_worker(self, *, worker_id: str, display_name: str,
                      platform_labels: list[str]) -> dict[str, Any]:
        cleaned_id = (worker_id or "").strip().lower()
        if not WORKER_ID_RE.match(cleaned_id):
            raise BuildValidationFailed(
                "worker_id must be 2-128 chars of [a-z0-9-_], "
                "starting alphanumerically")
        labels = sorted({str(label).strip().lower()
                         for label in platform_labels})
        if not labels or not set(labels) <= WORKER_LABELS:
            raise BuildValidationFailed(
                f"platform_labels must be a non-empty subset of "
                f"{sorted(WORKER_LABELS)}")
        name = (display_name or "").strip()
        if not name or len(name) > 128:
            raise BuildValidationFailed(
                "display_name is required (max 128 chars)")
        with self._sf() as session:
            session.add(BuildWorkerModel(
                worker_id=cleaned_id, display_name=name,
                platform_labels=labels, status="pending"))
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise WorkerConflict(
                    f"worker '{cleaned_id}' already exists") from exc
            row = _worker_by_id(session, cleaned_id)
            return _worker_dict(row)

    def get_worker(self, worker_id: str) -> dict[str, Any]:
        with self._sf() as session:
            return _worker_dict(_worker_by_id(session, worker_id))

    def list_workers(self) -> list[dict[str, Any]]:
        with self._sf() as session:
            rows = list(session.scalars(
                select(BuildWorkerModel).order_by(BuildWorkerModel.id)))
            return [_worker_dict(row) for row in rows]

    def issue_register_token(self, worker_id: str, *,
                             ttl_seconds: int = 3600,
                             now: datetime | None = None) -> dict[str, Any]:
        if not 60 <= int(ttl_seconds) <= 86400:
            raise BuildValidationFailed(
                "ttl_seconds must be between 60 and 86400")
        token = secrets.token_urlsafe(32)
        moment = now or _utcnow()
        expires = moment + timedelta(seconds=int(ttl_seconds))
        with self._sf() as session:
            row = _worker_by_id(session, worker_id)
            if row.status == "retired":
                raise WorkerConflict("retired workers cannot re-enroll")
            row.register_token_hash = _token_hash(token)
            row.register_token_expires_at = expires
            session.commit()
        return {"register_token": token, "expires_at": expires}

    def exchange_register_token(self, worker_id: str, register_token: str, *,
                                now: datetime | None = None) -> str:
        moment = now or _utcnow()
        api_token = secrets.token_urlsafe(32)
        with self._sf() as session:
            row = _worker_by_id(session, worker_id)
            if row.status == "retired":
                raise WorkerAuthFailed("worker is retired")
            expiry = row.register_token_expires_at
            if expiry is not None and expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if (not _safe_compare(register_token, row.register_token_hash)
                    or expiry is None or expiry <= moment):
                raise WorkerAuthFailed(
                    "invalid or expired registration token")
            row.register_token_hash = None
            row.register_token_expires_at = None
            row.api_token_hash = _token_hash(api_token)
            row.status = "active"
            session.commit()
        return api_token

    def verify_worker_token(self, worker_id: str,
                            token: str) -> dict[str, Any]:
        with self._sf() as session:
            row = _worker_by_id(session, worker_id)
            if row.status != "active" or not _safe_compare(
                    token, row.api_token_hash):
                raise WorkerAuthFailed(
                    "invalid worker credentials or inactive worker")
            return _worker_dict(row)

    def heartbeat(self, worker_id: str) -> dict[str, Any]:
        with self._sf() as session:
            row = _worker_by_id(session, worker_id)
            row.last_seen_at = _utcnow()
            session.commit()
            return _worker_dict(row)

    # ---------------------------------------------------------- #
    # build credentials (metadata reads; material only on dispatch)
    # ---------------------------------------------------------- #
    def store_credential(self, *, scope: str, owner_ref: str, kind: str,
                         label: str, material: dict) -> dict[str, Any]:
        scope = (scope or "").strip().lower()
        kind = (kind or "").strip().lower()
        if scope not in CREDENTIAL_SCOPES:
            raise BuildValidationFailed(
                f"scope must be one of {sorted(CREDENTIAL_SCOPES)}")
        if kind not in CREDENTIAL_KINDS:
            raise BuildValidationFailed(
                f"kind must be one of {sorted(CREDENTIAL_KINDS)}")
        owner = (owner_ref or "").strip()
        if not owner or len(owner) > 128:
            raise BuildValidationFailed(
                "owner_ref is required (max 128 chars)")
        name = (label or "").strip()
        if not name or len(name) > 128:
            raise BuildValidationFailed(
                "label is required (max 128 chars)")
        if not isinstance(material, dict) or not material:
            raise BuildValidationFailed(
                "material must be a non-empty JSON object")
        try:
            blob_size = len(json.dumps(material).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise BuildValidationFailed(
                f"material is not JSON-serializable: {exc}") from exc
        if blob_size > 8192:
            raise BuildValidationFailed(
                "material exceeds 8 KiB")
        public_id = str(uuid4())
        envelope = self._cipher.encrypt_json(
            material, aad=f"build-credential:{public_id}")
        digest = hashlib.sha256(envelope.encode("utf-8")).hexdigest()
        with self._sf() as session:
            row = BuildCredentialModel(
                public_id=public_id, scope=scope, owner_ref=owner,
                kind=kind, label=name, encrypted_material=envelope,
                envelope_digest=digest)
            session.add(row)
            session.commit()
            return _credential_dict(row)

    def get_credential(self, public_id: str) -> dict[str, Any]:
        with self._sf() as session:
            return _credential_dict(_credential_by_id(session, public_id))

    def list_credentials(self, *, scope: str | None = None,
                         owner_ref: str | None = None,
                         include_revoked: bool = False,
                         ) -> list[dict[str, Any]]:
        with self._sf() as session:
            query = select(BuildCredentialModel)
            if scope is not None:
                query = query.where(BuildCredentialModel.scope == scope)
            if owner_ref is not None:
                query = query.where(
                    BuildCredentialModel.owner_ref == owner_ref)
            if not include_revoked:
                query = query.where(BuildCredentialModel.revoked.is_(False))
            rows = list(session.scalars(
                query.order_by(BuildCredentialModel.id.desc()).limit(200)))
            return [_credential_dict(row) for row in rows]

    def load_material(self, public_id: str) -> dict[str, Any]:
        """Decrypt for dispatch to an authenticated worker. Never an API read."""
        with self._sf() as session:
            row = _credential_by_id(session, public_id)
            if row.revoked:
                raise CredentialRevoked(
                    f"credential '{public_id}' is revoked")
            return dict(self._cipher.decrypt_json(
                row.encrypted_material,
                aad=f"build-credential:{row.public_id}"))

    def rotate_credential(self, public_id: str,
                          material: dict) -> dict[str, Any]:
        if not isinstance(material, dict) or not material:
            raise BuildValidationFailed(
                "material must be a non-empty JSON object")
        try:
            blob_size = len(json.dumps(material).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise BuildValidationFailed(
                f"material is not JSON-serializable: {exc}") from exc
        if blob_size > 8192:
            raise BuildValidationFailed("material exceeds 8 KiB")
        with self._sf() as session:
            row = _credential_by_id(session, public_id)
            if row.revoked:
                raise CredentialRevoked(
                    f"credential '{public_id}' is revoked")
            envelope = self._cipher.encrypt_json(
                material, aad=f"build-credential:{row.public_id}")
            row.encrypted_material = envelope
            row.envelope_digest = hashlib.sha256(
                envelope.encode("utf-8")).hexdigest()
            row.rotated_at = _utcnow()
            session.commit()
            return _credential_dict(row)

    def revoke_credential(self, public_id: str) -> dict[str, Any]:
        with self._sf() as session:
            row = _credential_by_id(session, public_id)
            if not row.revoked:
                row.revoked = True
                row.revoked_at = _utcnow()
                session.commit()
            return _credential_dict(row)


def _build_by_public_id(session, public_id: str) -> AppBuildModel:
    build = session.scalars(select(AppBuildModel).where(
        AppBuildModel.public_id == public_id)).one_or_none()
    if build is None:
        raise BuildNotFound(f"build '{public_id}' does not exist")
    return build


def _jobs_of(session, build_id: int) -> list[BuildPlatformJobModel]:
    return list(session.scalars(select(BuildPlatformJobModel).where(
        BuildPlatformJobModel.build_id == build_id).order_by(
            BuildPlatformJobModel.id)))


def _artifacts_of(session, build_id: int) -> list[AppBuildArtifactModel]:
    return list(session.scalars(select(AppBuildArtifactModel).where(
        AppBuildArtifactModel.build_id == build_id).order_by(
            AppBuildArtifactModel.id)))


def _job_by_ref(session, build_public_id: str, platform: str, arch: str,
                artifact: str = "apk",
                ) -> tuple[AppBuildModel, BuildPlatformJobModel]:
    build = _build_by_public_id(session, build_public_id)
    job = session.scalars(select(BuildPlatformJobModel).where(
        BuildPlatformJobModel.build_id == build.id,
        BuildPlatformJobModel.platform == platform,
        BuildPlatformJobModel.arch == arch,
        BuildPlatformJobModel.artifact == artifact)).one_or_none()
    if job is None:
        suffix = f"/{artifact}" if artifact != "apk" else ""
        raise BuildNotFound(
            f"build '{build_public_id}' has no "
            f"{platform}/{arch}{suffix} job")
    return build, job


def _worker_by_id(session, worker_id: str) -> BuildWorkerModel:
    row = session.scalars(select(BuildWorkerModel).where(
        BuildWorkerModel.worker_id == (worker_id or "").strip().lower())
    ).one_or_none()
    if row is None:
        raise WorkerNotFound(f"worker '{worker_id}' does not exist")
    return row


def _credential_by_id(session, public_id: str) -> BuildCredentialModel:
    row = session.scalars(select(BuildCredentialModel).where(
        BuildCredentialModel.public_id == public_id)).one_or_none()
    if row is None:
        raise CredentialNotFound(
            f"build credential '{public_id}' does not exist")
    return row


def _recompute_progress(session, build: AppBuildModel) -> None:
    jobs = _jobs_of(session, build.id)
    if not jobs:
        build.progress = 0
        return
    terminal = sum(1 for job in jobs if job.status in TERMINAL_JOB)
    build.progress = min(100, (terminal * 100) // len(jobs))


def _aggregate_build(session, build: AppBuildModel) -> None:
    jobs = _jobs_of(session, build.id)
    _recompute_progress(session, build)
    if not jobs or any(job.status not in TERMINAL_JOB for job in jobs):
        if build.status == "queued":
            build.status = "running"
            if build.started_at is None:
                build.started_at = _utcnow()
        return
    failed = [job for job in jobs if job.status == "failed"]
    cancelled = [job for job in jobs if job.status == "cancelled"]
    now = _utcnow()
    build.finished_at = now
    if failed:
        build.status = "failed"
        build.failure_code = failed[0].failure_code or "worker_error"
        build.failure_message = (
            failed[0].failure_message
            or f"{len(failed)} of {len(jobs)} platform jobs failed")
    elif cancelled and len(cancelled) == len(jobs):
        build.status = "cancelled"
        build.failure_code = "cancelled"
    elif cancelled:
        build.status = "failed"
        build.failure_code = "cancelled"
        build.failure_message = "some platform jobs were cancelled"
    else:
        build.status = "success"
        build.failure_code = None
        build.failure_message = None
