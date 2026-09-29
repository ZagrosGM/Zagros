"""Build orchestration: validate -> persist -> dispatch -> aggregate.

The service owns cross-boundary flows (SQL + RQ + artifact files);
single-boundary work stays in the repository, queue and store. Every
method is synchronous — routers run the service via ``asyncio.to_thread``.
"""
from __future__ import annotations

import os
from typing import Any, BinaryIO

from app.builder import JOB_CONTRACT_VERSION
from app.builder.artifacts import FileArtifactStore, MAX_ARTIFACT_BYTES
from app.builder.errors import (
    BuildConflict,
    BuildForbidden,
    BuildNotFound,
    BuildQueueUnavailable,
    BuildValidationFailed,
    CredentialRevoked,
)
from app.builder.queue import BuildQueue, log_stream_key


def _clean_artifact(artifact: str) -> str:
    """Normalize the worker-path artifact selector (default apk)."""
    cleaned = artifact.strip().lower() if isinstance(artifact, str) else ""
    # Mirrors validators.ARTIFACTS (the request-path source of truth).
    if cleaned not in ("apk", "aab", "zip", "tar.gz", "ipa"):
        raise BuildValidationFailed(
            f"unsupported artifact '{artifact}'")
    return cleaned
from app.builder.repository import BuildRepository, TERMINAL_BUILD
from app.builder.validators import (
    DEFAULT_SDK_ALLOWLIST,
    DEFAULT_SOURCE_ALLOWLIST,
    QUEUE_FOR_PLATFORM,
    redact_text,
    validate_build_config,
    validate_source_repo,
    validate_source_revision,
    validate_targets,
    validate_version,
)

TERMINAL_STATUSES = TERMINAL_BUILD

def _valid_source(entry: Any) -> bool:
    return (isinstance(entry, dict)
            and isinstance(entry.get("repo"), str)
            and bool(entry.get("repo"))
            and isinstance(entry.get("revision"), str)
            and bool(_HEX40_RE.fullmatch(entry.get("revision", ""))))


_HEX40_RE = __import__("re").compile(r"^[0-9a-f]{40}$")


_DEFAULT_SOURCE_CACHE: tuple[float, dict[str, Any]] | None = None

_PROBE_SCRIPT = '''
echo "---"
cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2-
echo nproc=$(nproc 2>/dev/null)
free -m | awk '/^Mem:/{print "mem=" $2 " " $7} /^Swap:/{print "swap=" $2}'
df -Pm /tmp | awk 'NR==2{print "disk=" $4}'
echo root=$(id -u)
echo git=$(command -v git >/dev/null && echo 1 || echo 0)
echo java=$(command -v java >/dev/null && echo 1 || echo 0)
echo flutter=$(test -x /opt/flutter/bin/flutter && echo 1 || echo 0)
echo sdkmanager=$(test -f /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager && echo 1 || echo 0)
'''


def _canonical_repo(allowlist: tuple[str, ...] | list[str]) -> str:
    for entry in allowlist:
        if entry.endswith(".git"):
            continue
        return entry
    return allowlist[0]


def _github_head(repo_url: str) -> str:
    """Resolve HEAD commit of an allowlisted GitHub repo (no git binary)."""
    import re as _re

    import requests as _requests

    match = _re.match(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$",
                      repo_url)
    if not match:
        raise BuildValidationFailed(f"unsupported default repo '{repo_url}'")
    owner, name = match.group(1), match.group(2)
    try:
        response = _requests.get(
            f"https://api.github.com/repos/{owner}/{name}/commits/HEAD",
            timeout=15,
            headers={"Accept": "application/vnd.github+json"})
        response.raise_for_status()
        sha = str(response.json().get("sha") or "")
    except Exception as exc:  # noqa: BLE001
        raise BuildValidationFailed(
            f"cannot resolve HEAD of {repo_url}: {exc}") from exc
    if not _re.fullmatch(r"[0-9a-f]{40}", sha):
        raise BuildValidationFailed(
            f"unexpected HEAD response for {repo_url}")
    return sha


def _parse_probe(text: str, result: dict[str, Any]) -> None:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("---") or not line:
            if line == "---":
                continue
        if line and not line.startswith("PRETTY") and "=" not in line \
                and result.get("os_pretty") is None and line != "---":
            result["os_pretty"] = line.strip('"')
        for key in ("nproc", "root", "git", "java", "flutter", "sdkmanager"):
            if line.startswith(key + "="):
                value = line.split("=", 1)[1]
                if key == "nproc":
                    try:
                        result["cores"] = int(value)
                    except ValueError:
                        pass
                elif key == "root":
                    result["is_root"] = value == "0"
                else:
                    result["toolchain"][key] = value == "1"
        if line.startswith("mem="):
            parts = line[4:].split()
            if len(parts) >= 2:
                try:
                    result["mem_total_mb"] = int(parts[0])
                    result["mem_avail_mb"] = int(parts[1])
                except ValueError:
                    pass
        elif line.startswith("swap="):
            try:
                result["swap_total_mb"] = int(line[5:])
            except ValueError:
                pass
        elif line.startswith("disk="):
            try:
                result["disk_free_mb"] = int(line[5:])
            except ValueError:
                pass




class BuildService:
    def __init__(self, repository: BuildRepository, queue: BuildQueue,
                 artifacts: FileArtifactStore, *,
                 source_allowlist: tuple[str, ...] | list[str] | None = None,
                 sdk_allowlist: tuple[str, ...] | list[str] | None = None,
                 ) -> None:
        self._repo = repository
        self._queue = queue
        self._artifacts = artifacts
        if source_allowlist is None:
            raw = os.environ.get("ZAGROS_BUILD_SOURCE_ALLOWLIST", "")
            entries = [entry.strip() for entry in raw.split(",") if entry.strip()]
            source_allowlist = tuple(entries) or DEFAULT_SOURCE_ALLOWLIST
        self._allowlist = tuple(source_allowlist)
        if sdk_allowlist is None:
            raw = os.environ.get("ZAGROS_BUILD_SDK_ALLOWLIST", "")
            entries = [entry.strip() for entry in raw.split(",") if entry.strip()]
            sdk_allowlist = tuple(entries) or DEFAULT_SDK_ALLOWLIST
        self._sdk_allowlist = tuple(sdk_allowlist)

    # ---------------------------------------------------------- #
    # admin: builds
    # ---------------------------------------------------------- #
    def create_build(self, *, owner_admin_id: int,
                     application_public_id: str, version: str,
                     source_repo: str, source_revision: str,
                     sdk_source_repo: str, sdk_source_revision: str,
                     build_config: dict,
                     targets: list[dict[str, str]],
                     credential_ids: list[str] | None = None,
                     ) -> dict[str, Any]:
        application = self._repo.get_application(application_public_id)
        if application["status"] != "active":
            raise BuildConflict(
                f"application '{application_public_id}' is "
                f"{application['status']}, not active")
        if int(application["owner_admin_id"]) != int(owner_admin_id):
            raise BuildForbidden(
                "owner_admin_id does not own this application")
        cleaned_version = validate_version(version)
        cleaned_repo = validate_source_repo(source_repo, self._allowlist)
        cleaned_revision = validate_source_revision(source_revision)
        cleaned_sdk_repo = validate_source_repo(
            sdk_source_repo, self._sdk_allowlist,
            field="sdk_source_repo")
        cleaned_sdk_revision = validate_source_revision(sdk_source_revision)
        canonical_config, digest = validate_build_config(build_config or {})
        cleaned_targets = validate_targets(targets)
        attached = self._authorize_attachments(
            application_public_id, credential_ids or [])
        build = self._repo.create_build(
            owner_admin_id=int(application["owner_admin_id"]),
            application_id=int(application["id"]),
            version=cleaned_version, source_repo=cleaned_repo,
            source_revision=cleaned_revision,
            sdk_source_repo=cleaned_sdk_repo,
            sdk_source_revision=cleaned_sdk_revision,
            build_config=canonical_config,
            config_digest=digest, targets=cleaned_targets,
            credential_ids=attached)
        dispatched: list[tuple[str, str, str, str]] = []
        try:
            for target in cleaned_targets:
                platform, arch = target["platform"], target["arch"]
                artifact = target["artifact"]
                queue_name = QUEUE_FOR_PLATFORM[platform]
                token = self._repo.issue_job_token(
                    build_public_id=build["public_id"],
                    platform=platform, arch=arch, artifact=artifact)
                job_id = self._queue.enqueue(
                    queue_name=queue_name,
                    payload={"build_public_id": build["public_id"],
                             "platform": platform, "arch": arch,
                             "artifact": artifact, "job_token": token})
                self._repo.attach_queue_job(
                    build_public_id=build["public_id"], platform=platform,
                    arch=arch, artifact=artifact, queue_job_id=job_id)
                dispatched.append(
                    (queue_name, job_id, platform, arch))
        except Exception as exc:
            for queue_name, job_id, _, _ in dispatched:
                try:
                    self._queue.cancel(queue_name, job_id)
                except Exception:
                    pass
            reason = ("build queue unavailable"
                      if isinstance(exc, BuildQueueUnavailable)
                      else f"dispatch failed: {exc}")
            self._repo.fail_build(
                build["public_id"], code="panel_error", message=reason)
            if isinstance(exc, BuildQueueUnavailable):
                raise
            raise BuildQueueUnavailable(reason) from exc
        return self._repo.get_build(build["public_id"])

    def get_build(self, public_id: str) -> dict[str, Any]:
        return self._repo.get_build(public_id)

    def list_builds(self, **kwargs) -> tuple[list[dict[str, Any]], int]:
        return self._repo.list_builds(**kwargs)

    def cancel_build(self, public_id: str) -> dict[str, Any]:
        build, live = self._repo.cancel_build(public_id)
        dropped: list[dict[str, str]] = []
        for queue_name, job_id in live:
            try:
                removed = self._queue.cancel(queue_name, job_id)
            except BuildQueueUnavailable:
                removed = False
            dropped.append({"queue": queue_name, "job_id": job_id,
                            "removed_from_queue": removed})
        build["queue_cancel"] = dropped
        return build

    # ---------------------------------------------------------- #
    # admin: logs + artifacts
    # ---------------------------------------------------------- #
    def read_logs(self, public_id: str, *, platform: str, arch: str,
                  cursor: str = "0", limit: int = 200) -> dict[str, Any]:
        build = self._repo.get_build(public_id)
        job = _find_job(build, platform, arch)
        terminal = job["status"] in ("success", "failed", "cancelled")
        if terminal and job.get("log_ref"):
            content, truncated = self._artifacts.read_log(job["log_ref"])
            return {
                "terminal": True, "truncated": truncated,
                "entries": [{"id": "final",
                             "text": content.decode("utf-8", "replace")}],
                "next_cursor": "final",
            }
        if terminal:
            return {"terminal": True, "truncated": False, "entries": [],
                    "next_cursor": "final"}
        stream = log_stream_key(public_id, platform, arch)
        page = self._queue.read_log_stream(stream, cursor=cursor, limit=limit)
        return {"terminal": False, "truncated": False, **page}

    def download_artifact(self, public_id: str, *, platform: str, arch: str,
                          filename: str):
        build = self._repo.get_build(public_id)
        for artifact in build["artifacts"]:
            if (artifact["platform"] == platform
                    and artifact["arch"] == arch
                    and artifact["filename"] == filename):
                path = self._artifacts.open_for_download(
                    artifact["rel_path"])
                return path, artifact
        raise BuildNotFound(
            f"no artifact '{filename}' for {platform}/{arch} "
            f"on build '{public_id}'")

    # ---------------------------------------------------------- #
    # worker: job lifecycle (job-token authenticated)
    # ---------------------------------------------------------- #
    def claim_job(self, *, build_public_id: str, platform: str, arch: str,
                  artifact: str = "apk", token: str, worker_id: str,
                  worker_token: str) -> dict[str, Any]:
        # Both proofs required: the job token (RQ payload possession) and
        # the worker API token (registered worker identity).
        cleaned = _clean_artifact(artifact)
        self._repo.verify_worker_token(worker_id, worker_token)
        return self._repo.claim_job(
            build_public_id=build_public_id, platform=platform, arch=arch,
            artifact=cleaned, token=token, worker_id=worker_id)

    def fetch_job(self, *, build_public_id: str, platform: str, arch: str,
                  artifact: str = "apk", token: str) -> dict[str, Any]:
        verified = self._repo.verify_job_token(
            build_public_id=build_public_id, platform=platform, arch=arch,
            artifact=_clean_artifact(artifact), token=token)
        build, job = verified["build"], verified["job"]
        if job["status"] != "running" or not job["worker_id"]:
            raise BuildConflict("job must be claimed before fetching")
        credentials = []
        for credential_id in build.get("credential_ids") or []:
            meta = self._repo.get_credential(credential_id)
            if meta["revoked"]:
                raise CredentialRevoked(
                    f"credential '{credential_id}' was revoked — "
                    f"rotate and rebuild")
            material = self._repo.load_material(credential_id)
            credentials.append({
                "public_id": meta["public_id"], "kind": meta["kind"],
                "label": meta["label"], "material": material,
            })
        for meta in self._repo.list_credentials(
                scope="worker", owner_ref=job["worker_id"]):
            credentials.append({
                "public_id": meta["public_id"], "kind": meta["kind"],
                "label": meta["label"],
                "material": self._repo.load_material(meta["public_id"]),
            })
        application = build["application"] or {}
        pack_ref = self._repo.job_icon_ref(build_public_id)
        icon_doc: dict[str, object] = {"present": pack_ref is not None}
        if pack_ref is not None:
            icon_doc.update({k: v for k, v in pack_ref.items()
                             if k != "public_id"})
        return {
            "v": JOB_CONTRACT_VERSION,
            "build_public_id": build["public_id"],
            "application": application,
            "version": build["version"],
            "build_number": build["build_number"],
            "platform": job["platform"],
            "arch": job["arch"],
            "artifact": job["artifact"],
            "source": {"repo": build["source_repo"],
                       "revision": build["source_revision"]},
            # Legacy (pre-Phase-14) rows carry no SDK pin; the v2 worker
            # refuses such documents loudly instead of misbuilding.
            "sdk_source": (
                {"repo": build["sdk_source_repo"],
                 "revision": build["sdk_source_revision"]}
                if build.get("sdk_source_repo") else None),
            "build_config": build["build_config"],
            "config_digest": build["config_digest"],
            "icon": icon_doc,
            "credentials": credentials,
            "log_stream": log_stream_key(
                build["public_id"], job["platform"], job["arch"],
                artifact=job["artifact"]),
        }

    def fetch_job_icon(self, *, build_public_id: str, platform: str,
                         arch: str, artifact: str = "apk",
                         token: str) -> dict[str, Any]:
        """Resolve the launcher pack for a claimed job (job-token authed).

        Same guards as [fetch_job]: the token must verify and the job must
        be claimed. Raises [BuildNotFound] when the application carries no
        rendered pack — the worker fails the job loudly instead of
        shipping a silently unbranded build.
        """
        verified = self._repo.verify_job_token(
            build_public_id=build_public_id, platform=platform, arch=arch,
            artifact=_clean_artifact(artifact), token=token)
        job = verified["job"]
        if job["status"] != "running" or not job["worker_id"]:
            raise BuildConflict("job must be claimed before fetching")
        ref = self._repo.job_icon_ref(build_public_id)
        if ref is None:
            raise BuildNotFound("application has no launcher icon pack")
        return ref

    def report_status(self, *, build_public_id: str, platform: str,
                      arch: str, artifact: str = "apk", token: str,
                      status: str, failure_code: str | None = None,
                      failure_message: str | None = None,
                      final_log: bytes | None = None) -> dict[str, Any]:
        if status not in ("success", "failed"):
            raise BuildValidationFailed(
                "status must be 'success' or 'failed'")
        cleaned = _clean_artifact(artifact)
        log_ref = None
        if final_log is not None:
            verified = self._repo.verify_job_token(
                build_public_id=build_public_id, platform=platform,
                arch=arch, artifact=cleaned, token=token)
            app_id = (verified["build"]["application"] or {}).get(
                "public_id", "unknown")
            rel = self._artifacts.log_rel_path(
                app_public_id=app_id, build_public_id=build_public_id,
                platform=platform, arch=arch, artifact=cleaned)
            clean = redact_text(
                final_log.decode("utf-8", "replace")).encode("utf-8")
            log_ref = self._artifacts.write_final_log(rel, clean)
        return self._repo.report_job(
            build_public_id=build_public_id, platform=platform, arch=arch,
            artifact=cleaned, token=token, success=(status == "success"),
            failure_code=failure_code, failure_message=failure_message,
            log_ref=log_ref)

    def upload_artifact(self, *, build_public_id: str, platform: str,
                        arch: str, artifact: str = "apk", token: str,
                        filename: str, stream: BinaryIO, sha256: str,
                        size_bytes: int,
                        toolchain: dict | None = None) -> dict[str, Any]:
        cleaned = _clean_artifact(artifact)
        verified = self._repo.verify_job_token(
            build_public_id=build_public_id, platform=platform, arch=arch,
            artifact=cleaned, token=token)
        build, job = verified["build"], verified["job"]
        if job["status"] != "running":
            raise BuildConflict(
                f"artifacts are only accepted while running "
                f"(job is {job['status']})")
        app_id = (build["application"] or {}).get("public_id", "unknown")
        rel = self._artifacts.artifact_rel_path(
            app_public_id=app_id, version=build["version"],
            build_number=build["build_number"], platform=platform,
            arch=arch, filename=filename)
        staged = self._artifacts.stage_upload()
        try:
            received = 0
            with open(staged, "wb") as handle:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > MAX_ARTIFACT_BYTES:
                        raise BuildValidationFailed(
                            "artifact exceeds the 1 GiB cap")
                    handle.write(chunk)
            self._artifacts.finalize(
                staged, rel_path=rel, expected_sha256=sha256,
                expected_size=int(size_bytes))
        except Exception:
            self._artifacts.discard_staged(staged)
            raise
        provenance = {
            "source_repo": build["source_repo"],
            "source_revision": build["source_revision"],
            "sdk_source_repo": build.get("sdk_source_repo"),
            "sdk_source_revision": build.get("sdk_source_revision"),
            "config_digest": build["config_digest"],
            "worker_id": job["worker_id"],
            "toolchain": toolchain or {},
        }
        return self._repo.record_artifact(
            job_id=int(verified["job_id"]), filename=filename,
            rel_path=rel, sha256=sha256.strip().lower(),
            size_bytes=int(size_bytes), provenance=provenance)

    # ---------------------------------------------------------- #
    # worker: identity
    # ---------------------------------------------------------- #
    def register_worker(self, worker_id: str,
                        register_token: str) -> dict[str, Any]:
        api_token = self._repo.exchange_register_token(
            worker_id, register_token)
        worker = self._repo.get_worker(worker_id)
        worker["api_token"] = api_token
        return worker

    def heartbeat(self, worker_id: str, token: str) -> dict[str, Any]:
        self._repo.verify_worker_token(worker_id, token)
        worker = self._repo.heartbeat(worker_id)
        depths: dict[str, int | None] = {}
        for label in worker["platform_labels"]:
            queue_name = f"builder:{label}"
            try:
                depths[queue_name] = self._queue.queue_depth(queue_name)
            except BuildQueueUnavailable:
                depths[queue_name] = None
        worker["queue_depths"] = depths
        return worker

    # ---------------------------------------------------------- #
    # admin: workers + credentials (thin pass-throughs)
    # ---------------------------------------------------------- #
    def create_worker(self, **kwargs) -> dict[str, Any]:
        return self._repo.create_worker(**kwargs)

    def get_worker(self, worker_id: str) -> dict[str, Any]:
        return self._repo.get_worker(worker_id)

    def list_workers(self) -> list[dict[str, Any]]:
        return self._repo.list_workers()

    def issue_register_token(self, worker_id: str, **kwargs):
        return self._repo.issue_register_token(worker_id, **kwargs)

    def store_credential(self, **kwargs) -> dict[str, Any]:
        return self._repo.store_credential(**kwargs)

    def get_credential(self, public_id: str) -> dict[str, Any]:
        return self._repo.get_credential(public_id)

    def list_credentials(self, **kwargs) -> list[dict[str, Any]]:
        return self._repo.list_credentials(**kwargs)

    def rotate_credential(self, public_id: str,
                          material: dict) -> dict[str, Any]:
        return self._repo.rotate_credential(public_id, material)

    def revoke_credential(self, public_id: str) -> dict[str, Any]:
        return self._repo.revoke_credential(public_id)

    # ---------------------------------------------------------- #
    # admin: build wizard helpers (f-panel-1)
    # ---------------------------------------------------------- #
    def resolve_default_source(self) -> dict[str, Any]:
        """Simple-mode default: HEAD of the allowlisted app + SDK repos."""
        import time as _time

        global _DEFAULT_SOURCE_CACHE
        now = _time.time()
        cached = _DEFAULT_SOURCE_CACHE
        if cached is not None and now - cached[0] < 300:
            return cached[1]
        import json as _json

        import os as _os

        # Deployment-configured default first (works without GitHub
        # access, e.g. local source mirrors on the master host).
        raw = (_os.environ.get("ZAGROS_BUILD_DEFAULT_SOURCE_JSON") or "").strip()
        if raw:
            doc = None
            try:
                doc = _json.loads(raw)
            except ValueError:
                doc = None
            if (isinstance(doc, dict)
                    and _valid_source(doc.get("source"))
                    and _valid_source(doc.get("sdk_source"))):
                _DEFAULT_SOURCE_CACHE = (now, doc)
                return doc
            raise BuildValidationFailed(
                "ZAGROS_BUILD_DEFAULT_SOURCE_JSON is set but invalid "
                "(want source+sdk_source with allowlisted repo + 40-hex "
                "revision)")
        app_repo = _canonical_repo(self._allowlist)
        sdk_repo = _canonical_repo(self._sdk_allowlist)
        doc = {
            "source": {"repo": app_repo,
                       "revision": _github_head(app_repo)},
            "sdk_source": {"repo": sdk_repo,
                           "revision": _github_head(sdk_repo)},
        }
        _DEFAULT_SOURCE_CACHE = (now, doc)
        return doc

    def probe_external_host(self, *, host: str, port: int, username: str,
                            password: str = "",
                            private_key: str = "") -> dict[str, Any]:
        """SSH probe for the wizard: host-key pin + resources + toolchain.

        Credentials are used for THIS connection only and never stored;
        the wizard separately stores them as a build credential.
        """
        import base64
        import hashlib as _hashlib
        import socket
        import time as _time

        import paramiko

        result: dict[str, Any] = {
            "reachable": False, "host_key_pin": None, "os_pretty": None,
            "cores": None, "mem_avail_mb": None, "mem_total_mb": None,
            "swap_total_mb": None, "disk_free_mb": None, "is_root": False,
            "toolchain": {}, "message": None,
        }
        sock = None
        transport = None
        try:
            sock = socket.create_connection((host, int(port)), timeout=10)
            transport = paramiko.Transport(sock)
            transport.start_client(timeout=10)
            server_key = transport.get_remote_server_key()
            pin = ("sha256:" + base64.b64encode(
                _hashlib.sha256(server_key.asbytes()).digest()
            ).decode("ascii").rstrip("="))
            result["host_key_pin"] = pin
            pkey = None
            if private_key.strip():
                handle = None
                import tempfile as _tempfile
                import os as _os
                handle, path = _tempfile.mkstemp(prefix="zagros-probe-")
                try:
                    with _os.fdopen(handle, "w") as fh:
                        fh.write(private_key)
                        if not private_key.endswith("\n"):
                            fh.write("\n")
                    last: Exception | None = None
                    for key_type in (paramiko.RSAKey, paramiko.Ed25519Key,
                                     paramiko.ECDSAKey):
                        try:
                            pkey = key_type.from_private_key_file(path)
                            break
                        except Exception as exc:  # noqa: BLE001
                            last = exc
                    if pkey is None:
                        raise BuildValidationFailed(
                            f"unusable private key material: {last}")
                finally:
                    try:
                        _os.unlink(path)
                    except OSError:
                        pass
            if pkey is not None:
                transport.auth_publickey(username, pkey)
            elif password:
                transport.auth_password(username, password)
            else:
                raise BuildValidationFailed(
                    "external host probe needs a password or private key")
            session = transport.open_session(timeout=15)
            session.settimeout(30)
            session.exec_command(_PROBE_SCRIPT)
            out = b""
            deadline = _time.monotonic() + 30
            while True:
                if session.exit_status_ready() and not session.recv_ready():
                    break
                if session.recv_ready():
                    out += session.recv(65536)
                if _time.monotonic() > deadline:
                    break
                _time.sleep(0.05)
            while session.recv_ready():
                out += session.recv(65536)
            text = out.decode("utf-8", "replace")
            _parse_probe(text, result)
            result["reachable"] = True
        except BuildError:
            raise
        except Exception as exc:  # noqa: BLE001 — probe reports, never throws
            result["message"] = f"{type(exc).__name__}: {exc}"
        finally:
            try:
                if transport is not None:
                    transport.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                if sock is not None:
                    sock.close()
            except Exception:  # noqa: BLE001
                pass
        return result

    # ---------------------------------------------------------- #
    # internals
    # ---------------------------------------------------------- #
    def _authorize_attachments(self, application_public_id: str,
                               credential_ids: list[str]) -> list[str]:
        attached: list[str] = []
        for credential_id in credential_ids or []:
            meta = self._repo.get_credential(credential_id)
            if meta["revoked"]:
                raise CredentialRevoked(
                    f"credential '{credential_id}' is revoked")
            allowed = (
                meta["scope"] == "global"
                or (meta["scope"] == "application"
                    and meta["owner_ref"] == application_public_id))
            if not allowed:
                raise BuildForbidden(
                    f"credential '{credential_id}' "
                    f"(scope={meta['scope']}) cannot attach to "
                    f"application '{application_public_id}'")
            attached.append(meta["public_id"])
        return attached


def _find_job(build: dict[str, Any], platform: str,
              arch: str) -> dict[str, Any]:
    for job in build.get("targets", []):
        if job["platform"] == platform and job["arch"] == arch:
            return job
    raise BuildNotFound(
        f"build '{build['public_id']}' has no {platform}/{arch} job")
