"""RQ/Redis transport for build dispatch plus live-log streams.

Redis is infrastructure, not truth: every job payload re-validates
against SQL on the worker side, and a lost Redis loses at most queued
(not yet claimed) jobs plus ephemeral logs. The panel boots and serves
reads fine with no Redis configured — only dispatch and live logs
answer 503.
"""
from __future__ import annotations

import os
from typing import Any
from uuid import uuid4

from app.builder import JOB_CONTRACT_VERSION, WORKER_JOB_FUNCTION
from app.builder.errors import BuildQueueUnavailable

LOG_STREAM_PREFIX = "zagros:build:log:"
LOG_STREAM_CAP = 5000  # worker trims streams to this many entries


def log_stream_key(build_public_id: str, platform: str, arch: str,
                   *, artifact: str = "apk") -> str:
    # Sibling jobs share (build, platform, arch): the aab stream gets its
    # own key while apk keeps the exact historical format.
    suffix = ":aab" if artifact == "aab" else ""
    return f"{LOG_STREAM_PREFIX}{build_public_id}:{platform}:{arch}{suffix}"


class BuildQueue:
    def __init__(self, redis_url: str | None, *,
                 job_timeout_seconds: int = 6 * 3600) -> None:
        self._redis_url = (redis_url or "").strip() or None
        self._job_timeout = int(job_timeout_seconds)
        self._client = None

    @classmethod
    def from_env(cls, redis_url: str | None = None, **kwargs) -> "BuildQueue":
        url = (redis_url if redis_url is not None
               else os.environ.get("ZAGROS_REDIS_URL")
               or os.environ.get("REDIS_URL"))
        return cls(url, **kwargs)

    @property
    def available(self) -> bool:
        return self._redis_url is not None

    def _connection(self):
        if not self.available:
            raise BuildQueueUnavailable(
                "no Redis configured (set ZAGROS_REDIS_URL)")
        if self._client is None:
            try:
                import redis
            except ImportError as exc:
                raise BuildQueueUnavailable(
                    "the 'redis' package is not installed") from exc
            try:
                client = redis.Redis.from_url(
                    self._redis_url, socket_timeout=5,
                    socket_connect_timeout=5)
                client.ping()
            except Exception as exc:
                raise BuildQueueUnavailable(
                    f"Redis is unreachable: {exc}") from exc
            self._client = client
        return self._client

    def enqueue(self, *, queue_name: str, payload: dict[str, Any],
                job_id: str | None = None) -> str:
        """Enqueue by STRING function reference (panel never imports it)."""
        try:
            from rq import Queue
        except ImportError as exc:
            raise BuildQueueUnavailable(
                "the 'rq' package is not installed") from exc
        connection = self._connection()
        body = {"v": JOB_CONTRACT_VERSION, **payload}
        try:
            queue = Queue(queue_name, connection=connection)
            job = queue.enqueue(
                WORKER_JOB_FUNCTION, body,
                job_id=job_id or f"build-{uuid4().hex}",
                job_timeout=self._job_timeout,
                result_ttl=86400, failure_ttl=86400)
        except Exception as exc:
            raise BuildQueueUnavailable(
                f"could not enqueue on '{queue_name}': {exc}") from exc
        return str(job.id)

    def fetch_payload(self, queue_name: str,
                      job_id: str) -> dict[str, Any] | None:
        try:
            from rq.job import Job
        except ImportError as exc:
            raise BuildQueueUnavailable(
                "the 'rq' package is not installed") from exc
        connection = self._connection()
        try:
            job = Job.fetch(job_id, connection=connection)
        except Exception:
            return None
        if job.origin != queue_name:
            return None
        args = job.args or []
        return dict(args[0]) if args and isinstance(args[0], dict) else None

    def cancel(self, queue_name: str, job_id: str) -> bool:
        """Drop a queued job. Running jobs are stopped via token
        invalidation (a cancelled job's callbacks 401, so the worker
        aborts) — RQ cannot kill work already executing."""
        try:
            from rq.job import Job
        except ImportError as exc:
            raise BuildQueueUnavailable(
                "the 'rq' package is not installed") from exc
        connection = self._connection()
        try:
            job = Job.fetch(job_id, connection=connection)
        except Exception:
            return False
        if job.origin != queue_name:
            return False
        try:
            job.cancel()
        except Exception:
            return False
        try:
            job.delete()
        except Exception:
            pass
        return True

    def queue_depth(self, queue_name: str) -> int:
        try:
            from rq import Queue
        except ImportError as exc:
            raise BuildQueueUnavailable(
                "the 'rq' package is not installed") from exc
        try:
            return len(Queue(queue_name, connection=self._connection()))
        except Exception as exc:
            raise BuildQueueUnavailable(
                f"could not inspect '{queue_name}': {exc}") from exc

    def read_log_stream(self, stream: str, *, cursor: str = "0",
                        limit: int = 200) -> dict[str, Any]:
        connection = self._connection()
        limit = min(max(int(limit), 1), 1000)
        start = "-" if cursor in ("0", "-", "") else f"({cursor}"
        try:
            raw = connection.xrange(stream, min=start, max="+", count=limit)
        except Exception as exc:
            raise BuildQueueUnavailable(
                f"could not read log stream: {exc}") from exc
        entries = []
        next_cursor = cursor
        for entry_id, fields in raw:
            text = fields.get(b"text", fields.get("text", b""))
            if isinstance(text, bytes):
                text = text.decode("utf-8", "replace")
            entry_id = (entry_id.decode("utf-8") if isinstance(entry_id, bytes)
                        else str(entry_id))
            entries.append({"id": entry_id, "text": str(text)})
            next_cursor = entry_id
        return {"entries": entries, "next_cursor": next_cursor}
