"""Scheduled backups, delivered to Telegram.

The operator configures *what* to back up and *when*; the panel builds the
archive with :mod:`app.platform.backup_store` and uploads it to a Telegram
chat. Credentials are stored **encrypted** and are never sent back to the UI in
the clear — the dashboard receives a mask, and writing an empty token keeps the
stored one.

Two honest limits are enforced rather than discovered the hard way:

* Telegram's Bot API accepts files up to **50 MB**. A bigger archive is kept on
  the server and reported as such instead of failing at upload time.
* A backup is only as good as its last successful run, so every attempt records
  its outcome where the UI can see it.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

from app import logger
from app.platform import backup_store

SETTINGS_KEY = "backup_service"
_AAD = "backup-service.token"
TELEGRAM_MAX_BYTES = 50 * 1024 * 1024  # Bot API hard limit
_TELEGRAM_API = "https://api.telegram.org"
_CRON_FIELDS = 5
_CRON_TOKEN = re.compile(r"^[\d*/,\-\s]+$")

PRESETS = ("hourly", "daily", "weekly", "cron")


class BackupServiceError(RuntimeError):
    """Raised when the scheduled service cannot be configured or run."""


# --------------------------------------------------------------------------- #
# settings
# --------------------------------------------------------------------------- #
@dataclass
class BackupServiceSettings:
    enabled: bool = False
    schedule: str = "daily"          # hourly | daily | weekly | cron
    cron: str = "0 3 * * *"          # used verbatim when schedule == "cron"
    at_hour: int = 3                 # daily / weekly
    at_minute: int = 0
    weekday: int = 0                 # weekly: 0 = Monday
    chat_id: str = ""                # numeric Telegram chat/channel id
    bot_token: str = ""              # write-only; stored encrypted
    include_logs: bool = False
    keep: int = 7                    # archives retained on the server

    # ---- schedule helpers ---- #
    def normalized(self) -> "BackupServiceSettings":
        schedule = self.schedule if self.schedule in PRESETS else "daily"
        hour = min(23, max(0, int(self.at_hour or 0)))
        minute = min(59, max(0, int(self.at_minute or 0)))
        weekday = min(6, max(0, int(self.weekday or 0)))
        keep = min(365, max(0, int(self.keep or 0)))
        return replace(self, schedule=schedule, at_hour=hour, at_minute=minute,
                       weekday=weekday, keep=keep,
                       cron=(self.cron or "0 3 * * *").strip(),
                       chat_id=str(self.chat_id or "").strip(),
                       bot_token=(self.bot_token or "").strip())

    def cron_expression(self) -> str:
        """The effective expression — presets are expanded to cron."""
        if self.schedule == "cron":
            return self.cron or "0 3 * * *"
        if self.schedule == "hourly":
            return f"{self.at_minute} * * * *"
        if self.schedule == "weekly":
            return f"{self.at_minute} {self.at_hour} * * {self.weekday}"
        return f"{self.at_minute} {self.at_hour} * * *"

    def validate(self) -> list[str]:
        problems: list[str] = []
        if self.schedule == "cron":
            parts = (self.cron or "").split()
            if len(parts) != _CRON_FIELDS or not all(_CRON_TOKEN.match(p) for p in parts):
                problems.append(
                    f"cron expression must have {_CRON_FIELDS} fields, got "
                    f"{self.cron!r}")
        if self.enabled:
            if not self.chat_id.lstrip("-").isdigit():
                problems.append("Telegram chat id must be numeric")
            if not self.bot_token and not self.has_stored_token:
                problems.append("a bot token is required to deliver backups")
        return problems

    has_stored_token: bool = False   # set by the store; never persisted

    def next_run_at(self, now: datetime | None = None) -> float | None:
        """Next due time for simple presets (cron is checked by the job)."""
        if not self.enabled:
            return None
        now = now or datetime.now(timezone.utc)
        if self.schedule == "hourly":
            nxt = (now + timedelta(hours=1)).replace(minute=self.at_minute,
                                                     second=0, microsecond=0)
        elif self.schedule == "weekly":
            nxt = now.replace(hour=self.at_hour, minute=self.at_minute,
                              second=0, microsecond=0)
            days = (self.weekday - now.weekday()) % 7
            nxt += timedelta(days=days)
            if nxt <= now:
                nxt += timedelta(days=7)
        else:  # daily
            nxt = now.replace(hour=self.at_hour, minute=self.at_minute,
                              second=0, microsecond=0)
            if nxt <= now:
                nxt += timedelta(days=1)
        return nxt.timestamp()

    # ---- presentation ---- #
    def public_dict(self) -> dict[str, Any]:
        """What the UI may see — the token is masked, never revealed."""
        token = (self.bot_token or "").strip()
        masked = ""
        if token:
            head = token.split(":", 1)[0] if ":" in token else token[:4]
            masked = f"{head}:••••••••"
        return {
            "enabled": self.enabled,
            "schedule": self.schedule,
            "cron": self.cron_expression(),
            "at_hour": self.at_hour,
            "at_minute": self.at_minute,
            "weekday": self.weekday,
            "chat_id": self.chat_id,
            "bot_token": masked,
            "has_token": bool(token),
            "include_logs": self.include_logs,
            "keep": self.keep,
            "next_run_at": self.next_run_at(),
            "telegram_max_bytes": TELEGRAM_MAX_BYTES,
        }


@dataclass
class BackupRunState:
    last_run_at: float | None = None
    last_status: str = ""            # ok | failed | skipped
    last_size_bytes: int = 0
    last_archive: str = ""
    last_error: str = ""
    delivered: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"last_run_at": self.last_run_at, "last_status": self.last_status,
                "last_size_bytes": self.last_size_bytes,
                "last_archive": self.last_archive, "last_error": self.last_error,
                "delivered": self.delivered}


# --------------------------------------------------------------------------- #
# store
# --------------------------------------------------------------------------- #
class SQLBackupServiceStore:
    """Settings + run state in the shared key/value settings table.

    The bot token is sealed with the deployment cipher; the row keeps a flag so
    validation can tell "no token" from "token present but not shown".
    """

    def __init__(self, session_factory, cipher) -> None:
        self._sf = session_factory
        self._cipher = cipher

    # -- internals -- #
    def _get_row(self, s):
        from app.persistence.models import SettingModel

        return s.get(SettingModel, SETTINGS_KEY)

    def _seal(self, token: str) -> str:
        """Encrypt the token; an empty token stores nothing at all."""
        if not token or self._cipher is None:
            return ""
        try:
            return self._cipher.encrypt_json({"token": token}, aad=_AAD)
        except Exception:  # noqa: BLE001 - never block configuration on crypto
            logger.error("backup service: could not seal the bot token")
            return ""

    def _open(self, sealed: str) -> str:
        if not sealed or self._cipher is None:
            return ""
        try:
            return str(self._cipher.decrypt_json(sealed, aad=_AAD).get("token") or "")
        except Exception:  # noqa: BLE001 - a rotated key must not crash the panel
            return ""

    # -- public API -- #
    def load(self) -> tuple[BackupServiceSettings, BackupRunState]:
        from app.persistence.models import SettingModel

        with self._sf() as s:
            row = s.get(SettingModel, SETTINGS_KEY)
            payload = dict(row.value_json or {}) if row else {}
        settings = BackupServiceSettings(
            enabled=bool(payload.get("enabled", False)),
            schedule=str(payload.get("schedule", "daily")),
            cron=str(payload.get("cron", "0 3 * * *")),
            at_hour=int(payload.get("at_hour", 3) or 0),
            at_minute=int(payload.get("at_minute", 0) or 0),
            weekday=int(payload.get("weekday", 0) or 0),
            chat_id=str(payload.get("chat_id", "") or ""),
            include_logs=bool(payload.get("include_logs", False)),
            keep=int(payload.get("keep", 7) or 0),
        ).normalized()
        settings.bot_token = self._open(str(payload.get("bot_token_enc", "") or ""))
        settings.has_stored_token = bool(settings.bot_token)
        state = BackupRunState(**{
            k: v for k, v in (payload.get("state") or {}).items()
            if k in BackupRunState().__dict__})
        return settings, state

    def save(self, settings: BackupServiceSettings) -> BackupServiceSettings:
        from app.persistence.models import SettingModel

        settings = settings.normalized()
        with self._sf() as s:
            row = self._get_row(s)
            payload = dict(row.value_json or {}) if row else {}
            previous_token = self._open(str(payload.get("bot_token_enc", "") or ""))
            # An empty token in the payload means "keep the stored one" — the UI
            # never receives the real value, so it cannot echo it back.
            token = settings.bot_token or previous_token
            payload.update({
                "enabled": settings.enabled,
                "schedule": settings.schedule,
                "cron": settings.cron,
                "at_hour": settings.at_hour,
                "at_minute": settings.at_minute,
                "weekday": settings.weekday,
                "chat_id": settings.chat_id,
                "include_logs": settings.include_logs,
                "keep": settings.keep,
                "bot_token_enc": self._seal(token),
            })
            if row is None:
                s.add(SettingModel(key=SETTINGS_KEY, value_json=payload))
            else:
                row.value_json = payload
            s.commit()
        saved = replace(settings, bot_token=token)
        saved.has_stored_token = bool(token)
        return saved

    def save_state(self, state: BackupRunState) -> None:
        from app.persistence.models import SettingModel

        with self._sf() as s:
            row = self._get_row(s)
            payload = dict(row.value_json or {}) if row else {}
            payload["state"] = state.to_dict()
            if row is None:
                s.add(SettingModel(key=SETTINGS_KEY, value_json=payload))
            else:
                row.value_json = payload
            s.commit()


# --------------------------------------------------------------------------- #
# delivery
# --------------------------------------------------------------------------- #
def send_to_telegram(token: str, chat_id: str, path: Path, *,
                     caption: str = "") -> dict[str, Any]:
    """Upload one archive; returns Telegram's answer or a raised error."""
    if not token or not chat_id:
        raise BackupServiceError("Telegram is not configured (token or chat id missing)")
    url = f"{_TELEGRAM_API}/bot{token}/sendDocument"
    with path.open("rb") as handle:
        response = requests.post(url, data={"chat_id": chat_id, "caption": caption},
                                 files={"document": (path.name, handle)}, timeout=300)
    try:
        payload = response.json()
    except ValueError:  # pragma: no cover - transport-level surprise
        payload = {"ok": False, "description": response.text[:400]}
    if response.status_code >= 400 or not payload.get("ok"):
        raise BackupServiceError(
            f"Telegram rejected the upload: {payload.get('description', response.reason)}")
    return payload


def cron_matches(expression: str, now: datetime | None = None) -> bool:
    """Minimal 5-field cron match (minute hour dom month dow).

    Supports ``*``, ``*/n`` steps, ranges and lists — the shapes an operator
    actually writes. Anything else is rejected by :meth:`validate`, not here.
    """
    now = now or datetime.now(timezone.utc)
    parts = (expression or "").split()
    if len(parts) != _CRON_FIELDS:
        return False
    # cron's weekday starts at Sunday (0); Python's weekday() starts at Monday
    dow = (now.weekday() + 1) % 7
    fields = ((parts[0], now.minute, 0, 59),
              (parts[1], now.hour, 0, 23),
              (parts[2], now.day, 1, 31),
              (parts[3], now.month, 1, 12),
              (parts[4], dow, 0, 6))
    for spec, value, low, high in fields:
        if not _field_matches(spec, value, low, high):
            # cron accepts 7 as Sunday as well as 0
            if not (low == 0 and high == 6 and value == 0
                    and _field_matches(spec, 7, low, 7)):
                return False
    return True


def _field_matches(spec: str, value: int, low: int, high: int) -> bool:
    for chunk in (spec or "*").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        step = 1
        if "/" in chunk:
            chunk, _, step_text = chunk.partition("/")
            try:
                step = max(1, int(step_text))
            except ValueError:
                return False
        if chunk == "*":
            start, end = low, high
        elif "-" in chunk:
            try:
                left, _, right = chunk.partition("-")
                start, end = int(left), int(right)
            except ValueError:
                return False
        else:
            try:
                start = end = int(chunk)
            except ValueError:
                return False
        if start <= value <= end and (value - start) % step == 0:
            return True
    return False


def test_token(token: str, chat_id: str) -> dict[str, Any]:
    """Send a one-line probe so the operator knows delivery works *now*."""
    if not token:
        raise BackupServiceError("no bot token configured")
    response = requests.post(f"{_TELEGRAM_API}/bot{token}/sendMessage",
                             data={"chat_id": chat_id,
                                   "text": "✅ Zagros backup service: delivery test"},
                             timeout=30)
    try:
        payload = response.json()
    except ValueError:  # pragma: no cover
        payload = {"ok": False, "description": response.text[:400]}
    if response.status_code >= 400 or not payload.get("ok"):
        raise BackupServiceError(
            f"Telegram rejected the test: {payload.get('description', response.reason)}")
    return {"ok": True, "chat": (payload.get("result") or {}).get("chat", {})}


# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #
def run_once(runtime) -> dict[str, Any]:
    """Build one archive and deliver it. Called by the job and by the API."""
    store = getattr(runtime, "backup_service", None)
    if store is None:
        return {"ok": False, "error": "backup service is not initialised"}
    settings, state = store.load()
    data_dir = _data_dir(runtime)
    started = time.time()
    try:
        artifact = backup_store.create(
            data_dir=data_dir,
            database_url=getattr(runtime, "database_url", None),
            legacy_database_url=_legacy_url(runtime),
            panel_version=getattr(runtime, "version", "") or "",
            include_logs=settings.include_logs,
        )
    except Exception as exc:  # noqa: BLE001 — a failed backup must be reported
        state.last_run_at = started
        state.last_status = "failed"
        state.last_error = f"archive: {exc}"
        state.delivered = False
        store.save_state(state)
        logger.error(f"backup service: archive failed — {exc}")
        return {"ok": False, "error": str(exc)}

    path = backup_store.path_for(artifact.name, data_dir)
    state.last_run_at = started
    state.last_status = "ok"
    state.last_size_bytes = artifact.size_bytes
    state.last_archive = artifact.name
    state.last_error = ""

    if path.stat().st_size > TELEGRAM_MAX_BYTES:
        state.delivered = False
        state.last_error = (
            f"archive is {path.stat().st_size // (1024 * 1024)} MB — above "
            f"Telegram's {TELEGRAM_MAX_BYTES // (1024 * 1024)} MB limit; "
            "download it from the panel instead")
        store.save_state(state)
        logger.warning(f"backup service: {state.last_error}")
        return {"ok": True, "archive": artifact.name, "delivered": False,
                "reason": state.last_error}

    try:
        send_to_telegram(settings.bot_token, settings.chat_id, path,
                         caption=f"Zagros backup {artifact.created_utc} "
                                 f"({artifact.size_bytes // 1024} KB)")
        state.delivered = True
    except Exception as exc:  # noqa: BLE001
        state.delivered = False
        state.last_error = f"telegram: {exc}"
        logger.error(f"backup service: delivery failed — {exc}")

    if settings.keep:
        removed = backup_store.prune(settings.keep, data_dir)
        if removed:
            logger.info(f"backup service: pruned {len(removed)} old archive(s)")
    store.save_state(state)
    return {"ok": True, "archive": artifact.name, "bytes": artifact.size_bytes,
            "delivered": state.delivered, "error": state.last_error}


def _data_dir(runtime) -> str:
    url = getattr(runtime, "database_url", "") or ""
    if url.startswith("sqlite:///"):
        return str(Path(url[10:]).parent)
    return "/var/lib/zagros"


def _legacy_url(runtime) -> str | None:
    import os

    return os.environ.get("SQLALCHEMY_DATABASE_URL")


async def run_once_async(runtime) -> dict[str, Any]:
    return await asyncio.to_thread(run_once, runtime)
