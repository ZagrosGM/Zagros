"""Application connection leases, teardown reconciliation and usage views."""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from app.applicationapi.connection_models import (
    ConnectionStatusList,
    ConnectionView,
    UsageHistoryBucket,
    UsageHistoryPage,
    UsageSummary,
)
from app.applicationapi.errors import ConnectionFailed, ProtocolUnavailable
from app.applicationapi.repository import (
    ApplicationAuthRepository,
    ConnectionLeaseContext,
    UserAuthContext,
)
from app.applicationapi.security import SignedRequest
from app.applicationapi.service import ApplicationAuthService
from app.cores.types import Capability, UserAccount

logger = logging.getLogger(__name__)

_LEASE_SETTING_KEYS = frozenset({
    "inbound_tags", "excluded_inbounds", "flow", "method",
})


class ApplicationConnectionService:
    def __init__(self, auth: ApplicationAuthService,
                 repository: ApplicationAuthRepository, online_data, runtime, *,
                 lease_ttl_seconds: int = 120,
                 now: Callable[[], float] = time.time) -> None:
        if not 60 <= int(lease_ttl_seconds) <= 300:
            raise ValueError("connection lease TTL must be between 60 and 300 seconds")
        self.auth = auth
        self.repository = repository
        self.online_data = online_data
        self.runtime = runtime
        self.lease_ttl_seconds = int(lease_ttl_seconds)
        self._now = now
        self._locks: dict[str, asyncio.Lock] = {}

    def _datetime(self) -> datetime:
        return datetime.fromtimestamp(self._now(), tz=timezone.utc)

    def _not_after(self, now: datetime) -> datetime:
        return now + timedelta(seconds=self.lease_ttl_seconds)

    async def _authorize(self, signed: SignedRequest,
                         access_token: str) -> UserAuthContext:
        return await self.auth.authorize_protected(
            signed=signed, access_token=access_token)

    async def _source(self, context: UserAuthContext, config_id: str):
        now = self._datetime()
        grant = await asyncio.to_thread(
            self.repository.inspect_config_grant,
            context=context, public_id=config_id, now=now)
        if not grant.protocol or not grant.source_account_id:
            raise ProtocolUnavailable("request a fresh config list")
        accounts = await self.online_data.get_core_accounts(context.user_id)
        selected = next((
            (driver, account) for driver, account in accounts
            if str(driver.metadata.id) == grant.core_id
            and account.account_id == grant.source_account_id
            and account.protocol == grant.protocol and account.enabled
        ), None)
        if selected is None:
            raise ProtocolUnavailable("protocol is not available")
        driver, account = selected
        if (Capability.USER_MANAGEMENT not in driver.metadata.capabilities
                or not driver.device_scoped_leases_supported()):
            raise ProtocolUnavailable(
                "protocol cannot provide an independent device identity")
        return grant, driver, account

    @staticmethod
    def _account(context: UserAuthContext, lease: ConnectionLeaseContext,
                 source: UserAccount, settings: dict) -> UserAccount:
        return UserAccount(
            user_id=context.user_id,
            username=lease.account_id,
            account_id=lease.account_id,
            protocol=lease.protocol,
            enabled=True,
            expire_at=lease.not_after,
            data_limit_bytes=context.data_limit_bytes,
            settings=dict(settings),
        )

    @staticmethod
    def _initial_settings(source: UserAccount) -> dict:
        # Credentials from the permanent account are deliberately excluded.
        return {key: value for key, value in source.settings.items()
                if key in _LEASE_SETTING_KEYS}

    async def _apply(self, *, context: UserAuthContext,
                     lease: ConnectionLeaseContext,
                     driver, source: UserAccount) -> tuple[dict, str]:
        settings = (dict(lease.settings) if lease.settings
                    else self._initial_settings(source))
        account = self._account(context, lease, source, settings)
        if lease.target_kind == "node":
            if lease.node_id is None:
                raise ConnectionFailed("connection node is unavailable")
            from app.nodes.service import apply_connection_lease

            result = await apply_connection_lease(
                self.runtime, lease.node_id,
                core_id=lease.core_id, lease_id=lease.lease_id,
                connection_id=lease.connection_id,
                account=account, not_after=lease.not_after)
            returned = result.get("settings")
            if not isinstance(returned, dict):
                raise ConnectionFailed("node returned incomplete lease state")
            return returned, str(
                result.get("teardown_capability") or "authorization_only")

        if lease.created:
            await driver.create_account(account)
        else:
            await driver.update_account(account)
        return dict(account.settings), driver.account_teardown_capability()

    async def start(self, *, signed: SignedRequest, access_token: str,
                    config_id: str) -> ConnectionView:
        context = await self._authorize(signed, access_token)
        _grant, driver, source = await self._source(context, config_id)
        node_id = await asyncio.to_thread(
            self.repository.eligible_connection_node, str(driver.metadata.id))
        now = self._datetime()
        not_after = self._not_after(now)
        lock = self._locks.setdefault(
            f"{context.application_db_id}:{context.device_db_id}:"
            f"{driver.metadata.id}:{source.protocol}", asyncio.Lock())
        async with lock:
            lease = await asyncio.to_thread(
                self.repository.reserve_connection,
                context=context, config_id=config_id, node_id=node_id,
                not_after=not_after, now=now)
            # Existing connections retain their original target even if node
            # availability changed between polls.
            try:
                settings, capability = await self._apply(
                    context=context, lease=lease, driver=driver, source=source)
                lease = await asyncio.to_thread(
                    self.repository.complete_connection,
                    connection_id=lease.connection_id, settings=settings,
                    teardown_capability=capability,
                    not_after=not_after, now=self._datetime())
            except Exception as exc:
                await asyncio.to_thread(
                    self.repository.fail_connection,
                    connection_id=lease.connection_id, now=self._datetime(),
                    reason=type(exc).__name__)
                logger.warning("Application lease provisioning failed for %s/%s: %s",
                               driver.metadata.id, source.protocol, exc)
                raise ConnectionFailed("connection could not be provisioned") from exc
        return self._view(lease, config_id=config_id)

    async def _teardown(self, lease: ConnectionLeaseContext) -> None:
        if lease.target_kind == "node":
            if lease.node_id is None:
                raise ConnectionFailed("connection node is unavailable")
            from app.nodes.service import revoke_connection_lease

            await revoke_connection_lease(
                self.runtime, lease.node_id,
                core_id=lease.core_id, lease_id=lease.lease_id)
            return
        driver = self.runtime.core_manager.get(lease.core_id)
        await driver.delete_account(lease.account_id)

    async def stop(self, *, signed: SignedRequest, access_token: str,
                   connection_id: str) -> ConnectionView:
        context = await self._authorize(signed, access_token)
        lease = await asyncio.to_thread(
            self.repository.request_connection_stop,
            context=context, connection_id=connection_id, now=self._datetime())
        try:
            await self._teardown(lease)
        except Exception as exc:
            await asyncio.to_thread(
                self.repository.mark_connection_removed,
                connection_id=lease.connection_id, now=self._datetime(),
                expired=False, error=type(exc).__name__)
        else:
            await asyncio.to_thread(
                self.repository.mark_connection_removed,
                connection_id=lease.connection_id, now=self._datetime(),
                expired=False)
        refreshed = (await asyncio.to_thread(
            self.repository.connection_statuses,
            context=context, now=self._datetime(),
            connection_id=connection_id))[0]
        return self._view(refreshed)

    async def _observe(self, lease: ConnectionLeaseContext) -> str:
        if lease.status not in {"active", "pending"}:
            return "offline"
        if lease.target_kind == "node":
            if lease.node_id is None:
                return "unknown"
            from app.nodes.service import connection_lease_status

            result = await connection_lease_status(
                self.runtime, lease.node_id,
                core_id=lease.core_id, lease_id=lease.lease_id)
            return str(result.get("observed_status") or "unknown")
        driver = self.runtime.core_manager.get(lease.core_id)
        if Capability.ONLINE_TRACKING not in driver.metadata.capabilities:
            return "unknown"
        sessions = await driver.get_online_devices(account_ids=[lease.account_id])
        return "online" if sessions else "offline"

    async def statuses(self, *, signed: SignedRequest, access_token: str,
                       connection_id: str | None = None,
                       renew: bool = False) -> ConnectionStatusList:
        context = await self._authorize(signed, access_token)
        rows = await asyncio.to_thread(
            self.repository.connection_statuses,
            context=context, now=self._datetime(), connection_id=connection_id)
        views: list[ConnectionView] = []
        for lease in rows:
            if renew and lease.status == "active":
                try:
                    lease = await asyncio.to_thread(
                        self.repository.renew_connection,
                        context=context, connection_id=lease.connection_id,
                        not_after=self._not_after(self._datetime()),
                        now=self._datetime())
                    # Re-apply the extended bound to the real node/local core.
                    accounts = await self.online_data.get_core_accounts(context.user_id)
                    source = next((account for driver, account in accounts
                                   if str(driver.metadata.id) == lease.core_id
                                   and account.protocol == lease.protocol), None)
                    driver = self.runtime.core_manager.get(lease.core_id)
                    if source is None:
                        raise ProtocolUnavailable("protocol is not available")
                    settings, capability = await self._apply(
                        context=context, lease=lease, driver=driver, source=source)
                    lease = await asyncio.to_thread(
                        self.repository.complete_connection,
                        connection_id=lease.connection_id, settings=settings,
                        teardown_capability=capability,
                        not_after=lease.not_after, now=self._datetime())
                except Exception as exc:  # report status; sweeper retains bound
                    logger.warning("Application lease renewal failed for %s: %s",
                                   lease.connection_id, exc)
            try:
                observed = await self._observe(lease)
                await asyncio.to_thread(
                    self.repository.update_connection_observation,
                    connection_id=lease.connection_id,
                    observed_status=observed, now=self._datetime())
                lease = replace(
                    lease, observed_status=observed, observed_at=self._datetime())
            except Exception as exc:
                await asyncio.to_thread(
                    self.repository.update_connection_observation,
                    connection_id=lease.connection_id,
                    observed_status="unknown", now=self._datetime(),
                    error=type(exc).__name__)
            views.append(self._view(lease))
        return ConnectionStatusList(connections=views)

    @staticmethod
    def _view(lease: ConnectionLeaseContext,
              config_id: str | None = None) -> ConnectionView:
        return ConnectionView(
            connection_id=lease.connection_id, config_id=config_id,
            core_id=lease.core_id, protocol=lease.protocol,
            desired_status=lease.status,
            observed_status=lease.observed_status,
            target=lease.target_kind,
            teardown_capability=lease.teardown_capability,
            not_after=lease.not_after, renewed_at=lease.renewed_at,
            last_observed_at=lease.observed_at,
            error=lease.last_error,
        )

    async def reconcile_local_core(self, core_id: str) -> int:
        """Re-assert live leases after a normal core/studio account rebuild."""
        leases = await asyncio.to_thread(
            self.repository.active_lease_accounts,
            core_id=core_id, node_id=None, now=self._datetime())
        if not leases:
            return 0
        driver = self.runtime.core_manager.get(core_id)
        applied = 0
        for lease in leases:
            owner = await asyncio.to_thread(self.runtime.users.get_user, lease.user_id)
            if owner is None:
                continue
            account = UserAccount(
                user_id=lease.user_id, username=lease.account_id,
                account_id=lease.account_id, protocol=lease.protocol,
                enabled=True, expire_at=lease.not_after,
                settings=dict(lease.settings),
            )
            await driver.update_account(account)
            applied += 1
        return applied

    async def sweep(self) -> int:
        now = self._datetime()
        due = await asyncio.to_thread(
            self.repository.due_connection_leases, now=now)
        removed = 0
        for lease in due:
            try:
                await self._teardown(lease)
            except Exception as exc:
                await asyncio.to_thread(
                    self.repository.mark_connection_removed,
                    connection_id=lease.connection_id, now=self._datetime(),
                    expired=lease.not_after <= now, error=type(exc).__name__)
                continue
            await asyncio.to_thread(
                self.repository.mark_connection_removed,
                connection_id=lease.connection_id, now=self._datetime(),
                expired=lease.not_after <= now)
            removed += 1
        if removed:
            # Capture disconnect/final counters while historical lease->user
            # attribution still exists in SQL.
            try:
                from app.platform.usage_recorder import record_once
                await record_once(self.runtime)
            except Exception as exc:
                logger.warning("post-lease-teardown usage fold failed: %s", exc)
        return removed

    async def usage_summary(self, *, signed: SignedRequest,
                            access_token: str) -> UsageSummary:
        context = await self._authorize(signed, access_token)
        value = await asyncio.to_thread(
            self.repository.usage_summary,
            context=context, now=self._datetime())
        return UsageSummary.model_validate(value)

    @staticmethod
    def _encode_cursor(value: datetime) -> str:
        raw = json.dumps({"before": int(value.timestamp())},
                         separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    @staticmethod
    def _decode_cursor(value: str) -> datetime:
        try:
            raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            stamp = int(json.loads(raw)["before"])
            return datetime.fromtimestamp(stamp, tz=timezone.utc)
        except Exception as exc:
            raise ValueError("invalid usage cursor") from exc

    async def usage_history(self, *, signed: SignedRequest, access_token: str,
                            start: datetime, end: datetime,
                            granularity: str, limit: int,
                            cursor: str | None) -> UsageHistoryPage:
        context = await self._authorize(signed, access_token)
        now = self._datetime()
        start = start.astimezone(timezone.utc)
        end = min(end.astimezone(timezone.utc), now + timedelta(seconds=1))
        maximum = timedelta(days=7 if granularity == "hour" else 90)
        if start >= end or end - start > maximum:
            raise ValueError("usage history range is invalid or too large")
        before = self._decode_cursor(cursor) if cursor else end
        before = min(before, end)
        records = await asyncio.to_thread(
            self.repository.usage_records,
            context=context, start=start, end=before, now=now)
        buckets: dict[datetime, list[int]] = {}
        for recorded_at, up, down in records:
            value = recorded_at if recorded_at.tzinfo else recorded_at.replace(
                tzinfo=timezone.utc)
            key = (value.replace(minute=0, second=0, microsecond=0)
                   if granularity == "hour" else
                   value.replace(hour=0, minute=0, second=0, microsecond=0))
            totals = buckets.setdefault(key, [0, 0])
            totals[0] += int(up or 0)
            totals[1] += int(down or 0)
        ordered = sorted(buckets, reverse=True)
        selected = ordered[:limit]
        step = timedelta(hours=1 if granularity == "hour" else 24)
        items = [UsageHistoryBucket(
            start=key, end=min(key + step, end),
            uplink_bytes=buckets[key][0], downlink_bytes=buckets[key][1],
            total_bytes=sum(buckets[key]),
        ) for key in selected]
        next_cursor = (self._encode_cursor(selected[-1])
                       if len(ordered) > len(selected) and selected else None)
        return UsageHistoryPage(
            granularity=granularity, from_time=start, to_time=end,
            items=items, next_cursor=next_cursor)
