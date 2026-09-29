"""Protected profile, device and sealed-config Application use cases."""
from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from app.applicationapi.config_crypto import (
    ApplicationConfigEnvelope,
    ConfigEnvelopeClaims,
    seal_application_config,
)
from app.applicationapi.errors import ApplicationApiError, ProtocolUnavailable
from app.applicationapi.repository import ApplicationAuthRepository, UserAuthContext
from app.applicationapi.resource_models import (
    ApplicationConfigList,
    ApplicationConfigView,
    ApplicationDeviceList,
    ApplicationDeviceView,
    ApplicationProfile,
    DeviceRevokeResult,
)
from app.applicationapi.security import SignedRequest
from app.applicationapi.service import ApplicationAuthService
from app.cores.types import Capability


class ApplicationResourceService:
    def __init__(self, auth: ApplicationAuthService,
                 repository: ApplicationAuthRepository, online_data, *,
                 config_grant_ttl_seconds: int = 60,
                 envelope_ttl_seconds: int = 30,
                 now: Callable[[], float] = time.time) -> None:
        if not 10 <= int(config_grant_ttl_seconds) <= 300:
            raise ValueError("config grant TTL must be between 10 and 300 seconds")
        if not 5 <= int(envelope_ttl_seconds) <= int(config_grant_ttl_seconds):
            raise ValueError("envelope TTL must be positive and no longer than grant TTL")
        self.auth = auth
        self.repository = repository
        self.online_data = online_data
        self.config_grant_ttl_seconds = int(config_grant_ttl_seconds)
        self.envelope_ttl_seconds = int(envelope_ttl_seconds)
        self._now = now

    def _datetime(self) -> datetime:
        return datetime.fromtimestamp(self._now(), tz=timezone.utc)

    async def _authorize(self, *, signed: SignedRequest,
                         access_token: str) -> UserAuthContext:
        return await self.auth.authorize_protected(
            signed=signed, access_token=access_token)

    async def profile(self, *, signed: SignedRequest,
                      access_token: str) -> ApplicationProfile:
        context = await self._authorize(
            signed=signed, access_token=access_token)
        payload = await asyncio.to_thread(
            self.repository.application_profile,
            context=context, now=self._datetime())
        return ApplicationProfile.model_validate(payload)

    async def devices(self, *, signed: SignedRequest,
                      access_token: str) -> ApplicationDeviceList:
        context = await self._authorize(
            signed=signed, access_token=access_token)
        rows = await asyncio.to_thread(
            self.repository.application_devices,
            context=context, now=self._datetime())
        return ApplicationDeviceList(devices=[
            ApplicationDeviceView.model_validate(row) for row in rows])

    async def revoke_device(self, *, signed: SignedRequest,
                            access_token: str, target_device_id: str,
                            password: str, source_ip: str) -> DeviceRevokeResult:
        context = await self._authorize(
            signed=signed, access_token=access_token)
        await self.auth.reauthenticate(
            context=context, password=password, source_ip=source_ip)
        result = await asyncio.to_thread(
            self.repository.revoke_application_device,
            context=context, target_device_key_id=target_device_id,
            source_ip=source_ip, now=self._datetime())
        return DeviceRevokeResult.model_validate(result)

    async def list_configs(self, *, signed: SignedRequest,
                           access_token: str) -> ApplicationConfigList:
        context = await self._authorize(
            signed=signed, access_token=access_token)
        accounts = await self.online_data.get_core_accounts(context.user_id)
        metadata: list[dict] = []
        selectors: list[dict] = []
        for driver, account in accounts:
            core_id = str(driver.metadata.id)
            # Application mode only advertises protocols that can actually
            # mint an independent device lease. In particular, OpenVPN static
            # auth shares one credential and must not become a dead-end item
            # that appears usable but fails at connection start.
            if (Capability.USER_MANAGEMENT not in driver.metadata.capabilities
                    or not driver.device_scoped_leases_supported()):
                continue
            if not account.enabled:
                metadata.append({
                    "config_id": None, "core_id": core_id,
                    "protocol": account.protocol, "engine": "",
                    "display_name": f"{account.protocol} · {driver.metadata.name}",
                    "status": "suspended", "expires_at": None,
                })
                continue
            try:
                config = await driver.build_client_config(account)
                if config.core_id != core_id:
                    raise ValueError("driver returned a mismatched core ID")
                public = config.public_view()
                metadata.append({
                    "config_id": None, "core_id": core_id,
                    "protocol": public["protocol"],
                    "engine": public["engine"],
                    "display_name": public["display_name"],
                    "status": "active", "expires_at": None,
                })
                row = metadata[-1]
                row["_source_account_id"] = account.account_id
                selectors.append({
                    "core_id": core_id,
                    "protocol": account.protocol,
                    "source_account_id": account.account_id,
                })
                del config
            except Exception:  # noqa: BLE001 - never expose driver/secret detail
                metadata.append({
                    "config_id": None, "core_id": core_id,
                    "protocol": account.protocol, "engine": "",
                    "display_name": f"{account.protocol} · {driver.metadata.name}",
                    "status": "unavailable", "expires_at": None,
                })
                await asyncio.to_thread(
                    self.repository.audit, "application.config.denied",
                    application_id=context.application_db_id,
                    user_id=context.user_id, device_id=context.device_db_id,
                    result="denied", reason="metadata_unavailable",
                    detail={"core_id": core_id})

        now = self._datetime()
        expires_at = now + timedelta(seconds=self.config_grant_ttl_seconds)
        grants = await asyncio.to_thread(
            self.repository.issue_config_grants,
            context=context, selectors=selectors,
            now=now, expires_at=expires_at)
        by_selector = {
            (grant.core_id, grant.protocol, grant.source_account_id): grant
            for grant in grants
        }
        for row in metadata:
            grant = by_selector.get((
                row["core_id"], row["protocol"], row.get("_source_account_id")))
            if row["status"] == "active" and grant is not None:
                row["config_id"] = grant.public_id
                row["expires_at"] = grant.expires_at
            row.pop("_source_account_id", None)
        return ApplicationConfigList(configs=[
            ApplicationConfigView.model_validate(row) for row in metadata])

    async def deliver_config(self, *, signed: SignedRequest,
                             access_token: str, config_id: str,
                             delivery_context=None) -> ApplicationConfigEnvelope:
        context = await self._authorize(
            signed=signed, access_token=access_token)
        now = self._datetime()
        try:
            grant = await asyncio.to_thread(
                self.repository.inspect_config_grant,
                context=context, public_id=config_id, now=now)
        except ApplicationApiError:
            await asyncio.to_thread(
                self.repository.audit, "application.config.denied",
                application_id=context.application_db_id,
                user_id=context.user_id, device_id=context.device_db_id,
                result="denied", reason="grant_rejected")
            raise
        lease = await asyncio.to_thread(
            self.repository.connection_for_config,
            context=context, config_id=config_id, now=now)
        accounts = await self.online_data.get_core_accounts(context.user_id)
        selected = next((
            (driver, account) for driver, account in accounts
            if str(driver.metadata.id) == grant.core_id
            and account.account_id == grant.source_account_id
            and account.protocol == grant.protocol and account.enabled
        ), None)
        if selected is None:
            await asyncio.to_thread(
                self.repository.audit, "application.config.denied",
                application_id=context.application_db_id,
                user_id=context.user_id, device_id=context.device_db_id,
                result="denied", reason="protocol_unavailable",
                detail={"core_id": grant.core_id})
            raise ProtocolUnavailable("protocol is not available")
        driver, source_account = selected
        from app.cores.delivery import DeliveryContext
        from app.cores.types import UserAccount

        account = UserAccount(
            user_id=context.user_id,
            username=lease.account_id,
            account_id=lease.account_id,
            protocol=lease.protocol,
            enabled=True,
            expire_at=lease.not_after,
            data_limit_bytes=context.data_limit_bytes,
            settings=dict(lease.settings),
        )
        target_context = delivery_context
        if lease.target_kind == "node":
            address = (await asyncio.to_thread(
                self.repository.connection_node_address, lease.node_id)
                if lease.node_id is not None else None)
            if not address:
                raise ProtocolUnavailable("connection target is unavailable")
            target_context = DeliveryContext(
                public_host=address, force_public_host=True)
        try:
            config = await driver.build_client_config(account, target_context)
            if config.core_id != grant.core_id:
                raise ValueError("driver returned a mismatched core ID")
            document = json.dumps({
                "v": 1,
                "application_id": context.application_public_id,
                "device_id": context.device_key_id,
                "config_id": grant.public_id,
                "connection_id": grant.connection_id,
                "issued_at": int(now.timestamp()),
                "not_before": int(now.timestamp()),
                "expires_at": min(
                    int(grant.expires_at.timestamp()),
                    int(lease.not_after.timestamp()),
                    int(now.timestamp()) + self.envelope_ttl_seconds),
                "config": {
                    "core_id": config.core_id,
                    "protocol": config.protocol,
                    "engine": config.engine,
                    "display_name": config.display_name,
                    "payload": config.payload,
                },
            }, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False).encode()
        except Exception as exc:
            await asyncio.to_thread(
                self.repository.audit, "application.config.denied",
                application_id=context.application_db_id,
                user_id=context.user_id, device_id=context.device_db_id,
                result="denied", reason="config_build_failed",
                detail={"core_id": grant.core_id})
            raise ProtocolUnavailable("protocol config is unavailable") from exc

        # Consume only after a complete payload exists. This is the final
        # transactional authority check and the cross-worker one-time claim.
        try:
            material = await asyncio.to_thread(
                self.repository.consume_config_grant,
                context=context, public_id=config_id, now=self._datetime())
        except ApplicationApiError:
            await asyncio.to_thread(
                self.repository.audit, "application.config.denied",
                application_id=context.application_db_id,
                user_id=context.user_id, device_id=context.device_db_id,
                result="denied", reason="consumption_rejected",
                detail={"core_id": grant.core_id})
            raise
        expires = min(
            int(material.expires_at.timestamp()),
            int(lease.not_after.timestamp()),
            int(now.timestamp()) + self.envelope_ttl_seconds)
        claims = ConfigEnvelopeClaims(
            application_id=material.application_public_id,
            application_key_id=material.config_key_id,
            signing_key_id=material.signing_key_id,
            device_id=material.device_key_id,
            config_id=material.public_id,
            connection_id=material.connection_id,
            core_id=config.core_id,
            protocol=config.protocol,
            engine=config.engine,
            issued_at=int(now.timestamp()),
            not_before=int(now.timestamp()),
            expires_at=expires,
        )
        try:
            envelope = seal_application_config(
                document, claims=claims,
                application_config_private_key=material.config_private_key,
                device_public_key=material.device_public_key,
                application_signing_private_key=material.signing_private_key)
        except Exception as exc:
            await asyncio.to_thread(
                self.repository.audit, "application.config.denied",
                application_id=context.application_db_id,
                user_id=context.user_id, device_id=context.device_db_id,
                result="denied", reason="envelope_failed",
                detail={"core_id": material.core_id})
            del config, document, material
            raise ProtocolUnavailable("config envelope is unavailable") from exc
        await asyncio.to_thread(
            self.repository.audit, "application.config.envelope_issued",
            application_id=context.application_db_id,
            user_id=context.user_id, device_id=context.device_db_id,
            detail={"core_id": material.core_id})
        del config, document, material
        return envelope
