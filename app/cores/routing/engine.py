"""RoutingEngine — the central, core-agnostic routing subsystem.

Owns rule validation/normalization and fan-out deployment to drivers. Every
core returns an explicit :class:`TranslatedRoute`; cores without routing
capability get deterministic *unsupported* entries so the admin always sees
the full coverage matrix. Persistence of rule-sets lands with the repository
layer (Phase 3); the engine itself stays pure logic + dispatch.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.cores.events import Event, EventBus
from app.cores.exceptions import CoreError, CoreNotFoundError
from app.cores.routing.model import (
    RouteContext,
    RouteDeploymentReport,
    RoutingRule,
    TranslatedRoute,
    UnsupportedRule,
)
from app.cores.types import Capability

if TYPE_CHECKING:
    from app.cores.manager import CoreManager
    from app.cores.outbounds.model import Outbound

logger = logging.getLogger("zagros.cores.routing")


class RoutingEngine:
    """Validates rules and deploys them across cores via their translators."""

    def __init__(
        self, core_manager: "CoreManager", bus: EventBus | None = None,
        *, policy_router=None,
    ) -> None:
        self._cores = core_manager
        self._bus = bus or EventBus()
        self._policy = policy_router
        self._last_report: "RouteDeploymentReport | None" = None

    # ------------------------------------------------------------------ #
    # validation / normalization
    # ------------------------------------------------------------------ #
    def validate(self, rules: list[RoutingRule]) -> list[RoutingRule]:
        """Dedupe names and order ALL rows by (priority, name).

        Disabled rules are persisted and surfaced by the UI; only deployment
        filters them. The old validator dropped them during Save, making the
        enable/disable switch destructive and breaking rollback history.
        """
        seen: set[str] = set()
        normalized: list[RoutingRule] = []
        for rule in rules:
            if rule.name in seen:
                raise CoreError(f"Duplicate routing rule name: '{rule.name}'.")
            seen.add(rule.name)
            normalized.append(rule)
        return sorted(normalized, key=lambda r: (r.priority, r.name))

    # ------------------------------------------------------------------ #
    # dry preview (rule builder "Check coverage" — zero core mutations)
    # ------------------------------------------------------------------ #
    async def preview(
        self,
        rules: list[RoutingRule],
        *,
        core_ids: list[str] | None = None,
        outbounds: list["Outbound"] | None = None,
    ) -> RouteDeploymentReport:
        """Translate the rule set per core WITHOUT applying anything.

        Same report shape as :meth:`deploy` (per-core applied/unsupported
        matrix), so the UI can show coverage before the operator commits.
        """
        normalized = [r for r in self.validate(rules) if r.enabled]
        ctx = RouteContext(
            available_outbounds=[o.name for o in (outbounds or [])],
        )
        targets = core_ids if core_ids is not None else self._cores.list_cores()

        policy = None
        # Xray/sing-box route inside their own processes. The host policy
        # plane only classifies service-core traffic.
        policy_cores = {"openvpn", "wireguard", "softether", "ssh"}
        if self._policy is not None and policy_cores.intersection(targets):
            import asyncio
            policy = await asyncio.to_thread(self._policy.preview_rules, normalized)

        results: dict[str, TranslatedRoute] = {}
        for core_id in targets:
            try:
                driver = self._cores.get(core_id)
            except CoreNotFoundError:
                continue
            if not driver.supports(Capability.ROUTING):
                if policy is not None:
                    results[core_id] = TranslatedRoute(
                        core_id=core_id,
                        applied=list(policy.applied.get(core_id, [])),
                        unsupported=list(policy.unsupported.get(core_id, [])),
                        notes=list(policy.notes.get(core_id, [])),
                    )
                else:
                    results[core_id] = TranslatedRoute(
                        core_id=core_id,
                        unsupported=[
                            UnsupportedRule(
                                rule=r.name,
                                reason=f"Core '{core_id}' has no routing support.",
                            )
                            for r in normalized
                        ],
                        notes=["routing rules are ignored by this core by design"],
                    )
                continue
            results[core_id] = await driver.translate_routing_rules(normalized, ctx)

        return RouteDeploymentReport(results=results)

    # ------------------------------------------------------------------ #
    # deployment
    # ------------------------------------------------------------------ #
    async def deploy(
        self,
        rules: list[RoutingRule],
        *,
        core_ids: list[str] | None = None,
        outbounds: list["Outbound"] | None = None,
    ) -> RouteDeploymentReport:
        """Translate + apply the rule set on every requested core.

        Every rule is accounted for on every core — either in ``applied`` or
        in ``unsupported`` with a reason. Nothing is dropped silently.
        """
        normalized = [r for r in self.validate(rules) if r.enabled]
        ctx = RouteContext(
            available_outbounds=[o.name for o in (outbounds or [])],
        )
        targets = core_ids if core_ids is not None else self._cores.list_cores()

        policy = None
        # Xray/sing-box route inside their own processes. The host policy
        # plane only classifies service-core traffic.
        policy_cores = {"openvpn", "wireguard", "softether", "ssh"}
        if self._policy is not None and policy_cores.intersection(targets):
            import asyncio
            policy = await asyncio.to_thread(self._policy.apply_rules, normalized)

        results: dict[str, TranslatedRoute] = {}
        for core_id in targets:
            try:
                driver = self._cores.get(core_id)
            except CoreNotFoundError:
                logger.warning("Routing deploy: core '%s' not installed; skipped.", core_id)
                continue

            if not driver.supports(Capability.ROUTING):
                if policy is not None:
                    results[core_id] = TranslatedRoute(
                        core_id=core_id,
                        applied=list(policy.applied.get(core_id, [])),
                        unsupported=list(policy.unsupported.get(core_id, [])),
                        notes=list(policy.notes.get(core_id, [])),
                    )
                else:
                    results[core_id] = TranslatedRoute(
                        core_id=core_id,
                        unsupported=[
                            UnsupportedRule(
                                rule=r.name,
                                reason=f"Core '{core_id}' has no routing support.",
                            )
                            for r in normalized
                        ],
                        notes=["routing rules are ignored by this core by design"],
                    )
                continue

            results[core_id] = await driver.deploy_routing_rules(normalized, ctx)

        report = RouteDeploymentReport(results=results)
        self._last_report = report
        await self._bus.emit(
            Event.ROUTE_DEPLOYED,
            {
                "rules": [r.name for r in normalized],
                "gaps": {cid: [u.rule for u in rs.unsupported] for cid, rs in results.items() if rs.unsupported},
            },
        )
        return report

    @property
    def last_report(self) -> "RouteDeploymentReport | None":
        """Most recent deployment report (dashboard/status surfaces)."""
        return self._last_report
