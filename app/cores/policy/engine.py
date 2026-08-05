"""PolicyEngine — pure admission logic + enforcement classification.

Two layers of truth:
  * **Panel-enforced** (always works, independent of the core): quota, expiry,
    device slots, allowed hours, IP caps — decided at API/login/connect time
    and re-checked by scheduled teardown via ``CoreManager``.
  * **Core-enforced** (native, real-time): speed caps, geo blocks — only where
    the driver advertises the matching capability. ``enforcement_map`` tells
    the admin exactly which layer is responsible for which constraint, and
    ``to_block_rules`` converts geo/ASN locks into routing rules for cores
    that CAN enforce them natively.

The engine itself is side-effect free: every decision is a pure function.
"""
from __future__ import annotations

from app.cores.policy.model import (
    AdmissionContext,
    PolicyDecision,
    PolicyProfile,
    Violation,
)
from app.cores.routing.model import RuleAction, RuleMatcher, RoutingRule
from app.cores.types import Capability


class PolicyEngine:
    """Evaluates a :class:`PolicyProfile` against an :class:`AdmissionContext`."""

    # ------------------------------------------------------------------ #
    # admission
    # ------------------------------------------------------------------ #
    def evaluate(self, profile: PolicyProfile, ctx: AdmissionContext) -> PolicyDecision:
        violations: list[Violation] = []

        if profile.expire_at is not None and ctx.now >= profile.expire_at:
            violations.append(Violation.EXPIRED)

        if profile.data_limit_bytes is not None and ctx.used_bytes >= profile.data_limit_bytes:
            violations.append(Violation.QUOTA_EXCEEDED)

        if (
            profile.device_limit is not None
            and ctx.device_uid not in ctx.active_device_uids
            and len(ctx.active_device_uids) >= profile.device_limit
        ):
            violations.append(Violation.DEVICE_LIMIT_REACHED)

        if (
            profile.max_ips is not None
            and ctx.client_ip is not None
            and ctx.client_ip not in ctx.active_ips
            and len(set(ctx.active_ips)) >= profile.max_ips
        ):
            violations.append(Violation.IP_LIMIT_REACHED)

        if profile.allowed_hours and not any(
            window.contains(ctx.now) for window in profile.allowed_hours
        ):
            violations.append(Violation.OUTSIDE_ALLOWED_HOURS)

        if ctx.country is not None:
            country = ctx.country.lower()
            if profile.allowed_countries is not None and country not in {
                c.lower() for c in profile.allowed_countries
            }:
                violations.append(Violation.COUNTRY_NOT_ALLOWED)
            if country in {c.lower() for c in profile.blocked_countries}:
                violations.append(Violation.COUNTRY_BLOCKED)

        if ctx.asn is not None:
            if profile.allowed_asns is not None and ctx.asn not in profile.allowed_asns:
                violations.append(Violation.ASN_NOT_ALLOWED)
            if ctx.asn in profile.blocked_asns:
                violations.append(Violation.ASN_BLOCKED)

        return PolicyDecision(allowed=not violations, violations=violations)

    # ------------------------------------------------------------------ #
    # enforcement classification (transparency for the admin UI)
    # ------------------------------------------------------------------ #
    #: which capability lets a core natively enforce a constraint
    _NATIVE_CAPABILITY = {
        "speed_limit_kbps": Capability.SPEED_LIMIT,
        "country_lock": Capability.GEO_ROUTING,
    }

    def enforcement_map(
        self, profile: PolicyProfile, capabilities: set[Capability]
    ) -> dict[str, str]:
        """constraint → 'panel' | 'core' | 'unsupported' for a given core."""
        mapping: dict[str, str] = {}
        for constraint in profile.active_constraints():
            required = self._NATIVE_CAPABILITY.get(constraint)
            if required is None:
                mapping[constraint] = "panel"
            elif required in capabilities:
                mapping[constraint] = "core"
            else:
                mapping[constraint] = "unsupported-on-core (panel fallback)"
        return mapping

    # ------------------------------------------------------------------ #
    # geo locks -> routing rules (for cores with GEO_ROUTING)
    # ------------------------------------------------------------------ #
    def to_block_rules(self, profile: PolicyProfile) -> list[RoutingRule]:
        """Convert geo locks into native block rules.

        A whitelist (``allowed_countries``) cannot be expressed natively on
        most cores (no "not-in-set" geoip on xray) — the panel enforces it at
        admission; blacklist becomes routing rules.
        """
        rules: list[RoutingRule] = []
        if profile.blocked_countries:
            rules.append(
                RoutingRule(
                    name="policy-country-block",
                    matcher=RuleMatcher(
                        geoips=[c.lower() for c in profile.blocked_countries]
                    ),
                    action=RuleAction.BLOCK,
                    priority=10,
                )
            )
        return rules
