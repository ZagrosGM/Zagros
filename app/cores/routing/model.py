"""Core-agnostic routing rule model (the panel's single source of truth).

Admins define :class:`RoutingRule` once; every driver's translator maps it to
its native format (xray ``routing.rules``, sing-box ``route.rules``, ...).
A driver must *report* what it cannot translate (:class:`UnsupportedRule`) —
silently dropping rules is considered a bug and is caught by tests.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator

_HOST_PORT = re.compile(r"^[A-Za-z0-9.\-_]+:\d{1,5}$")


class RuleAction(str, Enum):
    ALLOW = "allow"            # forward via the core's default/direct path
    BLOCK = "block"            # reject/blackhole
    ROUTE_TO = "route_to"      # forward via a named outbound (chain hook)
    REDIRECT = "redirect"      # rewrite destination to host:port
    DNS = "dns"                # hijack/special DNS handling
    FAKE_DNS = "fake_dns"      # synthetic A-record answers (fakeip/fakedns)
    DNS_OVERRIDE = "dns_override"  # static DNS override for matched names


class RuleMatcher(BaseModel):
    """Field-level matchers; a rule matches when ALL non-empty fields match."""

    inbounds: list[str] = Field(default_factory=list)            # inbound tags (e.g. "reality-in")
    domains: list[str] = Field(default_factory=list)            # exact hosts
    domain_suffixes: list[str] = Field(default_factory=list)    # example.com + *.example.com
    domain_keywords: list[str] = Field(default_factory=list)
    domain_regexes: list[str] = Field(default_factory=list)
    geosites: list[str] = Field(default_factory=list)           # geosite:google / category-ir...
    geoips: list[str] = Field(default_factory=list)             # country codes: ir, cn, private...
    ip_cidrs: list[str] = Field(default_factory=list)
    source_ip_cidrs: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    port_ranges: list[str] = Field(default_factory=list)        # "8000-8100"
    process_names: list[str] = Field(default_factory=list)      # where supported (sing-box)
    protocols: list[str] = Field(default_factory=list)          # sniffed: tls/http/quic/bittorrent...
    networks: list[str] = Field(default_factory=list)           # "tcp" / "udp"

    def used_fields(self) -> list[str]:
        return [name for name in type(self).model_fields if getattr(self, name)]

    def is_empty(self) -> bool:
        return not self.used_fields()


class RuleScope(BaseModel):
    """f-routingscope-1 (installer FR groundwork): WHERE a rule applies.

    ``everywhere`` (default) reproduces today's behaviour exactly. ``master``
    pins a rule to the master's own policy plane. ``{"nodes": [ids]}`` targets
    specific node ids — such rules are EXCLUDED from the master's deploy and
    reported as ``skipped_by_scope``; since f-noderouting-2 they ARE pushed
    to exactly those nodes.
    """
    nodes: list[int] = Field(default_factory=list)

    def targets_nodes_only(self) -> bool:
        """True when the rule is pinned to specific node ids and must stay
        OFF the master's own deploy (it travels via the node policy plane)."""
        return bool(self.nodes)

    def applies_on_master(self) -> bool:
        """Historical name kept for call sites/tests: True when this rule is
        NOT node-pinned, i.e. it deploys on the master like any default rule.
        Prefer the explicit :meth:`targets_nodes_only` at new call sites."""
        return not self.targets_nodes_only()

    def applies_on_node(self, node_id: int) -> bool:
        """f-noderouting-2: default scopes reach EVERY node; a scoped rule
        reaches only the nodes it lists."""
        return not self.nodes or int(node_id) in {int(n) for n in self.nodes}


def effective_rules_for_node(rules: list["RoutingRule"],
                             node_id: int) -> list["RoutingRule"]:
    """The rule set ONE node should enforce (f-noderouting-2, phase A)."""
    return [r for r in rules if r.enabled and r.scope.applies_on_node(node_id)]


class RoutingRule(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    matcher: RuleMatcher = Field(default_factory=RuleMatcher)
    action: RuleAction
    outbound: str | None = None            # target outbound name for ROUTE_TO
    redirect_to: str | None = None         # host:port for REDIRECT
    dns_server: str | None = None          # optional DNS target for DNS/DNS_OVERRIDE
    priority: int = 100                    # lower evaluates first
    enabled: bool = True
    scope: RuleScope = Field(default_factory=RuleScope)

    @model_validator(mode="after")
    def _validate(self) -> "RoutingRule":
        if self.matcher.is_empty():
            raise ValueError(f"Routing rule '{self.name}' has an empty matcher.")
        if self.action is RuleAction.ROUTE_TO and not self.outbound:
            raise ValueError(f"Rule '{self.name}': action route_to requires 'outbound'.")
        if self.action is RuleAction.REDIRECT and not (
            self.redirect_to and _HOST_PORT.match(self.redirect_to)
        ):
            raise ValueError(
                f"Rule '{self.name}': action redirect requires 'redirect_to' as host:port."
            )
        return self


class UnsupportedRule(BaseModel):
    """Explicit gap report — the admin UI surfaces these, never silent drops."""

    rule: str
    reason: str
    fields: list[str] = Field(default_factory=list)


class RouteContext(BaseModel):
    """What a translator may reference: known outbound names etc."""

    available_outbounds: list[str] = Field(default_factory=list)
    dns_override_target: str | None = None


class TranslatedRoute(BaseModel):
    """Per-core deployment result."""

    core_id: str
    applied: list[str] = Field(default_factory=list)        # rule names
    unsupported: list[UnsupportedRule] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    payload: dict[str, Any] | None = None                    # native form (opaque)

    @property
    def complete(self) -> bool:
        return not self.unsupported


class RouteDeploymentReport(BaseModel):
    results: dict[str, TranslatedRoute]
    deployed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    # f-routingscope-1: node-scoped rules excluded from THIS host's deploy,
    # with the reason — the operator sees what is stored but not applied.
    skipped_by_scope: list[dict[str, str]] = Field(default_factory=list)

    @property
    def gaps(self) -> dict[str, list[UnsupportedRule]]:
        """Cores with reported gaps — drives the admin warning banner."""
        return {cid: r.unsupported for cid, r in self.results.items() if r.unsupported}
