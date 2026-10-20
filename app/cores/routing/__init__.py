"""Central routing subsystem: core-agnostic rules + deployment engine."""
# f-noderouting-2: shared home for the persisted rule-set key — the node
# sync reads the same store the Routing page writes, without importing the
# (huge) admin_api module.
RULES_KV_KEY = "admin.routing.rules.v1"
from app.cores.routing.engine import RoutingEngine
from app.cores.routing.model import (
    RouteContext,
    RouteDeploymentReport,
    RoutingRule,
    RuleAction,
    RuleMatcher,
    RuleScope,
    TranslatedRoute,
    UnsupportedRule,
)

__all__ = [
    "RoutingEngine",
    "RoutingRule",
    "RuleAction",
    "RuleMatcher",
    "RuleScope",
    "RouteContext",
    "RouteDeploymentReport",
    "TranslatedRoute",
    "UnsupportedRule",
]
