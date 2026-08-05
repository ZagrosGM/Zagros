"""Central routing subsystem: core-agnostic rules + deployment engine."""
from app.cores.routing.engine import RoutingEngine
from app.cores.routing.model import (
    RouteContext,
    RouteDeploymentReport,
    RoutingRule,
    RuleAction,
    RuleMatcher,
    TranslatedRoute,
    UnsupportedRule,
)

__all__ = [
    "RoutingEngine",
    "RoutingRule",
    "RuleAction",
    "RuleMatcher",
    "RouteContext",
    "RouteDeploymentReport",
    "TranslatedRoute",
    "UnsupportedRule",
]
