"""Central outbound subsystem: registry, materialization, chain resolution."""
from app.cores.outbounds.manager import OutboundManager
from app.cores.outbounds.model import (
    Outbound,
    OutboundDeploymentReport,
    OutboundKind,
    TranslatedOutbound,
    UnsupportedOutbound,
)

__all__ = [
    "OutboundManager",
    "Outbound",
    "OutboundKind",
    "OutboundDeploymentReport",
    "TranslatedOutbound",
    "UnsupportedOutbound",
]
