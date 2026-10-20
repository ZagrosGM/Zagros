"""Central outbound subsystem: registry, materialization, chain resolution."""
# f-noderouting-2: shared home for the persisted outbound-profile key.
OUTBOUNDS_KV_KEY = "admin.outbounds.v1"
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
