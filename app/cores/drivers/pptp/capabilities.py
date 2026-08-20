"""Independent, implementation-backed PPTP provider identity."""
from __future__ import annotations

from app.cores.types import FeatureAvailability


def provider_capability(*, installed: bool) -> dict:
    return {
        "provider": "pptp",
        "engine": "accel-ppp",
        "version": "1.14.0",
        "dataplane": "pptp_server",
        "direction": "inbound",
        "state": (FeatureAvailability.SUPPORTED.value if installed
                  else FeatureAvailability.NOT_INSTALLED.value),
        "control": "tcp/1723",
        "carrier": "gre/47",
        "authentication": "MS-CHAPv2",
        "encryption": "MPPE128",
        "network": "IPv4",
        "ipv6": False,
        "security_class": "legacy_insecure",
        "label": "Legacy / Insecure",
        "reason": (
            "Independent ACCEL-PPP server provider; it is not a SoftEther "
            "transport. The optional outbound is a separate pptp-linux/pppd "
            "policy provider with its own lifecycle."
        ),
    }
