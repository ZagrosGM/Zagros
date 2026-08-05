"""Zagros Admin API service layer (framework-agnostic use-cases).

Routers stay thin; aggregation logic for the dashboard lives here and is
covered by executable tests with fake providers.
"""
from app.adminapi.dashboard import (
    Alert,
    AlertSeverity,
    CoreHealthView,
    DashboardService,
    DashboardSnapshot,
    LiveUsageGauge,
)

__all__ = [
    "Alert",
    "AlertSeverity",
    "CoreHealthView",
    "DashboardService",
    "DashboardSnapshot",
    "LiveUsageGauge",
]
