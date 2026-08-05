"""Zagros platform composition root + HTTP wiring.

`PlatformRuntime` wires the environment (ZAGROS_* settings) to the hexagonal
services; `zagros_router` exposes them over HTTP. Routers are thin — every
rule lives in the tested service layer.
"""
from app.platform.runtime import PlatformRuntime, PlatformConfigError

__all__ = ["PlatformRuntime", "PlatformConfigError"]
