"""Exception hierarchy for the multi-core plugin system.

All errors raised by the core abstraction layer derive from ``CoreError``
so API layers can map them to HTTP codes with a single exception handler.
"""
from __future__ import annotations


class CoreError(Exception):
    """Base class for every core-management error."""


class DriverRegistrationError(CoreError):
    """A driver class is invalid, has no metadata, or its id conflicts."""


class DriverNotFoundError(CoreError):
    """No driver class is registered for the requested core type."""

    def __init__(self, core_id: str):
        self.core_id = core_id
        super().__init__(f"No driver registered for core type '{core_id}'.")


class CoreNotFoundError(CoreError):
    """The requested core instance is not installed/managed."""

    def __init__(self, core_id: str):
        self.core_id = core_id
        super().__init__(f"Core '{core_id}' is not installed or not managed.")


class CoreStateError(CoreError):
    """Illegal lifecycle transition for the current state of a core."""


class CapabilityNotSupportedError(CoreError):
    """The driver does not implement a requested capability."""

    def __init__(self, core_id: str, capability: str):
        self.core_id = core_id
        self.capability = capability
        super().__init__(
            f"Core '{core_id}' does not support capability '{capability}'."
        )


class ProvisioningError(CoreError):
    """Fan-out provisioning finished with one or more failed cores.

    Carries every per-core ``ProvisionResult`` so callers can mark the
    affected ``user_core_accounts`` rows for later ``sync`` reconciliation.
    """

    def __init__(self, results: list):
        self.results = results
        self.failed_cores = [r.core_id for r in results if not r.success]
        super().__init__(
            f"Provisioning failed on cores: {', '.join(self.failed_cores)}"
        )
