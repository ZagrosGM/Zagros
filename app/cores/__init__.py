"""app.cores — the multi-core plugin system (CoreHub).

Xray is just **one** driver among many. The panel talks to cores exclusively
through :class:`CoreManager`; drivers implement :class:`BaseCoreDriver`.

Central subsystems living above the drivers:
  * :mod:`app.cores.routing`   — central rule model + routing engine
  * :mod:`app.cores.outbounds` — outbound registry + chain routing (cycles)
  * :mod:`app.cores.policy`    — global policy engine (quota/time/geo/ASN...)
  * :mod:`app.cores.quota`     — unified per-user quota across all cores
  * :mod:`app.cores.devices`   — unified device registry (global device limit)
  * :mod:`app.cores.sessions`  — unified active sessions + history
  * :mod:`app.cores.qr`        — dependency-free QR generator (share links)

Adding a new core:
    1. create a module under ``app/cores/drivers/<your_core>/``
    2. subclass ``BaseCoreDriver``, set ``metadata``, implement abstract methods
    3. done — it registers itself; no other file changes.

External plugins can also ship via pip + ``zagros.core_drivers`` entry point.
"""
from app.cores.base import BaseCoreDriver
from app.cores.devices import (
    DeviceInfo,
    DeviceManager,
    DeviceStore,
    DeviceViolation,
    InMemoryDeviceStore,
    device_identity,
)
from app.cores.events import Event, EventBus
from app.cores.exceptions import (
    CapabilityNotSupportedError,
    CoreError,
    CoreNotFoundError,
    CoreStateError,
    DriverNotFoundError,
    DriverRegistrationError,
    ProvisioningError,
)
from app.cores.delivery import (
    ArtifactKind,
    DeliveryArtifact,
    DeliveryContext,
    DeliveryField,
    DeliveryProfile,
    DeliverySection,
    ShareLinkError,
    fields_from_mapping,
    is_secret_field,
    profile_from_client_config,
    share_url_for_outbound,
)
from app.cores.manager import CoreManager, CoreStateStore
from app.cores.quota import (
    AppliedUsage,
    DroppedRecord,
    InMemoryQuotaStore,
    QuotaEntry,
    QuotaStore,
    QuotaView,
    UnifiedQuotaService,
)
from app.cores.registry import (
    available_drivers,
    discover_builtin,
    get_driver_class,
    load_entry_points,
    register_driver,
    unregister_driver,
)
from app.cores.sessions import (
    ActiveSession,
    InMemorySessionStore,
    SessionManager,
    SessionRecord,
    SessionReport,
    SessionStore,
)
from app.cores.types import (
    Capability,
    ClientConfig,
    CoreMetadata,
    CoreMetrics,
    CoreState,
    CoreStatus,
    DeviceSession,
    HealthStatus,
    ProvisionResult,
    UsageRecord,
    UserAccount,
)

__all__ = [
    "ArtifactKind",
    "DeliveryArtifact",
    "DeliveryContext",
    "DeliveryField",
    "DeliveryProfile",
    "DeliverySection",
    "ShareLinkError",
    "fields_from_mapping",
    "is_secret_field",
    "profile_from_client_config",
    "share_url_for_outbound",
    # contract
    "BaseCoreDriver",
    # orchestration
    "CoreManager",
    "CoreStateStore",
    # registry
    "available_drivers",
    "discover_builtin",
    "get_driver_class",
    "load_entry_points",
    "register_driver",
    "unregister_driver",
    # central subsystems
    "DeviceInfo",
    "DeviceManager",
    "DeviceStore",
    "DeviceViolation",
    "InMemoryDeviceStore",
    "device_identity",
    "AppliedUsage",
    "DroppedRecord",
    "InMemoryQuotaStore",
    "QuotaEntry",
    "QuotaStore",
    "QuotaView",
    "UnifiedQuotaService",
    "ActiveSession",
    "InMemorySessionStore",
    "SessionManager",
    "SessionRecord",
    "SessionReport",
    "SessionStore",
    # events
    "Event",
    "EventBus",
    # DTOs
    "Capability",
    "ClientConfig",
    "CoreMetadata",
    "CoreMetrics",
    "CoreState",
    "CoreStatus",
    "DeviceSession",
    "HealthStatus",
    "ProvisionResult",
    "UsageRecord",
    "UserAccount",
    # errors
    "CapabilityNotSupportedError",
    "CoreError",
    "CoreNotFoundError",
    "CoreStateError",
    "DriverNotFoundError",
    "DriverRegistrationError",
    "ProvisioningError",
]
