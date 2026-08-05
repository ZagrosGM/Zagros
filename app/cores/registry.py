"""Global registry of available core *driver classes*.

Three ways a driver enters the registry — none requires touching existing code:

1. **Auto-registration**: every concrete :class:`BaseCoreDriver` subclass is
   registered at import time via ``__init_subclass__``.
2. **Built-in discovery**: :func:`discover_builtin` imports every module under
   ``app.cores.drivers``.
3. **External plugins**: :func:`load_entry_points` loads pip-installed packages
   exposing the ``zagros.core_drivers`` entry-point group.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import TYPE_CHECKING

from app.cores.exceptions import DriverNotFoundError, DriverRegistrationError

if TYPE_CHECKING:
    from app.cores.base import BaseCoreDriver
    from app.cores.types import CoreMetadata

logger = logging.getLogger("zagros.cores.registry")

_drivers: dict[str, type["BaseCoreDriver"]] = {}


def register_driver(cls: type["BaseCoreDriver"]) -> None:
    """Register a concrete driver class by its ``metadata.id``."""
    meta = getattr(cls, "metadata", None)
    if meta is None:
        raise DriverRegistrationError(
            f"{cls.__name__} has no 'metadata' CoreMetadata attribute."
        )
    existing = _drivers.get(meta.id)
    if existing is not None and existing is not cls:
        raise DriverRegistrationError(
            f"Driver id '{meta.id}' already taken by {existing.__module__}.{existing.__name__}."
        )
    _drivers[meta.id] = cls
    logger.debug("Registered core driver '%s' (%s)", meta.id, cls.__name__)


def get_driver_class(core_id: str) -> type["BaseCoreDriver"]:
    try:
        return _drivers[core_id]
    except KeyError:
        raise DriverNotFoundError(core_id) from None


def available_drivers() -> dict[str, "CoreMetadata"]:
    """Metadata of every installable core type (for ``GET /api/core-types``)."""
    return {cid: cls.metadata for cid, cls in _drivers.items()}


def unregister_driver(core_id: str) -> None:
    """Remove a driver class (used by tests and hot-unload scenarios)."""
    _drivers.pop(core_id, None)


def discover_builtin(package: str = "app.cores.drivers") -> int:
    """Import every built-in driver module; returns how many were imported."""
    pkg = importlib.import_module(package)
    count = 0
    for mod in pkgutil.iter_modules(pkg.__path__, prefix=f"{package}."):
        importlib.import_module(mod.name)
        count += 1
    logger.info("Discovered %d built-in driver module(s).", count)
    return count


def load_entry_points(group: str = "zagros.core_drivers") -> int:
    """Register drivers exposed by installed distributions.

    Example ``pyproject.toml`` of an external plugin::

        [project.entry-points."zagros.core_drivers"]
        wireguard = "my_pkg.wireguard:WireGuardDriver"
    """
    from importlib.metadata import entry_points

    count = 0
    for ep in entry_points(group=group):
        try:
            cls = ep.load()
            register_driver(cls)
            count += 1
        except Exception:
            logger.exception("Failed loading core driver entry point '%s'.", ep.name)
    return count
