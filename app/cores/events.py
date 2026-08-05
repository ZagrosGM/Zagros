"""In-process async pub/sub event bus.

Domain events decouple user/admin actions from core provisioning: services
publish, the CoreManager (and notification/reporting subsystems) subscribe.
Replaces today's hardwired calls into ``app.xray.operations``.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Any

logger = logging.getLogger("zagros.cores.events")


class Event(str, Enum):
    # user lifecycle
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_ENABLED = "user.enabled"
    USER_DISABLED = "user.disabled"
    USER_EXPIRED = "user.expired"
    USER_DATA_LIMIT_REACHED = "user.data_limit_reached"
    # core lifecycle
    CORE_STATE_CHANGED = "core.state_changed"
    CORE_HEALTH_CHANGED = "core.health_changed"
    # platform subsystems
    ROUTE_DEPLOYED = "routing.deployed"
    POLICY_VIOLATION = "policy.violation"
    DEVICE_BLOCKED = "device.blocked"
    DEVICE_REMOVED = "device.removed"


EventPayload = dict[str, Any]
EventHandler = Callable[[EventPayload], Awaitable[None]]


class EventBus:
    """Minimal, dependency-free async event bus (thread-unsafe by design)."""

    def __init__(self) -> None:
        self._handlers: dict[Event, list[EventHandler]] = defaultdict(list)

    def subscribe(self, event: Event, handler: EventHandler) -> Callable[[], None]:
        """Attach a handler; returns an unsubscribe callable."""
        self._handlers[event].append(handler)

        def _unsubscribe() -> None:
            with contextlib.suppress(ValueError):
                self._handlers[event].remove(handler)

        return _unsubscribe

    async def emit(self, event: Event, payload: EventPayload | None = None) -> None:
        """Fan out to all handlers concurrently; one failure never blocks others."""
        handlers = list(self._handlers.get(event, ()))
        if not handlers:
            return
        results = await asyncio.gather(
            *(h(payload or {}) for h in handlers), return_exceptions=True
        )
        for handler, result in zip(handlers, results):
            if isinstance(result, BaseException):
                logger.error(
                    "Handler %r failed for event '%s'",
                    getattr(handler, "__qualname__", handler),
                    event.value,
                    exc_info=result,
                )

    def clear(self) -> None:
        self._handlers.clear()
