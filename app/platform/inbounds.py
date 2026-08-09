"""Unified multi-core inbound catalog.

One dashboard view of every selectable inbound across ALL managed cores —
the "Marzban inbounds picker, but multi-core" data source. Two families:

* **studio cores** (xray, sing-box, …): drivers declare a
  ``studio_inbounds_path``; entries come straight from the core's live
  config document (tag / protocol / port).
* **service cores** (openvpn, wireguard, ssh, softether): there is no JSON
  ``inbounds[]`` array — the core IS the service. Entries are derived from
  the core's real settings (listen ports, advertised transports, enabled
  compat protocols) so the UI shows exactly what the server would serve.

Honesty rules: a core that is not installed/enabled yields NO entries (the
picker must never offer what cannot be provisioned), and derivation sticks
to driver-declared facts — no invented protocols.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class CatalogInbound:
    tag: str
    protocol: str
    port: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"tag": self.tag, "protocol": self.protocol, "port": self.port}


@dataclass
class CatalogGroup:
    core_id: str
    name: str
    enabled: bool
    inbounds: list[CatalogInbound] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "core_id": self.core_id,
            "name": self.name,
            "enabled": self.enabled,
            "inbounds": [i.as_dict() for i in self.inbounds],
        }


# service-core derivations: core_id → list of (tag, protocol, settings-port-key)
_SERVICE_ENTRIES: dict[str, tuple[tuple[str, str, str | None], ...]] = {
    "openvpn": (
        ("openvpn-tcp", "openvpn", "port"),
        ("openvpn-udp", "openvpn", "port"),
    ),
    "wireguard": (("wireguard", "wireguard", "port"),),
    "ssh": (("ssh", "ssh", "port"),),
    "softether": (
        ("l2tp", "l2tp", None),
        ("sstp", "sstp", None),
        ("pptp", "pptp", None),
        ("softether", "ovpn", None),
    ),
}


def _doc_inbounds(doc: Any) -> list[CatalogInbound]:
    """inbound entries out of a studio OR native-core config document.

    Both shapes are accepted (alpha.7.5 item 17): the studio payload
    (tag/protocol/port) AND native core renders (sing-box/xray carry
    'type' + 'listen_port').
    """
    if not doc:
        return []
    try:
        data = json.loads(doc) if isinstance(doc, str) else doc
    except json.JSONDecodeError:
        return []
    out: list[CatalogInbound] = []
    for item in data.get("inbounds") or []:
        if not isinstance(item, dict):
            continue
        tag = item.get("tag")
        protocol = item.get("protocol") or item.get("type")
        if not tag or not protocol:
            continue
        out.append(CatalogInbound(
            tag=str(tag), protocol=str(protocol),
            port=item.get("port", item.get("listen_port"))))
    return out


async def _studio_inbounds(runtime, core_id: str) -> list[CatalogInbound]:
    doc = await runtime.studio_store.get_document(core_id)
    found = _doc_inbounds(doc)
    if found:
        return found
    if core_id in _SERVICE_ENTRIES:
        return []  # healthy static fallback below in catalog()
    # Studio-first cores (sing-box & co, alpha.7.5 item 17): with NO
    # persisted studio document the EFFECTIVE inbound set lives in the
    # driver's live render (derived listeners exist as soon as accounts do,
    # with zero studio state). A fresh core with no accounts still exports
    # zero inbounds — by design a "clean start" — and simply stays out of
    # host-facing surfaces until its first inbound/user.
    try:
        driver = runtime.core_manager.get(core_id)
        export = getattr(driver, "export_config_document", None)
        doc = export() if callable(export) else None
    except Exception:  # noqa: BLE001 — a broken driver must not blank the page
        logger.warning("export_config_document failed for core %s", core_id)
        return []
    return _doc_inbounds(doc)


def _service_inbounds(core_id: str, settings: dict[str, Any]) -> list[CatalogInbound]:
    out: list[CatalogInbound] = []
    for tag, protocol, port_key in _SERVICE_ENTRIES.get(core_id, ()):
        port = None
        if port_key is not None:
            try:
                port = int(settings.get(port_key)) if settings.get(port_key) else None
            except (TypeError, ValueError):
                port = None
        out.append(CatalogInbound(tag=tag, protocol=protocol, port=port))
    return out


def _legacy_xray_group() -> CatalogGroup | None:
    """The always-on legacy xray core (Marzban stack) — inbound truth comes
    from its RUNNING config (``xray.config.inbounds_by_protocol``), exactly
    like the legacy ``/api/inbounds`` endpoint serves. Shown in the catalog
    so admins see one unified tree; GRANTS on "xray" stay governed by the
    legacy proxies path (provisioning skips it by design)."""
    try:
        from app import xray
    except Exception:  # noqa: BLE001 — minimal installs without the legacy core
        return None
    groups = getattr(xray.config, "inbounds_by_protocol", None) or {}
    inbounds: list[CatalogInbound] = []
    for protocol, items in groups.items():
        for item in items:
            tag = item.get("tag") if isinstance(item, dict) else getattr(item, "tag", None)
            port = item.get("port") if isinstance(item, dict) else getattr(item, "port", None)
            if tag:
                inbounds.append(CatalogInbound(tag=str(tag), protocol=str(protocol), port=port))
    if not inbounds:
        return None
    return CatalogGroup(core_id="xray", name="Xray (built-in)", enabled=True,
                        inbounds=inbounds)


async def catalog(runtime) -> list[CatalogGroup]:
    """All selectable inbounds across installed & enabled cores."""
    manager = runtime.core_manager
    groups: list[CatalogGroup] = []
    legacy = _legacy_xray_group()
    if legacy is not None:
        groups.append(legacy)
    for core_id in manager.list_cores():
        if not manager.is_enabled(core_id):
            continue
        if core_id == "xray":
            # covered by _legacy_xray_group above (the running legacy config is
            # the inbound truth for the built-in engine) — never emit twice.
            continue
        try:
            driver = manager.get(core_id)
        except Exception:  # noqa: BLE001 — not loaded: skip honestly
            continue
        settings = getattr(driver, "settings", {}) or {}
        try:
            inbounds = await _studio_inbounds(runtime, core_id)
        except Exception as exc:  # noqa: BLE001 — fall back to service entries
            logger.warning("studio read failed for core %s: %s", core_id, exc)
            inbounds = []
        if not inbounds:
            inbounds = _service_inbounds(core_id, settings)
        groups.append(CatalogGroup(
            core_id=core_id,
            name=driver.metadata.name or core_id,
            enabled=True,
            inbounds=inbounds,
        ))
    return groups
