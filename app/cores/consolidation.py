"""Core consolidation — standalone hysteria2/tuic cores fold into sing-box.

Architecture decision (alpha.7.2, batch item 1), recorded with evidence:

* **TUIC v5**: ``tuic-server`` exposes NO stats/online API at all — per-user
  accounting was *impossible* on the standalone core (documented in its own
  driver). Through sing-box's native ``tuic`` inbound + the vendored
  ``with_v2ray_api`` build, TUIC users get real per-user counters for the
  first time. Consolidation is the only path to unified quota for TUIC.
* **Hysteria 2**: the standalone driver *did* have usage accounting (the
  official ``/traffic`` API), but sing-box serves the identical protocol
  natively and equips it with the same v2ray-API accounting — one verified
  protocol × transport × security matrix (26/26 cells probed against the
  real binary) instead of two divergent ones, and one fewer daemon,
  installer, health surface and failure mode to operate.
* The sing-box studio blueprint already hosts both protocols
  (``hysteria2``/``tuic`` wizard entries verified against sing-box 1.12.4),
  so delivery/catalog/provisioning infrastructure needs no new concepts.

This module is the SINGLE source of truth for moving standalone-core state
into the sing-box core. Alembic revision ``0007_core_consolidation`` is a
thin IO shell around these pure functions. Everything here is deterministic
and unit-testable: callers inject file material (TLS certs) explicitly.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

#: cores that no longer exist as independent engines after alpha.7.2 —
#: their protocol layer lives on inside the sing-box core.
MERGED_CORES: tuple[str, str] = ("hysteria2", "tuic")

#: the core that absorbs every merged-core listener and account.
TARGET_CORE_ID = "sing-box"

#: standalone-driver studio-doc bookkeeping keys that are NOT wizard fields
#: (UI hints about driver-internal state). They must never reach sing-box's
#: strict translator (unknown keys are refused loudly, by design).
_BOOKKEEPING_KEYS = ("has_obfs", "has_certificate")


class ConsolidationError(ValueError):
    """A merged-core document row is malformed — fail loudly, never guess."""


def _protocol_for(core_id: str) -> str:
    if core_id not in MERGED_CORES:
        raise ConsolidationError(
            f"'{core_id}' is not a consolidated core {MERGED_CORES}."
        )
    return core_id  # protocol name == old core id, by design


def _int_mbps(value: Any, *, field: str, tag: str) -> int | None:
    """Standalone hy2 stored bandwidth as free strings ("100", "100 mbps");
    sing-box hy2 takes integer Mbps. Parse the leading integer; anything
    else is rejected loudly (a silent 0 would *change* the user's limits)."""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    head = str(value).strip().split()[0] if str(value).strip() else ""
    try:
        return int(head)
    except ValueError as exc:
        raise ConsolidationError(
            f"merged inbound '{tag}': {field} value {value!r} is not an "
            "integer Mbps figure sing-box can serve — edit it before migrating."
        ) from exc


def translate_entry(
    core_id: str,
    entry: Mapping[str, Any],
    *,
    certificate: str | None = None,
    certificate_key: str | None = None,
) -> dict[str, Any]:
    """One standalone-driver studio entry → sing-box wizard-shape entry.

    The result is a *wizard-shape* entry (``protocol``/``port``/…, NOT native
    ``type``/``listen_port``) so it flows through sing-box's strict,
    verified translator exactly like a wizard-built inbound. TLS is always
    declared: both protocols are TLS-mandatory, and the sing-box translator
    generates a fresh self-signed pair when no certificate material is
    supplied (identical to the standalone drivers' default behavior).
    """
    proto = _protocol_for(core_id)
    if not isinstance(entry, Mapping):
        raise ConsolidationError(
            f"{core_id} studio entry is not an object: {entry!r}"
        )
    doc_proto = entry.get("protocol") or proto
    if doc_proto != proto:
        raise ConsolidationError(
            f"a {core_id} studio document cannot host a '{doc_proto}' listener."
        )
    tag = str(entry.get("tag") or proto)
    out: dict[str, Any] = {
        "tag": tag,
        "protocol": proto,
        "listen": entry.get("listen") or "::",
        "port": int(entry.get("port") or (443 if proto == "hysteria2" else 8443)),
        "security": "tls",
        "transport": "quic",
        "sni": str(entry.get("sni") or ""),
    }
    if proto == "hysteria2":
        for src, dst in (("up_mbps", "up_mbps"), ("down_mbps", "down_mbps"),
                         ("bandwidth_up", "up_mbps"), ("bandwidth_down", "down_mbps")):
            mbps = _int_mbps(entry.get(src), field=src, tag=tag)
            if mbps:
                out[dst] = mbps
        if entry.get("obfs"):
            out["obfs"] = str(entry["obfs"])
        elif entry.get("has_obfs") and entry.get("obfs_password"):
            out["obfs"] = str(entry["obfs_password"])
        if entry.get("masquerade"):
            out["masquerade"] = str(entry["masquerade"])
    else:  # tuic
        if entry.get("congestion_control"):
            out["congestion_control"] = str(entry["congestion_control"])
        if entry.get("zero_rtt") is not None:
            out["zero_rtt"] = bool(entry.get("zero_rtt"))
        elif entry.get("zero_rtt_handshake") is not None:
            out["zero_rtt"] = bool(entry.get("zero_rtt_handshake"))
    if certificate and certificate_key:
        out["certificate"] = str(certificate)
        out["certificate_key"] = str(certificate_key)
    # driver bookkeeping never crosses over (has_obfs/has_certificate)
    for key in _BOOKKEEPING_KEYS:
        out.pop(key, None)
    return out


def synthesize_default_entry(
    core_id: str,
    settings: Mapping[str, Any] | None,
    *,
    certificate: str | None = None,
    certificate_key: str | None = None,
) -> dict[str, Any]:
    """Sing-box wizard-shape entry for a merged core that has NO studio
    document (the operator never opened the studio — the driver served from
    plain settings). Mirrors the old drivers' ``export_config_document``
    seed so the listener survives with identical port/sni/obfs/bandwidth."""
    proto = _protocol_for(core_id)
    s = dict(settings or {})
    if proto == "hysteria2":
        raw: dict[str, Any] = {
            "tag": "hysteria2",
            "protocol": "hysteria2",
            "listen": s.get("listen") or "::",
            "port": int(s.get("port") or 443),
            "sni": s.get("advertise_sni") or s.get("cert_common_name") or "",
            "masquerade": s.get("masquerade_url") or "",
            "up_mbps": s.get("bandwidth_up") or "",
            "down_mbps": s.get("bandwidth_down") or "",
            "obfs": s.get("obfs_password") or "",
        }
    else:
        raw = {
            "tag": "tuic",
            "protocol": "tuic",
            "listen": str(s.get("listen") or "[::]"),
            "port": int(s.get("port") or 8443),
            "sni": s.get("advertise_sni") or s.get("cert_common_name") or "",
            "congestion_control": s.get("congestion_control") or "bbr",
            "zero_rtt": bool(s.get("zero_rtt_handshake", False)),
        }
    return translate_entry(
        core_id, raw, certificate=certificate, certificate_key=certificate_key,
    )


def merge_inbound_entries(
    existing: Iterable[Mapping[str, Any]],
    incoming: Iterable[tuple[str, Mapping[str, Any]]],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Append translated entries to the sing-box document, resolving tag
    collisions deterministically.

    ``incoming`` items are ``(origin_core_id, translated_entry)`` pairs.
    A tag already present (or claimed twice by merged cores) is renamed to
    ``"{tag}-from-{core_id}"`` (suffixed further if that collides too) and
    recorded in the returned ``renames`` map as ``"{core_id}:{old}" -> new``
    so grant rows can be re-pointed at the renamed inbound tag.
    """
    merged = [dict(e) for e in existing]
    used = {str(e.get("tag")) for e in merged}
    renames: dict[str, str] = {}
    for core_id, entry in incoming:
        item = dict(entry)
        tag = str(item.get("tag") or "")
        if not tag:
            raise ConsolidationError(
                f"merged {core_id} entry without a tag: {entry!r}"
            )
        if tag in used:
            candidate = f"{tag}-from-{core_id}"
            suffix = 2
            while candidate in used:
                candidate = f"{tag}-from-{core_id}-{suffix}"
                suffix += 1
            renames[f"{core_id}:{tag}"] = candidate
            item["tag"] = candidate
        used.add(str(item["tag"]))
        merged.append(item)
    return merged, renames


def merge_core_access(
    access: Mapping[str, Any] | None,
    renames: Mapping[str, str],
) -> dict[str, list[str]] | None:
    """Re-point a ``core_access`` grant mapping ({core_id: [tags]}).

    Merged cores fold into ``sing-box``: their tag lists are unioned with any
    existing sing-box selection (deduplicated, order preserved) and renamed
    tags re-pointed. Unknown cores pass through untouched. ``None`` in,
    ``None`` out (the column stays NULL for legacy users without grants).
    """
    if access is None:
        return None
    if not isinstance(access, Mapping):
        raise ConsolidationError(f"core_access must be an object, got {access!r}")
    out: dict[str, list[str]] = {}
    for core_id, tags in access.items():
        target = TARGET_CORE_ID if core_id in MERGED_CORES else str(core_id)
        bucket = out.setdefault(target, [])
        for tag in tags or []:
            tag = str(tag)
            renamed = renames.get(f"{core_id}:{tag}", tag)
            if renamed not in bucket:
                bucket.append(renamed)
    return out
