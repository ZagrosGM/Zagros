// Pure selection ↔ wire-model mapping for the UNIFIED inbound tree
//.
//
// The dashboard shows ONE tree across every core, but the wire keeps the two
// contracts the backend actually owns:
//
//   * xray branch  → legacy Marzban model: ``inbounds = {protocol: [tags]}``
//     — an INCLUSION list; ``[]`` is canonical for "all inbounds of that
//     protocol" (the server's create/update validator expands an empty list
//     to every tag of the protocol, see app/models/user.py).
//   * every other core → ``core_access = {core_id: [tags]}`` — an explicit
//     grant list; an ABSENT key means "no access on that core".
//
// Keeping this logic pure and in one place means Users / Templates (and any
// future picker host) share exactly one source of truth for the mapping.
import type { InboundCatalogGroup } from "./types";

/** The built-in legacy core id in the unified catalog. */
export const XRAY_CORE_ID = "xray";

/** Legacy model: protocol -> included tags ([] = all tags of the protocol). */
export type LegacyInboundSel = Record<string, string[]>;
/** Multi-core model: core_id -> included tags (absent key = no access). */
export type CoreAccessSel = Record<string, string[]>;

/** Ordered tag list of one catalog group. */
export function tagsOf(group: InboundCatalogGroup): string[] {
  return group.inbounds.map((i) => i.tag);
}

/** protocol -> tags breakdown of one catalog group (entries carry protocol). */
export function tagsByProtocol(group: InboundCatalogGroup): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const i of group.inbounds) (out[i.protocol ?? ""] ??= []).push(i.tag);
  return out;
}

/** xray: canonical "everything selected" — ``{proto: []}`` per protocol. */
export function allLegacySelected(xray: InboundCatalogGroup): LegacyInboundSel {
  return Object.fromEntries(Object.keys(tagsByProtocol(xray)).map((p) => [p, []]));
}

/** Multi-core "everything selected" for all NON-xray groups. */
export function allCoreAccess(groups: InboundCatalogGroup[]): CoreAccessSel {
  const out: CoreAccessSel = {};
  for (const g of groups) {
    if (g.core_id === XRAY_CORE_ID || !g.inbounds.length) continue;
    out[g.core_id] = tagsOf(g);
  }
  return out;
}

/** Which xray tags the legacy model currently selects (for tree display).
 *  ``[]`` under a protocol means every tag of that protocol. */
export function legacySelectedTags(xray: InboundCatalogGroup, sel: LegacyInboundSel): string[] {
  const out: string[] = [];
  for (const [proto, tags] of Object.entries(tagsByProtocol(xray))) {
    if (!(proto in sel)) continue;
    const chosen = sel[proto];
    out.push(...(chosen.length ? tags.filter((t) => chosen.includes(t)) : tags));
  }
  return out;
}

/** Backwards mapping: a tree tag-set → legacy model. A fully selected
 *  protocol canonicalizes to ``[]``; a protocol with zero tags is omitted. */
export function legacyFromTags(xray: InboundCatalogGroup, selected: ReadonlySet<string>): LegacyInboundSel {
  const out: LegacyInboundSel = {};
  for (const [proto, tags] of Object.entries(tagsByProtocol(xray))) {
    const chosen = tags.filter((t) => selected.has(t));
    if (!chosen.length) continue;
    out[proto] = chosen.length === tags.length ? [] : chosen;
  }
  return out;
}
