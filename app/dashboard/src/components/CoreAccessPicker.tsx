// CoreAccessPicker — the unified INBOUND TREE (alpha.7.2, item 11).
//
// Contract:
//   * EVERY core of the catalog appears as one tree row (xray included) —
//     fed live from GET /zagros/inbounds;
//   * toggling a core row selects/deselects ALL of its inbounds (with an
//     indeterminate state for partial selections);
//   * the ⋯ button next to each core opens a per-inbound checklist — a
//     portal-mounted RowMenu, so it is never clipped inside dialogs;
//   * wire models stay honest: the xray row edits the legacy proxies model
//     (xrayValue/xrayValueChange), the other rows edit core_access
//     (value/ onChange). The pure mapping lives in lib/inboundTree.ts.
import { Box, MoreHorizontal } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import {
  XRAY_CORE_ID, allLegacySelected, legacyFromTags, legacySelectedTags, tagsOf,
  type CoreAccessSel, type LegacyInboundSel,
} from "../lib/inboundTree";
import type { InboundCatalogGroup } from "../lib/types";
import { Badge } from "./ui";
import { RowMenu } from "./overlays";

interface Props {
  groups: InboundCatalogGroup[];
  value: CoreAccessSel;
  onChange: (next: CoreAccessSel) => void;
  /** xray branch state (legacy proxies model) — required, the tree always
   *  lists xray too. */
  xrayValue: LegacyInboundSel;
  onXrayChange: (next: LegacyInboundSel) => void;
  /** Template hosts: an EMPTY legacy selection means "all of them" there.
   *  When true (and untouched), the xray row displays everything selected. */
  xrayWildcardAll?: boolean;
  disabled?: boolean;
}

function TriCheck({ state, onToggle, disabled, label }: {
  state: "on" | "off" | "partial";
  onToggle: () => void;
  disabled?: boolean;
  label: string;
}) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = state === "partial";
  }, [state]);
  return (
    <input
      ref={ref} type="checkbox" checked={state === "on"} disabled={disabled}
      onChange={onToggle} aria-label={label}
      className="h-4 w-4 shrink-0 cursor-pointer accent-brand disabled:cursor-not-allowed"
    />
  );
}

export default function CoreAccessPicker({ groups, value, onChange, xrayValue, onXrayChange, xrayWildcardAll, disabled }: Props) {
  const [menu, setMenu] = useState<{ core: string; anchor: HTMLElement } | null>(null);

  const selectedFor = (g: InboundCatalogGroup): string[] => {
    if (g.core_id === XRAY_CORE_ID) {
      if (xrayWildcardAll && Object.keys(xrayValue).length === 0) return tagsOf(g);
      return legacySelectedTags(g, xrayValue);
    }
    return value[g.core_id] ?? [];
  };

  const applySelection = (g: InboundCatalogGroup, nextTags: string[]) => {
    if (g.core_id === XRAY_CORE_ID) {
      onXrayChange(legacyFromTags(g, new Set(nextTags)));
      return;
    }
    const next = { ...value };
    if (nextTags.length) next[g.core_id] = nextTags;
    else delete next[g.core_id];
    onChange(next);
  };

  const toggleCore = (g: InboundCatalogGroup, on: boolean) =>
    applySelection(g, on ? tagsOf(g) : []);

  const totalSelected = groups.reduce((n, g) => n + selectedFor(g).length, 0);
  const totalInbounds = groups.reduce((n, g) => n + g.inbounds.length, 0);
  const menuGroup = menu ? groups.find((g) => g.core_id === menu.core) : undefined;

  return (
    <div className="space-y-2.5">
      <div className="flex items-center justify-between">
        <p className="text-[12px] font-medium text-content-2">inbound tree — every core</p>
        {totalInbounds > 0 && <Badge tone="brand">{totalSelected}/{totalInbounds} selected</Badge>}
      </div>
      {!groups.length && (
        <p className="rounded-xl bg-surface-2 p-3 text-[11.5px] leading-5 text-content-3">
          no cores are installed yet — install cores (sing-box, WireGuard, OpenVPN,
          SoftEther, SSH…) from <b>Cores → catalog</b> and their inbounds appear here.
        </p>
      )}
      {!!groups.length && (
        <div className="overflow-hidden rounded-xl border border-border">
          {groups.map((g, gi) => {
            const all = tagsOf(g);
            const selected = selectedFor(g);
            const state: "on" | "off" | "partial" =
              !all.length || selected.length === 0 ? "off" : selected.length >= all.length ? "on" : "partial";
            const rowDisabled = disabled || !g.inbounds.length;
            return (
              <div key={g.core_id}
                className={`flex items-center gap-2.5 px-3 py-2.5 ${gi ? "border-t border-border/60" : ""} ${state !== "off" ? "bg-brand-soft/30" : ""}`}>
                <TriCheck state={state} disabled={rowDisabled} label={`toggle all ${g.name} inbounds`}
                  onToggle={() => toggleCore(g, state === "off")} />
                <button type="button" disabled={rowDisabled} onClick={() => toggleCore(g, state === "off")}
                  className="flex min-w-0 flex-1 items-center gap-2 text-start">
                  <Box size={13} className={state !== "off" ? "text-brand" : "text-content-3"} />
                  <span className={`truncate text-[12.5px] font-semibold ${state !== "off" ? "text-content" : "text-content-2"}`}>
                    {g.name}
                  </span>
                  <code className="text-[10px] font-normal text-content-3">{g.core_id}</code>
                </button>
                <span className="text-[10.5px] tabular-nums text-content-3">
                  {g.inbounds.length ? `${selected.length}/${g.inbounds.length}` : "no inbounds"}
                </span>
                <button type="button" aria-label={`choose ${g.name} inbounds`}
                  disabled={disabled || !g.inbounds.length}
                  onClick={(e) => setMenu((m) => (m?.core === g.core_id ? null : { core: g.core_id, anchor: e.currentTarget }))}
                  className="rounded-lg p-1.5 text-content-3 hover:bg-surface-3 hover:text-content disabled:opacity-40">
                  <MoreHorizontal size={15} />
                </button>
              </div>
            );
          })}
        </div>
      )}

      {/* portal-mounted per-core inbound checklist — never clipped */}
      <RowMenu open={!!menuGroup} anchor={menu?.anchor ?? null} onClose={() => setMenu(null)} width={264}>
        {menuGroup && (
          <>
            <div className="flex items-center justify-between border-b border-border px-3.5 py-2">
              <span className="text-[11.5px] font-semibold">{menuGroup.name} — inbounds</span>
              <span className="flex gap-2">
                <button type="button" className="text-[11px] font-medium text-brand hover:underline"
                  onClick={() => applySelection(menuGroup, tagsOf(menuGroup))}>all</button>
                <button type="button" className="text-[11px] font-medium text-content-3 hover:underline"
                  onClick={() => applySelection(menuGroup, [])}>none</button>
              </span>
            </div>
            <div className="max-h-60 overflow-y-auto">
              {menuGroup.inbounds.map((inb) => {
                const selected = selectedFor(menuGroup);
                const on = selected.includes(inb.tag);
                return (
                  <button key={inb.tag} type="button"
                    onClick={() => applySelection(menuGroup, on ? selected.filter((t) => t !== inb.tag) : [...selected, inb.tag])}
                    className="flex w-full items-center gap-2.5 px-3.5 py-2 text-start text-[12.5px] text-content-2 transition-colors hover:bg-surface-2 hover:text-content">
                    <input type="checkbox" readOnly checked={on} tabIndex={-1}
                      className="pointer-events-none h-3.5 w-3.5 accent-brand" />
                    <span className="min-w-0 flex-1 truncate">{inb.tag}</span>
                    {inb.protocol && <span className={`text-[10px] ${inb.security_class === "legacy_insecure" ? "text-danger" : "text-content-3"}`}>
                      {inb.protocol}{inb.security_class === "legacy_insecure" ? " · Legacy / Insecure" : ""}
                    </span>}
                    {inb.port != null && <span className="font-mono text-[10px] text-content-3">:{inb.port}</span>}
                  </button>
                );
              })}
            </div>
          </>
        )}
      </RowMenu>
    </div>
  );
}
