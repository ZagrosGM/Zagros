// CoreAccessPicker — the "Marzban inbounds picker, multi-core".
// One checkbox tree across EVERY installed core: Xray / Sing-box / WireGuard /
// OpenVPN / SSH / SoftEther (L2TP · SSTP · PPTP · SoftEther VPN) — fed live
// from GET /api/zagros/inbounds. The value maps directly to `core_access`.
import { Box, CheckSquare, Square } from "lucide-react";
import type { InboundCatalogGroup } from "../lib/types";
import { Badge } from "./ui";

interface Props {
  groups: InboundCatalogGroup[];
  value: Record<string, string[]>;
  onChange: (next: Record<string, string[]>) => void;
  disabled?: boolean;
}

export default function CoreAccessPicker({ groups, value, onChange, disabled }: Props) {
  const toggle = (coreId: string, tag: string) => {
    const current = value[coreId] ?? [];
    const next = current.includes(tag)
      ? current.filter((t) => t !== tag)
      : [...current, tag];
    const out = { ...value };
    if (next.length === 0 && !(coreId in value)) delete out[coreId];
    else out[coreId] = next;
    onChange(out);
  };

  const toggleCore = (g: InboundCatalogGroup) => {
    const out = { ...value };
    const selected = value[g.core_id] ?? [];
    if (selected.length >= g.inbounds.length) out[g.core_id] = [];
    else out[g.core_id] = g.inbounds.map((i) => i.tag);
    onChange(out);
  };

  const total = Object.values(value).reduce((n, tags) => n + tags.length, 0);

  // The built-in xray core is governed by the legacy proxy picker above this
  // section (its own protocol/tag chips) — offering it again here would
  // double-manage the same accounts, so it is deliberately not grantable.
  const grantable = groups.filter((g) => g.core_id !== "xray");

  return (
    <div className="space-y-2.5">
      <div className="flex items-center justify-between">
        <p className="text-[12px] font-medium text-content-2">multi-core access</p>
        {total > 0 && <Badge tone="brand">{total} selected</Badge>}
      </div>
      {!grantable.length && (
        <p className="rounded-xl bg-surface-2 p-3 text-[11.5px] leading-5 text-content-3">
          no other cores are installed yet — install cores (sing-box, WireGuard, OpenVPN,
          SoftEther, SSH…) from <b>Cores → catalog</b> and their inbounds appear here.
        </p>
      )}
      <div className="grid gap-2.5 sm:grid-cols-2">
        {grantable.map((g) => {
          const selected = value[g.core_id] ?? [];
          const all = g.inbounds.length > 0 && selected.length >= g.inbounds.length;
          return (
            <div key={g.core_id} className="rounded-xl border border-border p-3">
              <button type="button" disabled={disabled || !g.inbounds.length}
                onClick={() => toggleCore(g)}
                className="mb-2 flex w-full items-center justify-between gap-2 text-start">
                <span className="flex items-center gap-2 text-[12.5px] font-semibold">
                  <Box size={13} className="text-brand" /> {g.name}
                  <code className="text-[10px] font-normal text-content-3">{g.core_id}</code>
                </span>
                {all
                  ? <CheckSquare size={14} className="text-brand" />
                  : <Square size={14} className="text-content-3" />}
              </button>
              {!g.inbounds.length ? (
                <p className="text-[11px] text-content-3">no inbounds configured on this core</p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {g.inbounds.map((inb) => {
                    const on = selected.includes(inb.tag);
                    return (
                      <button type="button" key={inb.tag} disabled={disabled}
                        onClick={() => toggle(g.core_id, inb.tag)}
                        className={`rounded-lg border px-2 py-1 text-[11px] transition-colors ${
                          on ? "border-brand bg-brand-soft text-brand" : "border-border text-content-2 hover:border-border-strong"
                        }`}>
                        {inb.tag}
                        {inb.protocol && <span className="ms-1 text-[9.5px] opacity-70">{inb.protocol}</span>}
                        {inb.port != null && <span className="ms-1 font-mono text-[9.5px] opacity-70">:{inb.port}</span>}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
