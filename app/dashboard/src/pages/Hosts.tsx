// Host Settings (alpha.7.2, item 13) — Marzban-parity, panel-native.
//
// One page, one API surface for EVERY core: GET/PUT /zagros/cores/{id}/hosts.
// The server keeps the honest split (xray → legacy hosts table, byte-parity;
// every other core → the platform Host Settings engine), so this page never
// special-cases. Full Marzban field set per entry; an entry's ROW ORDER is
// its priority (first = highest) — reorder with the arrows; no drag lib for
// a 2-button action.
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ChevronDown, ChevronUp, Plus, RefreshCcw, Save, ServerCog, Trash2,
} from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "../components/feedback";
import { Badge, Button, Card, EmptyState, ErrorState, Field, Input, Select, Switch, cn } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useT } from "../lib/i18n";
import type { InboundCatalogGroup } from "../lib/types";

// the full wire shape the API serves (both backends)
interface HostRow {
  remark: string;
  address: string;
  port: number | null;
  sni: string;
  host: string;
  path: string;
  security: string;
  alpn: string;
  fingerprint: string;
  allowinsecure: boolean;
  is_disabled: boolean;
  mux_enable: boolean;
  fragment_setting: string;
  noise_setting: string;
  random_user_agent: boolean;
  use_sni_as_host: boolean;
  [key: string]: unknown; // unknown extras preserved verbatim on save
}

type HostMap = Record<string, HostRow[]>;

const ALPN_OPTIONS = ["", "h3", "h2", "http/1.1", "h3,h2", "h2,http/1.1", "h3,h2,http/1.1"];
const FP_OPTIONS = ["", "chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"];
const SECURITY_OPTIONS = ["inbound_default", "none", "tls"];

const blank = (): HostRow => ({
  remark: "", address: "", port: null, sni: "", host: "", path: "",
  security: "inbound_default", alpn: "", fingerprint: "",
  allowinsecure: false, is_disabled: false,
  mux_enable: false, fragment_setting: "", noise_setting: "",
  random_user_agent: false, use_sni_as_host: false,
});

const normalize = (raw: Record<string, unknown>): HostRow => ({
  ...blank(), ...raw,
  remark: String(raw.remark ?? ""),
  address: String(raw.address ?? ""),
  port: (raw.port as number | null) ?? null,
  sni: String(raw.sni ?? ""), host: String(raw.host ?? ""), path: String(raw.path ?? ""),
  security: String(raw.security ?? "inbound_default") || "inbound_default",
  alpn: String(raw.alpn ?? ""), fingerprint: String(raw.fingerprint ?? ""),
  allowinsecure: Boolean(raw.allowinsecure), is_disabled: Boolean(raw.is_disabled),
  mux_enable: Boolean(raw.mux_enable),
  fragment_setting: String(raw.fragment_setting ?? ""),
  noise_setting: String(raw.noise_setting ?? ""),
  random_user_agent: Boolean(raw.random_user_agent),
  use_sni_as_host: Boolean(raw.use_sni_as_host),
});

/** server-side shape: empty strings become null/omitted semantics */
const denormalize = (row: HostRow): Record<string, unknown> => ({
  ...row,
  port: row.port ?? null,
  sni: row.sni || null, host: row.host || null, path: row.path || null,
  security: row.security === "inbound_default" ? null : row.security,
  alpn: row.alpn || null, fingerprint: row.fingerprint || null,
  fragment_setting: row.fragment_setting || null,
  noise_setting: row.noise_setting || null,
});

// item 16: protocol-aware editor — rendered from the server's own field
// matrix (GET …/hosts/schema); xray keeps the full legacy Marzban set.
const XRAY_ALL_FIELDS = [
  "remark", "address", "port", "is_disabled", "host", "path", "sni",
  "allowinsecure", "use_sni_as_host", "security", "alpn", "fingerprint",
  "fragment_setting", "noise_setting", "mux_enable", "random_user_agent",
];

export default function Hosts() {
  const t = useT();
  const qc = useQueryClient();
  const [coreId, setCoreId] = useState<string>("");
  const [dirty, setDirty] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState<string | null>(null); // tag | "all" | null
  const [edited, setEdited] = useState<HostMap | null>(null);

  const catalogQ = useQuery({
    queryKey: ["zagros", "inbounds-catalog"],
    queryFn: () => api.get<{ groups: InboundCatalogGroup[] }>("/zagros/inbounds"),
    staleTime: 60000,
  });
  const groups = useMemo(
    () => (catalogQ.data?.groups ?? []).filter((g) => (g.inbounds ?? []).length > 0),
    [catalogQ.data]);
  const effectiveCore = coreId || groups[0]?.core_id || "";

  const hostsQ = useQuery({
    queryKey: ["zagros", "hosts", effectiveCore],
    enabled: !!effectiveCore,
    queryFn: () => api.get<HostMap>(`/zagros/cores/${effectiveCore}/hosts`),
  });
  // edit buffer = server state until the admin starts typing
  const live: HostMap = useMemo(() => {
    const map: HostMap = {};
    for (const [tag, rows] of Object.entries(hostsQ.data ?? {}))
      map[tag] = (rows as Record<string, unknown>[]).map(normalize);
    return map;
  }, [hostsQ.data]);
  const hosts: HostMap = edited ?? live;

  const schemaQ = useQuery({
    queryKey: ["zagros", "hosts-schema", effectiveCore],
    enabled: !!effectiveCore && effectiveCore !== "xray",
    queryFn: () => api.get<{ engine: string | null; inbounds: { tag: string; protocol: string; fields: string[] }[] }>(`/zagros/cores/${effectiveCore}/hosts/schema`),
    staleTime: 60000,
  });
  const allowedFieldsFor = (tag: string): Set<string> => {
    if (effectiveCore === "xray") return new Set(XRAY_ALL_FIELDS);
    const found = schemaQ.data?.inbounds.find((i) => i.tag === tag);
    return new Set(found?.fields ?? ["remark", "address", "port", "is_disabled"]);
  };

  const group = groups.find((g) => g.core_id === effectiveCore);
  const tags = useMemo(() => {
    const fromCatalog = group ? group.inbounds.map((i) => i.tag) : [];
    for (const tag of Object.keys(hosts)) if (!fromCatalog.includes(tag)) fromCatalog.push(tag);
    return fromCatalog;
  }, [group, hosts]);
  const isXray = effectiveCore === "xray";

  const setHosts = (next: HostMap, tag?: string) => {
    setEdited(next);
    setDirty((d) => ({ ...d, [tag ?? "*all*"]: true }));
  };
  const update = (tag: string, idx: number, patch: Partial<HostRow>) =>
    setHosts({ ...hosts, [tag]: (hosts[tag] ?? []).map((r, i) => (i === idx ? { ...r, ...patch } : r)) }, tag);
  const addRow = (tag: string) => setHosts({ ...hosts, [tag]: [...(hosts[tag] ?? []), blank()] }, tag);
  const removeRow = (tag: string, idx: number) =>
    setHosts({ ...hosts, [tag]: (hosts[tag] ?? []).filter((_, i) => i !== idx) }, tag);
  const move = (tag: string, idx: number, dir: -1 | 1) => {
    const rows = [...(hosts[tag] ?? [])];
    const j = idx + dir;
    if (j < 0 || j >= rows.length) return;
    [rows[idx], rows[j]] = [rows[j], rows[idx]];
    setHosts({ ...hosts, [tag]: rows }, tag);
  };

  const save = async (tag: string | "all") => {
    setSaving(tag === "all" ? "all" : tag);
    try {
      const payload = tag === "all"
        ? Object.fromEntries(Object.entries(hosts).map(([tg, rows]) => [tg, rows.map(denormalize)]))
        : { [tag]: (hosts[tag] ?? []).map(denormalize) };
      await api.put(`/zagros/cores/${effectiveCore}/hosts`, { hosts: payload });
      toast.ok(t("common.saved"));
      setEdited(null);
      setDirty({});
      qc.invalidateQueries({ queryKey: ["zagros", "hosts", effectiveCore] });
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t("common.error"));
    } finally {
      setSaving(null);
    }
  };

  if (catalogQ.isError) return <ErrorState message={(catalogQ.error as Error).message} onRetry={() => catalogQ.refetch()} />;

  return (
    <div className="space-y-4 animate-fade-up">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <ServerCog size={18} className="text-brand" />{t("hosts.title")}
        </h1>
        <Select value={effectiveCore} onChange={(e) => { setCoreId(e.target.value); setEdited(null); setDirty({}); }}
          className="w-48" aria-label="core">
          {groups.map((g) => (
            <option key={g.core_id} value={g.core_id}>
              {g.name} ({g.core_id})
            </option>
          ))}
        </Select>
        <Button variant="ghost" size="icon" onClick={() => hostsQ.refetch()} aria-label={t("common.refresh")}>
          <RefreshCcw size={15} className={cn(hostsQ.isFetching && "animate-spin")} />
        </Button>
        <Button size="sm" onClick={() => save("all")} loading={saving === "all"}
          disabled={!tags.length}>
          <Save size={14} /> {t("hosts.saveAll")}
        </Button>
      </div>

      <Card className="p-3 text-[12px] leading-5 text-content-3">
        {isXray
          ? t("hosts.xrayHint")
          : t("hosts.engineHint")}
      </Card>

      {hostsQ.isError ? (
        <ErrorState message={(hostsQ.error as Error).message} onRetry={() => hostsQ.refetch()} />
      ) : tags.length === 0 ? (
        <EmptyState title={t("hosts.empty")} hint={t("hosts.emptyHint")} />
      ) : (
        tags.map((tag) => {
          const rows = hosts[tag] ?? [];
          return (
            <Card key={tag} className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Badge tone="brand">{tag}</Badge>
                  <span className="text-[11px] text-content-3">
                    {rows.length} {t("hosts.entries")}{dirty[tag] ? ` · ${t("hosts.unsaved")}` : ""}
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  <Button variant="ghost" size="sm" onClick={() => addRow(tag)}>
                    <Plus size={14} /> {t("hosts.add")}
                  </Button>
                  <Button variant="secondary" size="sm" onClick={() => save(tag)}
                    loading={saving === tag} disabled={!dirty[tag] && !dirty["*all*"]}>
                    <Save size={13} /> {t("common.save")}
                  </Button>
                </div>
              </div>

              {rows.length > 0 && (
                <div className="space-y-3">
                  {rows.map((row, idx) => {
                    const ok = allowedFieldsFor(tag);
                    return (
                    <div key={idx} className={cn("rounded-xl border p-3 space-y-3",
                      row.is_disabled ? "border-border opacity-70" : "border-border-strong")}>
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-medium text-content-3">
                          #{idx + 1} · {t("hosts.priority")}{idx === 0 ? ` — ${t("hosts.highest")}` : ""}
                        </span>
                        <div className="flex items-center gap-0.5">
                          <Button variant="ghost" size="icon" aria-label="move up"
                            disabled={idx === 0}
                            onClick={() => move(tag, idx, -1)}>
                            <ChevronUp size={14} />
                          </Button>
                          <Button variant="ghost" size="icon" aria-label="move down"
                            disabled={idx === rows.length - 1}
                            onClick={() => move(tag, idx, 1)}>
                            <ChevronDown size={14} />
                          </Button>
                          <Button variant="ghost" size="icon" aria-label={t("hosts.remove")}
                            onClick={() => removeRow(tag, idx)}>
                            <Trash2 size={14} className="text-danger" />
                          </Button>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
                        <Field label={t("hosts.remark")}
                          hint="blank → 🛸 Zagros ({USERNAME}) [{PROTOCOL} - {TRANSPORT}] » {SERVER_IP}">
                          <Input value={row.remark} placeholder="🛸 Zagros ({USERNAME})"
                            onChange={(e) => update(tag, idx, { remark: e.target.value })} />
                        </Field>
                        <Field label={t("hosts.address")} required>
                          <Input value={row.address} dir="ltr"
                            placeholder="cdn.example.com, edge-*.example.com"
                            onChange={(e) => update(tag, idx, { address: e.target.value })} />
                        </Field>
                        <Field label={t("hosts.port")}>
                          <Input type="number" min={1} max={65535} value={row.port ?? ""}
                            placeholder={t("hosts.portInherit")}
                            onChange={(e) => update(tag, idx, { port: e.target.value === "" ? null : Number(e.target.value) })} />
                        </Field>
                        {/* item 16: only fields this (core, protocol) can apply */}
                        {ok.has("security") && (
                        <Field label={t("hosts.security")}>
                          <Select value={row.security}
                            onChange={(e) => update(tag, idx, { security: e.target.value })}>
                            {SECURITY_OPTIONS.map((s) => <option key={s} value={s}>{s}</option>)}
                          </Select>
                        </Field>)}
                        {ok.has("sni") && (
                        <Field label="SNI">
                          <Input value={row.sni} dir="ltr" placeholder="a.com,b.com"
                            onChange={(e) => update(tag, idx, { sni: e.target.value })} />
                        </Field>)}
                        {ok.has("host") && (
                        <Field label={t("hosts.hostHeader")}>
                          <Input value={row.host} dir="ltr"
                            onChange={(e) => update(tag, idx, { host: e.target.value })} />
                        </Field>)}
                        {ok.has("path") && (
                        <Field label={t("hosts.path")}>
                          <Input value={row.path} dir="ltr" placeholder="/ws"
                            onChange={(e) => update(tag, idx, { path: e.target.value })} />
                        </Field>)}
                        {ok.has("alpn") && (
                        <Field label="ALPN">
                          <Select value={row.alpn}
                            onChange={(e) => update(tag, idx, { alpn: e.target.value })}>
                            {ALPN_OPTIONS.map((s) => <option key={s} value={s}>{s || "—"}</option>)}
                          </Select>
                        </Field>)}
                        {ok.has("fingerprint") && (
                        <Field label={t("hosts.fingerprint")}>
                          <Select value={row.fingerprint}
                            onChange={(e) => update(tag, idx, { fingerprint: e.target.value })}>
                            {FP_OPTIONS.map((s) => <option key={s} value={s}>{s || "—"}</option>)}
                          </Select>
                        </Field>)}
                        {ok.has("fragment_setting") && (
                        <Field label="fragment">
                          <Input value={row.fragment_setting} dir="ltr"
                            placeholder="10-20,10-20,tlshello"
                            onChange={(e) => update(tag, idx, { fragment_setting: e.target.value })} />
                        </Field>)}
                        {ok.has("noise_setting") && (
                        <Field label="noise">
                          <Input value={row.noise_setting} dir="ltr"
                            onChange={(e) => update(tag, idx, { noise_setting: e.target.value })} />
                        </Field>)}
                      </div>

                      <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
                        {ok.has("allowinsecure") && (<>
                        <Switch checked={row.allowinsecure} label="allowInsecure"
                          onChange={(v) => update(tag, idx, { allowinsecure: v })} />
                        <span className="-ms-3 text-[11.5px] text-content-2">allowInsecure</span></>)}
                        {ok.has("mux_enable") && (<>
                        <Switch checked={row.mux_enable} label="mux"
                          onChange={(v) => update(tag, idx, { mux_enable: v })} />
                        <span className="-ms-3 text-[11.5px] text-content-2">mux</span></>)}
                        {ok.has("random_user_agent") && (<>
                        <Switch checked={row.random_user_agent} label="random user-agent"
                          onChange={(v) => update(tag, idx, { random_user_agent: v })} />
                        <span className="-ms-3 text-[11.5px] text-content-2">random UA</span></>)}
                        {ok.has("use_sni_as_host") && (<>
                        <Switch checked={row.use_sni_as_host} label="use sni as host"
                          onChange={(v) => update(tag, idx, { use_sni_as_host: v })} />
                        <span className="-ms-3 text-[11.5px] text-content-2">SNI→Host</span></>)}
                        <Switch checked={row.is_disabled} label="disabled"
                          onChange={(v) => update(tag, idx, { is_disabled: v })} />
                        <span className="-ms-3 text-[11.5px] text-content-2">{t("hosts.disabled")}</span>
                      </div>
                    </div>
                    );
                  })}
                </div>
              )}
            </Card>
          );
        })
      )}
    </div>
  );
}
