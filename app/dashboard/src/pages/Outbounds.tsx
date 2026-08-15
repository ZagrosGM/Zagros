// Outbounds — graphical management: cards with health/latency, test, clone,
// edit, delete, save + deploy. No JSON.
//
// alpha.7: the editor is SCHEMA-DRIVEN (fields come from
// /zagros/outbounds/schema — every transport and security option the core
// translation layer understands, incl. ws/gRPC/HTTP/HTTPUpgrade/KCP/
// SplitHTTP/QUIC + TLS/REALITY), names accept uppercase (validation bug
// fix), and any URL-based protocol fills itself from a pasted share link
// ("Import URL"). OpenVPN profiles can be uploaded (.ovpn) and re-exported.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity, Copy, Download, Import, Network, Pencil, Plus, Rocket, Save,
  Trash2, Upload, Zap,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "../components/feedback";
import { ConfirmDialog, Dialog } from "../components/overlays";
import { Badge, Button, Card, EmptyState, Field, Input, Select, StatusDot, Switch, Textarea, cn } from "../components/ui";
import { api, ApiError, getToken } from "../lib/api";
import { useT } from "../lib/i18n";
import type { Outbound, OutboundKindSchema, OutboundSchemas, OutboundTest, ParsedShareURL } from "../lib/types";

interface TestState { [name: string]: { loading: boolean; result?: OutboundTest } }

// which transport sub-fields apply to which network (UI visibility only —
// the schema itself stays the single source of truth for what EXISTS).
const TRANSPORT_FIELDS: Record<string, Set<string>> = {
  tcp: new Set(),
  kcp: new Set(["headerType", "seed"]),
  ws: new Set(["path", "host"]),
  http: new Set(["path", "host"]),
  grpc: new Set(["serviceName", "authority", "mode"]),
  quic: new Set(),
  httpupgrade: new Set(["path", "host"]),
  splithttp: new Set(["path", "host"]),
};
const SECURITY_FIELDS: Record<string, Set<string>> = {
  none: new Set(),
  tls: new Set(["sni", "alpn", "fingerprint", "allow_insecure"]),
  reality: new Set(["sni", "alpn", "fingerprint", "allow_insecure", "reality_public_key", "reality_short_id", "reality_spider_x"]),
};
const URL_BASED = new Set(["vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic"]);
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$/;

export default function Outbounds() {
  const t = useT();
  const qc = useQueryClient();
  const [items, setItems] = useState<Outbound[]>([]);
  const [dirty, setDirty] = useState(false);
  const [dialog, setDialog] = useState<{ ob: Outbound; index: number | null } | null>(null);
  const [deleteFor, setDeleteFor] = useState<string | null>(null);
  const [tests, setTests] = useState<TestState>({});

  const load = useQuery({
    queryKey: ["zagros", "outbounds"],
    queryFn: () => api.get<{ outbounds: Outbound[] }>("/zagros/outbounds"),
  });
  const schemas = useQuery({
    queryKey: ["zagros", "outbound-schemas"],
    queryFn: () => api.get<{ schemas: OutboundSchemas }>("/zagros/outbounds/schema"),
    staleTime: 300000,
  });
  useEffect(() => { if (load.data) setItems(load.data.outbounds); }, [load.data]);

  const markDirty = (next: Outbound[]) => { setItems(next); setDirty(true); };

  const save = useMutation({
    mutationFn: () => api.put("/zagros/outbounds", { outbounds: items }),
    onSuccess: () => { toast.ok(t("common.saved")); setDirty(false); qc.invalidateQueries({ queryKey: ["zagros", "outbounds"] }); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });
  const deploy = useMutation({
    mutationFn: () => api.post("/zagros/outbounds/deploy", { outbounds: items }),
    onSuccess: () => { toast.ok("deployed to running cores"); setDirty(false); qc.invalidateQueries({ queryKey: ["zagros", "outbounds"] }); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const testOne = async (ob: Outbound) => {
    setTests((s) => ({ ...s, [ob.name]: { loading: true } }));
    try {
      const result = await api.post<OutboundTest>("/zagros/outbounds/test", ob);
      setTests((s) => ({ ...s, [ob.name]: { loading: false, result } }));
    } catch (e) {
      setTests((s) => ({ ...s, [ob.name]: { loading: false, result: { ok: false, latency_ms: null, error: e instanceof ApiError ? e.message : t("common.error") } } }));
    }
  };
  const testAll = async () => { for (const ob of items) await testOne(ob); };

  const exportOvpn = async (name: string) => {
    try {
      const res = await fetch(`/api/zagros/outbounds/export?name=${encodeURIComponent(name)}`, {
        headers: { Authorization: `Bearer ${getToken()}` },
      });
      if (!res.ok) throw new Error(`export failed (${res.status})`);
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `${name}.ovpn`;
      a.click();
      URL.revokeObjectURL(a.href);
      toast.ok(`${name}.ovpn downloaded`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t("common.error"));
    }
  };

  const names = useMemo(() => new Set(items.map((i) => i.name)), [items]);
  const KINDS = useMemo(() => Object.keys(schemas.data?.schemas ?? {}), [schemas.data]);
  const UPSTREAM = useMemo(() => new Set(KINDS.filter((k) => {
    const req = schemas.data?.schemas[k]?.required ?? [];
    return req.includes("server") && req.includes("server_port");
  })), [KINDS, schemas.data]);

  return (
    <div className="space-y-4 animate-fade-up">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <Network size={18} className="text-brand" />{t("nav.outbounds")}
          {dirty && <Badge tone="warn" dot>unsaved</Badge>}
        </h1>
        <Button variant="ghost" size="sm" onClick={testAll} disabled={!items.length}><Activity size={13} /> test all</Button>
        <Button variant="secondary" size="sm" onClick={() => save.mutate()} loading={save.isPending} disabled={!dirty}><Save size={13} /> {t("common.save")}</Button>
        <Button size="sm" onClick={() => deploy.mutate()} loading={deploy.isPending} disabled={!items.length}><Rocket size={13} /> {t("common.deploy")}</Button>
        <Button size="sm" variant="secondary" onClick={() => setDialog({ ob: { name: "", kind: "direct", settings: {}, enabled: true }, index: null })}>
          <Plus size={13} /> outbound
        </Button>
      </div>

      {load.isLoading ? null : items.length === 0 ? (
        <Card>
          <EmptyState
            title="No outbounds configured"
            hint="Routing rules target these — e.g. a WARP socks5 chain, an imported VLESS upstream, direct egress, or a block sink."
            action={<Button size="sm" onClick={() => setDialog({ ob: { name: "", kind: "vless", settings: { server: "", server_port: 443 }, enabled: true }, index: null })}><Plus size={13} /> create outbound</Button>}
          />
        </Card>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {items.map((ob, idx) => {
            const ts = tests[ob.name];
            return (
              <Card key={ob.name || idx} className={cn(!ob.enabled && "opacity-60")}>
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <StatusDot tone={ts?.result ? (ts.result.ok ? "ok" : "danger") : "muted"} pulse={ts?.loading} />
                      <h3 className="truncate text-sm font-semibold">{ob.name || "(unnamed)"}</h3>
                    </div>
                    <p className="mt-1 truncate font-mono text-[11px] text-content-3" dir="ltr">
                      {UPSTREAM.has(ob.kind) ? `${String(ob.settings?.server ?? "?")}:${String(ob.settings?.server_port ?? "?")}` : ob.kind === "core" ? `core: ${String(ob.settings?.core_id ?? "?")}` : ob.kind}
                    </p>
                  </div>
                  <Badge tone={ob.kind === "block" || ob.kind === "blackhole" ? "danger" : ob.kind === "direct" ? "ok" : "info"}>{ob.kind}</Badge>
                </div>

                <div className="mt-3 flex items-center gap-2 text-[11px] text-content-3">
                  {ts?.loading ? "testing…" : ts?.result ? (
                    ts.result.ok
                      ? <span className="inline-flex items-center gap-1 text-ok"><Zap size={11} /> healthy · {ts.result.latency_ms ?? "—"} ms</span>
                      : <span className="truncate text-danger" title={ts.result.error}>{ts.result.error ?? "unreachable"}</span>
                  ) : "not tested"}
                </div>

                <div className="mt-3.5 flex flex-wrap items-center gap-1 border-t border-border pt-3">
                  <Button variant="ghost" size="sm" onClick={() => testOne(ob)} disabled={ts?.loading}><Zap size={13} /> {t("common.test")}</Button>
                  <Button variant="ghost" size="sm" onClick={() => setDialog({ ob, index: idx })}><Pencil size={13} /> {t("common.edit")}</Button>
                  <Button variant="ghost" size="sm" onClick={() => setDialog({ ob: { ...structuredClone(ob), name: `${ob.name}-copy` }, index: null })}><Copy size={13} /></Button>
                  {ob.kind === "openvpn" && (
                    <Button variant="ghost" size="sm" onClick={() => exportOvpn(ob.name)} title={t("outbounds.export")}><Download size={13} /></Button>
                  )}
                  <div className="ms-auto flex items-center gap-1">
                    <Switch checked={ob.enabled} label="enabled" onChange={(v) => markDirty(items.map((x, i) => i === idx ? { ...x, enabled: v } : x))} />
                    <Button variant="ghost" size="icon" onClick={() => setDeleteFor(ob.name)} aria-label="delete"><Trash2 size={14} /></Button>
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {dialog && (
        <OutboundDialog
          outbound={dialog.ob}
          isNew={dialog.index === null}
          takenNames={names}
          schemas={schemas.data?.schemas ?? {}}
          onClose={() => setDialog(null)}
          onSave={(ob) => {
            markDirty(dialog.index === null ? [...items, ob] : items.map((x, i) => i === dialog.index ? ob : x));
            setDialog(null);
          }}
        />
      )}

      <ConfirmDialog
        open={!!deleteFor}
        onClose={() => setDeleteFor(null)}
        onConfirm={() => { markDirty(items.filter((x) => x.name !== deleteFor)); setDeleteFor(null); }}
        title={`delete outbound — ${deleteFor}`}
        body="Routing rules that reference it will fail validation until re-pointed."
        danger
      />
    </div>
  );
}

// ------------------------------------------------- schema-driven editor ---

function OutboundDialog({ outbound, isNew, takenNames, schemas, onClose, onSave }: {
  outbound: Outbound; isNew: boolean; takenNames: Set<string>;
  schemas: OutboundSchemas;
  onClose: () => void; onSave: (ob: Outbound) => void;
}) {
  const t = useT();
  const [ob, setOb] = useState<Outbound>(structuredClone(outbound));
  const [error, setError] = useState("");
  const [importUrl, setImportUrl] = useState("");
  const [importing, setImporting] = useState(false);
  const [importOK, setImportOK] = useState("");
  const s = ob.settings as Record<string, unknown>;
  const setS = (patch: Record<string, unknown>) => setOb((cur) => ({ ...cur, settings: { ...cur.settings, ...patch } }));

  const schema: OutboundKindSchema | undefined = schemas[ob.kind];
  const props = schema?.properties ?? {};
  const required = new Set(schema?.required ?? []);

  const coresQ = useQuery({
    queryKey: ["zagros", "cores"],
    queryFn: () => api.get<{ cores: { id: string }[] }>("/zagros/cores"),
    enabled: ob.kind === "core",
  });

  const network = String(s.network ?? "tcp");
  const security = String(s.security ?? "none");
  const visible = (key: string, group?: string) => {
    if (group !== "transport" && group !== "security") return true;
    if (key === "network" || key === "security") return true;
    if (group === "transport") {
      // ovpn/wg/etc transport fields that are not network-driven stay
      if (!("network" in props) || !["path", "host", "serviceName", "authority", "mode", "headerType", "seed"].includes(key)) return true;
      return (TRANSPORT_FIELDS[network] ?? new Set()).has(key);
    }
    if (!("security" in props)) return true;
    return (SECURITY_FIELDS[security] ?? new Set()).has(key);
  };

  const importLink = async () => {
    setImporting(true); setError(""); setImportOK("");
    try {
      const parsed = await api.post<ParsedShareURL>("/zagros/utils/parse-share-url", { url: importUrl.trim() });
      setOb((cur) => ({
        ...cur,
        kind: parsed.kind,
        name: cur.name || (parsed.name_hint ? parsed.name_hint.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64) : cur.name),
        settings: parsed.settings,
      }));
      setImportOK(`imported as ${parsed.kind} — review the fields below`);
      setImportUrl("");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t("common.error"));
    } finally {
      setImporting(false);
    }
  };

  const uploadOvpn = (file: File) => {
    const reader = new FileReader();
    reader.onload = () => setS({ ovpn_content: String(reader.result ?? "") });
    reader.readAsText(file);
  };

  const uploadWireGuard = (file: File) => {
    const reader = new FileReader();
    setImporting(true); setError(""); setImportOK("");
    reader.onerror = () => { setError("could not read WireGuard profile"); setImporting(false); };
    reader.onload = async () => {
      try {
        const parsed = await api.post<{
          kind: "wireguard"; settings: Record<string, unknown>; name_hint?: string;
        }>("/zagros/utils/parse-wireguard-profile", {
          content: String(reader.result ?? ""),
        });
        setOb((cur) => ({
          ...cur,
          kind: "wireguard",
          name: cur.name || parsed.name_hint || file.name.replace(/\.conf$/i, ""),
          settings: parsed.settings,
        }));
        setImportOK(`imported ${file.name} — review the endpoint and keys below`);
      } catch (e) {
        setError(e instanceof ApiError ? e.message : t("common.error"));
      } finally {
        setImporting(false);
      }
    };
    reader.readAsText(file);
  };

  const validate = () => {
    if (!NAME_RE.test(ob.name)) return "name: 2–64 chars, letters/digits with -_. separators (uppercase is fine)";
    if (isNew && takenNames.has(ob.name)) return `outbound "${ob.name}" already exists`;
    for (const key of required) {
      if (String(s[key] ?? "").trim() === "") return `${key} is required for kind "${ob.kind}"`;
    }
    if (ob.kind === "core" && !String(s.core_id ?? "")) return "choose the core to chain";
    return "";
  };

  const save = () => {
    const err = validate();
    if (err) return setError(err);
    // drop hidden transport/security leaves so only effective settings persist
    const cleaned: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(s)) {
      const group = (props[key]?.["x-group"]) ?? undefined;
      if ((group === "transport" || group === "security") && !visible(key, group)) continue;
      if (value === "" || value === undefined) continue;
      cleaned[key] = value;
    }
    onSave({ ...ob, settings: cleaned });
  };

  const groups: { id: string; label: string }[] = [
    { id: "basic", label: "endpoint" },
    { id: "auth", label: "credentials" },
    { id: "transport", label: "transport" },
    { id: "security", label: "security" },
  ];
  const groupFields = (g: string) =>
    Object.entries(props).filter(([key, f]) => (f["x-group"] ?? "basic") === g && visible(key, f["x-group"]));

  return (
    <Dialog open onClose={onClose} title={isNew ? "new outbound" : `edit — ${outbound.name}`}
      subtitle={schema?.description}
      wide
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button onClick={save} disabled={schema?.["x-supported"] === false}>{t("common.save")}</Button>
        </>
      }>
      {URL_BASED.has(ob.kind) && (
        <div className="mb-4 rounded-xl border border-brand/30 bg-brand-soft/30 p-3">
          <p className="mb-2 flex items-center gap-1.5 text-[12px] font-medium text-brand">
            <Import size={13} /> {t("outbounds.importUrl")}
          </p>
          <div className="flex items-start gap-2">
            <Textarea
              value={importUrl}
              onChange={(e) => setImportUrl(e.target.value)}
              placeholder={`${t("outbounds.importHint")}  —  vless://…  trojan://…  hy2://…`}
              dir="ltr" rows={2}
              className="flex-1 font-mono text-[11px]"
            />
            <Button size="sm" variant="secondary" onClick={importLink} loading={importing} disabled={!importUrl.trim()}>
              import
            </Button>
          </div>
          {importOK && <p className="mt-2 text-[11px] text-ok">{importOK}</p>}
        </div>
      )}

      {ob.kind === "openvpn" && (
        <div className="mb-4 flex items-center justify-between gap-2 rounded-xl border border-border bg-surface-2 px-3 py-2.5">
          <span className="text-[12px] text-content-2">have a ready profile? upload the .ovpn file — it wins over individual fields</span>
          <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg bg-surface-3 px-3 py-1.5 text-[12px] font-medium text-content hover:bg-border-strong">
            <Upload size={13} /> upload .ovpn
            <input type="file" accept=".ovpn,.conf,.txt" className="hidden"
              onChange={(e) => e.target.files?.[0] && uploadOvpn(e.target.files[0])} />
          </label>
        </div>
      )}

      {ob.kind === "wireguard" && (
        <div className="mb-4 flex items-center justify-between gap-2 rounded-xl border border-brand/30 bg-brand-soft/30 px-3 py-2.5">
          <span className="text-[12px] text-content-2">upload a WireGuard client .conf to import Endpoint, Address, DNS, MTU and all keys</span>
          <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg bg-brand px-3 py-1.5 text-[12px] font-medium text-white hover:opacity-90">
            <Upload size={13} /> {importing ? "importing…" : "upload .conf"}
            <input type="file" accept=".conf,.txt" className="hidden" disabled={importing}
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) uploadWireGuard(file);
                e.target.value = "";
              }} />
          </label>
        </div>
      )}
      {ob.kind === "wireguard" && importOK && <p className="mb-4 text-[11px] text-ok">{importOK}</p>}

      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="name" required>
          <Input value={ob.name} onChange={(e) => setOb({ ...ob, name: e.target.value })} placeholder="Warp-EU" dir="ltr" />
        </Field>
        <Field label="protocol" required>
          <Select value={ob.kind} onChange={(e) => setOb({ ...ob, kind: e.target.value as Outbound["kind"], settings: {} })}>
            {Object.keys(schemas).map((k) => {
              const supported = schemas[k]?.["x-supported"] !== false;
              const availability = schemas[k]?.["x-availability"] ?? "unsupported";
              return <option key={k} value={k} disabled={!supported}>{k}{availability === "supported" ? "" : ` — ${availability.replace(/_/g, " ")}`}</option>;
            })}
          </Select>
        </Field>

        {schema?.["x-availability"] && schema["x-availability"] !== "supported" && (
          <div className="sm:col-span-2 rounded-xl border border-warn/40 bg-warn-soft px-3 py-2 text-xs text-warn">
            <b>{schema["x-availability"].replace(/_/g, " ")}:</b>{" "}
            {schema["x-disabled-reason"] ?? "This client runtime is not currently available."}
          </div>
        )}

        {groups.map((g) => {
          const fields = groupFields(g.id);
          if (!fields.length) return null;
          return (
            <div key={g.id} className="sm:col-span-2">
              <p className="mb-2 text-[10.5px] font-semibold uppercase tracking-wide text-content-3">{g.label}</p>
              <div className="grid gap-4 sm:grid-cols-2">
                {fields.map(([key, f]) => {
                  const widget = f["x-widget"] ?? "text";
                  const value = s[key];
                  if (ob.kind === "core" && key === "core_id") {
                    return (
                      <Field key={key} label={f.title ?? key} hint={f.description} required>
                        <Select value={String(value ?? "")} onChange={(e) => setS({ core_id: e.target.value })}>
                          <option value="">— choose —</option>
                          {(coresQ.data?.cores ?? []).map((c) => <option key={c.id} value={c.id}>{c.id}</option>)}
                        </Select>
                      </Field>
                    );
                  }
                  if (widget === "toggle") {
                    return (
                      <label key={key} className="flex items-center gap-2.5 text-sm text-content-2">
                        <Switch checked={Boolean(value ?? f.default ?? false)} onChange={(v) => setS({ [key]: v })} label={f.title ?? key} />
                        {f.title ?? key}
                      </label>
                    );
                  }
                  return (
                    <Field key={key} label={f.title ?? key} hint={f.description} required={required.has(key)}>
                      {f.enum ? (
                        <Select value={String(value ?? f.default ?? "")} onChange={(e) => setS({ [key]: e.target.value })}>
                          {f.enum.map((o) => <option key={o} value={o}>{o === "" ? "—" : o}</option>)}
                        </Select>
                      ) : widget === "textarea" ? (
                        <Textarea rows={3} dir="ltr" className="font-mono text-[11px]"
                          value={String(value ?? "")} onChange={(e) => setS({ [key]: e.target.value })} />
                      ) : (
                        <Input
                          type={widget === "password" ? "password" : widget === "number" ? "number" : "text"}
                          min={f.minimum} max={f.maximum}
                          dir="ltr"
                          placeholder={f.default !== undefined ? String(f.default) : ""}
                          value={widget === "number" ? String(value ?? "") : String(value ?? "")}
                          onChange={(e) => setS({ [key]: widget === "number" ? (e.target.value === "" ? "" : Number(e.target.value)) : e.target.value })}
                        />
                      )}
                    </Field>
                  );
                })}
              </div>
            </div>
          );
        })}

        <label className="flex items-center gap-2.5 text-sm text-content-2">
          <Switch checked={ob.enabled} onChange={(v) => setOb({ ...ob, enabled: v })} label="enabled" />
          enabled
        </label>
      </div>
      {error && <p role="alert" className="mt-3 rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}
