// Outbounds — graphical management: cards with health/latency, test, clone,
// edit, delete, save + deploy. No JSON.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, Copy, Network, Pencil, Plus, Rocket, Save, Trash2, Zap } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "../components/feedback";
import { ConfirmDialog, Dialog } from "../components/overlays";
import { Badge, Button, Card, EmptyState, Field, Input, Select, StatusDot, Switch, cn } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useT } from "../lib/i18n";
import type { Outbound, OutboundTest } from "../lib/types";

const KINDS = ["direct", "block", "blackhole", "dns", "socks", "http", "vless", "vmess", "trojan", "shadowsocks", "wireguard", "hysteria2", "tuic", "openvpn", "ssh", "core"] as const;
const UPSTREAM = new Set(["socks", "http", "vless", "vmess", "trojan", "shadowsocks", "wireguard", "hysteria2", "tuic"]);

interface TestState { [name: string]: { loading: boolean; result?: OutboundTest } }

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

  const names = useMemo(() => new Set(items.map((i) => i.name)), [items]);

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
            hint="Routing rules target these — e.g. a WARP socks5 chain, direct egress, or a block sink."
            action={<Button size="sm" onClick={() => setDialog({ ob: { name: "", kind: "socks", settings: { server: "", server_port: 1080 }, enabled: true }, index: null })}><Plus size={13} /> create outbound</Button>}
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
          cores={undefined}
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

function OutboundDialog({ outbound, isNew, takenNames, onClose, onSave }: {
  outbound: Outbound; isNew: boolean; takenNames: Set<string>; cores?: unknown;
  onClose: () => void; onSave: (ob: Outbound) => void;
}) {
  const t = useT();
  const [ob, setOb] = useState<Outbound>(structuredClone(outbound));
  const [error, setError] = useState("");
  const s = ob.settings as Record<string, unknown>;
  const setS = (patch: Record<string, unknown>) => setOb({ ...ob, settings: { ...s, ...patch } });
  const upstream = UPSTREAM.has(ob.kind);

  const coresQ = useQuery({
    queryKey: ["zagros", "cores"],
    queryFn: () => api.get<{ cores: { id: string }[] }>("/zagros/cores"),
    enabled: ob.kind === "core",
  });

  const validate = () => {
    if (!/^[a-z0-9][a-z0-9._-]{1,63}$/.test(ob.name)) return "name: lowercase letters/digits with -_. separators";
    if (isNew && takenNames.has(ob.name)) return `outbound "${ob.name}" already exists`;
    if (upstream && !String(s.server ?? "").trim()) return "server/address is required for upstream protocols";
    if (upstream && !(Number(s.server_port) > 0)) return "a valid port is required";
    if (ob.kind === "core" && !String(s.core_id ?? "")) return "choose the core to chain";
    return "";
  };

  return (
    <Dialog open onClose={onClose} title={isNew ? "new outbound" : `edit — ${outbound.name}`}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button onClick={() => {
            const err = validate();
            if (err) return setError(err);
            onSave(ob);
          }}>{t("common.save")}</Button>
        </>
      }>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="name" required>
          <Input value={ob.name} onChange={(e) => setOb({ ...ob, name: e.target.value })} placeholder="warp-up" dir="ltr" />
        </Field>
        <Field label="protocol" required>
          <Select value={ob.kind} onChange={(e) => setOb({ ...ob, kind: e.target.value as Outbound["kind"] })}>
            {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
          </Select>
        </Field>
        {upstream && (
          <>
            <Field label="server / address" required>
              <Input value={String(s.server ?? "")} onChange={(e) => setS({ server: e.target.value })} placeholder="engage.cloudflareclient.com" dir="ltr" />
            </Field>
            <Field label="port" required>
              <Input type="number" value={String(s.server_port ?? "")} onChange={(e) => setS({ server_port: Number(e.target.value) })} placeholder="2408" dir="ltr" />
            </Field>
            {(ob.kind === "socks" || ob.kind === "http") && (
              <>
                <Field label="username (optional)">
                  <Input value={String(s.username ?? "")} onChange={(e) => setS({ username: e.target.value })} dir="ltr" />
                </Field>
                <Field label="password (optional)">
                  <Input type="password" value={String(s.password ?? "")} onChange={(e) => setS({ password: e.target.value })} dir="ltr" />
                </Field>
              </>
            )}
            {(ob.kind === "vless" || ob.kind === "trojan" || ob.kind === "vmess") && (
              <Field label="uuid / password" required>
                <Input type="password" value={String(s.uuid ?? s.password ?? "")} onChange={(e) => setS({ uuid: e.target.value, password: e.target.value })} dir="ltr" />
              </Field>
            )}
          </>
        )}
        {ob.kind === "core" && (
          <Field label="chain through core" required hint="traffic exits via another running core">
            <Select value={String(s.core_id ?? "")} onChange={(e) => setS({ core_id: e.target.value })}>
              <option value="">— choose —</option>
              {(coresQ.data?.cores ?? []).map((c) => <option key={c.id} value={c.id}>{c.id}</option>)}
            </Select>
          </Field>
        )}
        {ob.kind === "dns" && (
          <Field label="dns resolver address" hint="leave empty for the core's internal resolver">
            <Input value={String(s.address ?? "")} onChange={(e) => setS({ address: e.target.value })} placeholder="1.1.1.1" dir="ltr" />
          </Field>
        )}
        <label className="flex items-center gap-2.5 text-sm text-content-2">
          <Switch checked={ob.enabled} onChange={(v) => setOb({ ...ob, enabled: v })} label="enabled" />
          enabled
        </label>
      </div>
      {error && <p role="alert" className="mt-3 rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}
