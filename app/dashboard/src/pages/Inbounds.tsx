// Inbounds — visual list + per-protocol creation wizard. The wizard maps a
// structured spec through the studio service (preview → apply); no JSON is
// ever shown to the operator.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, Eye, Plus, Trash2, Waypoints, Wand2 } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "../components/feedback";
import { ConfirmDialog, Dialog } from "../components/overlays";
import { Badge, Button, Card, CardHeader, EmptyState, Field, Input, Select, Skeleton } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useT } from "../lib/i18n";
import type { CoreView } from "../lib/types";

// Protocol wizard field plans — per-protocol structured forms (identity-level:
// tag/listen/port + protocol-specific essentials). Backend validates the rest.
interface ProtoPlan {
  key: string;
  label: string;
  defaultPort: number;
  fields: { key: string; label: string; type: "text" | "number" | "select" | "password"; options?: string[]; placeholder?: string; required?: boolean }[];
}
const PROTOCOLS: ProtoPlan[] = [
  { key: "vless-reality", label: "VLESS + Reality", defaultPort: 443, fields: [
    { key: "sni", label: "camouflage SNI", type: "text", placeholder: "www.microsoft.com", required: true },
    { key: "fp", label: "fingerprint", type: "select", options: ["chrome", "firefox", "safari", "random"] },
    { key: "flow", label: "flow", type: "select", options: ["xtls-rprx-vision", ""] },
  ]},
  { key: "vless", label: "VLESS (TLS)", defaultPort: 8443, fields: [
    { key: "sni", label: "SNI / certificate name", type: "text", placeholder: "panel.example.com" },
  ]},
  { key: "vmess", label: "VMess (WS)", defaultPort: 2053, fields: [
    { key: "path", label: "WebSocket path", type: "text", placeholder: "/ws" },
    { key: "host", label: "Host header", type: "text", placeholder: "cdn.example.com" },
  ]},
  { key: "trojan", label: "Trojan (TLS)", defaultPort: 2087, fields: [
    { key: "sni", label: "SNI", type: "text" },
  ]},
  { key: "shadowsocks", label: "Shadowsocks 2022", defaultPort: 8388, fields: [
    { key: "method", label: "cipher", type: "select", options: ["2022-blake3-aes-128-gcm", "aes-128-gcm", "chacha20-ietf-poly1305"] },
  ]},
  { key: "hysteria2", label: "Hysteria 2", defaultPort: 4430, fields: [
    { key: "up_mbps", label: "up (Mbps)", type: "number" },
    { key: "down_mbps", label: "down (Mbps)", type: "number" },
    { key: "obfs", label: "obfs password", type: "password" },
  ]},
  { key: "tuic", label: "TUIC v5", defaultPort: 5443, fields: [
    { key: "congestion_control", label: "congestion control", type: "select", options: ["bbr", "cubic", "new_reno"] },
  ]},
  { key: "wireguard", label: "WireGuard", defaultPort: 51820, fields: [
    { key: "mtu", label: "MTU", type: "number", placeholder: "1420" },
  ]},
];

interface InboundRow { tag: string; protocol: string; listen?: string; port: number | string; [k: string]: unknown }

export default function Inbounds() {
  const t = useT();
  const qc = useQueryClient();
  const [coreId, setCoreId] = useState<string>("");
  const [wizard, setWizard] = useState(false);
  const [deleteFor, setDeleteFor] = useState<InboundRow | null>(null);

  const cores = useQuery({
    queryKey: ["zagros", "cores"],
    queryFn: () => api.get<{ cores: CoreView[] }>("/zagros/cores"),
  });
  const effectiveCore = coreId || cores.data?.cores[0]?.id || "";

  const raw = useQuery({
    queryKey: ["zagros", "studio", "raw", effectiveCore],
    queryFn: () => api.get<{ core_id: string; json: string }>(`/zagros/studio/${effectiveCore}/raw`),
    enabled: !!effectiveCore,
  });

  const inbounds = useMemo<InboundRow[]>(() => {
    if (!raw.data?.json) return [];
    try {
      const doc = JSON.parse(raw.data.json) as { inbounds?: InboundRow[] };
      return Array.isArray(doc.inbounds) ? doc.inbounds : [];
    } catch { return []; }
  }, [raw.data]);

  const removeInbound = useMutation({
    mutationFn: async (tag: string) => {
      const idx = inbounds.findIndex((i) => i.tag === tag);
      const path = `/inbounds/${idx}`;
      const ops = [{ op: "remove", path }];
      const preview = await api.post<{ valid: boolean; errors: string[] }>(`/zagros/studio/${effectiveCore}/preview`, { operations: ops });
      if (!preview.valid) throw new ApiError(422, preview.errors.join("; "));
      return api.post(`/zagros/studio/${effectiveCore}/apply`, { operations: ops });
    },
    onSuccess: () => {
      toast.ok(t("common.deleted")); setDeleteFor(null);
      qc.invalidateQueries({ queryKey: ["zagros", "studio", "raw", effectiveCore] });
      qc.invalidateQueries({ queryKey: ["inbounds"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  return (
    <div className="space-y-4 animate-fade-up">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <Waypoints size={18} className="text-brand" />{t("nav.inbounds")}
        </h1>
        <Field label="core">
          <Select value={effectiveCore} onChange={(e) => setCoreId(e.target.value)} className="w-40">
            {(cores.data?.cores ?? []).map((c) => <option key={c.id} value={c.id}>{c.id}</option>)}
            {!cores.data?.cores.length && <option value="">—</option>}
          </Select>
        </Field>
        <Button size="sm" onClick={() => setWizard(true)} disabled={!effectiveCore}><Wand2 size={13} /> add inbound</Button>
      </div>

      {!effectiveCore ? (
        <Card><EmptyState title="Install a core first" hint="Inbounds live inside a core's configuration document." /></Card>
      ) : raw.isLoading ? (
        <Skeleton className="h-64" />
      ) : inbounds.length === 0 ? (
        <Card>
          <EmptyState title="No inbounds on this core"
            hint="Run the wizard for a protocol-specific, validated creation flow — no hand-written config."
            action={<Button size="sm" onClick={() => setWizard(true)}><Wand2 size={13} /> launch wizard</Button>} />
        </Card>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {inbounds.map((ib) => (
            <Card key={ib.tag} className="flex items-start justify-between gap-3 p-4">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <h3 className="truncate text-sm font-semibold" dir="ltr">{ib.tag}</h3>
                  <Badge tone="brand">{ib.protocol}</Badge>
                </div>
                <p className="mt-1 font-mono text-[11px] text-content-3" dir="ltr">
                  {String(ib.listen ?? "0.0.0.0")}:{String(ib.port)}
                </p>
              </div>
              <Button variant="ghost" size="icon" aria-label={`remove ${ib.tag}`} onClick={() => setDeleteFor(ib)}>
                <Trash2 size={14} />
              </Button>
            </Card>
          ))}
          <button onClick={() => setWizard(true)}
            className="grid min-h-[92px] place-items-center rounded-2xl border border-dashed border-border-strong text-content-3 transition-colors hover:border-brand hover:text-brand">
            <span className="flex items-center gap-2 text-sm"><Plus size={16} /> add inbound</span>
          </button>
        </div>
      )}

      {wizard && effectiveCore && (
        <WizardDialog coreId={effectiveCore} existingTags={inbounds.map((i) => i.tag)}
          onClose={() => setWizard(false)}
          onDone={() => {
            setWizard(false);
            qc.invalidateQueries({ queryKey: ["zagros", "studio", "raw", effectiveCore] });
            qc.invalidateQueries({ queryKey: ["inbounds"] });
          }} />
      )}

      <ConfirmDialog
        open={!!deleteFor}
        onClose={() => setDeleteFor(null)}
        onConfirm={() => deleteFor && removeInbound.mutate(deleteFor.tag)}
        title={`remove inbound — ${deleteFor?.tag ?? ""}`}
        body="The inbound is removed from the core document and the change is validated before applying. Users attached only to this inbound lose connectivity."
        danger
        loading={removeInbound.isPending}
      />
    </div>
  );
}

function WizardDialog({ coreId, existingTags, onClose, onDone }: {
  coreId: string; existingTags: string[]; onClose: () => void; onDone: () => void;
}) {
  const t = useT();
  const [step, setStep] = useState(0);
  const [plan, setPlan] = useState<ProtoPlan>(PROTOCOLS[0]);
  const [tag, setTag] = useState("");
  const [listen, setListen] = useState("0.0.0.0");
  const [port, setPort] = useState(PROTOCOLS[0].defaultPort);
  const [fields, setFields] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const wireProtocol = plan.key.startsWith("vless") ? "vless" : plan.key;

  const spec = useMemo(() => ({
    tag: tag.trim() || `${wireProtocol}-${port}`,
    protocol: wireProtocol,
    listen: listen || null,
    port: Number(port),
    settings: {
      inbound_variant: plan.key,
      ...Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== "")),
    },
  }), [tag, wireProtocol, listen, port, fields, plan.key]);

  const submit = async () => {
    setBusy(true); setError("");
    try {
      await api.post(`/zagros/studio/${coreId}/wizard/inbound`, spec);
      toast.ok(`inbound "${spec.tag}" created on ${coreId}`);
      onDone();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t("common.error"));
      setBusy(false);
    }
  };

  const step1Invalid = !port || port < 1 || port > 65535 || existingTags.includes(spec.tag);

  return (
    <Dialog open onClose={onClose} wide
      title={<span className="inline-flex items-center gap-2"><Wand2 size={16} className="text-brand" /> inbound wizard — {coreId}</span>}
      subtitle={`step ${step + 1} of 2 — ${step === 0 ? "choose protocol" : "details & review"}`}
      footer={
        <>
          {step === 1 && <Button variant="ghost" onClick={() => setStep(0)}><ChevronLeft size={14} /> back</Button>}
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          {step === 0
            ? <Button onClick={() => setStep(1)}>continue</Button>
            : <Button onClick={submit} loading={busy} disabled={step1Invalid}><Wand2 size={14} /> create inbound</Button>}
        </>
      }>
      {step === 0 ? (
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
          {PROTOCOLS.map((p) => (
            <button
              key={p.key}
              onClick={() => { setPlan(p); setPort(p.defaultPort); }}
              className={`rounded-xl border p-3 text-start transition-colors ${plan.key === p.key ? "border-brand bg-brand-soft" : "border-border hover:border-border-strong"}`}
            >
              <p className="text-[13px] font-semibold">{p.label}</p>
              <p className="mt-1 text-[10.5px] text-content-3">:{p.defaultPort}</p>
            </button>
          ))}
        </div>
      ) : (
        <div className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="tag" hint={existingTags.includes(spec.tag) ? "this tag already exists" : "unique on this core"}>
              <Input value={tag} placeholder={spec.tag} onChange={(e) => setTag(e.target.value)} dir="ltr" invalid={existingTags.includes(spec.tag)} />
            </Field>
            <Field label="listen">
              <Select value={listen} onChange={(e) => setListen(e.target.value)}>
                <option value="0.0.0.0">0.0.0.0 (all)</option>
                <option value="127.0.0.1">127.0.0.1</option>
              </Select>
            </Field>
            <Field label="port" required>
              <Input type="number" min={1} max={65535} value={port} onChange={(e) => setPort(Number(e.target.value))} dir="ltr" />
            </Field>
          </div>
          <div className="grid gap-4 rounded-xl border border-border p-3.5 sm:grid-cols-3">
            <p className="text-[11px] font-semibold uppercase tracking-wide text-content-3 sm:col-span-3">{plan.label} — specifics</p>
            {plan.fields.map((f) => (
              <Field key={f.key} label={f.label} required={f.required}>
                {f.type === "select" ? (
                  <Select value={fields[f.key] ?? (f.options?.[0] ?? "")} onChange={(e) => setFields({ ...fields, [f.key]: e.target.value })}>
                    {f.options?.map((o) => <option key={o} value={o}>{o || "—"}</option>)}
                  </Select>
                ) : (
                  <Input type={f.type === "number" ? "number" : f.type === "password" ? "password" : "text"}
                    placeholder={f.placeholder} value={fields[f.key] ?? ""}
                    onChange={(e) => setFields({ ...fields, [f.key]: e.target.value })} dir="ltr" />
                )}
              </Field>
            ))}
          </div>
          <div className="rounded-xl bg-surface-2 p-3.5 text-[12px] text-content-2">
            <p className="mb-1 flex items-center gap-1.5 font-medium"><Eye size={13} className="text-brand" /> summary</p>
            <p>
              <b>{plan.label}</b> inbound <code className="font-mono text-[11px]" dir="ltr">{spec.tag}</code> listening on{" "}
              <code className="font-mono text-[11px]" dir="ltr">{listen}:{port}</code> will be validated against the{" "}
              <b>{coreId}</b> schema and appended to its configuration. New users need it enabled in their protocol list.
            </p>
          </div>
        </div>
      )}
      {error && <p role="alert" className="mt-3 rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}
