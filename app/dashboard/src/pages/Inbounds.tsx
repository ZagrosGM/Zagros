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

// Dynamic wizard blueprint — fetched per core from the backend
// (GET /zagros/cores/{id}/wizard-schema): protocols × transports × securities
// × fields. NOTHING is hardcoded here anymore; switching cores changes the
// entire flow (the alpha.7 fixed-list complaint, fixed at the source).
interface WizardField {
  key: string; label: string; type: "string" | "int" | "bool" | "select" | "multiselect" | "password";
  required?: boolean; default?: string | number | boolean | string[];
  options?: string[]; placeholder?: string; help?: string;
}
interface WizardSecurity { id: string; label: string; fields: WizardField[] }
interface WizardTransport { id: string; label: string; securities: WizardSecurity[] }
interface WizardProtocol { id: string; label: string; default_port: number; transports: WizardTransport[] }
interface WizardSchema { core_id: string; protocols: WizardProtocol[] }

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
            {!cores.data?.cores?.length && <option value="">—</option>}
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
  const [proto, setProto] = useState<WizardProtocol | null>(null);
  const [transport, setTransport] = useState<WizardTransport | null>(null);
  const [security, setSecurity] = useState<WizardSecurity | null>(null);
  const [tag, setTag] = useState("");
  const [listen, setListen] = useState("0.0.0.0");
  const [port, setPort] = useState(443);
  const [fields, setFields] = useState<Record<string, string | string[]>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const schema = useQuery({
    queryKey: ["zagros", "wizard-schema", coreId],
    queryFn: () => api.get<WizardSchema>(`/zagros/cores/${coreId}/wizard-schema`),
    retry: false, staleTime: 600000,
  });

  // sensible defaults once the blueprint lands / whenever an ancestor changes
  const effProto = proto ?? schema.data?.protocols[0] ?? null;
  const effTransport = transport ?? effProto?.transports[0] ?? null;
  const effSecurity = security ?? effTransport?.securities[0] ?? null;

  const pickProto = (p: WizardProtocol) => {
    setProto(p); setTransport(null); setSecurity(null); setFields({}); setPort(p.default_port || 443);
  };
  const pickTransport = (tr: WizardTransport) => { setTransport(tr); setSecurity(null); };

  const spec = useMemo(() => {
    if (!effProto || !effTransport || !effSecurity) return null;
    const settings: Record<string, unknown> = {
      transport: effTransport.id,
      security: effSecurity.id,
    };
    for (const f of effSecurity.fields) {
      const v = fields[f.key];
      if (v === undefined || v === "") continue;
      settings[f.key] = f.type === "int" ? Number(v) : f.type === "bool" ? v === "true" : v;
    }
    return {
      tag: tag.trim() || `${effProto.id}-${port}`,
      protocol: effProto.id,
      listen: listen || null,
      port: Number(port),
      settings,
    };
  }, [effProto, effTransport, effSecurity, tag, listen, port, fields]);

  const submit = async () => {
    if (!spec) return;
    setBusy(true); setError("");
    try {
      const res = await api.post<{ materialized?: boolean; notice?: string }>(`/zagros/studio/${coreId}/wizard/inbound`, spec);
      toast.ok(res.materialized === false
        ? `inbound "${spec.tag}" saved on ${coreId} (applies on next start)`
        : `inbound "${spec.tag}" created on ${coreId}`);
      onDone();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t("common.error"));
      setBusy(false);
    }
  };

  const stepNames = ["choose protocol", "transport", "security", "details & review"];
  const invalid =
    step === 0 ? !effProto
    : step === 1 ? !effTransport
    : step === 2 ? !effSecurity
    : !spec || !port || port < 1 || port > 65535 || existingTags.includes(spec.tag);

  const renderChoice = (
    <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
      {(step === 0 ? schema.data?.protocols ?? [] : step === 1 ? effProto?.transports ?? [] : effTransport?.securities ?? []).map((o: { id: string; label: string; default_port?: number }) => {
        const active =
          step === 0 ? effProto?.id === o.id : step === 1 ? effTransport?.id === o.id : effSecurity?.id === o.id;
        return (
          <button key={o.id} onClick={() => (step === 0 ? pickProto(o as WizardProtocol) : step === 1 ? pickTransport(o as WizardTransport) : setSecurity(o as WizardSecurity))}
            className={`rounded-xl border p-3 text-start transition-colors ${active ? "border-brand bg-brand-soft" : "border-border hover:border-border-strong"}`}>
            <p className="text-[13px] font-semibold">{o.label}</p>
            {o.default_port ? <p className="mt-1 text-[10.5px] text-content-3">:{o.default_port}</p> : null}
          </button>
        );
      })}
    </div>
  );

  return (
    <Dialog open onClose={onClose} wide
      title={<span className="inline-flex items-center gap-2"><Wand2 size={16} className="text-brand" /> inbound wizard — {coreId}</span>}
      subtitle={`step ${step + 1} of 4 — ${stepNames[step]}`}
      footer={
        <>
          {step > 0 && <Button variant="ghost" onClick={() => setStep(step - 1)}><ChevronLeft size={14} /> back</Button>}
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          {step < 3
            ? <Button onClick={() => setStep(step + 1)} disabled={invalid}>continue</Button>
            : <Button onClick={submit} loading={busy} disabled={invalid}><Wand2 size={14} /> create inbound</Button>}
        </>
      }>
      {schema.isLoading && <div className="space-y-2"><Skeleton className="h-10" /><Skeleton className="h-24" /></div>}
      {schema.isError && (
        <p role="alert" className="rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">
          no dynamic wizard blueprint for this core — use Advanced Mode for raw edits.
        </p>
      )}
      {schema.data && step < 3 && renderChoice}
      {schema.data && step === 3 && spec && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-1.5 text-[11.5px] text-content-2">
            {[effProto?.label, effTransport?.label, effSecurity?.label].filter(Boolean).map((x, i, arr) => (
              <span key={String(x)} className="inline-flex items-center gap-1.5">
                <span className="rounded-lg bg-brand-soft px-2 py-0.5 font-medium text-brand">{x}</span>
                {i < arr.length - 1 && <span className="text-content-3">→</span>}
              </span>
            ))}
          </div>
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
          {effSecurity && effSecurity.fields.length > 0 && (
            <div className="grid gap-4 rounded-xl border border-border p-3.5 sm:grid-cols-3">
              <p className="text-[11px] font-semibold uppercase tracking-wide text-content-3 sm:col-span-3">
                {effProto?.label} / {effTransport?.label} / {effSecurity.label} — settings
              </p>
              {effSecurity.fields.map((f) => (
                <Field key={f.key} label={f.label} required={f.required} hint={f.help}>
                  {f.type === "select" ? (
                    <Select value={(fields[f.key] as string) ?? String(f.default ?? f.options?.[0] ?? "")}
                      onChange={(e) => setFields({ ...fields, [f.key]: e.target.value })}>
                      {f.options?.map((o) => <option key={o} value={o}>{o || "—"}</option>)}
                    </Select>
                  ) : f.type === "multiselect" ? (
                    <div className="flex flex-wrap gap-2 pt-1.5">
                      {f.options?.map((o) => {
                        const cur = (fields[f.key] as string[]) ?? (Array.isArray(f.default) ? f.default : []);
                        const on = cur.includes(o);
                        return (
                          <button key={o} type="button"
                            onClick={() => setFields({ ...fields, [f.key]: on ? cur.filter((x) => x !== o) : [...cur, o] })}
                            className={`rounded-lg border px-2.5 py-1 text-[11.5px] ${on ? "border-brand bg-brand-soft text-brand" : "border-border text-content-2"}`}>
                            {o}
                          </button>
                        );
                      })}
                    </div>
                  ) : (
                    <Input type={f.type === "int" ? "number" : f.type === "password" ? "password" : "text"}
                      placeholder={f.placeholder}
                      value={(fields[f.key] as string) ?? String(f.default ?? "")}
                      onChange={(e) => setFields({ ...fields, [f.key]: e.target.value })} dir="ltr" />
                  )}
                </Field>
              ))}
            </div>
          )}
          <div className="rounded-xl bg-surface-2 p-3.5 text-[12px] text-content-2">
            <p className="mb-1 flex items-center gap-1.5 font-medium"><Eye size={13} className="text-brand" /> summary</p>
            <p>
              <b>{effProto?.label}</b> over <b>{effTransport?.label}</b> with <b>{effSecurity?.label}</b> — inbound{" "}
              <code className="font-mono text-[11px]" dir="ltr">{spec.tag}</code> on{" "}
              <code className="font-mono text-[11px]" dir="ltr">{listen}:{port}</code> will be validated against the{" "}
              <b>{coreId}</b> schema and materialized into its configuration. New users need it granted in their core access.
            </p>
          </div>
        </div>
      )}
      {error && <p role="alert" className="mt-3 rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}
