// Inbounds — visual list + per-protocol creation wizard. The wizard maps a
// structured spec through the studio service (preview → apply); no JSON is
// ever shown to the operator.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, ChevronLeft, Eye, FileUp, Link2, Loader2, Plus, Trash2, Waypoints, Wand2, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "../components/feedback";
import { ConfirmDialog, Dialog } from "../components/overlays";
import { Badge, Button, Card, CardHeader, EmptyState, Field, Input, Select, Skeleton, Textarea } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useT } from "../lib/i18n";
import type { CoreView } from "../lib/types";

// Dynamic wizard blueprint — fetched per core from the backend
// (GET /zagros/cores/{id}/wizard-schema): protocols × transports × securities
// × fields. NOTHING is hardcoded here anymore; switching cores changes the
// entire flow (the alpha.7 fixed-list complaint, fixed at the source).
interface WizardField {
  key: string; label: string; type: "string" | "int" | "bool" | "select" | "multiselect" | "password" | "textarea" | "file";
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

  // wizard capability is a FUNCTION of the selected core (dynamic, from the
  // backend's own metadata — never hardcode a per-core assumption here)
  const selectedCore = useMemo(
    () => (cores.data?.cores ?? []).find((c) => c.id === effectiveCore) ?? null,
    [cores.data, effectiveCore],
  );
  const wizardCapable = selectedCore?.studio_inbounds_path != null;

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
        <Button size="sm" onClick={() => setWizard(true)}
          disabled={!effectiveCore || !wizardCapable}
          title={wizardCapable ? undefined : "this core does not expose studio inbounds — the wizard is unavailable for it"}>
          <Wand2 size={13} /> add inbound</Button>
      </div>

      {!effectiveCore ? (
        <Card><EmptyState title="Install a core first" hint="Inbounds live inside a core's configuration document." /></Card>
      ) : raw.isLoading ? (
        <Skeleton className="h-64" />
      ) : inbounds.length === 0 ? (
        <Card>
          <EmptyState title="No inbounds on this core"
            hint={wizardCapable
              ? "Run the wizard for a protocol-specific, validated creation flow — no hand-written config."
              : "This core does not expose studio inbounds, so no wizard is offered for it."}
            action={wizardCapable
              ? <Button size="sm" onClick={() => setWizard(true)}><Wand2 size={13} /> launch wizard</Button>
              : undefined} />
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
          {wizardCapable && (
            <button onClick={() => setWizard(true)}
              className="grid min-h-[92px] place-items-center rounded-2xl border border-dashed border-border-strong text-content-3 transition-colors hover:border-brand hover:text-brand">
              <span className="flex items-center gap-2 text-sm"><Plus size={16} /> add inbound</span>
            </button>
          )}
        </div>
      )}

      {wizard && effectiveCore && wizardCapable && (
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

interface WizardImportResult {
  tag: string; protocol: string; listen: string | null; port: number;
  transport: string; security: string;
  settings: Record<string, string | number | boolean | string[]>;
  unmapped: { key: string; value: string; reason: string }[];
  source_name?: string;
}
interface WizardPreviewResult { valid: boolean; errors: string[]; diff?: string | null }

function WizardDialog({ coreId, existingTags, onClose, onDone }: {
  coreId: string; existingTags: string[]; onClose: () => void; onDone: () => void;
}) {
  const t = useT();
  const [step, setStep] = useState(0);
  // item 6: Simple/Advanced — Simple asks only what genuinely has no sane
  // default (tag auto-derived, listen fixed to 0.0.0.0, defaulted optional
  // fields hidden); Advanced shows everything a Marzban-style admin expects.
  const [advanced, setAdvanced] = useState(false);
  const [proto, setProto] = useState<WizardProtocol | null>(null);
  const [transport, setTransport] = useState<WizardTransport | null>(null);
  const [security, setSecurity] = useState<WizardSecurity | null>(null);
  const [tag, setTag] = useState("");
  const [listen, setListen] = useState("0.0.0.0");
  const [port, setPort] = useState(443);
  const [fields, setFields] = useState<Record<string, string | string[]>>({});
  const [touched, setTouched] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  // item 6 Import: prefill the stepper from an existing client share link
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importBusy, setImportBusy] = useState(false);
  const [importError, setImportError] = useState("");
  const [importNote, setImportNote] = useState<string[]>([]);

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
    setProto(p); setTransport(null); setSecurity(null); setFields({}); setTouched(new Set()); setPort(p.default_port || 443);
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

  // item 6 Validation: schema-driven, per-field, BEFORE the server round
  // (required fields, int parse, port range, tag uniqueness); honesty rule —
  // the preview call below is still the authoritative server-side verdict.
  const fieldErrors = useMemo(() => {
    const errs: Record<string, string> = {};
    for (const f of effSecurity?.fields ?? []) {
      const raw = fields[f.key];
      const empty = raw === undefined || raw === "" || (Array.isArray(raw) && raw.length === 0);
      const val = raw === undefined ? f.default : raw;
      if (f.required && (val === undefined || val === "" || (Array.isArray(val) && val.length === 0)))
        errs[f.key] = "required";
      else if (!empty && f.type === "int" && !/^-?\d+$/.test(String(raw)))
        errs[f.key] = "must be an integer";
    }
    return errs;
  }, [effSecurity, fields]);
  const missingRequired = (effSecurity?.fields ?? []).filter((f) => {
    const val = fields[f.key] === undefined ? f.default : fields[f.key];
    return f.required && (val === undefined || val === "" || (Array.isArray(val) && val.length === 0));
  });

  // item 6 Preview: server-side dry-run of the EXACT create patch (shared
  // backend path with apply) — schema verdict + unified diff, nothing saved.
  const specKey = JSON.stringify(spec);
  const preview = useQuery({
    queryKey: ["zagros", "wizard-preview", coreId, specKey],
    queryFn: () => api.post<WizardPreviewResult>(`/zagros/studio/${coreId}/wizard/preview`, spec),
    enabled: !!spec && step === 3 && missingRequired.length === 0,
    retry: false,
  });

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

  const doImport = async () => {
    const link = importText.trim();
    if (!link || !schema.data) return;
    setImportBusy(true); setImportError(""); setImportNote([]);
    try {
      const res = await api.post<WizardImportResult>(`/zagros/cores/${coreId}/wizard/import`, { link });
      const p = schema.data.protocols.find((x) => x.id === res.protocol);
      const tr = p?.transports.find((x) => x.id === res.transport);
      const sec = tr?.securities.find((x) => x.id === res.security);
      if (!p || !tr || !sec) throw new Error("imported cell missing from the fetched blueprint — refetch the schema");
      setProto(p); setTransport(tr); setSecurity(sec);
      const mapped: Record<string, string | string[]> = {};
      for (const [k, v] of Object.entries(res.settings)) {
        mapped[k] = Array.isArray(v) ? v.map(String) : typeof v === "boolean" ? String(v) : String(v);
      }
      setFields(mapped); setTouched(new Set());
      setTag(res.tag); setPort(res.port);
      if (res.listen) setListen(res.listen);
      if (res.unmapped.length) {
        setImportNote(res.unmapped.map((u) => `${u.key} = ${u.value} — ${u.reason}`));
      }
      setImportOpen(false); setImportText("");
      setStep(3); // review before create — never auto-apply an import
    } catch (e) {
      setImportError(e instanceof ApiError ? e.message : e instanceof Error ? e.message : t("common.error"));
    } finally {
      setImportBusy(false);
    }
  };

  const stepNames = ["choose protocol", "transport", "security", "details & review"];
  const formInvalid = missingRequired.length > 0 || Object.keys(fieldErrors).length > 0;
  const invalid =
    step === 0 ? !effProto
    : step === 1 ? !effTransport
    : step === 2 ? !effSecurity
    : !spec || !port || port < 1 || port > 65535 || existingTags.includes(spec.tag) || formInvalid;

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

  // a field earns its place in Simple mode when it is required, has no
  // default (the server cannot guess it), or the operator already set it —
  // everything else lives under Advanced (full Marzban-style control).
  const fieldVisible = (f: WizardField) =>
    advanced || !!f.required || f.default === undefined ||
    (fields[f.key] !== undefined && fields[f.key] !== "" &&
     !(Array.isArray(fields[f.key]) && (fields[f.key] as string[]).length === 0));

  return (
    <Dialog open onClose={onClose} wide
      title={<span className="inline-flex items-center gap-2"><Wand2 size={16} className="text-brand" /> inbound wizard — {coreId}</span>}
      subtitle={`step ${step + 1} of 4 — ${stepNames[step]}${advanced ? "" : " · simple"}`}
      headerActions={
        <div className="flex items-center gap-1.5">
          <Button variant="ghost" size="sm" onClick={() => { setImportOpen((v) => !v); setImportError(""); }}
            title="prefill the wizard from an existing client share link">
            <Link2 size={13} /> import</Button>
          <div className="flex overflow-hidden rounded-lg border border-border" role="group" aria-label="wizard mode">
            {(["simple", "advanced"] as const).map((m) => (
              <button key={m} onClick={() => setAdvanced(m === "advanced")}
                className={`px-2.5 py-1 text-[11px] font-medium transition-colors ${
                  (m === "advanced") === advanced ? "bg-brand-soft text-brand" : "text-content-3 hover:text-content-2"}`}>
                {m}
              </button>
            ))}
          </div>
        </div>
      }
      footer={
        <>
          {step > 0 && <Button variant="ghost" onClick={() => setStep(step - 1)}><ChevronLeft size={14} /> back</Button>}
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          {step < 3
            ? <Button onClick={() => setStep(step + 1)} disabled={invalid}>continue</Button>
            : <Button onClick={submit} loading={busy}
                disabled={invalid || (!!preview.data && !preview.data.valid)}
                title={preview.data && !preview.data.valid ? "server validation failed — fix the fields first" : undefined}>
                <Wand2 size={14} /> create inbound</Button>}
        </>
      }>
      {importOpen && (
        <div className="mb-3 space-y-2 rounded-xl border border-border p-3">
          <p className="flex items-center gap-1.5 text-[12px] font-medium text-content-2">
            <FileUp size={13} className="text-brand" /> import from a share link
            <span className="text-content-3">— vless / vmess / trojan / ss / hysteria2 / tuic</span>
          </p>
          <Textarea rows={2} dir="ltr" className="font-mono text-[11px]"
            placeholder="vless://…?type=ws&security=tls#name"
            value={importText} onChange={(e) => setImportText(e.target.value)} />
          <div className="flex items-center gap-2">
            <Button size="sm" onClick={doImport} loading={importBusy} disabled={!importText.trim()}>
              <Link2 size={13} /> parse &amp; prefill</Button>
            <span className="text-[11px] text-content-3">
              the link's credentials belong to a user account — only listener facts are imported;
              anything unmappable is reported, never guessed.
            </span>
          </div>
          {importError && <p role="alert" className="rounded-lg border border-danger/30 bg-danger-soft px-2.5 py-1.5 text-[11px] text-danger">{importError}</p>}
        </div>
      )}
      {importNote.length > 0 && (
        <div className="mb-3 rounded-xl border border-border-strong bg-surface-2 px-3 py-2">
          <p className="mb-1 text-[11px] font-semibold text-content-2">imported with notes (nothing guessed):</p>
          <ul className="list-inside list-disc font-mono text-[10.5px] text-content-3" dir="ltr">
            {importNote.map((n) => <li key={n}>{n}</li>)}
          </ul>
        </div>
      )}
      {schema.isLoading && <div className="space-y-2"><Skeleton className="h-10" /><Skeleton className="h-24" /></div>}
      {schema.isError && (
        <div role="alert" className="flex items-center justify-between gap-3 rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">
          {/* the REAL backend error, not a canned sentence (alpha.7.2):
              e.g. a 404 when the core exposes no wizard blueprint, or the
              panel's actual 5xx detail — actionable feedback for the user */}
          <span>
            {schema.error instanceof ApiError
              ? `${schema.error.message} (HTTP ${schema.error.status})`
              : schema.error instanceof Error
                ? schema.error.message
                : t("common.error")}
          </span>
          <Button variant="ghost" size="sm" onClick={() => schema.refetch()}>retry</Button>
        </div>
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
            {advanced && (
              <Field label="tag" hint={existingTags.includes(spec.tag) ? "this tag already exists" : "unique on this core"}>
                <Input value={tag} placeholder={spec.tag} onChange={(e) => setTag(e.target.value)} dir="ltr" invalid={existingTags.includes(spec.tag)} />
              </Field>
            )}
            {advanced && (
              <Field label="listen">
                <Select value={listen} onChange={(e) => setListen(e.target.value)}>
                  <option value="0.0.0.0">0.0.0.0 (all)</option>
                  <option value="127.0.0.1">127.0.0.1</option>
                </Select>
              </Field>
            )}
            <Field label="port" required
              hint={!port || port < 1 || port > 65535 ? "1–65535" : undefined}>
              <Input type="number" min={1} max={65535} value={port}
                onChange={(e) => setPort(Number(e.target.value))} dir="ltr"
                invalid={!port || port < 1 || port > 65535} />
            </Field>
          </div>
          {effSecurity && effSecurity.fields.some(fieldVisible) && (
            <div className="grid gap-4 rounded-xl border border-border p-3.5 sm:grid-cols-3">
              <p className="text-[11px] font-semibold uppercase tracking-wide text-content-3 sm:col-span-3">
                {effProto?.label} / {effTransport?.label} / {effSecurity.label} — settings
                {!advanced && <span className="ms-1.5 normal-case tracking-normal">(showing only what needs a decision — switch to advanced for the rest)</span>}
              </p>
              {effSecurity.fields.filter(fieldVisible).map((f) => {
                const err = fieldErrors[f.key];
                const showErr = !!err && (touched.has(f.key) || !!err && f.required && fields[f.key] !== undefined);
                const mark = () => setTouched((cur) => new Set(cur).add(f.key));
                return (
                <Field key={f.key} label={f.label} required={f.required}
                  hint={showErr ? err : f.help}>
                  {f.type === "select" ? (
                    <Select value={(fields[f.key] as string) ?? String(f.default ?? f.options?.[0] ?? "")}
                      onChange={(e) => { setFields({ ...fields, [f.key]: e.target.value }); mark(); }}>
                      {f.options?.map((o) => <option key={o} value={o}>{o || "—"}</option>)}
                    </Select>
                  ) : f.type === "bool" ? (
                    <Select value={(fields[f.key] as string) ?? String(f.default ?? "false")}
                      onChange={(e) => { setFields({ ...fields, [f.key]: e.target.value }); mark(); }}>
                      <option value="true">yes</option>
                      <option value="false">no</option>
                    </Select>
                  ) : f.type === "textarea" || f.type === "file" ? (
                    <div className="sm:col-span-2">
                      <Textarea rows={f.type === "file" ? 5 : 3}
                        placeholder={f.placeholder}
                        value={(fields[f.key] as string) ?? String(f.default ?? "")}
                        onChange={(e) => setFields({ ...fields, [f.key]: e.target.value })}
                        onBlur={mark} dir="ltr"
                        className="font-mono text-[11px]" />
                      {f.type === "file" && (
                        <label className="mt-1.5 inline-flex cursor-pointer items-center gap-1.5 text-[11px] text-brand hover:underline">
                          <input type="file" className="hidden" accept=".pem,.crt,.cer,.key,.txt"
                            onChange={(e) => {
                              const file = e.target.files?.[0];
                              if (!file) return;
                              const rd = new FileReader();
                              rd.onload = () => setFields((cur) => ({ ...cur, [f.key]: String(rd.result ?? "") }));
                              rd.readAsText(file);
                              e.target.value = "";
                            }} />
                          or choose a file to paste its content
                        </label>
                      )}
                    </div>
                  ) : f.type === "multiselect" ? (
                    <div className="flex flex-wrap gap-2 pt-1.5">
                      {f.options?.map((o) => {
                        const cur = (fields[f.key] as string[]) ?? (Array.isArray(f.default) ? f.default : []);
                        const on = cur.includes(o);
                        return (
                          <button key={o} type="button"
                            onClick={() => { setFields({ ...fields, [f.key]: on ? cur.filter((x) => x !== o) : [...cur, o] }); mark(); }}
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
                      onChange={(e) => setFields({ ...fields, [f.key]: e.target.value })}
                      onBlur={mark} dir="ltr" invalid={showErr} />
                  )}
                </Field>
                );
              })}
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
          {/* item 6 Preview — authoritative server-side verdict on the EXACT
              patch create would apply; the button stays enabled until the
              server definitively rejects, and then it cannot create. */}
          {missingRequired.length > 0 ? (
            <p className="flex items-center gap-1.5 rounded-xl border border-border px-3 py-2 text-[11.5px] text-content-3">
              <XCircle size={13} /> fill {missingRequired.length} required field(s) to run the server-side preview
            </p>
          ) : preview.isPending ? (
            <p className="flex items-center gap-1.5 rounded-xl border border-border px-3 py-2 text-[11.5px] text-content-3">
              <Loader2 size={13} className="animate-spin" /> server-side preview of the exact patch…
            </p>
          ) : preview.isError ? (
            <div className="flex items-center justify-between gap-3 rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">
              <span>{preview.error instanceof ApiError ? preview.error.message : "preview request failed"}</span>
              <Button variant="ghost" size="sm" onClick={() => preview.refetch()}>retry</Button>
            </div>
          ) : preview.data?.valid ? (
            <div className="rounded-xl border border-ok/30 bg-ok-soft px-3 py-2 text-[11.5px]">
              <p className="flex items-center gap-1.5 font-medium text-ok">
                <CheckCircle2 size={13} /> server validation passed — this exact patch will be applied:
              </p>
              {preview.data.diff && (
                <details className="mt-1.5">
                  <summary className="cursor-pointer text-content-3 hover:text-content-2">view diff</summary>
                  <pre className="mt-1 max-h-44 overflow-auto rounded-lg bg-surface-1 p-2 font-mono text-[10px] text-content-2" dir="ltr">{preview.data.diff}</pre>
                </details>
              )}
            </div>
          ) : preview.data ? (
            <div className="rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">
              <p className="flex items-center gap-1.5 font-medium"><XCircle size={13} /> server validation rejected this inbound:</p>
              <ul className="mt-1 list-inside list-disc font-mono text-[10.5px]" dir="ltr">
                {preview.data.errors.map((e) => <li key={e}>{e}</li>)}
              </ul>
            </div>
          ) : null}
        </div>
      )}
      {error && <p role="alert" className="mt-3 rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}
