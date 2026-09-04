// Inbounds — visual list + per-protocol creation wizard. The wizard maps a
// structured spec through the studio service (preview → apply); no JSON is
// ever shown to the operator.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, ChevronLeft, Copy, Eye, Loader2, Pencil, Plus, Trash2, Waypoints, Wand2, XCircle } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { toast } from "../components/feedback";
import { ConfirmDialog, Dialog } from "../components/overlays";
import { Badge, Button, Card, CardHeader, EmptyState, Field, Input, Select, Skeleton, Textarea } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { copyText } from "../lib/clipboard";
import { useT } from "../lib/i18n";
import type { CoreView } from "../lib/types";

// Dynamic wizard blueprint — fetched per core from the backend
// (GET /zagros/cores/{id}/wizard-schema): protocols × transports × securities
// × fields. NOTHING is hardcoded here anymore; switching cores changes the
// entire flow (the fixed-list complaint, fixed at the source).
interface WizardField {
  key: string; label: string; type: "string" | "int" | "bool" | "select" | "multiselect" | "password" | "textarea" | "file";
  required?: boolean; default?: string | number | boolean | string[];
  options?: string[]; placeholder?: string; help?: string;
  /** schema-driven UX grouping: which
   *  panel the field belongs to — the stepper renders groups, not a flat
   *  wall. "headers" joins for the transport verb/header depth. */
  section?: "general" | "transport" | "headers" | "tls" | "reality" | "certificate" | "advanced";
  /** {sibling key: allowed values} — the field applies (is shown AND
   *  submitted) only while every listed sibling holds an allowed value,
   *  e.g. the RAW/TCP camouflage facts only under header_type = http. */
  depends_on?: Record<string, string[]>;
}
interface WizardSecurity { id: string; label: string; fields: WizardField[] }
interface WizardTransport { id: string; label: string; securities: WizardSecurity[] }
interface WizardProtocol {
  id: string; label: string; default_port: number; fixed_port?: boolean;
  availability?: "supported" | "unsupported" | "environment_limited" | "not_installed" | "not_applicable";
  reason?: string | null;
  security_class?: string | null;
  transports: WizardTransport[];
}
interface WizardSchema { core_id: string; protocols: WizardProtocol[] }

interface InboundRow { tag: string; protocol: string; listen?: string; port: number | string; [k: string]: unknown }

export default function Inbounds() {
  const t = useT();
  const qc = useQueryClient();
  const [coreId, setCoreId] = useState<string>("");
  const [wizard, setWizard] = useState<null | { mode: "create" | "edit" | "clone"; row?: InboundRow }>(null);
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

  //: delete by STABLE IDENTITY (the tag) via the dedicated
  // endpoint — the old flow computed an INDEX off a possibly-stale snapshot
  // and removed a positional patch, which could delete the WRONG inbound
  // (or several, after concurrent edits shifted the list).
  const removeInbound = useMutation({
    mutationFn: (tag: string) =>
      api.delete<{ ok: boolean; deleted: string }>(
        `/zagros/studio/${effectiveCore}/wizard/inbound/${encodeURIComponent(tag)}`),
    onSuccess: (res) => {
      toast.ok(res?.ok === false ? t("common.error") : t("common.deleted"));
      setDeleteFor(null);
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
        <Field label={t("core")}>
          <Select value={effectiveCore} onChange={(e) => setCoreId(e.target.value)} className="w-40">
            {(cores.data?.cores ?? []).map((c) => <option key={c.id} value={c.id}>{c.id}</option>)}
            {!cores.data?.cores?.length && <option value="">—</option>}
          </Select>
        </Field>
        <Button size="sm" onClick={() => setWizard({ mode: "create" })}
          disabled={!effectiveCore || !wizardCapable}
          title={wizardCapable ? undefined : "this core does not expose studio inbounds — the wizard is unavailable for it"}>
          <Wand2 size={13} />{t("add inbound")}</Button>
      </div>

      {!effectiveCore ? (
        <Card><EmptyState title={t("Install a core first")} hint={t("Inbounds live inside a core's configuration document.")} /></Card>
      ) : raw.isLoading ? (
        <Skeleton className="h-64" />
      ) : inbounds.length === 0 ? (
        <Card>
          <EmptyState title={t("No inbounds on this core")}
            hint={wizardCapable
              ? "Run the wizard for a protocol-specific, validated creation flow — no hand-written config."
              : "This core does not expose studio inbounds, so no wizard is offered for it."}
            action={wizardCapable
              ? <Button size="sm" onClick={() => setWizard({ mode: "create" })}><Wand2 size={13} />{t("launch wizard")}</Button>
              : undefined} />
        </Card>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {inbounds.map((ib) => (
            <Card key={ib.tag} className="flex items-start justify-between gap-3 p-4">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <h3 className="truncate text-sm font-semibold" dir="ltr">{ib.tag}</h3>
                  <Badge tone={ib.security_class === "legacy_insecure" ? "danger" : "brand"}>
                    {ib.protocol}{ib.security_class === "legacy_insecure" ? " · Legacy / Insecure" : ""}
                  </Badge>
                </div>
                <p className="mt-1 font-mono text-[11px] text-content-3" dir="ltr">
                  {String(ib.listen ?? "0.0.0.0")}:{String(ib.port)}
                </p>
              </div>
              <div className="flex shrink-0 flex-col gap-0.5">
                {wizardCapable && (
                  <>
                    <Button variant="ghost" size="icon" aria-label={t("edit {tag}", { tag: ib.tag })}
                      title={t("edit this inbound through the wizard")}
                      onClick={() => setWizard({ mode: "edit", row: ib })}>
                      <Pencil size={13} />
                    </Button>
                    <Button variant="ghost" size="icon" aria-label={t("clone {tag}", { tag: ib.tag })}
                      title={t("clone into a new inbound")}
                      onClick={() => setWizard({ mode: "clone", row: ib })}>
                      <Copy size={13} />
                    </Button>
                  </>
                )}
                <Button variant="ghost" size="icon" aria-label={t("remove {tag}", { tag: ib.tag })} onClick={() => setDeleteFor(ib)}>
                  <Trash2 size={14} />
                </Button>
              </div>
            </Card>
          ))}
          {wizardCapable && (
            <button onClick={() => setWizard({ mode: "create" })}
              className="grid min-h-[92px] place-items-center rounded-2xl border border-dashed border-border-strong text-content-3 transition-colors hover:border-brand hover:text-brand">
              <span className="flex items-center gap-2 text-sm"><Plus size={16} />{t("add inbound")}</span>
            </button>
          )}
        </div>
      )}

      {wizard && effectiveCore && wizardCapable && (
        <WizardDialog coreId={effectiveCore} existingTags={inbounds.map((i) => i.tag)}
          mode={wizard.mode} initial={wizard.row}
          onClose={() => setWizard(null)}
          onDone={() => {
            setWizard(null);
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

interface WizardPreviewResult { valid: boolean; errors: string[]; diff?: string | null }

function WizardDialog({ coreId, existingTags, mode = "create", initial, onClose, onDone }: {
  coreId: string; existingTags: string[];
  /** item 11: Create | Edit | Clone — Edit replaces the existing document
   *  entry in place; Clone pre-fills everything but the tag */
  mode?: "create" | "edit" | "clone";
  initial?: InboundRow;
  onClose: () => void; onDone: () => void;
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
  //: the port starts EMPTY and fills from a host-aware
  // random five-digit suggestion (never a famous 443) — fully clearable and
  // overridable; "" is a valid in-progress state, validation catches intent.
  const [port, setPort] = useState<number | "">("");
  const portTouchedRef = useRef(false);
  // deterministic generation contract: ONE suggestion per wizard-open and
  // protocol — switching protocols re-suggests (untouched), re-opening the
  // wizard draws fresh, and a displayed suggestion never shuffles mid-edit.
  const [dialogSeed] = useState(() => Date.now());
  const [fields, setFields] = useState<Record<string, string | string[]>>({});
  const [touched, setTouched] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  //: TLS certificate source — stored (managed registry),
  // pasted PEM content, server-side file paths, or runtime self-signed
  // (auto; runtime-only, NEVER registered as a managed certificate).
  const [certMode, setCertMode] = useState<"ref" | "paste" | "path" | "auto">("auto");

  const schema = useQuery({
    queryKey: ["zagros", "wizard-schema", coreId],
    queryFn: () => api.get<WizardSchema>(`/zagros/cores/${coreId}/wizard-schema`),
    retry: false, staleTime: 600000,
  });
  // item 10: managed certs for the Certificate section (pick existing OR paste)
  const certsQ = useQuery({
    queryKey: ["zagros", "certificates"],
    queryFn: () => api.get<{ certificates: { name: string; managed: boolean; expired: boolean }[] }>("/zagros/certificates"),
    staleTime: 60000,
  });
  const [certRef, setCertRef] = useState("");

  //: host-aware random port suggestion — re-keyed per
  // protocol (fresh suggestion per selection) and per dialog lifetime
  // (dialogSeed: the deterministic-per-open contract). Edit mode never
  // touches the inbound's real port.
  const suggestPort = useQuery({
    queryKey: ["zagros", "suggest-port", coreId, proto?.id ?? "auto", dialogSeed],
    queryFn: () => api.get<{ port: number }>(`/zagros/cores/${coreId}/suggest-port`),
    enabled: mode !== "edit" && !!coreId && !proto?.fixed_port,
    staleTime: Infinity, gcTime: 0, retry: false,
  });
  useEffect(() => {
    if (mode === "edit" || portTouchedRef.current) return;
    if (suggestPort.data?.port) {
      setPort(suggestPort.data.port);
    } else if (suggestPort.isError) {
      // the suggestion service is unreachable — degrade to a client-side
      // random five-digit port (no host knowledge, never a static 443)
      setPort(10000 + Math.floor(Math.random() * 50000));
    }
  }, [suggestPort.data, suggestPort.isError, mode]);

  // sensible defaults once the blueprint lands / whenever an ancestor changes
  const effProto = proto ?? schema.data?.protocols[0] ?? null;
  const effTransport = transport ?? effProto?.transports[0] ?? null;
  const effSecurity = security ?? effTransport?.securities[0] ?? null;

  // item 11 prefill (Edit/Clone): replay the existing document entry into the
  // wizard EXACTLY — no field may reset without the operator touching it.
  useEffect(() => {
    if (!initial || !schema.data) return;
    const p = schema.data.protocols.find((x) => x.id === initial.protocol);
    const tr = p?.transports.find((x) => x.id === String(initial.transport ?? ""));
    const sec = tr?.securities.find((x) => x.id === String(initial.security ?? ""));
    if (!p || !tr || !sec) {
      setError(`inbound "${initial.tag}" was not wizard-authored (or its blueprint changed) — edit it in Advanced Mode`);
      return;
    }
    setProto(p); setTransport(tr); setSecurity(sec);
    setTag(mode === "clone" ? `${initial.tag}-copy` : String(initial.tag));
    if (typeof initial.listen === "string" && initial.listen) setListen(initial.listen);
    // Edit keeps the inbound's real port verbatim. Clone deliberately gets a
    // FRESH suggested port — cloning the port too would bind two listeners
    // to one socket; everything else is carried over, so re-typing the old
    // port is one keystroke if that is really intended.
    if (mode === "edit") {
      const portNum = p.fixed_port ? p.default_port : Number(initial.port);
      if (portNum > 0) { setPort(portNum); portTouchedRef.current = !p.fixed_port; }
    } else if (p.fixed_port) {
      setPort(p.default_port); portTouchedRef.current = false;
    }
    // certificate path mode restores cleanly (paths are not secrets); pasted
    // PEM content still never round-trips.
    if (initial.certificate_path && initial.certificate_key_path) setCertMode("path");
    const known = new Set(sec.fields.map((f) => f.key));
    const restored: Record<string, string | string[]> = {};
    for (const [k, v] of Object.entries(initial)) {
      if (!known.has(k) || v === undefined || v === null) continue;
      if (k === "certificate" || k === "certificate_key") continue; // secrets never round-trip
      restored[k] = Array.isArray(v) ? (v as unknown[]).map(String) : String(v);
    }
    setFields(restored);
    setStep(3); // review-first for edits
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initial, schema.data]);

  // certificate material keys — included in the spec ONLY for the active
  // cert mode, so a stale field from another mode can never leak into the
  // payload.
  const CERT_KEYS = new Set(["certificate", "certificate_key", "certificate_path", "certificate_key_path"]);

  const pickProto = (p: WizardProtocol) => {
    if (p.availability && p.availability !== "supported") return;
    setProto(p); setTransport(null); setSecurity(null); setFields({}); setTouched(new Set());
    setCertRef(""); setCertMode("auto");
    if (p.fixed_port) {
      // L2TP/IPsec and raw L2TP have wire-standard ports. Showing a random
      // editable value made Studio promise a listener SoftEther cannot bind.
      setPort(p.default_port); portTouchedRef.current = false;
    } else if (!portTouchedRef.current) {
      setPort(""); // the protocol-keyed suggestion query supplies a fresh port
    }
  };
  const pickTransport = (tr: WizardTransport) => { setTransport(tr); setSecurity(null); setCertRef(""); setCertMode("auto"); };
  const pickSecurity = (next: WizardSecurity) => {
    setSecurity(next);
    setCertRef("");
    setCertMode("auto");
    // TLS → None/REALITY must remove stale certificate material from local
    // state as well as from the payload. Switching back to TLS starts with a
    // clean certificate decision instead of resurrecting an old private key.
    setFields((current) => Object.fromEntries(
      Object.entries(current).filter(([key]) => !CERT_KEYS.has(key)),
    ));
  };

  // Effective value of a field: what the operator typed, else the schema
  // default (the input shows exactly this).
  const effectiveValue = (key: string): unknown => {
    if (fields[key] !== undefined) return fields[key];
    return effSecurity?.fields.find((f) => f.key === key)?.default;
  };
  // A dependent field only applies while its controlling siblings hold one
  // of the allowed values — otherwise it is neither shown nor submitted, so a
  // hidden default (GET / 200 / OK under header_type = none) can never
  // contradict the visible choice server-side.
  const depsMet = (f: WizardField): boolean =>
    Object.entries(f.depends_on ?? {}).every(([key, allowed]) => {
      const v = effectiveValue(key);
      return allowed.includes(v === undefined || v === null ? "" : String(v));
    });
  // Controllers (fields others depend on) are a real decision — visible even
  // in Simple mode.
  const isController = (f: WizardField): boolean =>
    (effSecurity?.fields ?? []).some((o) => o.depends_on && Object.keys(o.depends_on).includes(f.key));

  const spec = useMemo(() => {
    if (!effProto || !effTransport || !effSecurity) return null;
    const settings: Record<string, unknown> = {
      transport: effTransport.id,
      security: effSecurity.id,
    };
    for (const f of effSecurity.fields) {
      if (!depsMet(f)) continue;
      // The displayed schema default is part of the submitted spec. The old
      // code rendered defaults in the input but skipped them in the payload;
      // generated required values (notably SoftEther's L2TP PSK) therefore
      // looked filled while the backend received an empty field.
      const v = fields[f.key] === undefined ? f.default : fields[f.key];
      if (v === undefined || v === "") continue;
      if (CERT_KEYS.has(f.key)) {
        if (certMode === "paste" && (f.key === "certificate" || f.key === "certificate_key")) { /* keep */ }
        else if (certMode === "path" && f.key.endsWith("_path")) { /* keep */ }
        else continue; // ref/auto resolve server-side or are not material
      }
      settings[f.key] = f.type === "int"
        ? Number(v)
        : f.type === "bool"
          ? (typeof v === "boolean" ? v : v === "true")
          : v;
    }
    if (certMode === "ref" && certRef) settings.certificate_ref = certRef;
    return {
      tag: tag.trim() || `${effProto.id}-${port || "auto"}`,
      protocol: effProto.id,
      listen: listen || null,
      port: Number(port),
      settings,
    };
  }, [effProto, effTransport, effSecurity, tag, listen, port, fields, certRef, certMode]);

  // item 6 Validation: schema-driven, per-field, BEFORE the server round
  // (required fields, int parse, port range, tag uniqueness); honesty rule —
  // the preview call below is still the authoritative server-side verdict.
  const fieldErrors = useMemo(() => {
    const errs: Record<string, string> = {};
    for (const f of effSecurity?.fields ?? []) {
      if (!depsMet(f)) continue;
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
    if (!depsMet(f)) return false;
    const val = fields[f.key] === undefined ? f.default : fields[f.key];
    return f.required && (val === undefined || val === "" || (Array.isArray(val) && val.length === 0));
  });

  // item 6 Preview: server-side dry-run of the EXACT create patch (shared
  // backend path with apply) — schema verdict + unified diff, nothing saved.
  const specKey = JSON.stringify(spec);
  // certificate-mode completeness gates (item 6): a chosen source must be
  // FULLY specified — an empty "stored" pick or a half path/paste pair must
  // never silently degrade into an unintended self-signed default.
  const tlsCertInvalid = effSecurity?.id === "tls" && (
    (certMode === "ref" && !certRef) ||
    (certMode === "path" && (!String(fields.certificate_path ?? "").trim() ||
                             !String(fields.certificate_key_path ?? "").trim())) ||
    (certMode === "paste" && (!String(fields.certificate ?? "").trim() !==
                              !String(fields.certificate_key ?? "").trim()))
  );

  const preview = useQuery({
    queryKey: ["zagros", "wizard-preview", coreId, specKey, certMode, certRef],
    queryFn: () => api.post<WizardPreviewResult>(`/zagros/studio/${coreId}/wizard/preview`, spec),
    enabled: !!spec && step === 3 && missingRequired.length === 0 && !tlsCertInvalid,
    retry: false,
  });

  //: hard double-submit guard — a synchronous in-flight
  // ref (state lags one render; two fast clicks would both pass a
  // `if (busy)` check). Combined with the server-side idempotent create,
  // a double click CANNOT fork a duplicate inbound anymore.
  const inFlight = useRef(false);

  const submit = async () => {
    if (!spec || inFlight.current) return;
    inFlight.current = true;
    setBusy(true); setError("");
    try {
      const res = mode === "edit" && initial
        ? await api.put<{ materialized?: boolean | null; notice?: string; changed?: boolean }>(
            `/zagros/studio/${coreId}/wizard/inbound/${encodeURIComponent(String(initial.tag))}`, spec)
        : await api.post<{ materialized?: boolean | null; notice?: string; changed?: boolean }>(`/zagros/studio/${coreId}/wizard/inbound`, spec);
      toast.ok(
        mode === "edit"
          ? `inbound "${spec.tag}" updated on ${coreId}${res.materialized === false ? " (applies on next start)" : ""}`
          : res.changed === false
            ? `inbound "${spec.tag}" already exists as requested — nothing changed`
            : res.materialized === false
              ? `inbound "${spec.tag}" saved on ${coreId} (applies on next start)`
              : `inbound "${spec.tag}" created on ${coreId}`);
      onDone();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t("common.error"));
      setBusy(false);
      inFlight.current = false;
    }
  };

  const stepNames = ["choose protocol", "transport", "security", "details & review"];
  const formInvalid = missingRequired.length > 0 || Object.keys(fieldErrors).length > 0;
  // Edit keeps its own tag (replace-in-place); Create/Clone need a fresh one
  const tagClash = mode === "edit"
    ? existingTags.includes(spec?.tag ?? "") && spec?.tag !== initial?.tag
    : existingTags.includes(spec?.tag ?? "");
  const invalid =
    step === 0 ? !effProto
    : step === 1 ? !effTransport
    : step === 2 ? !effSecurity
    : !spec || !port || port < 1 || port > 65535 || tagClash || formInvalid || !!tlsCertInvalid;

  const renderChoice = (
    <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
      {(step === 0 ? schema.data?.protocols ?? [] : step === 1 ? effProto?.transports ?? [] : effTransport?.securities ?? []).map((o: { id: string; label: string; default_port?: number; availability?: string; reason?: string | null }) => {
        const active =
          step === 0 ? effProto?.id === o.id : step === 1 ? effTransport?.id === o.id : effSecurity?.id === o.id;
        const unavailable = step === 0 && o.availability && o.availability !== "supported";
        return (
          <button key={o.id} disabled={Boolean(unavailable)} title={o.reason ?? undefined}
            onClick={() => (step === 0 ? pickProto(o as WizardProtocol) : step === 1 ? pickTransport(o as WizardTransport) : pickSecurity(o as WizardSecurity))}
            className={`rounded-xl border p-3 text-start transition-colors ${unavailable ? "cursor-not-allowed border-border opacity-60" : active ? "border-brand bg-brand-soft" : "border-border hover:border-border-strong"}`}>
            <p className="text-[13px] font-semibold">{o.label}</p>
            {unavailable && <p className="mt-1 text-[10.5px] text-warn">{o.availability?.replace(/_/g, " ")} — {o.reason}</p>}
            {/* items 2+7: NO port line on initial protocol cards —
                neither a fabricated number nor a misleading placeholder. The
                real port is the suggested editable value in the review
                step, nothing before it. */}
          </button>
        );
      })}
    </div>
  );

  // a field earns its place in Simple mode when it is required, has no
  // default (the server cannot guess it), or the operator already set it —
  // everything else lives under Advanced (full Marzban-style control).
  const fieldVisible = (f: WizardField) =>
    depsMet(f) && (
      advanced || !!f.required || f.default === undefined || isController(f) ||
      (fields[f.key] !== undefined && fields[f.key] !== "" &&
       !(Array.isArray(fields[f.key]) && (fields[f.key] as string[]).length === 0)));

  return (
    <Dialog open onClose={onClose} wide
      title={<span className="inline-flex items-center gap-2"><Wand2 size={16} className="text-brand" /> {mode === "edit" ? "edit inbound" : mode === "clone" ? "clone inbound" : "inbound wizard"} — {coreId}</span>}
      subtitle={`step ${step + 1} of 4 — ${stepNames[step]}${advanced ? "" : " · simple"}`}
      headerActions={
        <div className="flex items-center gap-1.5">
          {/* the «import from URL» path is gone — the
              wizard is authored from the blueprint alone (the endpoint and
              its module were removed server-side too). */}
          <div className="flex overflow-hidden rounded-lg border border-border" role="group" aria-label={t("wizard mode")}>
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
                <Wand2 size={14} /> {mode === "edit" ? "save changes" : "create inbound"}</Button>}
        </>
      }>
      {schema.isLoading && <div className="space-y-2"><Skeleton className="h-10" /><Skeleton className="h-24" /></div>}
      {schema.isError && (
        <div role="alert" className="flex items-center justify-between gap-3 rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">
          {/* the REAL backend error, not a canned sentence:
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
          {effProto?.security_class === "legacy_insecure" && (
            <div className="rounded-xl border border-danger/40 bg-danger-soft p-3 text-xs text-danger">
              <p className="font-semibold">{t("Legacy / Insecure")}</p>
              <p className="mt-1">{t("PPTP has known cryptographic weaknesses. Both risk acceptance and Internet-exposure confirmation are required and validated again by the backend.")}</p>
            </div>
          )}
          <div className="flex flex-wrap items-center gap-1.5 text-[11.5px] text-content-2">
            {[effProto?.label, effTransport?.label, effSecurity?.label].filter(Boolean).map((x, i, arr) => (
              <span key={String(x)} className="inline-flex items-center gap-1.5">
                <span className="rounded-lg bg-brand-soft px-2 py-0.5 font-medium text-brand">{x}</span>
                {i < arr.length - 1 && <span className="text-content-3">→</span>}
              </span>
            ))}
          </div>
          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="tag" hint={tagClash ? "this tag already exists" : mode === "edit" ? "unchanged tag = replace in place" : "unique on this core"}>
                <Input value={tag} placeholder={spec.tag} onChange={(e) => setTag(e.target.value)} dir="ltr" invalid={tagClash} />
            </Field>
            {advanced && (
              <Field label="listen">
                <Select value={listen} onChange={(e) => setListen(e.target.value)}>
                  <option value="0.0.0.0">0.0.0.0 (all)</option>
                  <option value="127.0.0.1">127.0.0.1</option>
                </Select>
              </Field>
            )}
            <Field label="port" required
              hint={
                effProto?.fixed_port
                  ? "fixed by the protocol/SoftEther engine — not configurable"
                  : !port || port < 1 || port > 65535
                    ? "1–65535"
                    : mode !== "edit" && !portTouchedRef.current
                      ? "random suggestion (host-collision-checked) — clear or type your own"
                      : undefined
              }>
              <Input type="number" min={1} max={65535}
                value={port === "" ? "" : port}
                disabled={Boolean(effProto?.fixed_port)}
                placeholder={suggestPort.isFetching ? "suggesting…" : "e.g. 38472"}
                onChange={(e) => {
                  if (effProto?.fixed_port) return;
                  portTouchedRef.current = true;
                  setPort(e.target.value === "" ? "" : Number(e.target.value));
                }} dir="ltr"
                invalid={!port || port < 1 || port > 65535} />
            </Field>
          </div>
          {/* items 8+10 +: schema-driven GROUPS instead of a
             flat field wall — General / Transport / Headers / TLS / REALITY /
             Certificate / Advanced. A protocol renders only the groups its
             cell actually carries; certificate fields follow the chosen
             certificate source mode (item 6). */}
          {effSecurity && (["general", "transport", "headers", "tls", "reality", "certificate", "advanced"] as const).map((sec) => {
            const groupFields = effSecurity.fields.filter((f) => {
              if ((f.section ?? "advanced") !== sec || !fieldVisible(f)) return false;
              if (CERT_KEYS.has(f.key)) {
                if (certMode === "paste") return !f.key.endsWith("_path");
                if (certMode === "path") return f.key.endsWith("_path");
                return false; // ref/auto carry no inline certificate fields
              }
              return true;
            });
            // Certificate is a TLS capability, not a universal wizard panel.
            // None/REALITY cells neither render nor accept certificate state.
            if (sec === "certificate" && effSecurity.id !== "tls") return null;
            if (!groupFields.length && sec !== "certificate") return null;
            const titles: Record<string, string> = {
              general: "General", transport: "Transport / Network", headers: "Headers",
              tls: "TLS / Security", reality: "REALITY", certificate: "Certificate",
              advanced: "Advanced",
            };
            return (
            <div key={sec} data-wizard-section={sec}
              className="grid gap-4 rounded-xl border border-border p-3.5 sm:grid-cols-3">
              <p className="text-[11px] font-semibold uppercase tracking-wide text-content-3 sm:col-span-3">
                {titles[sec]}
                {!advanced && sec !== "general" && <span className="ms-1.5 normal-case tracking-normal">{t("(showing only what needs a decision — switch to advanced for the rest)")}</span>}
              </p>
              {sec === "certificate" && (
                <Field label={t("certificate source")} required
                  hint={t("exactly ONE source is applied — stored pairs and paths are validated (PEM + match + expiry) server-side")}>
                  <Select value={certMode}
                    onChange={(e) => setCertMode(e.target.value as "ref" | "paste" | "path" | "auto")}>
                    <option value="auto">{t("auto-generate (self-signed, runtime-only — not added to Certificates)")}</option>
                    <option value="ref">{t("stored certificate (from the Certificates registry)")}</option>
                    <option value="paste">{t("paste PEM content")}</option>
                    <option value="path">{t("file paths on this server")}</option>
                  </Select>
                </Field>
              )}
              {sec === "certificate" && certMode === "ref" && (
                <Field label={t("stored certificate")} required
                  hint={!certRef ? "pick a managed certificate (or switch the source mode)" : undefined}>
                  <Select value={certRef} onChange={(e) => setCertRef(e.target.value)}>
                    <option value="">— choose a managed certificate —</option>
                    {(certsQ.data?.certificates ?? []).filter((c) => c.managed).map((c) => (
                      <option key={c.name} value={c.name}>{c.name}{c.expired ? " (EXPIRED)" : ""}</option>
                    ))}
                  </Select>
                </Field>
              )}
              {sec === "certificate" && certMode === "ref" && certRef && (
                <p className="sm:col-span-3 rounded-lg border border-brand/30 bg-brand-soft/30 px-2.5 py-1.5 text-[11px] text-brand">
                  using stored certificate «{certRef}» — validated server-side (PEM pair + match + expiry) before applying.
                </p>
              )}
              {groupFields.map((f) => {
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
                            }} />{t("or choose a file to paste its content")}</label>
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
                  ) : f.key === "ipsec_psk" ? (
                    <div className="flex min-w-0 items-center gap-2" data-generated-secret="ipsec_psk">
                      <Input type="text" autoComplete="off"
                        placeholder={f.placeholder}
                        value={(fields[f.key] as string) ?? String(f.default ?? "")}
                        onChange={(e) => setFields({ ...fields, [f.key]: e.target.value })}
                        onBlur={mark} dir="ltr" invalid={showErr} />
                      <Button type="button" variant="secondary" size="icon"
                        aria-label={t("copy IPsec pre-shared key")}
                        title={t("copy IPsec pre-shared key")}
                        onClick={async () => {
                          const value = String(fields[f.key] ?? f.default ?? "");
                          (await copyText(value)) ? toast.ok("pre-shared key copied") : toast.error(t("common.error"));
                        }}>
                        <Copy size={13} />
                      </Button>
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
            );
          })}
          <div className="rounded-xl bg-surface-2 p-3.5 text-[12px] text-content-2">
            <p className="mb-1 flex items-center gap-1.5 font-medium"><Eye size={13} className="text-brand" /> summary</p>
            <p>
              <b>{effProto?.label}</b> over <b>{effTransport?.label}</b> with <b>{effSecurity?.label}</b> — inbound{" "}
              <code className="font-mono text-[11px]" dir="ltr">{spec.tag}</code> on{" "}
              <code className="font-mono text-[11px]" dir="ltr">{listen}:{port}</code> will be validated against the{" "}
              <b>{coreId}</b>{t("schema and materialized into its configuration. New users need it granted in their core access.")}</p>
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
              <Loader2 size={13} className="animate-spin" />{t("server-side preview of the exact patch…")}</p>
          ) : preview.isError ? (
            <div className="flex items-center justify-between gap-3 rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">
              <span>{preview.error instanceof ApiError ? preview.error.message : "preview request failed"}</span>
              <Button variant="ghost" size="sm" onClick={() => preview.refetch()}>retry</Button>
            </div>
          ) : preview.data?.valid ? (
            <div className="rounded-xl border border-ok/30 bg-ok-soft px-3 py-2 text-[11.5px]">
              <p className="flex items-center gap-1.5 font-medium text-ok">
                <CheckCircle2 size={13} />{t("server validation passed — this exact patch will be applied:")}</p>
              {preview.data.diff && (
                <details className="mt-1.5">
                  <summary className="cursor-pointer text-content-3 hover:text-content-2">view diff</summary>
                  <pre className="mt-1 max-h-44 overflow-auto rounded-lg bg-surface-1 p-2 font-mono text-[10px] text-content-2" dir="ltr">{preview.data.diff}</pre>
                </details>
              )}
            </div>
          ) : preview.data ? (
            <div className="rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">
              <p className="flex items-center gap-1.5 font-medium"><XCircle size={13} />{t("server validation rejected this inbound:")}</p>
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
