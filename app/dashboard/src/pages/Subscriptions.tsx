// Subscriptions — portal identity + subscription link plumbing management
// (portal settings), access mode, the operator's subscription page template
// (upload → validated → active at once, with a real preview), and per-user
// link helpers. ONE Save for the whole page, at the very end of it.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Download, ExternalLink, Eye, Radio, Save, Trash2, Upload } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "../components/feedback";
import { Dialog } from "../components/overlays";
import { Badge, Button, Card, CardHeader, Field, Input, Select, Skeleton, Switch } from "../components/ui";
import { api, ApiError, getToken } from "../lib/api";
import { useT, useTDynamic } from "../lib/i18n";
import type { CertificateInfo, PanelInfo, PortalSettings, SubscriptionTemplateFile, SubscriptionTemplatesResponse } from "../lib/types";

// canonical enum values of the backend contract (ClientAuthMode); the
// backend keeps accepting the shorthand "app_login" for stray
// integrations, but the dashboard speaks the canonical ids itself
const AUTH_MODES = [
  { id: "subscription_link", label: "Subscription link", hint: "users open the canonical tokenized /sub/<token> link from any client" },
  { id: "application_login", label: "Application login", hint: "the Zagros app signs in with issued credentials (app-credentials per user)" },
];

const API_BASE = (import.meta.env.VITE_BASE_API || "/api/").replace(/\/$/, "");
const DOCS_URL = "https://zagrosgm.github.io/zagros-docs/examples/subscription-page";
const NETWORK_ERROR = "__network__";

export default function Subscriptions() {
  const t = useT();
  const td = useTDynamic();
  const qc = useQueryClient();
  const settingsQ = useQuery({ queryKey: ["zagros", "portal"], queryFn: () => api.get<PortalSettings>("/zagros/settings/portal") });
  const info = useQuery({ queryKey: ["zagros", "panel-info"], queryFn: () => api.get<PanelInfo>("/zagros/panel/info") });
  const certsQ = useQuery({ queryKey: ["zagros", "certificates"], queryFn: () => api.get<{ certificates: CertificateInfo[] }>("/zagros/certificates") });
  const [form, setForm] = useState<PortalSettings | null>(null);
  const [testResult, setTestResult] = useState<Record<string, unknown> | null>(null);

  useEffect(() => { if (settingsQ.data) setForm(settingsQ.data); }, [settingsQ.data]);

  const save = useMutation({
    mutationFn: () => api.put("/zagros/settings/portal", { ...form, subscription_template: activeTemplate }),
    onSuccess: () => {
      toast.ok(t("common.saved"));
      qc.invalidateQueries({ queryKey: ["zagros", "portal"] });
      qc.invalidateQueries({ queryKey: ["zagros", "subscription-templates"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });
  const testConfig = useMutation({
    mutationFn: () => api.post<Record<string, unknown>>("/zagros/settings/portal/test", form),
    onSuccess: (data) => { setTestResult(data); toast.ok("URL generation is valid"); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  // — operator-authored subscription page template
  const fileRef = useRef<HTMLInputElement>(null);
  const templatesQ = useQuery({
    queryKey: ["zagros", "subscription-templates"],
    queryFn: () => api.get<SubscriptionTemplatesResponse>("/zagros/subscription/templates"),
    retry: false,
    refetchInterval: 30_000,
  });
  const templates: SubscriptionTemplateFile[] = templatesQ.data?.templates ?? [];
  const activeTemplate: string | null = templatesQ.data
    ? templatesQ.data.active
    : (form?.subscription_template ?? null);
  const activeMissing = Boolean(activeTemplate && templatesQ.data && !templatesQ.data.active_exists);
  const lastFailure = templatesQ.data?.last_failure ?? null;

  // The template selection is its own tiny setting (PUT …/templates/active):
  // picking a page never re-runs the listener/TLS validation the full portal
  // PUT performs, so it cannot be blocked by an unrelated network field — and
  // it takes effect immediately, exactly like Marzban's template does.
  // Template actions never refetch the portal form either: that refetch would
  // re-initialise it and throw away edits the operator has not saved yet. The
  // templates query is the source of truth for what is active; the form only
  // mirrors it so Save can never revert the selection.
  const setActiveInCache = (active: string | null) => {
    qc.setQueryData<SubscriptionTemplatesResponse>(["zagros", "subscription-templates"],
      (old) => (old ? { ...old, active, active_exists: Boolean(active) } : old));
    setForm((prev) => (prev ? { ...prev, subscription_template: active } : prev));
    qc.invalidateQueries({ queryKey: ["zagros", "subscription-templates"] });
  };
  const selectTemplate = useMutation({
    mutationFn: (name: string | null) => api.put<{ active: string | null }>("/zagros/subscription/templates/active", { name }),
    onSuccess: (data) => {
      setActiveInCache(data.active);
      toast.ok(data.active ? t("template.activated", { name: data.active }) : t("template.builtinActive"));
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });
  const uploadTemplate = useMutation({
    mutationFn: (file: File) => {
      const body = new FormData();
      body.append("file", file);
      body.append("activate", "true");
      return api.post<{ name: string; activated: boolean }>("/zagros/subscription/templates", body);
    },
    onSuccess: (data) => {
      toast.ok(data.activated ? t("template.uploaded", { name: data.name }) : t("template.uploadedOnly", { name: data.name }));
      if (data.activated) setActiveInCache(data.name);
      else qc.invalidateQueries({ queryKey: ["zagros", "subscription-templates"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? t("template.validationFailed", { error: e.message }) : t("common.error")),
  });
  const downloadStarter = useMutation({
    mutationFn: async () => {
      const text = await api.get<string>("/zagros/subscription/templates/starter");
      const url = URL.createObjectURL(new Blob([text], { type: "text/html" }));
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "subscription-starter.html";
      anchor.click();
      URL.revokeObjectURL(url);
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });
  const deleteTemplate = useMutation({
    mutationFn: (name: string) => api.delete(`/zagros/subscription/templates/${encodeURIComponent(name)}`),
    onSuccess: (_data, name) => {
      toast.ok(t("template.deleted", { name }));
      if (activeTemplate === name) setActiveInCache(null);
      else qc.invalidateQueries({ queryKey: ["zagros", "subscription-templates"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  // — preview (sample subscriber or a real user) rendered in a sandboxed iframe
  const [preview, setPreview] = useState<{ name: string; username: string } | null>(null);
  const [previewUser, setPreviewUser] = useState("");
  const [previewHtml, setPreviewHtml] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  useEffect(() => {
    if (!preview) { setPreviewHtml(null); setPreviewError(null); return; }
    let cancelled = false;
    setPreviewLoading(true); setPreviewError(null);
    const params = new URLSearchParams({ name: preview.name });
    if (preview.username) params.set("username", preview.username);
    const headers = new Headers();
    const token = getToken();
    if (token) headers.set("Authorization", `Bearer ${token}`);
    fetch(`${API_BASE}/zagros/subscription/templates/preview?${params}`, { headers })
      .then(async (res) => {
        const text = await res.text();
        if (cancelled) return;
        if (!res.ok) {
          let detail = text;
          try { detail = (JSON.parse(text) as { detail?: string }).detail ?? text; } catch { /* plain text */ }
          setPreviewError(detail || `request failed (${res.status})`);
          setPreviewHtml(null);
        } else {
          setPreviewHtml(text);
        }
      })
      .catch(() => { if (!cancelled) setPreviewError(NETWORK_ERROR); })
      .finally(() => { if (!cancelled) setPreviewLoading(false); });
    return () => { cancelled = true; };
    // `t` is deliberately NOT a dependency: useT() returns a fresh closure on
    // every render, which would restart this fetch endlessly.
  }, [preview]);
  const openPreviewTab = () => {
    if (!previewHtml) return;
    const url = URL.createObjectURL(new Blob([previewHtml], { type: "text/html" }));
    window.open(url, "_blank", "noopener");
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  };

  const host = form?.public_domain
    ? `${form.custom_subdomain ? `${form.custom_subdomain}.` : ""}${form.public_domain}`
    : "";
  const scheme = form?.force_https ? "https" : (form?.public_scheme ?? "https");
  const defaultPort = scheme === "https" ? 443 : 80;
  const port = form?.public_port && form.public_port !== defaultPort ? `:${form.public_port}` : "";
  const prefix = host ? `${scheme}://${host}${port}` : (form?.subscription_url_prefix || info.data?.panel_base_url || (info.data?.domain ? `https://${info.data.domain}` : ""));
  const example = `${prefix || "https://panel.example.com"}/${form?.subscription_path ?? "sub"}/<token>`;


  return (
    <div className="space-y-4 animate-fade-up">
      <h1 className="flex items-center gap-2 text-lg font-bold tracking-tight">
        <Radio size={18} className="text-brand" />{t("nav.subscriptions")}
      </h1>

      {settingsQ.isLoading || !form ? <Skeleton className="h-72" /> : (
        <>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader title={t("portal identity")} subtitle={t("what users see on their subscription page")} />
              <div className="grid gap-4">
                <Field label={t("portal title")}><Input value={form.portal_title} onChange={(e) => setForm({ ...form, portal_title: e.target.value })} /></Field>
                <Field label={t("app name")}><Input value={form.app_name} onChange={(e) => setForm({ ...form, app_name: e.target.value })} /></Field>
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field label={t("public domain")}><Input value={form.public_domain ?? ""} onChange={(e) => setForm({ ...form, public_domain: e.target.value || null })} dir="ltr" placeholder="example.com" /></Field>
                  <Field label={t("custom subdomain")}><Input value={form.custom_subdomain ?? ""} onChange={(e) => setForm({ ...form, custom_subdomain: e.target.value || null })} dir="ltr" placeholder={t("sub")} /></Field>
                  <Field label={t("scheme")}><Select value={form.public_scheme ?? "https"} onChange={(e) => setForm({ ...form, public_scheme: e.target.value as "http" | "https" })}><option value="http">HTTP</option><option value="https">HTTPS</option></Select></Field>
                  <Field label={t("public port")}><Input type="number" min={1} max={65535} value={form.public_port ?? ""} onChange={(e) => setForm({ ...form, public_port: e.target.value ? Number(e.target.value) : null })} dir="ltr" placeholder={form.public_scheme === "http" ? "80" : "443"} /></Field>
                  <Field label={t("listener ownership")} hint={t("shared = panel port; dedicated = Zagros opens this port; external proxy = Nginx/Caddy owns it")}>
                    <Select value={form.listener_mode ?? "shared"} onChange={(e) => setForm({ ...form, listener_mode: e.target.value as PortalSettings["listener_mode"] })}>
                      <option value="shared">{t("shared panel listener")}</option>
                      <option value="dedicated">{t("dedicated Zagros listener")}</option>
                      <option value="external_proxy">{t("external reverse proxy")}</option>
                    </Select>
                  </Field>
                  {form.listener_mode === "dedicated" && <Field label={t("listen address")}><Input value={form.listen_address ?? "0.0.0.0"} onChange={(e) => setForm({ ...form, listen_address: e.target.value })} dir="ltr" /></Field>}
                </div>
                <label className="flex items-center gap-2.5 text-sm text-content-2"><Switch checked={Boolean(form.force_https)} onChange={(v) => setForm({ ...form, force_https: v })} label={t("force HTTPS")} />{t("Force HTTPS")}</label>
                <Field label={t("TLS certificate")} hint={t("optional when an external reverse proxy terminates TLS")}>
                  <Select value={form.tls_certificate_id ?? ""} onChange={(e) => setForm({ ...form, tls_certificate_id: e.target.value || null })}>
                    <option value="">{t("external proxy / none")}</option>
                    {(certsQ.data?.certificates ?? []).filter((c) => c.has_key && !c.expired).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                  </Select>
                </Field>
                <Field label={t("subscription path")} hint={t("URL segment for token links")}>
                  <Input value={form.subscription_path} onChange={(e) => setForm({ ...form, subscription_path: e.target.value })} dir="ltr" />
                </Field>
                <Field label={t("QR base URL")} hint={t("optional endpoint host override used inside OpenVPN/WireGuard/QR material")}>
                  <Input value={form.qr_base_url ?? ""} onChange={(e) => setForm({ ...form, qr_base_url: e.target.value || null })} dir="ltr" placeholder="https://edge.example.com" />
                </Field>
                <Field label={t("legacy public URL prefix")} hint={t("migration fallback when public domain is empty")}>
                  <Input value={form.subscription_url_prefix ?? ""} onChange={(e) => setForm({ ...form, subscription_url_prefix: e.target.value || null })} dir="ltr" placeholder="https://panel.example.com" />
                </Field>
              </div>
            </Card>

            <div className="space-y-4">
              <Card>
                <CardHeader title={t("access mode")} subtitle={t("how clients consume a subscription")} />
                <div className="space-y-2">
                  {AUTH_MODES.map((m) => (
                    <button key={m.id} type="button"
                      onClick={() => setForm({ ...form, client_auth_mode: m.id })}
                      className={`w-full rounded-xl border p-3 text-start transition-colors ${form.client_auth_mode === m.id ? "border-brand bg-brand-soft" : "border-border hover:border-border-strong"}`}>
                      <span className="flex items-center justify-between text-[13px] font-medium">
                        {td(m.label)}
                        {form.client_auth_mode === m.id && <Badge tone="brand">{t("active")}</Badge>}
                      </span>
                      <span className="mt-1 block text-[11px] text-content-3">{td(m.hint)}</span>
                    </button>
                  ))}
                </div>
              </Card>

              <Card>
                <CardHeader
                  title={t("subscription page template")}
                  subtitle={t("template.cardSubtitle")}
                  actions={activeTemplate
                    ? <Badge tone={activeMissing ? "warn" : "ok"} dot><span dir="ltr">{activeTemplate}</span></Badge>
                    : <Badge tone="muted" dot>{t("built-in page")}</Badge>} />
                <div className="space-y-3">
                  <Field label={t("page template")} hint={t("template.pickerHint")}>
                    <Select
                      value={activeTemplate ?? ""}
                      disabled={selectTemplate.isPending}
                      onChange={(e) => selectTemplate.mutate(e.target.value || null)}>
                      <option value="">{t("built-in page")}</option>
                      {activeMissing && <option value={activeTemplate as string}>{activeTemplate} (missing)</option>}
                      {templates.map((tf) => (
                        <option key={tf.name} value={tf.name}>{tf.name}</option>
                      ))}
                    </Select>
                  </Field>

                  <div className="flex flex-wrap items-center gap-2">
                    <input
                      ref={fileRef}
                      type="file"
                      accept=".html,.htm,text/html"
                      className="hidden"
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (file) uploadTemplate.mutate(file);
                        e.target.value = "";
                      }} />
                    <Button variant="secondary" loading={uploadTemplate.isPending}
                      onClick={() => fileRef.current?.click()}>
                      <Upload size={14} />{t("upload template")}</Button>
                    {activeTemplate && !activeMissing && (
                      <Button variant="secondary"
                        onClick={() => { setPreviewUser(""); setPreview({ name: activeTemplate, username: "" }); }}>
                        <Eye size={14} />{t("template.preview")}</Button>
                    )}
                    <Button variant="ghost" loading={downloadStarter.isPending}
                      onClick={() => downloadStarter.mutate()}>
                      <Download size={14} />{t("download starter")}</Button>
                    {activeTemplate && !activeMissing && (
                      <Button variant="danger" loading={deleteTemplate.isPending}
                        onClick={() => deleteTemplate.mutate(activeTemplate)}>
                        <Trash2 size={14} /> {t("template.delete")}
                      </Button>
                    )}
                  </div>

                  {templates.length > 0 && (
                    <ul className="divide-y divide-border rounded-xl border border-border text-[12px]">
                      {templates.map((tf) => (
                        <li key={tf.name} className="flex items-center justify-between gap-2 px-3 py-1.5">
                          <span className="flex min-w-0 items-center gap-2">
                            <span className="truncate font-mono" dir="ltr">{tf.name}</span>
                            {tf.name === activeTemplate && <Badge tone="brand">{t("template.active")}</Badge>}
                            <span className="text-content-3" dir="ltr">{(tf.size / 1024).toFixed(1)} KB</span>
                          </span>
                          <span className="flex shrink-0 items-center gap-1">
                            <Button size="sm" variant="ghost" aria-label={t("template.preview")} title={t("template.preview")}
                              onClick={() => { setPreviewUser(""); setPreview({ name: tf.name, username: "" }); }}><Eye size={12} /></Button>
                            {tf.name !== activeTemplate && (
                              <Button size="sm" variant="ghost" onClick={() => selectTemplate.mutate(tf.name)}>{t("template.activate")}</Button>
                            )}
                            <Button size="sm" variant="ghost" aria-label={t("template.delete")} title={t("template.delete")}
                              onClick={() => deleteTemplate.mutate(tf.name)}><Trash2 size={12} /></Button>
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}

                  {activeMissing && (
                    <p className="flex items-start gap-2 rounded-xl border border-warn/30 bg-warn/5 px-3 py-2 text-[11px] text-warn">
                      <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                      {t("template.missing")}
                    </p>
                  )}
                  {lastFailure && lastFailure.template === activeTemplate && (
                    <div className="rounded-xl border border-danger/30 bg-danger/5 px-3 py-2 text-[11px]">
                      <p className="flex items-center gap-2 font-medium text-danger"><AlertTriangle size={14} />{t("template.lastFailure")}</p>
                      <code className="mt-1 block whitespace-pre-wrap break-all font-mono text-content-2" dir="ltr">
                        {lastFailure.line ? `${t("template.lastFailureLine", { line: lastFailure.line })}: ` : ""}{lastFailure.error}
                      </code>
                    </div>
                  )}

                  <p className="text-[11px] leading-5 text-content-3">
                    <span dir="ltr">{t("template.variablesBody")}</span>
                    {" "}<a className="text-brand hover:underline" href={DOCS_URL} target="_blank" rel="noopener noreferrer">{t("template.docs")} ↗</a>
                    <br />{t("template.failOpen")}
                  </p>
                </div>
              </Card>

              <Card>
                <CardHeader title={t("link shape")} subtitle={t("tokens are issued per user (Users → subscription link)")} />
                <code className="block overflow-x-auto rounded-xl bg-surface p-3 font-mono text-[11px] text-content-2" dir="ltr">{example}</code>
                {testResult && <pre className="mt-3 max-h-52 overflow-auto rounded-xl bg-surface p-3 text-[10px] text-content-2" dir="ltr">{JSON.stringify(testResult, null, 2)}</pre>}
                <p className="mt-3 text-[11px] leading-5 text-content-3">{t("Links auto-render the right format for v2rayNG / Streisand / Clash / sing-box clients (detected via user-agent). Revoking a user's subscription rotates the token immediately.")}</p>
                <div className="mt-3 flex items-center gap-2 text-[11px] text-content-3">
                  <ExternalLink size={12} />
                  panel: {info.data?.panel_base_url || info.data?.domain || "—"} · tls: {info.data?.tls_mode ?? "—"}
                </div>
              </Card>
            </div>
          </div>

          {/* ONE action row for the whole page — after every section, at the very end. */}
          <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border pt-4">
            <Button onClick={() => testConfig.mutate()} loading={testConfig.isPending} variant="secondary">{t("test configuration")}</Button>
            <Button onClick={() => save.mutate()} loading={save.isPending}><Save size={14} /> {t("common.save")}</Button>
          </div>
        </>
      )}

      <Dialog
        open={Boolean(preview)}
        onClose={() => setPreview(null)}
        wide
        title={<span className="inline-flex items-center gap-2"><Eye size={16} className="text-brand" />{t("template.previewTitle")}{preview && <span className="font-mono text-xs text-content-3" dir="ltr">· {preview.name}</span>}</span>}
        subtitle={t("template.previewHint")}
        headerActions={previewHtml ? <Button size="sm" variant="ghost" onClick={openPreviewTab}><ExternalLink size={12} />{t("template.openInTab")}</Button> : null}
        footer={<Button variant="secondary" onClick={() => setPreview(null)}>{t("common.close")}</Button>}
      >
        <div className="mb-3 flex flex-wrap items-end gap-2">
          <Button size="sm" variant={preview?.username ? "ghost" : "secondary"}
            onClick={() => preview && setPreview({ ...preview, username: "" })}>{t("template.previewSample")}</Button>
          <form className="flex items-end gap-2" onSubmit={(e) => { e.preventDefault(); if (preview && previewUser.trim()) setPreview({ ...preview, username: previewUser.trim() }); }}>
            <Field label={t("template.previewUsername")}>
              <Input value={previewUser} onChange={(e) => setPreviewUser(e.target.value)} dir="ltr" placeholder="username" className="h-8 w-48" />
            </Field>
            <Button size="sm" type="submit" variant={preview?.username ? "secondary" : "ghost"} disabled={!previewUser.trim()}>{t("template.previewUser")}</Button>
          </form>
        </div>
        {previewLoading && <Skeleton className="h-[60vh]" />}
        {!previewLoading && previewError && (
          <div className="rounded-xl border border-danger/30 bg-danger/5 p-3 text-xs">
            <p className="flex items-center gap-2 font-medium text-danger"><AlertTriangle size={14} />{t("template.lastFailure")}</p>
            <code className="mt-1 block whitespace-pre-wrap break-all font-mono text-content-2" dir="ltr">{previewError === NETWORK_ERROR ? t("network error — the panel is unreachable") : previewError}</code>
          </div>
        )}
        {!previewLoading && previewHtml && (
          <iframe
            title="subscription page preview"
            // scripts run so Alpine/Tailwind-style templates behave; no
            // same-origin → the preview cannot touch the dashboard session
            sandbox="allow-scripts allow-popups"
            srcDoc={previewHtml}
            className="h-[60vh] w-full rounded-xl border border-border bg-white" />
        )}
      </Dialog>
    </div>
  );
}
