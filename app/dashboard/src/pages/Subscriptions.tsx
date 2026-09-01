// Subscriptions — portal identity + subscription link plumbing management
// (portal settings), live template info, and per-user link helpers.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, ExternalLink, Radio, Save, Trash2, Upload } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "../components/feedback";
import { Badge, Button, Card, CardHeader, Field, Input, Select, Skeleton, Switch } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useT, useTDynamic } from "../lib/i18n";
import type { CertificateInfo, PanelInfo, PortalSettings, SubscriptionTemplateFile } from "../lib/types";

// canonical enum values of the backend contract (ClientAuthMode); the
// backend keeps accepting the shorthand "app_login" for stray
// integrations, but the dashboard speaks the canonical ids itself
const AUTH_MODES = [
  { id: "subscription_link", label: "Subscription link", hint: "users open the canonical tokenized /sub/<token> link from any client" },
  { id: "application_login", label: "Application login", hint: "the Zagros app signs in with issued credentials (app-credentials per user)" },
];

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
    mutationFn: () => api.put("/zagros/settings/portal", form),
    onSuccess: () => { toast.ok(t("common.saved")); qc.invalidateQueries({ queryKey: ["zagros", "portal"] }); },
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
    queryFn: () => api.get<{ templates: SubscriptionTemplateFile[] }>("/zagros/subscription/templates"),
    retry: false,
  });
  const uploadTemplate = useMutation({
    mutationFn: (file: File) => {
      const body = new FormData();
      body.append("file", file);
      return api.post<{ name: string }>("/zagros/subscription/templates", body);
    },
    onSuccess: (data) => {
      toast.ok(`template uploaded: ${data.name}`);
      setForm((prev) => (prev ? { ...prev, subscription_template: data.name } : prev));
      qc.invalidateQueries({ queryKey: ["zagros", "subscription-templates"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
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
      toast.ok(`template deleted: ${name}`);
      setForm((prev) => (prev?.subscription_template === name
        ? { ...prev, subscription_template: null } : prev));
      qc.invalidateQueries({ queryKey: ["zagros", "subscription-templates"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

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
              <div className="flex flex-wrap gap-2 pt-1">
                <Button onClick={() => testConfig.mutate()} loading={testConfig.isPending} variant="secondary">{t("test configuration")}</Button>
                <Button onClick={() => save.mutate()} loading={save.isPending}><Save size={14} /> {t("common.save")}</Button>
              </div>
            </div>
          </Card>

          <div className="space-y-4">
            <Card>
              <CardHeader title={t("access mode")} subtitle={t("how clients consume a subscription")} />
              <div className="space-y-2">
                {AUTH_MODES.map((m) => (
                  <button key={m.id}
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
                subtitle={t("upload your own HTML for the page subscribers see — or keep the built-in one")} />
              <div className="space-y-3">
                <Field label={t("page template")} hint={t("built-in = the panel's own page; a template is HTML with Jinja2 variables")}>
                  <Select
                    value={form.subscription_template ?? ""}
                    onChange={(e) => setForm({ ...form, subscription_template: e.target.value || null })}>
                    <option value="">{t("built-in page")}</option>
                    {(templatesQ.data?.templates ?? []).map((tf) => (
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
                  <Button variant="ghost" loading={downloadStarter.isPending}
                    onClick={() => downloadStarter.mutate()}>
                    <Download size={14} />{t("download starter")}</Button>
                  {form.subscription_template && (
                    <Button variant="danger" loading={deleteTemplate.isPending}
                      onClick={() => deleteTemplate.mutate(form.subscription_template as string)}>
                      <Trash2 size={14} /> delete
                    </Button>
                  )}
                </div>

                <p className="text-[11px] leading-5 text-content-3">{t("Variables:")}<code dir="ltr">{"{{ user.username }}"} · {"{{ links }}"} · {"{{ used_bytes }}"} · {"{{ format_bytes(used_bytes) }}"} · {"{{ expire_at }}"}</code>.
                  A template that fails to render never breaks a subscriber's page — the built-in one is served and the reason is logged.
                </p>
                {form.subscription_template && !(templatesQ.data?.templates ?? []).some((t) => t.name === form.subscription_template) && (
                  <p className="text-[11px] text-warn">{t("this template is not on the server — upload it again or pick another, otherwise the built-in page is served.")}</p>
                )}
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
      )}
    </div>
  );
}
