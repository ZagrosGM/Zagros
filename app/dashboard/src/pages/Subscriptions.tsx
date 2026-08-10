// Subscriptions — portal identity + subscription link plumbing management
// (portal settings), live template info, and per-user link helpers.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Radio, Save } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "../components/feedback";
import { Badge, Button, Card, CardHeader, Field, Input, Select, Skeleton } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useT } from "../lib/i18n";
import type { PanelInfo, PortalSettings } from "../lib/types";

// canonical enum values of the backend contract (ClientAuthMode); the
// backend keeps accepting the alpha.7 shorthand "app_login" for stray
// integrations, but the dashboard speaks the canonical ids itself
const AUTH_MODES = [
  { id: "subscription_link", label: "Subscription link", hint: "users open the canonical tokenized /sub/<token> link from any client" },
  { id: "application_login", label: "Application login", hint: "the Zagros app signs in with issued credentials (app-credentials per user)" },
];

export default function Subscriptions() {
  const t = useT();
  const qc = useQueryClient();
  const settingsQ = useQuery({ queryKey: ["zagros", "portal"], queryFn: () => api.get<PortalSettings>("/zagros/settings/portal") });
  const info = useQuery({ queryKey: ["zagros", "panel-info"], queryFn: () => api.get<PanelInfo>("/zagros/panel/info") });
  const [form, setForm] = useState<PortalSettings | null>(null);

  useEffect(() => { if (settingsQ.data) setForm(settingsQ.data); }, [settingsQ.data]);

  const save = useMutation({
    mutationFn: () => api.put("/zagros/settings/portal", form),
    onSuccess: () => { toast.ok(t("common.saved")); qc.invalidateQueries({ queryKey: ["zagros", "portal"] }); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const prefix = settingsQ.data?.subscription_url_prefix || info.data?.panel_base_url || (info.data?.domain ? `https://${info.data.domain}` : "");
  const example = `${prefix || "https://panel.example.com"}/zagros/${settingsQ.data?.subscription_path ?? "sub"}/<token>`;

  return (
    <div className="space-y-4 animate-fade-up">
      <h1 className="flex items-center gap-2 text-lg font-bold tracking-tight">
        <Radio size={18} className="text-brand" />{t("nav.subscriptions")}
      </h1>

      {settingsQ.isLoading || !form ? <Skeleton className="h-72" /> : (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader title="portal identity" subtitle="what users see on their subscription page" />
            <div className="grid gap-4">
              <Field label="portal title"><Input value={form.portal_title} onChange={(e) => setForm({ ...form, portal_title: e.target.value })} /></Field>
              <Field label="app name"><Input value={form.app_name} onChange={(e) => setForm({ ...form, app_name: e.target.value })} /></Field>
              <Field label="subscription path" hint="URL segment for token links">
                <Input value={form.subscription_path} onChange={(e) => setForm({ ...form, subscription_path: e.target.value })} dir="ltr" />
              </Field>
              <Field label="public URL prefix" hint="empty = derived from panel domain">
                <Input value={form.subscription_url_prefix ?? ""} onChange={(e) => setForm({ ...form, subscription_url_prefix: e.target.value || null })} dir="ltr" placeholder="https://panel.example.com" />
              </Field>
              <div className="pt-1">
                <Button onClick={() => save.mutate()} loading={save.isPending}><Save size={14} /> {t("common.save")}</Button>
              </div>
            </div>
          </Card>

          <div className="space-y-4">
            <Card>
              <CardHeader title="access mode" subtitle="how clients consume a subscription" />
              <div className="space-y-2">
                {AUTH_MODES.map((m) => (
                  <button key={m.id}
                    onClick={() => setForm({ ...form, client_auth_mode: m.id })}
                    className={`w-full rounded-xl border p-3 text-start transition-colors ${form.client_auth_mode === m.id ? "border-brand bg-brand-soft" : "border-border hover:border-border-strong"}`}>
                    <span className="flex items-center justify-between text-[13px] font-medium">
                      {m.label}
                      {form.client_auth_mode === m.id && <Badge tone="brand">active</Badge>}
                    </span>
                    <span className="mt-1 block text-[11px] text-content-3">{m.hint}</span>
                  </button>
                ))}
              </div>
            </Card>

            <Card>
              <CardHeader title="link shape" subtitle="tokens are issued per user (Users → subscription link)" />
              <code className="block overflow-x-auto rounded-xl bg-surface p-3 font-mono text-[11px] text-content-2" dir="ltr">{example}</code>
              <p className="mt-3 text-[11px] leading-5 text-content-3">
                Links auto-render the right format for v2rayNG / Streisand / Clash / sing-box clients
                (detected via user-agent). Revoking a user's subscription rotates the token immediately.
              </p>
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
