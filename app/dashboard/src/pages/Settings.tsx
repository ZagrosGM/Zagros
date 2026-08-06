// Settings — admins, user templates, panel info, and the Advanced Mode gate.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, RefreshCcw, Settings as SettingsIcon, ShieldCheck, TerminalSquare, Trash2, Users } from "lucide-react";
import { useState } from "react";
import { toast } from "../components/feedback";
import { ConfirmDialog, Dialog } from "../components/overlays";
import { Badge, Button, Card, CardHeader, EmptyState, Field, Input, Skeleton, Switch, cn } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useDigits, formatBytes, formatDuration } from "../lib/format";
import { useT } from "../lib/i18n";
import { applyUiState, useUI } from "../stores/ui";
import type { AdminUser, PanelInfo, UserTemplate } from "../lib/types";

export default function Settings() {
  const t = useT();
  const digits = useDigits();
  const { advancedMode, setAdvancedMode, theme, locale } = useUI();

  const info = useQuery({ queryKey: ["zagros", "panel-info"], queryFn: () => api.get<PanelInfo>("/zagros/panel/info"), retry: false });
  const admins = useQuery({ queryKey: ["admins"], queryFn: () => api.get<AdminUser[]>("/admins"), retry: false });
  const templates = useQuery({ queryKey: ["user_templates"], queryFn: () => api.get<UserTemplate[]>("/user_template"), retry: false });

  const [adminDialog, setAdminDialog] = useState(false);
  const [deleteAdmin, setDeleteAdmin] = useState<AdminUser | null>(null);
  const qc = useQueryClient();
  const del = useMutation({
    mutationFn: (username: string) => api.delete(`/admin/${username}`),
    onSuccess: () => { toast.ok(t("common.deleted")); setDeleteAdmin(null); qc.invalidateQueries({ queryKey: ["admins"] }); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  return (
    <div className="space-y-4 animate-fade-up">
      <h1 className="flex items-center gap-2 text-lg font-bold tracking-tight">
        <SettingsIcon size={18} className="text-brand" />{t("nav.settings")}
      </h1>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="panel" subtitle="identity & runtime (read-only, .env is the source of truth)" />
          {info.isLoading ? <Skeleton className="h-40" /> : info.isError ? (
            <p className="py-4 text-xs text-content-3">requires sudo admin</p>
          ) : (
            <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-[12.5px]">
              <Meta k="version" v={<Badge tone="brand">{info.data!.version}</Badge>} />
              <Meta k="app" v={info.data!.app_name} />
              <Meta k="domain" v={info.data!.domain || "—"} />
              <Meta k="tls mode" v={info.data!.tls_mode} />
              <Meta k="database" v={info.data!.database_driver} />
              <Meta k="uptime" v={formatDuration(info.data!.uptime_seconds, digits)} />
              <Meta k="panel url" v={<span className="break-all" dir="ltr">{info.data!.panel_base_url || "—"}</span>} />
              <Meta k="auth mode" v={info.data!.client_auth_mode} />
            </dl>
          )}
        </Card>

        <Card>
          <CardHeader title={<span className="inline-flex items-center gap-2"><TerminalSquare size={16} className="text-brand" /> Advanced Mode</span>} />
          <p className="text-[12.5px] leading-6 text-content-2">
            Advanced Mode unlocks the in-panel <b>Config Studio</b> (raw per-core document editing with
            schema validation and diff preview) and shows the <b>{t("nav.advanced")}</b> entry in the sidebar.
            Everything outside it stays graphical — regular operators never touch JSON.
          </p>
          <div className="mt-4 flex items-center gap-2.5">
            <Switch checked={advancedMode} onChange={(v) => { setAdvancedMode(v); applyUiState(theme, locale); }} label="advanced mode" />
            <span className="text-sm">{advancedMode ? "enabled" : "disabled"}</span>
            {advancedMode && <Badge tone="warn" dot>JSON exposed in Advanced page only</Badge>}
          </div>
        </Card>

        <Card>
          <CardHeader title={<span className="inline-flex items-center gap-2"><ShieldCheck size={16} className="text-brand" /> admins</span>}
            actions={<Button size="sm" variant="secondary" onClick={() => setAdminDialog(true)}><Plus size={13} /> admin</Button>} />
          {admins.isLoading ? <Skeleton className="h-32" /> : admins.isError ? (
            <p className="py-4 text-xs text-content-3">requires sudo admin</p>
          ) : (
            <ul className="divide-y divide-border">
              {(admins.data ?? []).map((a) => (
                <li key={a.username} className="flex items-center justify-between gap-3 py-2.5">
                  <div className="flex items-center gap-2.5">
                    <span className="text-sm font-medium">{a.username}</span>
                    {a.is_sudo && <Badge tone="brand">sudo</Badge>}
                    {a.enabled === false && <Badge tone="muted">disabled</Badge>}
                  </div>
                  <Button variant="ghost" size="icon" aria-label={`delete ${a.username}`} onClick={() => setDeleteAdmin(a)}>
                    <Trash2 size={14} />
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardHeader title={<span className="inline-flex items-center gap-2"><Users size={16} className="text-brand" /> user templates</span>}
            actions={<span className="text-[11px] text-content-3">{(templates.data ?? []).length}</span>} />
          {templates.isLoading ? <Skeleton className="h-32" /> : templates.isError || !templates.data?.length ? (
            <EmptyState title="No templates" hint="Templates pre-fill data limit, expiry and inbound sets when creating users." />
          ) : (
            <ul className="divide-y divide-border">
              {templates.data.map((tp) => (
                <li key={tp.id} className="flex items-center justify-between gap-3 py-2.5">
                  <span className="text-sm font-medium">{tp.name}</span>
                  <span className="text-[11px] text-content-3 tabular-nums">
                    {tp.data_limit ? formatBytes(tp.data_limit, digits) : "∞"} · {tp.expire_duration ? `${Math.round(tp.expire_duration / 86400)}d` : "no expiry"}
                  </span>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-3 border-t border-border pt-3 text-[11px] leading-5 text-content-3">
            Template editor is part of the Users workflow roadmap; existing templates apply at user creation.
          </p>
        </Card>
      </div>

      {adminDialog && <AdminDialog onClose={() => setAdminDialog(false)} />}
      <ConfirmDialog open={!!deleteAdmin} onClose={() => setDeleteAdmin(null)}
        onConfirm={() => deleteAdmin && del.mutate(deleteAdmin.username)}
        title={`delete admin — ${deleteAdmin?.username ?? ""}`}
        body="Their panel access stops immediately; users they own keep working."
        danger loading={del.isPending} />
    </div>
  );
}

function Meta({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[10.5px] uppercase tracking-wide text-content-3">{k}</dt>
      <dd className="mt-0.5 truncate text-content">{v}</dd>
    </div>
  );
}

function AdminDialog({ onClose }: { onClose: () => void }) {
  const t = useT();
  const qc = useQueryClient();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [sudo, setSudo] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <Dialog open onClose={onClose} title="new admin"
      footer={<>
        <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
        <Button loading={busy} disabled={!username.trim() || !password} onClick={async () => {
          setBusy(true); setError("");
          try {
            await api.post("/admin", { username: username.trim(), password, is_sudo: sudo });
            toast.ok(`admin ${username} created`);
            qc.invalidateQueries({ queryKey: ["admins"] });
            onClose();
          } catch (e) { setError(e instanceof ApiError ? e.message : t("common.error")); } finally { setBusy(false); }
        }}>{t("common.create")}</Button>
      </>}>
      <div className="grid gap-4">
        <Field label="username" required><Input value={username} onChange={(e) => setUsername(e.target.value)} /></Field>
        <Field label="password" required><Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
        <label className="flex items-center gap-2.5 text-sm text-content-2">
          <Switch checked={sudo} onChange={setSudo} label="sudo" />
          sudo — full platform access (cores, routing, settings)
        </label>
        {error && <p role="alert" className="rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
      </div>
    </Dialog>
  );
}
