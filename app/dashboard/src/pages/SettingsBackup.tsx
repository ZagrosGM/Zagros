// Settings → Backup & Restore — on-demand archives, scheduled delivery to
// Telegram, and restores from Zagros / Marzban / Pasarguard / 3x-ui.
//
// The restore flow is preview-first on purpose: nothing is written until the
// operator has seen the report and pressed restore.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArchiveRestore, DatabaseBackup, Download, HardDriveDownload, Send, Trash2, Upload,
} from "lucide-react";
import { useRef, useState } from "react";
import { toast } from "../components/feedback";
import { Badge, Button, Card, CardHeader, Field, Input, Select, Skeleton, Switch } from "../components/ui";
import { api, ApiError, download } from "../lib/api";
import { useT } from "../lib/i18n";

interface BackupArtifact {
  name: string; size_bytes: number; created_utc: string; kind: string;
  panel_version: string; db_kind: string;
}
interface ServiceSettings {
  enabled: boolean; schedule: string; cron: string; at_hour: number; at_minute: number;
  weekday: number; chat_id: string; bot_token: string; has_token: boolean;
  include_logs: boolean; keep: number; next_run_at: number | null; telegram_max_bytes: number;
}
interface ServiceState {
  last_run_at: number | null; last_status: string; last_size_bytes: number;
  last_archive: string; last_error: string; delivered: boolean;
}
interface ServicePayload { settings: ServiceSettings; state: ServiceState }
interface RestoreReport {
  source: string; dry_run: boolean; ok: boolean; steps: string[]; warnings: string[];
  notes?: string[];
  counts: Record<string, number>; credentials: Record<string, string>; restart?: Record<string, unknown>;
}

const SOURCES = [
  { id: "zagros", label: "Zagros (this panel)" },
  { id: "marzban", label: "Marzban" },
  { id: "pasarguard", label: "Pasarguard" },
  { id: "3x-ui", label: "3x-ui" },
] as const;

const SCHEDULES = [
  { id: "hourly", label: "hourly" },
  { id: "daily", label: "daily" },
  { id: "weekly", label: "weekly" },
  { id: "cron", label: "custom cron" },
] as const;

const WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];

function humanBytes(bytes: number): string {
  const units = ["B", "KB", "MB", "GB"];
  let value = Number(bytes || 0);
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function when(ts: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export default function SettingsBackup() {
  const t = useT();
  const qc = useQueryClient();
  const fileInput = useRef<HTMLInputElement>(null);

  const artifacts = useQuery({
    queryKey: ["zagros", "backup", "artifacts"],
    queryFn: () => api.get<{ artifacts: BackupArtifact[] }>("/zagros/backup/artifacts"),
  });
  const service = useQuery({
    queryKey: ["zagros", "backup", "service"],
    queryFn: () => api.get<ServicePayload>("/zagros/backup/service"),
    retry: false,
  });

  const [form, setForm] = useState<ServiceSettings | null>(null);
  const settings: ServiceSettings | null = form ?? service.data?.settings ?? null;

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["zagros", "backup"] });
    setForm(null);
  };

  const create = useMutation({
    mutationFn: () => api.post<{ artifact: BackupArtifact }>("/zagros/backup/create", {}),
    onSuccess: (data) => { toast.ok(`backup ready: ${data.artifact.name}`); invalidate(); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const remove = useMutation({
    mutationFn: (name: string) => api.delete(`/zagros/backup/artifacts/${encodeURIComponent(name)}`),
    onSuccess: () => { toast.ok(t("common.saved")); invalidate(); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const saveService = useMutation({
    mutationFn: () => api.put("/zagros/backup/service", settings),
    onSuccess: () => { toast.ok(t("common.saved")); invalidate(); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const testService = useMutation({
    mutationFn: () => api.post("/zagros/backup/service/test", {}),
    onSuccess: () => toast.ok("test message delivered"),
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const runService = useMutation({
    mutationFn: () => api.post<{ ok: boolean; archive?: string; delivered?: boolean; reason?: string }>(
      "/zagros/backup/service/run", {}),
    onSuccess: (data) => {
      if (data.delivered) toast.ok(`delivered: ${data.archive}`);
      else toast.error(data.reason || "backup created but not delivered");
      invalidate();
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  // ---- restore ---- //
  const [source, setSource] = useState<string>("zagros");
  const [staged, setStaged] = useState<string | null>(null);
  const [stagedName, setStagedName] = useState<string>("");
  const [report, setReport] = useState<RestoreReport | null>(null);

  const upload = useMutation({
    mutationFn: async (file: File) => {
      const body = new FormData();
      body.append("file", file);
      body.append("source", source);
      return api.post<{ staged: string; bytes: number }>("/zagros/restore/upload", body);
    },
    onSuccess: (data, file) => {
      setStaged(data.staged); setStagedName(file.name); setReport(null);
      toast.ok("archive uploaded — inspect before restoring");
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const inspect = useMutation({
    mutationFn: () => api.post<RestoreReport>("/zagros/restore/inspect", { staged, source }),
    onSuccess: (data) => setReport(data),
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const apply = useMutation({
    mutationFn: () => api.post<RestoreReport>("/zagros/restore/apply", { staged, source }),
    onSuccess: (data) => {
      setReport(data); setStaged(null);
      toast.ok(data.restart?.accepted ? "restore applied — restarting the panel"
                                      : "restore applied");
      invalidate();
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader
          title={<span className="inline-flex items-center gap-2"><DatabaseBackup size={16} className="text-brand" />{t("settings.backup.now")}</span>}
          subtitle={t("database + configuration + certificates + core state")}
        />
        <div className="flex flex-wrap items-center gap-2">
          <Button onClick={() => create.mutate()} loading={create.isPending}>
            <DatabaseBackup size={14} />take backup
          </Button>
          <Button variant="secondary" onClick={() => runService.mutate()} loading={runService.isPending}>
            <Send size={14} />{t("run scheduled job now")}</Button>
        </div>
        <p className="mt-3 text-[11.5px] leading-5 text-content-3">{t("Core binaries and the backup folder itself are excluded — they are re-installable, and an archive must never contain itself.")}</p>
      </Card>

      <Card>
        <CardHeader title={t("settings.backup.service")} subtitle={t("build an archive on a schedule and send it to Telegram")} />
        {service.isLoading || !settings ? <Skeleton className="h-56" /> : (
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="flex items-center gap-2.5 text-sm text-content-2 sm:col-span-2">
              <Switch checked={settings.enabled} onChange={(v) => setForm({ ...settings, enabled: v })} label={t("enabled")} />{t("enabled")}</label>
            <Field label="schedule">
              <Select value={settings.schedule} onChange={(e) => setForm({ ...settings, schedule: e.target.value })}>
                {SCHEDULES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
              </Select>
            </Field>
            {settings.schedule === "cron" ? (
              <Field label={t("cron (UTC)")} hint={t("minute hour day month weekday")}>
                <Input value={settings.cron} onChange={(e) => setForm({ ...settings, cron: e.target.value })} dir="ltr" placeholder="0 3 * * *" />
              </Field>
            ) : (
              <Field label={t("at (UTC)")}>
                <div className="flex items-center gap-2">
                  <Input type="number" min={0} max={23} value={settings.at_hour} onChange={(e) => setForm({ ...settings, at_hour: Number(e.target.value) })} dir="ltr" />
                  <span className="text-content-3">:</span>
                  <Input type="number" min={0} max={59} value={settings.at_minute} onChange={(e) => setForm({ ...settings, at_minute: Number(e.target.value) })} dir="ltr" />
                </div>
              </Field>
            )}
            {settings.schedule === "weekly" && (
              <Field label="weekday">
                <Select value={String(settings.weekday)} onChange={(e) => setForm({ ...settings, weekday: Number(e.target.value) })}>
                  {WEEKDAYS.map((day, index) => <option key={day} value={String(index)}>{day}</option>)}
                </Select>
              </Field>
            )}
            <Field label={t("Telegram chat id")} hint={t("numeric — e.g. -1001234567890")}>
              <Input value={settings.chat_id} onChange={(e) => setForm({ ...settings, chat_id: e.target.value })} dir="ltr" />
            </Field>
            <Field label={t("bot token")} hint={settings.has_token ? "stored encrypted — leave blank to keep it" : "from @BotFather"}>
              <Input type="password" value={""} onChange={(e) => setForm({ ...settings, bot_token: e.target.value })} placeholder={settings.has_token ? "••••••••" : ""} dir="ltr" autoComplete="new-password" />
            </Field>
            <Field label={t("archives kept")} hint={t("older ones are pruned")}>
              <Input type="number" min={0} value={settings.keep} onChange={(e) => setForm({ ...settings, keep: Number(e.target.value) })} dir="ltr" />
            </Field>
            <label className="flex items-center gap-2.5 text-sm text-content-2">
              <Switch checked={settings.include_logs} onChange={(v) => setForm({ ...settings, include_logs: v })} label={t("include logs")} />{t("include logs")}</label>
            {settings.enabled && (
              <p className="text-[11.5px] text-content-3 sm:col-span-2">
                next run: {when(settings.next_run_at)} · effective schedule:{" "}
                <code className="rounded bg-surface px-1 py-0.5" dir="ltr">{settings.cron}</code> (UTC)
              </p>
            )}
            <div className="flex flex-wrap gap-2 sm:col-span-2">
              <Button variant="secondary" onClick={() => saveService.mutate()} loading={saveService.isPending}>save</Button>
              <Button variant="ghost" onClick={() => testService.mutate()} loading={testService.isPending}>{t("send test message")}</Button>
            </div>
            {service.data?.state?.last_status && (
              <p className="text-[11.5px] text-content-3 sm:col-span-2">
                last run: {when(service.data.state.last_run_at)}{" "}
                <Badge tone={service.data.state.last_status === "ok" ? "ok" : "warn"}>
                  {service.data.state.delivered ? "delivered" : service.data.state.last_status}
                </Badge>
                {service.data.state.last_error && ` — ${service.data.state.last_error}`}
              </p>
            )}
          </div>
        )}
      </Card>

      <Card>
        <CardHeader title={t("settings.backup.artifacts")} />
        {artifacts.isLoading ? <Skeleton className="h-32" /> : (
          <ul className="space-y-2">
            {(artifacts.data?.artifacts ?? []).map((item) => (
              <li key={item.name} className="flex items-center justify-between gap-3 rounded-xl border border-line px-3 py-2">
                <div className="min-w-0">
                  <p className="truncate text-[12.5px] text-content" dir="ltr">{item.name}</p>
                  <p className="text-[10.5px] text-content-3">
                    {humanBytes(item.size_bytes)} · {item.created_utc.replace("T", " ").replace("Z", " UTC")}
                    {item.panel_version ? ` · v${item.panel_version}` : ""}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <Button size="sm" variant="ghost" onClick={() => void download(`/zagros/backup/artifacts/${encodeURIComponent(item.name)}`, item.name).catch((e) => toast.error(e instanceof ApiError ? e.message : "download failed"))}>
                    <Download size={13} />
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => remove.mutate(item.name)} loading={remove.isPending}>
                    <Trash2 size={13} />
                  </Button>
                </div>
              </li>
            ))}
            {(artifacts.data?.artifacts ?? []).length === 0 && (
              <li className="py-6 text-center text-[12px] text-content-3">{t("no archives yet")}</li>
            )}
          </ul>
        )}
      </Card>

      <Card>
        <CardHeader
          title={<span className="inline-flex items-center gap-2"><ArchiveRestore size={16} className="text-brand" />{t("settings.backup.restore")}</span>}
          subtitle={t("upload an archive, inspect it, then restore")}
        />
        <div className="grid gap-3">
          <Field label={t("backup source")} hint={t("Zagros archives restore as-is; others are imported")}>
            <Select value={source} onChange={(e) => { setSource(e.target.value); setReport(null); }}>
              {SOURCES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
            </Select>
          </Field>
          <input
            ref={fileInput}
            type="file"
            accept=".tar.gz,.tgz,.tar,.zip,.db,.sqlite,.sqlite3,.sql"
            className="hidden"
            onChange={(e) => { const file = e.target.files?.[0]; if (file) upload.mutate(file); e.target.value = ""; }}
          />
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="secondary" onClick={() => fileInput.current?.click()} loading={upload.isPending}>
              <Upload size={14} />choose backup
            </Button>
            <p className="text-[11px] text-content-3">
              a Zagros/Marzban archive (.tar.gz or .zip), a bare database (.db/.sqlite),
              or a SQL dump (.sql) — Marzban&apos;s own backup is a .sql inside a .zip.
            </p>
            <Button variant="secondary" onClick={() => inspect.mutate()} disabled={!staged} loading={inspect.isPending}>
              inspect
            </Button>
            {source !== "zagros" && report?.dry_run === false && (
              <Button disabled className="opacity-50">{t("already restored")}</Button>
            )}
            {source !== "zagros" && report?.dry_run !== false && (
              <Button onClick={() => apply.mutate()} disabled={!staged} loading={apply.isPending}>
                <HardDriveDownload size={14} />restore &amp; import
              </Button>
            )}
            {source === "zagros" && (
              <Button onClick={() => apply.mutate()} disabled={!staged} loading={apply.isPending}>
                <HardDriveDownload size={14} />restore &amp; restart
              </Button>
            )}
          </div>
          {stagedName && <p className="text-[11.5px] text-content-3">staged: {stagedName}</p>}

          {report && (
            <div className="space-y-2 rounded-xl border border-line bg-surface-2 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone={report.ok ? "ok" : "warn"}>{report.dry_run ? "preview" : "applied"}</Badge>
                <Badge tone="muted">{report.source}</Badge>
                {Object.entries(report.counts ?? {})
                  .filter(([, v]) => typeof v === "number" && v > 0)
                  .map(([k, v]) => <Badge key={k} tone="muted">{k}: {String(v)}</Badge>)}
              </div>
              <ul className="list-inside list-disc text-[12px] text-content-2">
                {(report.steps ?? []).map((step, i) => <li key={i}>{step}</li>)}
              </ul>
              {(report.warnings ?? []).length > 0 && (
                <ul className="list-inside list-disc text-[12px] text-warn">
                  {report.warnings.slice(0, 24).map((warning, i) => <li key={i}>{warning}</li>)}
                  {report.warnings.length > 24 && <li>… +{report.warnings.length - 24}</li>}
                </ul>
              )}
              {(report.notes ?? []).length > 0 && (
                <ul className="list-inside list-disc text-[11.5px] text-content-3">
                  {(report.notes ?? []).slice(0, 24).map((note, i) => <li key={i}>{note}</li>)}
                </ul>
              )}
              {Object.keys(report.credentials ?? {}).length > 0 && (
                <div className="rounded-lg border border-warn/40 bg-warn-soft p-2 text-[11.5px]">
                  <p className="font-medium">{t("New passwords — shown once:")}</p>
                  {Object.entries(report.credentials).map(([user, password]) => (
                    <p key={user} dir="ltr">{user}: <b>{password}</b></p>
                  ))}
                </div>
              )}
              {Boolean(report.restart?.reason) && !report.restart?.accepted && (
                <p className="text-[11.5px] text-content-3">
                  restart: {String(report.restart?.reason)} — {String(report.restart?.detail ?? "")}
                </p>
              )}
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}
