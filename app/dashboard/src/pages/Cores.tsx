// Cores — full lifecycle in-panel: catalog (registry), install (schema-driven
// form — no hardcoding), start/stop/restart/enable/disable/update/uninstall,
// live status + logs drawer. The CLI is never needed for daily core ops.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Cpu, Download, FileText, HardDriveDownload, Play, Power, PowerOff,
  RefreshCcw, RotateCw, Settings2, Square, Trash2, UploadCloud,
} from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "../components/feedback";
import { ConfirmDialog, Dialog, Drawer } from "../components/overlays";
import { Badge, Button, Card, CardHeader, EmptyState, ErrorState, Field, Input, Select, Skeleton, StatusDot, Switch, Tabs, cn } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useDigits, formatBytes, formatDuration, formatNumber } from "../lib/format";
import { useT } from "../lib/i18n";
import type { CoreRegistryEntry, CoreView } from "../lib/types";

const stateTone = (s: string) =>
  s === "running" ? "ok" : s === "error" ? "danger" : s === "stopped" || s === "installed" ? "info" : "muted";

export default function Cores() {
  const t = useT();
  const digits = useDigits();
  const qc = useQueryClient();
  const [tab, setTab] = useState("installed");
  const [installFor, setInstallFor] = useState<CoreRegistryEntry | null>(null);
  const [logsFor, setLogsFor] = useState<string | null>(null);
  const [uninstallFor, setUninstallFor] = useState<CoreView | null>(null);
  const [purge, setPurge] = useState(false);

  const registry = useQuery({
    queryKey: ["zagros", "core-registry"],
    queryFn: () => api.get<{ registry: CoreRegistryEntry[] }>("/zagros/cores/registry"),
  });
  const cores = useQuery({
    queryKey: ["zagros", "cores"],
    queryFn: () => api.get<{ cores: CoreView[] }>("/zagros/cores"),
    refetchInterval: 5000,
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["zagros", "cores"] });
    qc.invalidateQueries({ queryKey: ["zagros", "core-registry"] });
  };

  const act = useMutation({
    mutationFn: ({ id, action }: { id: string; action: string }) =>
      api.post(`/zagros/cores/${id}/${action}`),
    onSuccess: (_d, v) => { toast.ok(`${v.id}: ${v.action}`); invalidate(); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
    onSettled: invalidate,
  });

  const uninstall = useMutation({
    mutationFn: ({ id, purge }: { id: string; purge: boolean }) =>
      api.post(`/zagros/cores/${id}/uninstall`, { purge }),
    onSuccess: () => { toast.ok(t("common.deleted")); setUninstallFor(null); invalidate(); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const installedIds = useMemo(() => new Set((cores.data?.cores ?? []).map((c) => c.id)), [cores.data]);
  const catalog = useMemo(
    () => (registry.data?.registry ?? []).filter((r) => !installedIds.has(r.id)),
    [registry.data, installedIds],
  );

  return (
    <div className="space-y-4 animate-fade-up">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <Cpu size={18} className="text-brand" />{t("nav.cores")}
        </h1>
        <Tabs
          active={tab} onChange={setTab}
          tabs={[
            { id: "installed", label: `${t("nav.cores")} (${(cores.data?.cores ?? []).length})`, icon: <Cpu size={13} /> },
            { id: "catalog", label: `catalog (${catalog.length})`, icon: <Download size={13} /> },
          ]}
        />
      </div>

      {cores.isError && (
        <Card><ErrorState message={(cores.error as Error).message} onRetry={() => invalidate()} /></Card>
      )}

      {tab === "installed" && (
        cores.isLoading ? (
          <div className="grid gap-4 md:grid-cols-2">{[1, 2].map((i) => <Skeleton key={i} className="h-56" />)}</div>
        ) : !cores.data?.cores.length ? (
          <Card>
            <EmptyState
              title="No cores installed"
              hint="Install an official core binary from the catalog — the panel downloads and manages it, no CLI needed."
              action={<Button size="sm" onClick={() => setTab("catalog")}><Download size={14} /> open catalog</Button>}
            />
          </Card>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            {cores.data.cores.map((c) => (
              <Card key={c.id} className={cn(!c.enabled && "opacity-70")}>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex min-w-0 items-center gap-3">
                    <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-brand-soft text-brand">
                      <Cpu size={19} />
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <h3 className="truncate text-[15px] font-semibold">{c.id}</h3>
                        <StatusDot tone={c.state === "running" ? "ok" : c.state === "error" ? "danger" : "muted"} pulse={c.state === "running"} />
                      </div>
                      <p className="truncate text-[11px] text-content-3">
                        {(c.protocols ?? []).join(" · ") || "—"}
                      </p>
                    </div>
                  </div>
                  <Switch
                    checked={c.enabled}
                    label="enabled"
                    onChange={() => act.mutate({ id: c.id, action: c.enabled ? "disable" : "enable" })}
                  />
                </div>

                <div className="mt-4 grid grid-cols-2 gap-x-4 gap-y-2.5 text-[12px] sm:grid-cols-3">
                  <Meta k={t("common.status")} v={<Badge tone={stateTone(c.state) as never} dot>{c.state}{c.health ? ` · ${c.health}` : ""}</Badge>} />
                  <Meta k="version" v={<span className="tabular-nums">{c.core_version ?? "—"}</span>} />
                  <Meta k="uptime" v={formatDuration(c.uptime_seconds, digits)} />
                  <Meta k="accounts" v={formatNumber(c.metrics?.active_accounts ?? 0, digits)} />
                  <Meta k="traffic" v={`${formatBytes(c.metrics?.rx_bytes ?? 0, digits)} ↓ / ${formatBytes(c.metrics?.tx_bytes ?? 0, digits)} ↑`} />
                  <Meta k="binary" v={<code className="block max-w-full truncate font-mono text-[10.5px]" dir="ltr" title={c.binary_path ?? ""}>{c.binary_path ?? "—"}</code>} />
                </div>
                {c.message && <p className="mt-2 rounded-lg bg-warn-soft px-2.5 py-1.5 text-[11px] text-warn">{c.message}</p>}

                <div className="mt-4 flex flex-wrap items-center gap-1.5 border-t border-border pt-3.5">
                  {c.state === "running" ? (
                    <>
                      <Button size="sm" variant="secondary" onClick={() => act.mutate({ id: c.id, action: "stop" })}><Square size={13} /> stop</Button>
                      <Button size="sm" variant="secondary" onClick={() => act.mutate({ id: c.id, action: "restart" })}><RotateCw size={13} /> restart</Button>
                    </>
                  ) : (
                    <Button size="sm" onClick={() => act.mutate({ id: c.id, action: "start" })} disabled={!c.enabled}><Play size={13} /> start</Button>
                  )}
                  <Button size="sm" variant="ghost" onClick={() => setLogsFor(c.id)}><FileText size={13} /> logs</Button>
                  <Button size="sm" variant="ghost" onClick={() => act.mutate({ id: c.id, action: "update" })}><UploadCloud size={13} /> update</Button>
                  <div className="ms-auto">
                    <Button size="sm" variant="danger" onClick={() => { setPurge(false); setUninstallFor(c); }}><Trash2 size={13} /></Button>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )
      )}

      {tab === "catalog" && (
        registry.isLoading ? (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{[1, 2, 3].map((i) => <Skeleton key={i} className="h-44" />)}</div>
        ) : !catalog.length ? (
          <Card><EmptyState title="Every available core is installed" /></Card>
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {catalog.map((r) => (
              <Card key={r.id}>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h3 className="text-[15px] font-semibold">{r.name || r.id}</h3>
                    <p className="mt-0.5 line-clamp-2 min-h-[2em] text-[11px] text-content-3">{r.description || "—"}</p>
                  </div>
                  <Badge tone="muted">{r.id}</Badge>
                </div>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {(r.protocols ?? []).slice(0, 6).map((p) => <Badge key={p} tone="info">{p}</Badge>)}
                  {(r.capabilities ?? []).slice(0, 4).map((c) => <Badge key={c} tone="brand">{c}</Badge>)}
                </div>
                <div className="mt-4 flex items-center justify-between border-t border-border pt-3.5">
                  <span className="text-[10.5px] text-content-3">
                    {r.driver_version ? `driver ${r.driver_version}` : ""}
                  </span>
                  <Button size="sm" onClick={() => setInstallFor(r)}><HardDriveDownload size={13} /> install</Button>
                </div>
              </Card>
            ))}
          </div>
        )
      )}

      {installFor && (
        <InstallDialog entry={installFor} onClose={() => setInstallFor(null)} onDone={() => { setInstallFor(null); invalidate(); }} />
      )}

      <LogsDrawer coreId={logsFor} onClose={() => setLogsFor(null)} />

      <Dialog
        open={!!uninstallFor}
        onClose={() => setUninstallFor(null)}
        title={`uninstall — ${uninstallFor?.id}`}
        footer={
          <>
            <Button variant="ghost" onClick={() => setUninstallFor(null)}>{t("common.cancel")}</Button>
            <Button variant="danger" loading={uninstall.isPending}
              onClick={() => uninstallFor && uninstall.mutate({ id: uninstallFor.id, purge })}>
              <PowerOff size={13} /> uninstall
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-sm text-content-2">
            The core binary is removed from the panel. Accounts and routing stay configured.
          </p>
          <label className="flex items-center gap-2.5 text-sm text-content-2">
            <Switch checked={purge} onChange={setPurge} label="purge" />
            also delete the core's data directory (certs/keys stored there)
          </label>
        </div>
      </Dialog>
    </div>
  );
}

function Meta({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <p className="text-[10px] uppercase tracking-wide text-content-3">{k}</p>
      <div className="mt-0.5 truncate">{v}</div>
    </div>
  );
}

// -- install: renders fields straight from the driver's JSON Schema (no hardcode)

function InstallDialog({ entry, onClose, onDone }: { entry: CoreRegistryEntry; onClose: () => void; onDone: () => void }) {
  const t = useT();
  const schema = entry.config_schema as { properties?: Record<string, { type?: string; title?: string; description?: string; default?: unknown; enum?: unknown[] }>; required?: string[] } | null | undefined;
  const props = schema?.properties ?? {};
  const required = new Set(schema?.required ?? []);
  const [values, setValues] = useState<Record<string, string>>({});
  const [startNow, setStartNow] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const install = async () => {
    setBusy(true); setError("");
    const settings: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(values)) {
      if (v === "") continue;
      const type = props[k]?.type;
      settings[k] = type === "integer" || type === "number" ? Number(v)
        : type === "boolean" ? v === "true" : v;
    }
    try {
      await api.post(`/zagros/cores/${entry.id}/install`, { settings, enabled: true });
      toast.ok(`${entry.id} installed`);
      if (startNow) {
        try { await api.post(`/zagros/cores/${entry.id}/start`); toast.ok(`${entry.id} started`); }
        catch (e) { toast.error(`start: ${e instanceof ApiError ? e.message : t("common.error")}`); }
      }
      onDone();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t("common.error"));
    } finally { setBusy(false); }
  };

  const fields = Object.entries(props);
  return (
    <Dialog open onClose={onClose} title={`install — ${entry.name || entry.id}`}
      subtitle={entry.description ?? undefined}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button onClick={install} loading={busy}><HardDriveDownload size={14} /> install</Button>
        </>
      }>
      <div className="space-y-3.5">
        {fields.length === 0 && (
          <p className="rounded-xl bg-surface-2 p-3 text-xs text-content-2">
            This core needs no settings — the official binary is downloaded and verified automatically.
          </p>
        )}
        {fields.map(([key, meta]) => (
          <Field key={key} label={meta?.title ?? key} hint={meta?.description} required={required.has(key)}>
            {meta?.enum ? (
              <Select value={values[key] ?? String(meta.default ?? "")} onChange={(e) => setValues({ ...values, [key]: e.target.value })}>
                {(meta.enum as string[]).map((o) => <option key={o} value={String(o)}>{String(o)}</option>)}
              </Select>
            ) : meta?.type === "boolean" ? (
              <Select value={values[key] ?? String(meta.default ?? false)} onChange={(e) => setValues({ ...values, [key]: e.target.value })}>
                <option value="true">{t("common.yes")}</option>
                <option value="false">{t("common.no")}</option>
              </Select>
            ) : (
              <Input
                type={key.toLowerCase().match(/secret|password|token|key/) ? "password" : meta?.type === "integer" || meta?.type === "number" ? "number" : "text"}
                placeholder={meta?.default !== undefined ? String(meta.default) : ""}
                value={values[key] ?? ""}
                onChange={(e) => setValues({ ...values, [key]: e.target.value })}
              />
            )}
          </Field>
        ))}
        <label className="flex items-center gap-2.5 pt-1 text-sm text-content-2">
          <Switch checked={startNow} onChange={setStartNow} label="start after install" />
          start the core right after installation
        </label>
        {error && <p role="alert" className="rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
      </div>
    </Dialog>
  );
}

function LogsDrawer({ coreId, onClose }: { coreId: string | null; onClose: () => void }) {
  const [lines, setLines] = useState(200);
  const logs = useQuery({
    queryKey: ["zagros", "core-logs", coreId, lines],
    queryFn: () => api.get<{ lines: string[] }>(`/zagros/cores/${coreId}/logs?lines=${lines}`),
    enabled: !!coreId,
    refetchInterval: 3000,
  });
  return (
    <Drawer open={!!coreId} onClose={onClose} title={`logs — ${coreId ?? ""}`}
      footer={
        <div className="flex items-center gap-2">
          <Select value={String(lines)} onChange={(e) => setLines(Number(e.target.value))} className="w-32">
            {[100, 200, 500, 1000].map((n) => <option key={n} value={n}>{n} lines</option>)}
          </Select>
          <Button variant="secondary" size="sm" onClick={() => logs.refetch()} className="ms-auto"><RefreshCcw size={13} /> refresh</Button>
        </div>
      }>
      {logs.isLoading ? <Skeleton className="h-64" /> : (
        <pre className="whitespace-pre-wrap break-all rounded-xl bg-surface p-3 font-mono text-[11px] leading-5 text-content-2" dir="ltr">
          {(logs.data?.lines ?? []).join("\n") || "— no log output yet —"}
        </pre>
      )}
    </Drawer>
  );
}
