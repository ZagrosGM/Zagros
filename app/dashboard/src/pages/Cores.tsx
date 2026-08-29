// Cores — full lifecycle in-panel: catalog (registry), install with a
// SIMPLE zero-input flow (version pick + auto everything) and an ADVANCED
// escape hatch (the schema-driven form), start/stop/restart/enable/disable/
// upgrade/reinstall/uninstall, live CPU/RAM/uptime, logs drawer.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Cpu, Download, FileText, HardDriveDownload, Loader2, Play, PowerOff,
  RefreshCcw, RotateCw, Server, Settings2, Square, Trash2, UploadCloud,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { toast } from "../components/feedback";
import { ConfirmDialog, Dialog, Drawer } from "../components/overlays";
import { Badge, Button, Card, EmptyState, ErrorState, Field, Input, Select, Skeleton, StatusDot, Switch, Tabs, cn } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useDigits, formatBytes, formatDuration, formatNumber } from "../lib/format";
import { useT } from "../lib/i18n";
import type {
  CoreRegistryEntry, CoreRelease, CoreView, Node, NodeCatalogEntry,
  NodeCores, NodeCoreStatus, NodeList,
} from "../lib/types";

// --------------------------------------------------------------------------- //
// Cores — tab host.
//
// "Master" is the panel's own core set (unchanged behaviour). Every paired
// node gets its own tab: the same catalog → install → manage flow, executed
// remotely over the node's signed control plane. Deep-linkable with
// ?node=<id> so the Nodes page can hand off directly.
// --------------------------------------------------------------------------- //
export default function Cores() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const nodeParam = params.get("node");
  const [tab, setTab] = useState<string>(nodeParam ? `node:${nodeParam}` : "master");

  const nodes = useQuery({
    queryKey: ["zagros", "nodes"],
    queryFn: () => api.get<NodeList>("/zagros/nodes"),
    refetchInterval: 20000,
  });

  // Arriving from the Nodes page (or a bookmark) focuses that node.
  useEffect(() => {
    if (nodeParam) setTab(`node:${nodeParam}`);
  }, [nodeParam]);

  const select = (id: string) => {
    setTab(id);
    if (id.startsWith("node:")) setParams({ node: id.slice(5) }, { replace: true });
    else setParams({}, { replace: true });
  };

  const tabs = [
    { id: "master", label: "Master", icon: <Cpu size={13} /> },
    ...(nodes.data?.nodes ?? []).map((n: Node) => ({
      id: `node:${n.id}`,
      label: `${n.name}${n.status === "connected" ? "" : " ⚠"}`,
      icon: <Server size={13} />,
    })),
  ];

  const activeNode = tab.startsWith("node:")
    ? (nodes.data?.nodes ?? []).find((n) => n.id === Number(tab.slice(5))) ?? null
    : null;

  return (
    <div className="space-y-4 animate-fade-up">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <Cpu size={18} className="text-brand" />{t("nav.cores")}
        </h1>
        <Tabs active={tab} onChange={select} tabs={tabs} />
      </div>
      {activeNode
        ? <NodeCoresPanel key={activeNode.id} node={activeNode} />
        : <MasterCores />}
    </div>
  );
}

// --------------------------------------------------------------------------- //
// One node's cores — installed / catalog, driven entirely through the node's
// signed API (installs run as jobs on the node, so this call can legitimately
// take minutes; the UI says so instead of timing out silently).
// --------------------------------------------------------------------------- //
function NodeCoresPanel({ node }: { node: Node }) {
  const t = useT();
  const digits = useDigits();
  const qc = useQueryClient();
  const [tab, setTab] = useState("installed");
  const [installFor, setInstallFor] = useState<NodeCatalogEntry | null>(null);
  const [logsFor, setLogsFor] = useState<string | null>(null);
  const [settingsFor, setSettingsFor] = useState<string | null>(null);
  const [uninstallFor, setUninstallFor] = useState<NodeCoreStatus | null>(null);
  const [purge, setPurge] = useState(false);

  const inventory = useQuery({
    queryKey: ["zagros", "node-cores", node.id],
    queryFn: () => api.get<NodeCores>(`/zagros/nodes/${node.id}/cores`),
    refetchInterval: 8000,
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["zagros", "node-cores", node.id] });
    qc.invalidateQueries({ queryKey: ["zagros", "nodes"] });
  };

  const act = useMutation({
    mutationFn: ({ core, action, settings, purge: doPurge }: {
      core: string; action: string; settings?: Record<string, unknown>; purge?: boolean;
    }) => api.post(`/zagros/nodes/${node.id}/cores/${encodeURIComponent(core)}/lifecycle`,
      { action, settings: settings ?? {}, purge: Boolean(doPurge), force: false }),
    onSuccess: (_d, v) => { toast.ok(`${node.name}: ${v.core} ${v.action}`); invalidate(); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
    onSettled: invalidate,
  });

  const installed = Object.values(inventory.data?.installed ?? {});
  const catalog = Object.values(inventory.data?.preview ?? {})
    .filter((entry) => !installed.some((c) => c.core_id === entry.id));
  const busy = act.isPending
    ? `${act.variables?.action ?? "working"} on ${act.variables?.core ?? ""}`
    : null;

  if (node.status !== "connected") {
    return (
      <Card>
        <EmptyState
          title={`${node.name} is not paired`}
          hint="Finish pairing from the Nodes page (confirm the certificate fingerprint) before managing its cores."
        />
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <p className="me-auto text-[11px] text-content-3" dir="ltr">
          {node.address}:{node.port}{node.agent_version ? ` · agent ${node.agent_version}` : ""}
        </p>
        <Tabs
          active={tab} onChange={setTab}
          tabs={[
            { id: "installed", label: `cores (${installed.length})`, icon: <Cpu size={13} /> },
            { id: "catalog", label: `catalog (${catalog.length})`, icon: <Download size={13} /> },
          ]}
        />
      </div>

      {inventory.isError && (
        <Card>
          <ErrorState message={(inventory.error as Error).message} onRetry={() => invalidate()} />
        </Card>
      )}
      {inventory.data?.stale && (
        <p className="rounded-xl bg-warn-soft px-3 py-2 text-[11px] text-warn">
          Showing the last known inventory — the node did not answer ({inventory.data.error}).
        </p>
      )}
      {busy && (
        <p role="status" aria-live="polite"
          className="flex items-center gap-2 rounded-xl border border-brand/30 bg-brand-soft/30 px-3 py-2 text-xs text-brand">
          <Loader2 size={13} className="animate-spin" />
          {busy} — this can take a few minutes for downloads
        </p>
      )}

      {tab === "installed" && (
        inventory.isLoading ? (
          <div className="grid gap-4 md:grid-cols-2">{[1, 2].map((i) => <Skeleton key={i} className="h-52" />)}</div>
        ) : !installed.length ? (
          <Card>
            <EmptyState
              title="No cores installed on this node"
              hint="Install one from the catalog — the node downloads and verifies the official release itself."
              action={<Button size="sm" onClick={() => setTab("catalog")}><Download size={14} /> open catalog</Button>}
            />
          </Card>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            {installed.map((core) => (
              <Card key={core.core_id}>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex min-w-0 items-center gap-3">
                    <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-brand-soft text-brand">
                      <Cpu size={19} />
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <h3 className="truncate text-[15px] font-semibold">{core.core_id}</h3>
                        <StatusDot tone={(core.state === "running" ? "ok"
                          : core.state === "error" ? "danger" : "muted") as never}
                          pulse={core.state === "running"} />
                      </div>
                      <p className="truncate text-[11px] text-content-3">
                        {core.core_version ? `version ${core.core_version}` : "version unknown"}
                        {core.uptime_seconds ? ` · up ${formatDuration(core.uptime_seconds, digits)}` : ""}
                      </p>
                    </div>
                  </div>
                  <Badge tone={stateTone(core.state ?? "") as never} dot>{core.state}</Badge>
                </div>

                {core.binary_path && (
                  <p className="mt-3 truncate font-mono text-[10.5px] text-content-3" dir="ltr"
                    title={core.binary_path}>{core.binary_path}</p>
                )}
                {core.message && (
                  <p className="mt-2 rounded-lg bg-warn-soft px-2.5 py-1.5 text-[11px] text-warn">{core.message}</p>
                )}

                <div className="mt-4 flex flex-wrap items-center gap-1.5 border-t border-border pt-3.5">
                  {core.state === "running" ? (
                    <>
                      <Button size="sm" variant="secondary"
                        onClick={() => act.mutate({ core: core.core_id, action: "stop" })}>
                        <Square size={13} /> stop</Button>
                      <Button size="sm" variant="secondary"
                        onClick={() => act.mutate({ core: core.core_id, action: "restart" })}>
                        <RotateCw size={13} /> restart</Button>
                    </>
                  ) : (
                    <Button size="sm"
                      onClick={() => act.mutate({ core: core.core_id, action: "start" })}>
                      <Play size={13} /> start</Button>
                  )}
                  <Button size="sm" variant="ghost" onClick={() => setLogsFor(core.core_id)}>
                    <FileText size={13} /> logs</Button>
                  <Button size="sm" variant="ghost" onClick={() => setSettingsFor(core.core_id)}>
                    <Settings2 size={13} /> settings</Button>
                  <Button size="sm" variant="ghost"
                    onClick={() => act.mutate({ core: core.core_id, action: "update" })}>
                    <UploadCloud size={13} /> update</Button>
                  <div className="ms-auto">
                    <Button size="sm" variant="danger"
                      onClick={() => { setPurge(false); setUninstallFor(core); }}>
                      <Trash2 size={13} />
                    </Button>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )
      )}

      {tab === "catalog" && (
        inventory.isLoading ? (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {[1, 2, 3].map((i) => <Skeleton key={i} className="h-44" />)}
          </div>
        ) : !catalog.length ? (
          <Card><EmptyState title="Every available core is installed on this node" /></Card>
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {catalog.map((entry) => (
              <Card key={entry.id}>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h3 className="text-[15px] font-semibold">{entry.name || entry.id}</h3>
                    <p className="mt-0.5 line-clamp-2 min-h-[2em] text-[11px] text-content-3">
                      {entry.description || "—"}
                    </p>
                  </div>
                  <Badge tone="muted">{entry.id}</Badge>
                </div>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {(entry.protocols ?? []).slice(0, 6).map((p) => <Badge key={p} tone="info">{p}</Badge>)}
                </div>
                <div className="mt-4 flex items-center justify-between border-t border-border pt-3.5">
                  <span className="text-[10.5px] text-content-3">installed on the node</span>
                  <Button size="sm" onClick={() => setInstallFor(entry)}>
                    <HardDriveDownload size={13} /> install
                  </Button>
                </div>
              </Card>
            ))}
          </div>
        )
      )}

      {installFor && (
        <NodeInstallDialog
          node={node} entry={installFor}
          onClose={() => setInstallFor(null)}
          onDone={() => { setInstallFor(null); setTab("installed"); invalidate(); }}
        />
      )}

      <Dialog
        open={!!uninstallFor}
        onClose={() => setUninstallFor(null)}
        title={`uninstall — ${uninstallFor?.core_id}`}
        footer={
          <>
            <Button variant="ghost" onClick={() => setUninstallFor(null)}>{t("common.cancel")}</Button>
            <Button variant="danger" loading={act.isPending}
              onClick={() => uninstallFor && act.mutate(
                { core: uninstallFor.core_id, action: "uninstall", purge })}>
              <PowerOff size={13} /> uninstall
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-sm text-content-2">
            The core binary and its runtime are removed on {node.name}. Users assigned to it stop
            being served there.
          </p>
          <label className="flex items-center gap-2.5 text-sm text-content-2">
            <Switch checked={purge} onChange={setPurge} label="purge" />
            also delete the core's data directory on the node
          </label>
        </div>
      </Dialog>

      <NodeLogsDrawer nodeId={node.id} coreId={logsFor} onClose={() => setLogsFor(null)} />
      <NodeSettingsDrawer
        nodeId={node.id} coreId={settingsFor}
        onClose={() => { setSettingsFor(null); invalidate(); }}
      />
    </div>
  );
}

// --------------------------------------------------------------------------- //
function NodeInstallDialog({ node, entry, onClose, onDone }: {
  node: Node; entry: NodeCatalogEntry; onClose: () => void; onDone: () => void;
}) {
  const t = useT();
  const schema = entry.config_schema as
    { properties?: Record<string, { type?: string; title?: string; description?: string; default?: unknown; enum?: unknown[] }>;
      required?: string[] } | null | undefined;
  const props = schema?.properties ?? {};
  const required = new Set(schema?.required ?? []);
  const [mode, setMode] = useState<"simple" | "advanced">("simple");
  const [version, setVersion] = useState("");       // "" = latest
  const [customVersion, setCustomVersion] = useState("");
  const [values, setValues] = useState<Record<string, string>>({});
  const [startNow, setStartNow] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // Release tags come from the panel's registry endpoint (the driver's own
  // release repo). It is advisory only: if the list is unavailable the node
  // simply installs the latest build.
  const versions = useQuery({
    queryKey: ["zagros", "core-versions", entry.id],
    queryFn: () => api.get<{ releases: CoreRelease[] }>(`/zagros/cores/${entry.id}/versions`),
    retry: false, staleTime: 600000,
  });

  const install = async () => {
    setBusy(true); setError("");
    const settings: Record<string, unknown> = {};
    if (mode === "advanced") {
      for (const [k, v] of Object.entries(values)) {
        if (v === "") continue;
        const type = props[k]?.type;
        settings[k] = type === "integer" || type === "number" ? Number(v)
          : type === "boolean" ? v === "true" : v;
      }
    }
    const chosen = customVersion.trim() || version;
    if (chosen) settings.release_version = chosen.replace(/^v/, "");
    try {
      await api.post(
        `/zagros/nodes/${node.id}/cores/${encodeURIComponent(entry.id)}/lifecycle`,
        { action: "install", settings, purge: false, force: false });
      toast.ok(`${entry.id} installed on ${node.name}`);
      if (startNow) {
        try {
          await api.post(
            `/zagros/nodes/${node.id}/cores/${encodeURIComponent(entry.id)}/lifecycle`,
            { action: "start", settings: {}, purge: false, force: false });
          toast.ok(`${entry.id} started`);
        } catch (e) {
          toast.error(`start: ${e instanceof ApiError ? e.message : t("common.error")}`);
        }
      }
      onDone();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t("common.error"));
    } finally {
      setBusy(false);
    }
  };

  const fields = Object.entries(props);

  return (
    <Dialog open wide onClose={onClose} title={`install on ${node.name} — ${entry.name || entry.id}`}
      subtitle={entry.description ?? undefined}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button onClick={install} loading={busy}>
            <HardDriveDownload size={14} /> install
          </Button>
        </>
      }>
      <Tabs active={mode} onChange={(m) => setMode(m as "simple" | "advanced")}
        tabs={[
          { id: "simple", label: t("cores.install.simple") },
          { id: "advanced", label: t("cores.install.advanced") },
        ]} />
      <div className="mt-4 space-y-3.5">
        {mode === "simple" && (
          <>
            <p className="rounded-xl bg-surface-2 p-3 text-[12px] leading-5 text-content-2">
              {t("cores.install.autoNote")} The node downloads and verifies the official release
              itself — nothing is transferred from the panel.
            </p>
            <Field label={t("cores.install.version")}>
              {versions.isLoading ? <Skeleton className="h-9" /> : (
                <>
                  <Select value={version} onChange={(e) => setVersion(e.target.value)}
                    disabled={!versions.data?.releases?.length}>
                    <option value="">{t("cores.install.latest")}</option>
                    {(versions.data?.releases ?? []).map((r) => (
                      <option key={r.tag} value={r.tag}>{r.tag}{r.prerelease ? " (pre)" : ""}</option>
                    ))}
                  </Select>
                  {!versions.data?.releases?.length && (
                    <p className="mt-1 text-[11px] text-content-3">
                      version list unavailable — the latest build will be installed
                    </p>
                  )}
                </>
              )}
            </Field>
            <Field label="custom tag (optional)" hint="e.g. 1.8.23 — overrides the picker">
              <Input value={customVersion} onChange={(e) => setCustomVersion(e.target.value)}
                dir="ltr" placeholder="leave empty" />
            </Field>
          </>
        )}

        {mode === "advanced" && (
          <>
            {fields.length === 0 && (
              <p className="rounded-xl bg-surface-2 p-3 text-xs text-content-2">
                This core needs no settings — the official binary is downloaded and verified
                automatically.
              </p>
            )}
            {fields.map(([key, meta]) => (
              <Field key={key} label={meta?.title ?? key} hint={meta?.description}
                required={required.has(key)}>
                {meta?.enum ? (
                  <Select value={values[key] ?? String(meta.default ?? "")}
                    onChange={(e) => setValues({ ...values, [key]: e.target.value })}>
                    {(meta.enum as string[]).map((o) => <option key={o} value={String(o)}>{String(o)}</option>)}
                  </Select>
                ) : meta?.type === "boolean" ? (
                  <Select value={values[key] ?? String(meta.default ?? false)}
                    onChange={(e) => setValues({ ...values, [key]: e.target.value })}>
                    <option value="true">{t("common.yes")}</option>
                    <option value="false">{t("common.no")}</option>
                  </Select>
                ) : (
                  <Input
                    type={key.toLowerCase().match(/secret|password|token|key/) ? "password"
                      : meta?.type === "integer" || meta?.type === "number" ? "number" : "text"}
                    placeholder={meta?.default !== undefined ? String(meta.default) : ""}
                    value={values[key] ?? ""}
                    onChange={(e) => setValues({ ...values, [key]: e.target.value })}
                  />
                )}
              </Field>
            ))}
          </>
        )}

        <label className="flex items-center gap-2.5 pt-1 text-sm text-content-2">
          <Switch checked={startNow} onChange={setStartNow} label={t("cores.install.startAfter")} />
          {t("cores.install.startAfter")}
        </label>

        {busy && (
          <div role="status" aria-live="polite"
            className="rounded-xl border border-brand/30 bg-brand-soft/30 px-3 py-2.5 text-xs text-content-2">
            <p className="flex items-center gap-2 font-medium text-brand">
              <Loader2 size={13} className="animate-spin" />
              installing on {node.name} — the node downloads and verifies the release
            </p>
          </div>
        )}
        {error && (
          <p role="alert" className="rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">
            {error}
          </p>
        )}
      </div>
    </Dialog>
  );
}

// --------------------------------------------------------------------------- //
function NodeSettingsDrawer({ nodeId, coreId, onClose }: {
  nodeId: number; coreId: string | null; onClose: () => void;
}) {
  const t = useT();
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [error, setError] = useState("");

  const settings = useQuery({
    queryKey: ["zagros", "node-core-settings", nodeId, coreId],
    queryFn: () => api.get<{ settings: Record<string, unknown> }>(
      `/zagros/nodes/${nodeId}/cores/${encodeURIComponent(coreId ?? "")}/settings`),
    enabled: !!coreId,
  });

  const current = settings.data?.settings ?? {};
  // Values are strings here for editing; the node re-parses them against the
  // driver's schema (so "644" becomes 644 for an integer setting).
  const value = (key: string) =>
    draft[key] ?? (current[key] === null || current[key] === undefined
      ? "" : String(current[key]));

  const save = useMutation({
    mutationFn: () => {
      const patch: Record<string, unknown> = {};
      for (const [key, raw] of Object.entries(draft)) {
        const before = current[key];
        if (String(before ?? "") === raw) continue;   // only send real changes
        patch[key] = raw === "" ? null
          : typeof before === "number" ? Number(raw)
          : typeof before === "boolean" ? raw === "true" : raw;
      }
      return api.put(`/zagros/nodes/${nodeId}/cores/${encodeURIComponent(coreId ?? "")}/settings`,
        { settings: patch });
    },
    onSuccess: () => { setDraft({}); toast.ok("settings applied — restart the core to load them"); onClose(); },
    onError: (e) => setError(e instanceof ApiError ? e.message : t("common.error")),
  });

  const entries = Object.entries(current);
  const changed = Object.keys(draft).filter(
    (k) => String(current[k] ?? "") !== draft[k]).length;

  return (
    <Drawer open={!!coreId} onClose={onClose} title={`settings — ${coreId ?? ""}`}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.close")}</Button>
          <Button onClick={() => save.mutate()} loading={save.isPending} disabled={!changed}>
            save{changed ? ` (${changed})` : ""}
          </Button>
        </>
      }>
      {settings.isLoading ? <Skeleton className="h-40" /> : !entries.length ? (
        <EmptyState title="This core has no editable settings"
          hint="Its driver needs nothing beyond the installed binary." />
      ) : (
        <div className="space-y-3.5">
          <p className="rounded-xl bg-surface-2 p-3 text-[11px] leading-5 text-content-2">
            Secrets are masked by the node and cannot be read back. Every value is validated on the
            node against the driver's schema before it is written.
          </p>
          {entries.map(([key, raw]) => (
            <Field key={key} label={key}
              hint={raw === null || raw === undefined ? "unset" : undefined}>
              {typeof raw === "boolean" ? (
                <Select value={value(key)} onChange={(e) => setDraft({ ...draft, [key]: e.target.value })}>
                  <option value="true">{t("common.yes")}</option>
                  <option value="false">{t("common.no")}</option>
                </Select>
              ) : (
                <Input
                  type={typeof raw === "number" ? "number" : "text"}
                  dir="ltr" value={value(key)}
                  onChange={(e) => setDraft({ ...draft, [key]: e.target.value })}
                />
              )}
            </Field>
          ))}
          {error && <p role="alert" className="rounded-xl bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
        </div>
      )}
    </Drawer>
  );
}

function NodeLogsDrawer({ nodeId, coreId, onClose }: {
  nodeId: number; coreId: string | null; onClose: () => void;
}) {
  const [lines, setLines] = useState(200);
  const logs = useQuery({
    queryKey: ["zagros", "node-core-logs", nodeId, coreId, lines],
    queryFn: () => api.get<{ lines: string[] }>(
      `/zagros/nodes/${nodeId}/cores/${encodeURIComponent(coreId ?? "")}/logs?tail=${lines}`),
    enabled: !!coreId,
    refetchInterval: 5000,
  });
  return (
    <Drawer open={!!coreId} onClose={onClose} title={`logs — ${coreId ?? ""}`}
      footer={
        <div className="flex items-center gap-2">
          <Select value={String(lines)} onChange={(e) => setLines(Number(e.target.value))} className="w-32">
            {[100, 200, 500, 1000].map((n) => <option key={n} value={n}>{n} lines</option>)}
          </Select>
          <Button variant="secondary" size="sm" onClick={() => logs.refetch()} className="ms-auto">
            <RefreshCcw size={13} /> refresh
          </Button>
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

const stateTone = (s: string) =>
  s === "running" ? "ok" : s === "error" ? "danger" : s === "stopped" || s === "installed" ? "info" : "muted";

function MasterCores() {
  const t = useT();
  const digits = useDigits();
  const qc = useQueryClient();
  const [tab, setTab] = useState("installed");
  const [installFor, setInstallFor] = useState<CoreRegistryEntry | null>(null);
  const [logsFor, setLogsFor] = useState<string | null>(null);
  const [uninstallFor, setUninstallFor] = useState<CoreView | null>(null);
  const [reinstallFor, setReinstallFor] = useState<CoreView | null>(null);
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
  // item 17: REAL per-core user-traffic totals (usage journal + legacy xray
  // rollup) — the process/host NIC counters from backend metrics are NOT
  // user traffic and must never be presented as such.
  const traffic = useQuery({
    queryKey: ["zagros", "cores-traffic"],
    queryFn: () => api.get<{ totals: Record<string, { uplink_bytes: number; downlink_bytes: number; total_bytes: number }> }>("/zagros/cores/traffic/totals"),
    refetchInterval: 30000,
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

  const reinstall = useMutation({
    mutationFn: (id: string) => api.post(`/zagros/cores/${id}/reinstall`),
    onSuccess: (_d, id) => { toast.ok(`${id}: reinstalled (settings kept)`); setReinstallFor(null); invalidate(); },
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
        ) : !cores.data?.cores?.length ? (
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
                        {c.security_class === "legacy_insecure" && (
                          <Badge tone="danger">Legacy / Insecure</Badge>
                        )}
                        {c.builtin && (
                          <span className="rounded-md bg-brand-soft px-1.5 py-0.5 text-[10px] font-semibold text-brand" title={t("cores.builtinHint")}>
                            {t("cores.builtin")}
                          </span>
                        )}
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
                    disabled={!!c.builtin}
                    onChange={() => act.mutate({ id: c.id, action: c.enabled ? "disable" : "enable" })}
                  />
                </div>

                <div className="mt-4 grid grid-cols-2 gap-x-4 gap-y-2.5 text-[12px] sm:grid-cols-3">
                  <Meta k={t("common.status")} v={<Badge tone={stateTone(c.state) as never} dot>{c.state}{c.health ? ` · ${c.health}` : ""}</Badge>} />
                  <Meta k="version" v={<span className="tabular-nums">{c.core_version ?? "—"}</span>} />
                  <Meta k="uptime" v={formatDuration(c.uptime_seconds, digits)} />
                  <Meta k="cpu" v={<span className="tabular-nums">{(c.metrics?.cpu_percent ?? 0).toFixed(1)}%</span>} />
                  <Meta k="ram" v={formatBytes(c.metrics?.memory_bytes ?? 0, digits)} />
                  <Meta k="accounts" v={formatNumber(c.metrics?.active_accounts ?? 0, digits)} />
                  <Meta k="traffic" v={(() => {
                    const tot = traffic.data?.totals?.[c.id];
                    return tot
                      ? <span title={`user traffic: ${formatBytes(tot.uplink_bytes, digits)} ↑ + ${formatBytes(tot.downlink_bytes, digits)} ↓`}>{formatBytes(tot.total_bytes, digits)}</span>
                      : "—";
                  })()} />
                  <Meta k="binary" v={<code className="block max-w-full truncate font-mono text-[10.5px]" dir="ltr" title={c.binary_path ?? ""}>{c.binary_path ?? "—"}</code>} />
                  <Meta k="config" v={<code className="block max-w-full truncate font-mono text-[10.5px]" dir="ltr" title={String(c.settings?.config_path ?? "")}>{c.settings?.config_path ? String(c.settings.config_path) : "—"}</code>} />
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
                  {!c.builtin && (
                    <>
                      <Button size="sm" variant="ghost" onClick={() => act.mutate({ id: c.id, action: "update" })}><UploadCloud size={13} /> {t("cores.upgrade")}</Button>
                      <Button size="sm" variant="ghost" loading={false}
                        onClick={() => setReinstallFor(c)}><RefreshCcw size={13} /> {t("cores.reinstall")}</Button>
                      <div className="ms-auto">
                        <Button size="sm" variant="danger" onClick={() => { setPurge(false); setUninstallFor(c); }}><Trash2 size={13} /></Button>
                      </div>
                    </>
                  )}
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
                    {r.driver_version ? `driver ${r.driver_version}` : (r.capabilities ?? []).includes("self_install") ? "" : t("cores.catalog.osManagedHint")}
                  </span>
                  <Button size="sm" onClick={() => setInstallFor(r)} disabled={!(r.capabilities ?? []).includes("self_install")}
                    title={(r.capabilities ?? []).includes("self_install") ? undefined : t("cores.catalog.osManaged")}>
                    <HardDriveDownload size={13} /> install
                  </Button>
                </div>
              </Card>
            ))}
          </div>
        )
      )}

      {installFor && (
        <InstallDialog entry={installFor} onClose={() => setInstallFor(null)} onDone={() => { setInstallFor(null); invalidate(); }} />
      )}

      <ConfirmDialog
        open={!!reinstallFor}
        onClose={() => setReinstallFor(null)}
        onConfirm={() => reinstallFor && reinstall.mutate(reinstallFor.id)}
        title={`${t("cores.reinstall")} — ${reinstallFor?.id ?? ""}`}
        body="The binary is fetched fresh; settings, data directory and the running state are preserved server-side (secrets never leave the panel)."
        loading={reinstall.isPending}
      />

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

// -- install: SIMPLE (zero-developer-fields) by default; ADVANCED keeps the
// schema-driven form for operators who really need executable paths etc.

type SchemaProps = Record<string, { type?: string; title?: string; description?: string; default?: unknown; enum?: unknown[] }>;

function InstallDialog({ entry, onClose, onDone }: { entry: CoreRegistryEntry; onClose: () => void; onDone: () => void }) {
  const t = useT();
  const schema = entry.config_schema as { properties?: SchemaProps; required?: string[] } | null | undefined;
  const props = schema?.properties ?? {};
  const required = new Set(schema?.required ?? []);
  const [mode, setMode] = useState<"simple" | "advanced">("simple");
  const [version, setVersion] = useState(""); // "" = latest
  const [customVersion, setCustomVersion] = useState("");
  const [values, setValues] = useState<Record<string, string>>({});
  const legacyInsecure = entry.security_class === "legacy_insecure";
  const [legacyRiskAck, setLegacyRiskAck] = useState(false);
  const [internetExposureAck, setInternetExposureAck] = useState(false);
  const [startNow, setStartNow] = useState(!legacyInsecure);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // Release list, straight from the driver's own repo (release_repo) —
  // empty/404 for OS-managed cores: then the picker honestly degrades.
  const versions = useQuery({
    queryKey: ["zagros", "core-versions", entry.id],
    queryFn: () => api.get<{ releases: CoreRelease[] }>(`/zagros/cores/${entry.id}/versions`),
    retry: false, staleTime: 600000,
  });
  const progress = useQuery({
    queryKey: ["zagros", "core-install-progress", entry.id],
    queryFn: () => api.get<{ stage: string; detail?: string }>(`/zagros/cores/${entry.id}/install-progress`),
    enabled: busy,
    refetchInterval: busy ? 750 : false,
    retry: false,
  });

  const install = async () => {
    setBusy(true); setError("");
    const settings: Record<string, unknown> = {};
    if (mode === "advanced") {
      for (const [k, v] of Object.entries(values)) {
        if (v === "") continue;
        const type = props[k]?.type;
        settings[k] = type === "integer" || type === "number" ? Number(v)
          : type === "boolean" ? v === "true" : v;
      }
    }
    if (legacyInsecure) {
      settings.legacy_risk_ack = legacyRiskAck;
      settings.internet_exposure_ack = internetExposureAck;
    }
    const chosen = customVersion.trim() || version;
    if (chosen) settings.release_version = chosen.replace(/^v/, "");
    try {
      const installed = await api.post<{ enabled?: boolean }>(`/zagros/cores/${entry.id}/install`, { settings, enabled: !legacyInsecure });
      toast.ok(`${entry.id} installed${installed.enabled === false ? " (disabled)" : ""}`);
      if (startNow && !legacyInsecure) {
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
          <Button onClick={install} loading={busy}
            disabled={legacyInsecure && (!legacyRiskAck || !internetExposureAck)}>
            <HardDriveDownload size={14} /> install</Button>
        </>}
    >
      <Tabs
        active={mode}
        onChange={(m) => setMode(m as "simple" | "advanced")}
        tabs={[
          { id: "simple", label: t("cores.install.simple") },
          { id: "advanced", label: t("cores.install.advanced") },
        ]}
      />

      <div className="mt-4 space-y-3.5">
        {legacyInsecure && (
          <div className="space-y-3 rounded-xl border border-danger/40 bg-danger-soft p-3 text-xs text-danger">
            <p className="font-semibold">Legacy / Insecure</p>
            <p>PPTP uses MS-CHAPv2 and MPPE128, which have known cryptographic weaknesses. Use it only for legacy clients with no modern VPN option.</p>
            <label className="flex items-start gap-2">
              <input type="checkbox" checked={legacyRiskAck} onChange={(e) => setLegacyRiskAck(e.target.checked)} />
              <span>I accept the Legacy / Insecure risk.</span>
            </label>
            <label className="flex items-start gap-2">
              <input type="checkbox" checked={internetExposureAck} onChange={(e) => setInternetExposureAck(e.target.checked)} />
              <span>I explicitly allow Internet exposure on TCP/1723 and GRE/47.</span>
            </label>
            <p>The provider will be installed disabled and will not start automatically.</p>
          </div>
        )}
        {mode === "simple" && (
          <>
            <p className="rounded-xl bg-surface-2 p-3 text-[12px] leading-5 text-content-2">
              {t("cores.install.autoNote")}
            </p>
            <Field label={t("cores.install.version")}>
              {versions.isLoading ? (
                <Skeleton className="h-9" />
              ) : (
                <>
                  <Select value={version} onChange={(e) => setVersion(e.target.value)} disabled={!versions.data?.releases?.length}>
                    <option value="">{t("cores.install.latest")}</option>
                    {(versions.data?.releases ?? []).map((r) => (
                      <option key={r.tag} value={r.tag}>
                        {r.tag}{r.prerelease ? " (pre)" : ""}
                      </option>
                    ))}
                  </Select>
                  {(!versions.data?.releases?.length) && (
                    <p className="mt-1 text-[11px] text-content-3">
                      version list unavailable for this core/host — the latest build will be installed
                    </p>
                  )}
                </>
              )}
            </Field>
            <Field label="custom tag (optional)" hint="e.g. 1.8.23 — overrides the picker">
              <Input value={customVersion} onChange={(e) => setCustomVersion(e.target.value)} dir="ltr" placeholder="leave empty" />
            </Field>
          </>
        )}

        {mode === "advanced" && (
          <>
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
          </>
        )}

        {!legacyInsecure && (
          <label className="flex items-center gap-2.5 pt-1 text-sm text-content-2">
            <Switch checked={startNow} onChange={setStartNow} label={t("cores.install.startAfter")} />
            {t("cores.install.startAfter")}
          </label>
        )}
        {busy && (
          <div role="status" aria-live="polite" data-install-stage={progress.data?.stage ?? "starting"}
            className="rounded-xl border border-brand/30 bg-brand-soft/30 px-3 py-2.5 text-xs text-content-2">
            <p className="flex items-center gap-2 font-medium text-brand">
              <Loader2 size={13} className="animate-spin" />
              {progress.data?.stage?.replace(/_/g, " ") ?? "starting installation"}
            </p>
            {progress.data?.detail && <p className="mt-1 text-[11px] text-content-3">{progress.data.detail}</p>}
          </div>
        )}
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
