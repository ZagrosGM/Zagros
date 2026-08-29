// Native Zagros Node Management.
//
// A node is a separate Docker-deployed agent that can host EVERY core the
// panel supports (xray, sing-box, OpenVPN, WireGuard, SSH, SoftEther, PPTP).
// The flow implemented here:
//
//   add node (name / address / port / api port)
//     → Generate installer command  (panel issues a one-time token)
//     → run it on the node server
//     → discover                    (node publishes its certificate)
//     → confirm fingerprint         (trust on first use, like an SSH host key)
//     → paired: manage its cores from the Cores page.
//
// "set manual" is the same pairing step without discovery, for operators who
// copy the fingerprint straight from the node's console.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity, ClipboardCopy, HardDrive, KeyRound, Plus, RefreshCcw, Server,
  Terminal, Trash2, Wifi,
} from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "../components/feedback";
import { ConfirmDialog, Dialog } from "../components/overlays";
import {
  Badge, Button, Card, EmptyState, ErrorState, Field, Input, Skeleton,
  StatusDot, Switch, cn,
} from "../components/ui";
import { api, ApiError } from "../lib/api";
import { copyText } from "../lib/clipboard";
import { useDigits, formatBytes } from "../lib/format";
import { useT } from "../lib/i18n";
import type {
  InstallerCommand, Node, NodeDiscovery, NodeList, SyncResult,
} from "../lib/types";

const statusTone = (status: string) =>
  status === "connected" ? "ok" : status === "error" ? "danger" : "warn";

const stateTone = (s: string) =>
  s === "running" ? "ok" : s === "error" ? "danger" : s === "stopped" || s === "installed" ? "info" : "muted";

/** The command an operator pastes into the node server. */
function CommandBlock({ value }: { value: string }) {
  return (
    <div className="rounded-xl border border-border bg-surface p-3">
      <pre className="whitespace-pre-wrap break-all font-mono text-[11px] leading-5 text-content-2" dir="ltr">
        {value}
      </pre>
    </div>
  );
}

export default function Nodes() {
  const t = useT();
  const digits = useDigits();
  const qc = useQueryClient();
  const [addOpen, setAddOpen] = useState(false);
  const [installerFor, setInstallerFor] = useState<
    { node: Node; installer: InstallerCommand } | number | null
  >(null);
  const [pairFor, setPairFor] = useState<Node | null>(null);
  const [deleteFor, setDeleteFor] = useState<Node | null>(null);

  const invalidate = () => qc.invalidateQueries({ queryKey: ["zagros", "nodes"] });

  const list = useQuery({
    queryKey: ["zagros", "nodes"],
    queryFn: () => api.get<NodeList>("/zagros/nodes"),
    refetchInterval: 15000,
  });

  const heartbeat = useMutation({
    mutationFn: (id: number) => api.post(`/zagros/nodes/${id}/heartbeat`),
    onSuccess: () => { toast.ok("signed heartbeat verified"); invalidate(); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const sync = useMutation({
    mutationFn: (id: number) => api.post<SyncResult>(`/zagros/nodes/${id}/sync`),
    onSuccess: (data) => {
      const pushed = data.pushed?.length ?? 0;
      const hosts = data.hosts?.length ?? 0;
      toast.ok(`synced ${pushed} core(s), ${hosts} host entr(y/ies)`);
      if (data.errors?.length) toast.error(data.errors.join(" · "));
      invalidate();
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const remove = useMutation({
    mutationFn: ({ id, force }: { id: number; force: boolean }) =>
      api.delete(`/zagros/nodes/${id}${force ? "?force=true" : ""}`),
    onSuccess: () => { setDeleteFor(null); toast.ok("node revoked and removed"); invalidate(); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const nodes = list.data?.nodes ?? [];

  return (
    <div className="space-y-4 animate-fade-up">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <HardDrive size={18} className="text-brand" />{t("nav.nodes")}
        </h1>
        <Button variant="ghost" size="sm" onClick={() => list.refetch()}>
          <RefreshCcw size={13} />
        </Button>
        <Button size="sm" onClick={() => setAddOpen(true)}><Plus size={13} /> add node</Button>
      </div>

      <p className="rounded-xl border border-brand/30 bg-brand-soft px-3 py-2 text-[11px] leading-5 text-content-2">
        Nodes use certificate-pinned HTTPS, a one-time registration token and HMAC-signed commands
        with replay protection. No Docker socket or shell endpoint is exposed. Core management for a
        paired node lives on the <Link to="/cores" className="text-brand underline">Cores</Link> page.
      </p>

      {list.isError && (
        <Card><ErrorState message={(list.error as Error).message} onRetry={invalidate} /></Card>
      )}

      {list.isLoading ? <Skeleton className="h-40" /> : !nodes.length ? (
        <Card>
          <EmptyState
            title="No nodes yet"
            hint="Add a node, generate its installer command, run it on the remote server and confirm the certificate fingerprint."
            action={<Button size="sm" onClick={() => setAddOpen(true)}><Plus size={13} /> add node</Button>}
          />
        </Card>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          {nodes.map((node) => {
            const resources = node.health?.resources ?? {};
            const installed = Object.values(node.cores?.installed ?? {});
            const pending = node.status !== "connected";
            return (
              <Card key={node.id} className={cn(pending && "border-warn/40")}>
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <StatusDot tone={statusTone(node.status) as never} pulse={node.status === "connected"} />
                      <h3 className="truncate text-sm font-semibold">{node.name}</h3>
                      <Badge tone="brand">Zagros Node</Badge>
                    </div>
                    <p className="mt-1 font-mono text-[11px] text-content-3" dir="ltr">
                      {node.address}:{node.port}
                      <span className="text-content-3/70"> · info {node.api_port}</span>
                      {node.agent_version ? ` · agent ${node.agent_version}` : ""}
                    </p>
                  </div>
                  <Badge tone={statusTone(node.status) as never} dot>{node.status}</Badge>
                </div>

                <div className="mt-3 grid grid-cols-3 gap-2 text-[11px] text-content-3">
                  <span>cores <b className="text-content">{installed.length}</b></span>
                  <span>memory <b className="text-content">
                    {typeof resources.memory_used === "number" ? formatBytes(resources.memory_used, digits) : "—"}
                  </b></span>
                  <span>CPU <b className="text-content">
                    {typeof resources.cpu_percent === "number" ? `${resources.cpu_percent.toFixed(0)}%` : "—"}
                  </b></span>
                </div>

                {installed.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {installed.map((core) => (
                      <Badge key={core.core_id}
                        tone={stateTone(core.state ?? "") as never}>
                        {core.core_id} · {core.state}
                        {core.core_version ? ` · ${core.core_version}` : ""}
                      </Badge>
                    ))}
                  </div>
                )}

                {node.last_error && (
                  <p className="mt-2 rounded-lg bg-warn-soft px-2.5 py-1.5 text-[11px] text-warn">
                    {node.last_error}
                  </p>
                )}
                {pending && !node.last_error && (
                  <p className="mt-2 rounded-lg bg-brand-soft px-2.5 py-1.5 text-[11px] text-content-2">
                    Not paired yet — run the installer command on the node, then confirm its fingerprint.
                  </p>
                )}

                <div className="mt-3 flex flex-wrap items-center gap-1.5 border-t border-border pt-3">
                  {pending ? (
                    <>
                      <Button variant="secondary" size="sm" onClick={() => setInstallerFor(node.id)}>
                        <Terminal size={13} /> installer command
                      </Button>
                      <Button size="sm" onClick={() => setPairFor(node)}>
                        <KeyRound size={13} /> set manual
                      </Button>
                    </>
                  ) : (
                    <>
                      <Button variant="ghost" size="sm" onClick={() => heartbeat.mutate(node.id)}
                        loading={heartbeat.isPending}>
                        <Activity size={13} /> verify
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => sync.mutate(node.id)}
                        loading={sync.isPending}>
                        <Wifi size={13} /> sync config
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => setInstallerFor(node.id)}>
                        <Terminal size={13} /> installer
                      </Button>
                    </>
                  )}
                  <Link to={`/cores?node=${node.id}`}
                    className="inline-flex h-8 select-none items-center gap-1.5 rounded-xl px-3 text-xs font-medium text-content-2 transition-colors hover:bg-surface-3 hover:text-content">
                    <Server size={13} /> cores
                  </Link>
                  <Button variant="ghost" size="icon" className="ms-auto" aria-label="delete node"
                    onClick={() => setDeleteFor(node)}><Trash2 size={14} /></Button>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {addOpen && (
        <AddNodeDialog
          onClose={() => setAddOpen(false)}
          onCreated={(node, installer) => { setAddOpen(false); setInstallerFor({ node, installer }); invalidate(); }}
        />
      )}
      {installerFor !== null && (
        <InstallerDialog
          preset={typeof installerFor === "number" ? null : installerFor}
          nodeId={typeof installerFor === "number" ? installerFor : installerFor.node.id}
          onClose={() => { setInstallerFor(null); invalidate(); }}
          onPair={(node) => { setInstallerFor(null); setPairFor(node); }}
        />
      )}
      {pairFor && (
        <PairDialog node={pairFor} onClose={() => { setPairFor(null); invalidate(); }} />
      )}
      <ConfirmDialog
        open={Boolean(deleteFor)} onClose={() => setDeleteFor(null)}
        onConfirm={() => deleteFor && remove.mutate({ id: deleteFor.id, force: false })}
        danger loading={remove.isPending}
        title={`revoke and delete — ${deleteFor?.name ?? ""}`}
        body="The panel first sends a signed revoke to the agent. If the node is offline, deletion fails closed — use force only after isolating the node."
      />
    </div>
  );
}

// --------------------------------------------------------------------------- //
function AddNodeDialog({ onClose, onCreated }: {
  onClose: () => void;
  onCreated: (node: Node, installer: InstallerCommand) => void;
}) {
  const t = useT();
  const [form, setForm] = useState({
    name: "", address: "", port: 62050, api_port: 62051,
    usage_coefficient: 1, add_as_new_host: true,
  });
  const [error, setError] = useState("");

  const create = useMutation({
    mutationFn: () => api.post<{ node: Node; installer: InstallerCommand }>("/zagros/nodes", form),
    onSuccess: (data) => onCreated(data.node, data.installer),
    onError: (e) => setError(e instanceof ApiError ? e.message : t("common.error")),
  });

  const valid = Boolean(form.name.trim() && form.address.trim()
    && form.port !== form.api_port);

  return (
    <Dialog open onClose={onClose} title="add Zagros node"
      subtitle="The panel issues a one-time token and builds the installer command."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button onClick={() => create.mutate()} loading={create.isPending} disabled={!valid}>
            <Plus size={14} /> create node
          </Button>
        </>
      }>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="name" required>
          <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </Field>
        <Field label="address" required hint="IP or DNS name the panel reaches the node on">
          <Input dir="ltr" value={form.address} onChange={(e) => setForm({ ...form, address: e.target.value })}
            placeholder="203.0.113.10" />
        </Field>
        <Field label="control-plane port" hint="HTTPS, signed commands">
          <Input type="number" min={1} max={65535} value={form.port}
            onChange={(e) => setForm({ ...form, port: Number(e.target.value) })} />
        </Field>
        <Field label="api port" hint="read-only bootstrap/info endpoint">
          <Input type="number" min={1} max={65535} value={form.api_port}
            onChange={(e) => setForm({ ...form, api_port: Number(e.target.value) })} />
        </Field>
        <Field label="usage coefficient">
          <Input type="number" min="0.1" step="0.1" value={form.usage_coefficient}
            onChange={(e) => setForm({ ...form, usage_coefficient: Number(e.target.value) })} />
        </Field>
        <Field label="add as host" hint="bind the node address as a Host on sync, so configs can target it">
          <Switch checked={form.add_as_new_host} label="add as new host"
            onChange={(v) => setForm({ ...form, add_as_new_host: v })} />
        </Field>
      </div>
      {form.port === form.api_port && (
        <p className="mt-3 text-[11px] text-danger">control-plane port and api port must differ.</p>
      )}
      {error && <p role="alert" className="mt-3 rounded-xl bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}

// --------------------------------------------------------------------------- //
function InstallerDialog({ nodeId, preset, onClose, onPair }: {
  nodeId: number;
  preset: { node: Node; installer: InstallerCommand } | null;
  onClose: () => void;
  onPair: (node: Node) => void;
}) {
  const t = useT();
  const [rotated, setRotated] = useState(false);

  const command = useQuery({
    queryKey: ["zagros", "node-installer", nodeId, rotated],
    queryFn: () => api.get<InstallerCommand>(`/zagros/nodes/${nodeId}/installer-command`),
    enabled: !preset,
    staleTime: 0,
  });
  const node = useQuery({
    queryKey: ["zagros", "nodes"],
    queryFn: () => api.get<NodeList>("/zagros/nodes"),
    select: (data) => data.nodes.find((n) => n.id === nodeId) ?? null,
  });

  const rotate = useMutation({
    mutationFn: () => api.get<InstallerCommand>(
      `/zagros/nodes/${nodeId}/installer-command?rotate=true`),
    onSuccess: () => { setRotated((v) => !v); toast.ok("a new one-time token was issued"); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const installer = preset?.installer ?? command.data;
  const current = preset?.node ?? node.data;

  return (
    <Dialog open wide onClose={onClose} title="installer command"
      subtitle="Run this once, as root, on the node server."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.close")}</Button>
          {current && (
            <Button onClick={() => onPair(current)}><KeyRound size={14} /> set manual</Button>
          )}
        </>
      }>
      {!installer ? <Skeleton className="h-32" /> : (
        <div className="space-y-3">
          <CommandBlock value={installer.command} />
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="secondary" onClick={async () => {
              await copyText(installer.command); toast.ok("command copied");
            }}>
              <ClipboardCopy size={13} /> copy
            </Button>
            {!preset && current?.status !== "connected" && (
              <Button size="sm" variant="ghost" onClick={() => rotate.mutate()} loading={rotate.isPending}>
                <RefreshCcw size={13} /> rotate token
              </Button>
            )}
          </div>
          {installer.registration_token && (
            <div className="rounded-xl border border-warn/40 bg-warn-soft p-3">
              <p className="text-[11px] font-semibold text-warn">one-time registration token</p>
              <code className="mt-1 block break-all font-mono text-[11px]" dir="ltr">
                {installer.registration_token}
              </code>
              <p className="mt-1.5 text-[11px] text-content-2">
                Shown once. The panel keeps it sealed only until pairing completes.
              </p>
            </div>
          )}
          <ul className="space-y-1 text-[11px] text-content-3">
            {installer.notes.map((note) => <li key={note}>• {note}</li>)}
          </ul>
        </div>
      )}
    </Dialog>
  );
}

// --------------------------------------------------------------------------- //
function PairDialog({ node, onClose }: { node: Node; onClose: () => void }) {
  const t = useT();
  const [fingerprint, setFingerprint] = useState("");
  const [token, setToken] = useState("");
  const [nodeIdHint, setNodeIdHint] = useState("");
  const [error, setError] = useState("");

  const discover = useMutation({
    mutationFn: () => api.post<NodeDiscovery>(`/zagros/nodes/${node.id}/discover`),
    onSuccess: (data) => {
      if (!data.reachable) { setError(data.error ?? "node is unreachable"); return; }
      setFingerprint(data.certificate_sha256 ?? "");
      setNodeIdHint(data.node_id ?? "");
      toast.ok(`found node ${data.node_id?.slice(0, 12)}… (agent ${data.agent_version})`);
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : t("common.error")),
  });

  const pair = useMutation({
    mutationFn: () => api.post(`/zagros/nodes/${node.id}/pair`, {
      certificate_fingerprint: fingerprint.replace(/:/g, "").trim(),
      registration_token: token.trim() || null,
      node_id: nodeIdHint.trim() || null,
    }),
    onSuccess: () => { toast.ok("node paired"); onClose(); },
    onError: (e) => setError(e instanceof ApiError ? e.message : t("common.error")),
  });

  const normalized = fingerprint.replace(/:/g, "").trim();

  return (
    <Dialog open wide onClose={onClose} title={`pair — ${node.name}`}
      subtitle="Confirm the certificate the node actually serves. This is the trust-on-first-use step, the same as accepting an SSH host key."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button onClick={() => pair.mutate()} loading={pair.isPending}
            disabled={normalized.length !== 64}>
            <KeyRound size={14} /> pair node
          </Button>
        </>
      }>
      <div className="space-y-3.5">
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="secondary" onClick={() => discover.mutate()} loading={discover.isPending}>
            <Wifi size={13} /> discover ({node.address}:{node.api_port})
          </Button>
          <span className="text-[11px] text-content-3">
            or paste the values the installer printed on the node
          </span>
        </div>
        <Field label="TLS SHA-256 fingerprint" required
          hint="64 hex characters — printed by the installer as “SHA-256 pin”">
          <Input dir="ltr" value={fingerprint} onChange={(e) => setFingerprint(e.target.value)}
            placeholder="9e338246aa505395…" className="font-mono" />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="node id" hint="optional — reject if the node answers with another id">
            <Input dir="ltr" value={nodeIdHint} onChange={(e) => setNodeIdHint(e.target.value)} className="font-mono" />
          </Field>
          <Field label="registration token" hint="optional — only if the node was installed with its own token">
            <Input type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} />
          </Field>
        </div>
        {error && <p role="alert" className="rounded-xl bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
      </div>
    </Dialog>
  );
}
