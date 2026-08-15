// Native Zagros Node Management. The legacy Marzban Xray-only node transport
// remains server-side for migration, but this page uses the authenticated,
// signed, multi-core Zagros agent API exclusively.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, HardDrive, Plus, RefreshCcw, ScrollText, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "../components/feedback";
import { ConfirmDialog, Dialog } from "../components/overlays";
import { Badge, Button, Card, EmptyState, Field, Input, Select, Skeleton, StatusDot } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { formatBytes, useDigits } from "../lib/format";
import { useT } from "../lib/i18n";

interface AgentCoreStatus {
  core_id: string; state: string; health: string;
  core_version?: string | null; version_reason?: string | null;
  message?: string | null;
}
interface AgentCoreInventory {
  installed: Record<string, AgentCoreStatus>;
  available: string[];
}
interface NativeNode {
  id: number; name: string; address: string; port: number; status: string;
  usage_coefficient: number; agent_type: "zagros_native";
  agent_identity: string; certificate_fingerprint: string;
  last_seen?: string | null;
  health?: { healthy?: boolean; resources?: Record<string, number | number[] | null> } | null;
  cores?: AgentCoreInventory | null;
}
interface NativeNodes { nodes: NativeNode[] }

const statusTone = (status: string) => status === "connected" ? "ok" : status === "error" ? "danger" : "warn";

export default function Nodes() {
  const t = useT();
  const digits = useDigits();
  const qc = useQueryClient();
  const [registerOpen, setRegisterOpen] = useState(false);
  const [deleteFor, setDeleteFor] = useState<NativeNode | null>(null);
  const [coreFor, setCoreFor] = useState<NativeNode | null>(null);

  const list = useQuery({
    queryKey: ["zagros", "native-nodes"],
    queryFn: () => api.get<NativeNodes>("/zagros/nodes"),
    refetchInterval: 15000,
  });
  const heartbeat = useMutation({
    mutationFn: (id: number) => api.post(`/zagros/nodes/${id}/heartbeat`),
    onSuccess: () => { toast.ok("signed heartbeat verified"); qc.invalidateQueries({ queryKey: ["zagros", "native-nodes"] }); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });
  const remove = useMutation({
    mutationFn: (id: number) => api.delete(`/zagros/nodes/${id}`),
    onSuccess: () => { setDeleteFor(null); toast.ok("node authority revoked and removed"); qc.invalidateQueries({ queryKey: ["zagros", "native-nodes"] }); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  return (
    <div className="space-y-4 animate-fade-up">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <HardDrive size={18} className="text-brand" />{t("nav.nodes")}
        </h1>
        <Button variant="ghost" size="sm" onClick={() => list.refetch()}><RefreshCcw size={13} /></Button>
        <Button size="sm" onClick={() => setRegisterOpen(true)}><Plus size={13} /> register Zagros Node</Button>
      </div>
      <p className="rounded-xl border border-brand/30 bg-brand-soft px-3 py-2 text-[11px] text-content-2">
        Native nodes use certificate-pinned HTTPS, one-time registration and HMAC-signed commands with replay protection. No Docker socket or arbitrary shell endpoint is exposed. Legacy Marzban nodes are Xray-only and are not presented as multi-core nodes here.
      </p>

      {list.isLoading ? <Skeleton className="h-40" /> : !(list.data?.nodes.length) ? (
        <Card><EmptyState title="No native Zagros nodes"
          hint="Install zagros-node on the remote host, then register its one-time token and TLS SHA-256 fingerprint."
          action={<Button size="sm" onClick={() => setRegisterOpen(true)}><Plus size={13} /> register node</Button>} /></Card>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          {list.data.nodes.map((node) => {
            const resources = node.health?.resources ?? {};
            const installed = Object.values(node.cores?.installed ?? {});
            return <Card key={node.id}>
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <StatusDot tone={statusTone(node.status) as never} pulse={node.status === "connected"} />
                    <h3 className="truncate text-sm font-semibold">{node.name}</h3>
                    <Badge tone="brand">Zagros Node</Badge>
                  </div>
                  <p className="mt-1 font-mono text-[11px] text-content-3" dir="ltr">{node.address}:{node.port} · {node.agent_identity.slice(0, 12)}…</p>
                </div>
                <Badge tone={statusTone(node.status) as never} dot>{node.status}</Badge>
              </div>
              <div className="mt-3 grid grid-cols-3 gap-2 text-[11px] text-content-3">
                <span>cores <b className="text-content">{installed.length}</b></span>
                <span>memory <b className="text-content">{typeof resources.memory_used === "number" ? formatBytes(resources.memory_used, digits) : "—"}</b></span>
                <span>CPU <b className="text-content">{typeof resources.cpu_percent === "number" ? `${resources.cpu_percent.toFixed(0)}%` : "—"}</b></span>
              </div>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {installed.map((core) => <Badge key={core.core_id} tone={core.state === "running" ? "ok" : core.state === "error" ? "danger" : "muted"}>
                  {core.core_id} · {core.state} · {core.core_version ?? "unknown"}
                </Badge>)}
              </div>
              <div className="mt-3 flex items-center gap-1 border-t border-border pt-3">
                <Button variant="ghost" size="sm" onClick={() => heartbeat.mutate(node.id)} loading={heartbeat.isPending}><Activity size={13} /> verify health</Button>
                <Button variant="ghost" size="sm" onClick={() => setCoreFor(node)}><HardDrive size={13} /> core lifecycle</Button>
                <Button variant="ghost" size="icon" className="ms-auto" aria-label="delete node" onClick={() => setDeleteFor(node)}><Trash2 size={14} /></Button>
              </div>
            </Card>;
          })}
        </div>
      )}

      {registerOpen && <RegisterNodeDialog onClose={() => setRegisterOpen(false)} />}
      {coreFor && <NodeCoreDialog node={coreFor} onClose={() => setCoreFor(null)} />}
      <ConfirmDialog open={Boolean(deleteFor)} onClose={() => setDeleteFor(null)}
        onConfirm={() => deleteFor && remove.mutate(deleteFor.id)} danger loading={remove.isPending}
        title={`revoke and delete — ${deleteFor?.name ?? ""}`}
        body="The panel first sends a signed revoke to the agent. If the node is offline, deletion fails closed so an orphan authority is not silently left behind." />
    </div>
  );
}

function RegisterNodeDialog({ onClose }: { onClose: () => void }) {
  const t = useT();
  const qc = useQueryClient();
  const [form, setForm] = useState({ name: "", address: "", port: 62050, registration_token: "", certificate_fingerprint: "", usage_coefficient: 1 });
  const [error, setError] = useState("");
  const register = useMutation({
    mutationFn: () => api.post("/zagros/nodes/register", form),
    onSuccess: () => { toast.ok("node registered; bootstrap token consumed"); qc.invalidateQueries({ queryKey: ["zagros", "native-nodes"] }); onClose(); },
    onError: (e) => setError(e instanceof ApiError ? e.message : t("common.error")),
  });
  return <Dialog open onClose={onClose} title="register native Zagros Node"
    subtitle="The remote agent must already be running with TLS. Registration consumes its one-time token."
    footer={<><Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button><Button onClick={() => register.mutate()} loading={register.isPending} disabled={!form.name || !form.address || form.registration_token.length < 16 || form.certificate_fingerprint.replace(/:/g, "").length !== 64}>{t("common.save")}</Button></>}>
    <div className="grid gap-4 sm:grid-cols-2">
      <Field label="name" required><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
      <Field label="address" required hint="DNS name/IP covered by the node certificate"><Input dir="ltr" value={form.address} onChange={(e) => setForm({ ...form, address: e.target.value })} /></Field>
      <Field label="HTTPS port"><Input type="number" min={1} max={65535} value={form.port} onChange={(e) => setForm({ ...form, port: Number(e.target.value) })} /></Field>
      <Field label="usage coefficient"><Input type="number" min="0.1" step="0.1" value={form.usage_coefficient} onChange={(e) => setForm({ ...form, usage_coefficient: Number(e.target.value) })} /></Field>
      <Field label="one-time registration token" required><Input type="password" autoComplete="off" value={form.registration_token} onChange={(e) => setForm({ ...form, registration_token: e.target.value })} /></Field>
      <Field label="TLS SHA-256 fingerprint" required><Input dir="ltr" value={form.certificate_fingerprint} onChange={(e) => setForm({ ...form, certificate_fingerprint: e.target.value })} /></Field>
    </div>
    {error && <p role="alert" className="mt-3 rounded-xl bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
  </Dialog>;
}

function NodeCoreDialog({ node, onClose }: { node: NativeNode; onClose: () => void }) {
  const t = useT();
  const qc = useQueryClient();
  const installed = node.cores?.installed ?? {};
  const choices = useMemo(() => Array.from(new Set([...Object.keys(installed), ...(node.cores?.available ?? [])])).sort(), [installed, node.cores?.available]);
  const [coreId, setCoreId] = useState(choices[0] ?? "");
  const [action, setAction] = useState("start");
  const [logs, setLogs] = useState<string[]>([]);
  const [error, setError] = useState("");
  const lifecycle = useMutation({
    mutationFn: () => api.post(`/zagros/nodes/${node.id}/cores/${encodeURIComponent(coreId)}/lifecycle`, { action, settings: {}, purge: false, force: false }),
    onSuccess: async () => { toast.ok(`${action} completed on ${node.name}`); await api.post(`/zagros/nodes/${node.id}/heartbeat`); qc.invalidateQueries({ queryKey: ["zagros", "native-nodes"] }); },
    onError: (e) => setError(e instanceof ApiError ? e.message : t("common.error")),
  });
  const loadLogs = async () => {
    try {
      const result = await api.get<{ lines: string[] }>(`/zagros/nodes/${node.id}/cores/${encodeURIComponent(coreId)}/logs?tail=200`);
      setLogs(result.lines);
    } catch (e) { setError(e instanceof ApiError ? e.message : t("common.error")); }
  };
  return <Dialog open onClose={onClose} wide title={`core lifecycle — ${node.name}`}
    footer={<><Button variant="ghost" onClick={onClose}>{t("common.close")}</Button><Button onClick={() => lifecycle.mutate()} loading={lifecycle.isPending} disabled={!coreId}>{action}</Button></>}>
    <div className="grid gap-4 sm:grid-cols-2">
      <Field label="core"><Select value={coreId} onChange={(e) => setCoreId(e.target.value)}>{choices.map((id) => <option key={id} value={id}>{id}</option>)}</Select></Field>
      <Field label="allowlisted action"><Select value={action} onChange={(e) => setAction(e.target.value)}>{["install", "start", "stop", "restart", "uninstall"].map((value) => <option key={value}>{value}</option>)}</Select></Field>
    </div>
    <Button className="mt-3" variant="secondary" size="sm" onClick={loadLogs}><ScrollText size={13} /> load signed log tail</Button>
    {logs.length > 0 && <pre className="mt-3 max-h-72 overflow-auto rounded-xl bg-surface p-3 text-[10px]" dir="ltr">{logs.join("\n")}</pre>}
    {error && <p role="alert" className="mt-3 rounded-xl bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
  </Dialog>;
}
