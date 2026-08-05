// Nodes — legacy node inventory: status, version, usage share, reconnect,
// add/edit/remove. (Legacy API is the real backend for nodes.)
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { HardDrive, Pencil, Plus, RefreshCcw, RotateCw, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "../components/feedback";
import { ConfirmDialog, Dialog } from "../components/overlays";
import { Badge, Button, Card, CardHeader, EmptyState, Field, Input, Skeleton, StatusDot } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useDigits, formatBytes } from "../lib/format";
import { useT } from "../lib/i18n";
import type { Node, NodesUsage } from "../lib/types";

const statusTone = (s: string) => s === "connected" ? "ok" : s === "disabled" ? "muted" : s === "connecting" ? "warn" : "danger";

export default function Nodes() {
  const t = useT();
  const digits = useDigits();
  const qc = useQueryClient();
  const [dialog, setDialog] = useState<{ node?: Node } | null>(null);
  const [deleteFor, setDeleteFor] = useState<Node | null>(null);

  const list = useQuery({ queryKey: ["nodes"], queryFn: () => api.get<Node[]>("/nodes"), refetchInterval: 10000 });
  const usage = useQuery({ queryKey: ["nodes", "usage"], queryFn: () => api.get<NodesUsage>("/nodes/usage"), refetchInterval: 15000, retry: false });

  const reconnect = useMutation({
    mutationFn: (id: number) => api.post(`/node/${id}/reconnect`),
    onSuccess: () => { toast.ok("reconnect requested"); qc.invalidateQueries({ queryKey: ["nodes"] }); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });
  const del = useMutation({
    mutationFn: (id: number) => api.delete(`/node/${id}`),
    onSuccess: () => { toast.ok(t("common.deleted")); setDeleteFor(null); qc.invalidateQueries({ queryKey: ["nodes"] }); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const usageOf = (id: number) => usage.data?.usages.find((u) => u.node_id === id);

  return (
    <div className="space-y-4 animate-fade-up">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <HardDrive size={18} className="text-brand" />{t("nav.nodes")}
        </h1>
        <Button variant="ghost" size="sm" onClick={() => list.refetch()}><RefreshCcw size={13} /></Button>
        <Button size="sm" onClick={() => setDialog({})}><Plus size={13} /> add node</Button>
      </div>

      {list.isLoading ? (
        <div className="grid gap-3 md:grid-cols-2">{[1, 2].map((i) => <Skeleton key={i} className="h-40" />)}</div>
      ) : !list.data?.length ? (
        <Card>
          <EmptyState title="Master-only deployment"
            hint="Add remote nodes to distribute traffic — each node connects back to this panel for its config."
            action={<Button size="sm" onClick={() => setDialog({})}><Plus size={13} /> add node</Button>} />
        </Card>
      ) : (
        <div className="grid gap-3 md:grid-cols-2">
          {list.data.map((n) => {
            const u = usageOf(n.id);
            return (
              <Card key={n.id}>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex min-w-0 items-center gap-2.5">
                    <StatusDot tone={statusTone(n.status) as never} pulse={n.status === "connected"} />
                    <div className="min-w-0">
                      <h3 className="truncate text-sm font-semibold">{n.name}</h3>
                      <p className="font-mono text-[11px] text-content-3" dir="ltr">{n.address}:{n.port} · api:{n.api_port}</p>
                    </div>
                  </div>
                  <Badge tone={statusTone(n.status) as never} dot>{n.status}</Badge>
                </div>
                {n.message && <p className="mt-2 rounded-lg bg-danger-soft px-2.5 py-1.5 text-[11px] text-danger">{n.message}</p>}
                <div className="mt-3 grid grid-cols-3 gap-2 text-[11px] text-content-3">
                  <span>xray <b className="text-content">{n.xray_version ?? "—"}</b></span>
                  <span>coefficient <b className="text-content tabular-nums">×{n.usage_coefficient}</b></span>
                  <span>usage <b className="text-content tabular-nums">{u ? formatBytes(u.uplink + u.downlink, digits) : "—"}</b></span>
                </div>
                <div className="mt-3 flex items-center gap-1.5 border-t border-border pt-3">
                  <Button variant="ghost" size="sm" onClick={() => reconnect.mutate(n.id)}><RotateCw size={13} /> reconnect</Button>
                  <Button variant="ghost" size="sm" onClick={() => setDialog({ node: n })}><Pencil size={13} /> {t("common.edit")}</Button>
                  <Button variant="ghost" size="icon" className="ms-auto" aria-label="delete node" onClick={() => setDeleteFor(n)}><Trash2 size={14} /></Button>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {dialog && <NodeDialog node={dialog.node} onClose={() => setDialog(null)} />}
      <ConfirmDialog open={!!deleteFor} onClose={() => setDeleteFor(null)}
        onConfirm={() => deleteFor && del.mutate(deleteFor.id)}
        title={`delete node — ${deleteFor?.name ?? ""}`}
        body="The node loses its config feed; running services on it stop syncing."
        danger loading={del.isPending} />
    </div>
  );
}

function NodeDialog({ node, onClose }: { node?: Node; onClose: () => void }) {
  const t = useT();
  const qc = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [f, setF] = useState({
    name: node?.name ?? "", address: node?.address ?? "",
    port: node?.port ?? 62050, api_port: node?.api_port ?? 62051,
    usage_coefficient: node?.usage_coefficient ?? 1,
    add_as_new_host: node?.add_as_new_host ?? false,
  });
  return (
    <Dialog open onClose={onClose} title={node ? `edit — ${node.name}` : "add node"}
      subtitle={!node ? "after creation the panel shows the certificate — paste it into the node's config" : undefined}
      footer={<>
        <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
        <Button loading={busy} disabled={!f.name.trim() || !f.address.trim()} onClick={async () => {
          setBusy(true); setError("");
          try {
            if (node) await api.put(`/node/${node.id}`, f);
            else await api.post("/node", f);
            toast.ok(t("common.saved"));
            qc.invalidateQueries({ queryKey: ["nodes"] });
            onClose();
          } catch (e) { setError(e instanceof ApiError ? e.message : t("common.error")); } finally { setBusy(false); }
        }}>{t("common.save")}</Button>
      </>}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="name" required><Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
        <Field label="address" required hint="hostname or IP the panel dials">
          <Input value={f.address} onChange={(e) => setF({ ...f, address: e.target.value })} dir="ltr" />
        </Field>
        <Field label="service port"><Input type="number" value={f.port} onChange={(e) => setF({ ...f, port: Number(e.target.value) })} dir="ltr" /></Field>
        <Field label="API port"><Input type="number" value={f.api_port} onChange={(e) => setF({ ...f, api_port: Number(e.target.value) })} dir="ltr" /></Field>
        <Field label="usage coefficient" hint="traffic multiplier for accounting">
          <Input type="number" step="0.1" min="0" value={f.usage_coefficient} onChange={(e) => setF({ ...f, usage_coefficient: Number(e.target.value) })} />
        </Field>
      </div>
      {error && <p role="alert" className="mt-3 rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}
