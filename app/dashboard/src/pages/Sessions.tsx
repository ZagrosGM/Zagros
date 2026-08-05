// Sessions — live core sessions + client (Zagros app) refresh-token inventory
// with revoke actions.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, Ban, MonitorSmartphone, RefreshCcw } from "lucide-react";
import { toast } from "../components/feedback";
import { ConfirmDialog } from "../components/overlays";
import { Badge, Button, Card, CardHeader, EmptyState, Skeleton, Tabs } from "../components/ui";
import { DataTable } from "../components/DataTable";
import { api, ApiError } from "../lib/api";
import { useDigits, formatBytes, formatDate, formatDuration } from "../lib/format";
import { useT } from "../lib/i18n";
import { useState } from "react";
import type { ClientSession, SessionRecord } from "../lib/types";

export default function Sessions() {
  const t = useT();
  const digits = useDigits();
  const qc = useQueryClient();
  const [tab, setTab] = useState("live");
  const [revokeFor, setRevokeFor] = useState<ClientSession | null>(null);

  const live = useQuery({
    queryKey: ["zagros", "sessions"],
    queryFn: () => api.get<{ sessions: SessionRecord[] }>("/zagros/sessions"),
    refetchInterval: 5000,
  });
  const clients = useQuery({
    queryKey: ["zagros", "client-sessions"],
    queryFn: () => api.get<{ sessions: ClientSession[] }>("/zagros/client-sessions"),
    refetchInterval: 10000,
    enabled: tab === "clients",
  });
  const revoke = useMutation({
    mutationFn: (hash: string) => api.delete(`/zagros/client-sessions/${encodeURIComponent(hash)}`),
    onSuccess: () => { toast.ok("session revoked"); setRevokeFor(null); qc.invalidateQueries({ queryKey: ["zagros", "client-sessions"] }); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const liveCols = [
    { id: "user", header: "user", cell: (s: SessionRecord) => <span className="font-medium">#{s.user_id}</span> },
    { id: "core", header: "core", cell: (s: SessionRecord) => <Badge tone="brand">{s.core_id}</Badge> },
    { id: "ip", header: "ip", cell: (s: SessionRecord) => <code className="font-mono text-[11px]" dir="ltr">{s.ip ?? "—"}</code> },
    { id: "started", header: "started", cell: (s: SessionRecord) => <span className="text-[12px] tabular-nums text-content-2">{formatDate(s.started_at, digits)}</span> },
    { id: "dur", header: "duration", cell: (s: SessionRecord) => <span className="text-[12px] tabular-nums text-content-2">{formatDuration(s.duration_seconds, digits)}</span> },
    { id: "traffic", header: "traffic", cell: (s: SessionRecord) => <span className="text-[12px] tabular-nums">{formatBytes(s.rx_bytes, digits)} ↓ / {formatBytes(s.tx_bytes, digits)} ↑</span> },
    { id: "state", header: "", width: "90px", cell: (s: SessionRecord) => s.ended_at ? <Badge tone="muted">ended</Badge> : <Badge tone="ok" dot>live</Badge> },
  ];
  const clientCols = [
    { id: "user", header: "user", cell: (s: ClientSession) => <div><span className="font-medium">{s.username ?? `#${s.user_id}`}</span></div> },
    { id: "ua", header: "client", cell: (s: ClientSession) => <span className="block max-w-[220px] truncate text-[11px] text-content-3" title={s.user_agent ?? ""}>{s.user_agent ?? "—"}</span> },
    { id: "created", header: "issued", cell: (s: ClientSession) => <span className="text-[12px] tabular-nums text-content-2">{formatDate(s.created_at, digits)}</span> },
    { id: "expires", header: "expires", cell: (s: ClientSession) => <span className="text-[12px] tabular-nums text-content-2">{formatDate(s.expires_at, digits)}</span> },
    { id: "state", header: "state", width: "110px", cell: (s: ClientSession) => s.revoked ? <Badge tone="danger">revoked</Badge> : <Badge tone="ok" dot>active</Badge> },
    {
      id: "act", header: "", width: "100px",
      cell: (s: ClientSession) => !s.revoked && (
        <Button variant="danger" size="sm" onClick={() => setRevokeFor(s)}><Ban size={12} /> revoke</Button>
      ),
    },
  ];

  return (
    <div className="space-y-4 animate-fade-up">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <Activity size={18} className="text-brand" />{t("nav.sessions")}
        </h1>
        <Tabs active={tab} onChange={setTab} tabs={[
          { id: "live", label: "live core sessions", icon: <Activity size={13} /> },
          { id: "clients", label: "app sign-ins", icon: <MonitorSmartphone size={13} /> },
        ]} />
        <Button variant="ghost" size="sm" onClick={() => tab === "live" ? live.refetch() : clients.refetch()}><RefreshCcw size={13} /></Button>
      </div>

      {tab === "live" ? (
        live.isLoading ? <Skeleton className="h-72" /> : (
          <DataTable columns={liveCols as never} rows={live.data?.sessions ?? []} rowKey={(s: SessionRecord) => s.key}
            height={560}
            empty={<EmptyState title="No live sessions" hint="Sessions appear as users connect through cores — this is real data, not a placeholder." />} />
        )
      ) : (
        clients.isLoading ? <Skeleton className="h-72" /> : (
          <DataTable columns={clientCols as never} rows={(clients.data?.sessions ?? []).filter((s) => !s.revoked)} rowKey={(s: ClientSession) => s.token_hash}
            height={560}
            empty={<EmptyState title="No active app sign-ins" hint="Zagros app sessions (refresh tokens) appear here after a device signs in." />} />
        )
      )}

      <ConfirmDialog open={!!revokeFor} onClose={() => setRevokeFor(null)}
        onConfirm={() => revokeFor && revoke.mutate(revokeFor.token_hash)}
        title={`revoke sign-in — ${revokeFor?.username ?? revokeFor?.user_id ?? ""}`}
        body="The device's refresh token is invalidated; it must sign in again."
        danger loading={revoke.isPending} />
    </div>
  );
}
