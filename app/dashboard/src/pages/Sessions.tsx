// Monitoring · Live Connections — current authenticated core/node sessions.
// The API reads the existing IP-limit poll snapshot; opening this tab does not
// trigger a second driver scan.
import { useQuery } from "@tanstack/react-query";
import { Activity, RefreshCcw } from "lucide-react";
import { useState } from "react";
import { DataTable } from "../components/DataTable";
import { PaginationBar } from "../components/PaginationBar";
import { Badge, Button, EmptyState, Skeleton } from "../components/ui";
import { api } from "../lib/api";
import { formatBytes, formatDate, formatDuration, useDigits } from "../lib/format";
import { useT } from "../lib/i18n";
import type { MonitoringConnection } from "../lib/types";

const PAGE_SIZE = 100;

export default function LiveConnections({ embedded = false }: { embedded?: boolean }) {
  const t = useT();
  const digits = useDigits();
  const [page, setPage] = useState(1);
  const query = useQuery({
    queryKey: ["zagros", "monitoring", "connections", page],
    queryFn: () => api.get<{
      items: MonitoringConnection[]; total: number; page: number; page_size: number;
      failed_sources: string[]; generated_at?: string | null;
    }>(`/zagros/monitoring/live-connections?page=${page}&page_size=${PAGE_SIZE}`),
    refetchInterval: 5000,
    placeholderData: (previous) => previous,
  });

  const columns = [
    { id: "user", header: t("user"), cell: (row: MonitoringConnection) => <span className="font-medium">{row.username ?? `#${row.user_id}`}</span> },
    { id: "core", header: t("core"), cell: (row: MonitoringConnection) => <Badge tone="brand">{row.core_id}</Badge> },
    { id: "node", header: t("node"), cell: (row: MonitoringConnection) => <span className="text-content-2">{row.node_id == null ? t("Master") : (row.node_name ?? "—")}</span> },
    { id: "ip", header: "IP", cell: (row: MonitoringConnection) => <code className="font-mono text-[11px]" dir="ltr">{row.ip ?? "—"}</code> },
    { id: "device", header: "Device / HWID", cell: (row: MonitoringConnection) => <code className="font-mono text-[11px]" dir="ltr">{row.device ?? "—"}</code> },
    { id: "started", header: t("started"), cell: (row: MonitoringConnection) => <span className="text-[12px] tabular-nums text-content-2">{formatDate(row.started_at, digits)}</span> },
    { id: "duration", header: t("duration"), cell: (row: MonitoringConnection) => <span className="text-[12px] tabular-nums text-content-2">{formatDuration(row.duration_seconds, digits)}</span> },
    { id: "traffic", header: t("traffic"), cell: (row: MonitoringConnection) => <span className="text-[12px] tabular-nums">{formatBytes(row.download_bytes, digits)} ↓ / {formatBytes(row.upload_bytes, digits)} ↑</span> },
    { id: "status", header: t("common.status"), cell: () => <Badge tone="ok" dot>{t("active")}</Badge> },
  ];

  return (
    <div className="space-y-3">
      {!embedded && (
        <div className="flex items-center gap-2">
          <h1 className="me-auto flex items-center gap-2 text-lg font-bold"><Activity size={18} className="text-brand" />{t("monitoring.liveConnections")}</h1>
          <Button variant="ghost" size="sm" onClick={() => query.refetch()}><RefreshCcw size={13} />{t("common.refresh")}</Button>
        </div>
      )}
      {!!query.data?.failed_sources.length && (
        <p className="rounded-xl border border-warn/30 bg-warn-soft px-3 py-2 text-xs text-warn">
          {t("monitoring.partial")}: {query.data.failed_sources.join(", ")}
        </p>
      )}
      {query.isLoading ? <Skeleton className="h-72" /> : query.isError ? (
        <EmptyState title={t("common.loadFailed")} hint={t("common.tryAgain")} />
      ) : (
        <DataTable columns={columns as never} rows={query.data?.items ?? []}
          rowKey={(row: MonitoringConnection) => row.key} height={520}
          empty={<EmptyState title={t("monitoring.noConnections")} hint={t("monitoring.noConnectionsHint")} />} />
      )}
      {!query.isError && <PaginationBar page={page} pageSize={PAGE_SIZE} total={query.data?.total ?? 0} onChange={setPage} />}
    </div>
  );
}
