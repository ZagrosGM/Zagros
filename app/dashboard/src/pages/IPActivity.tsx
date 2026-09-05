// Monitoring · IP Activity — authenticated source addresses observed by the
// same cross-core poll that enforces IP limits.
import { useQuery } from "@tanstack/react-query";
import { Globe2, RefreshCcw } from "lucide-react";
import { useState } from "react";
import { DataTable } from "../components/DataTable";
import { PaginationBar } from "../components/PaginationBar";
import { Badge, Button, EmptyState, Skeleton } from "../components/ui";
import { api } from "../lib/api";
import { formatDate, formatRelative, useDigits } from "../lib/format";
import { useT } from "../lib/i18n";
import type { IPActivity as IPActivityRow } from "../lib/types";

const PAGE_SIZE = 100;
const TONE = { active: "ok", inactive: "muted", banned: "danger", unknown: "warn" } as const;

export default function IPActivity({ embedded = false }: { embedded?: boolean }) {
  const t = useT();
  const digits = useDigits();
  const [page, setPage] = useState(1);
  const query = useQuery({
    queryKey: ["zagros", "monitoring", "ip-activity", page],
    queryFn: () => api.get<{
      items: IPActivityRow[]; total: number; page: number; page_size: number;
      failed_sources: string[];
    }>(`/zagros/monitoring/ip-activity?page=${page}&page_size=${PAGE_SIZE}`),
    refetchInterval: 10000,
    placeholderData: (previous) => previous,
  });
  const columns = [
    { id: "user", header: t("user"), cell: (row: IPActivityRow) => <span className="font-medium">{row.username}</span> },
    { id: "ip", header: t("monitoring.ipAddress"), cell: (row: IPActivityRow) => <code className="font-mono text-[11px]" dir="ltr">{row.ip}</code> },
    { id: "core", header: t("core"), cell: (row: IPActivityRow) => <Badge tone="brand">{row.core_id}</Badge> },
    { id: "node", header: t("node"), cell: (row: IPActivityRow) => <span className="text-content-2">{row.node_id == null ? t("Master") : (row.node_name ?? "—")}</span> },
    { id: "first", header: t("monitoring.firstSeen"), cell: (row: IPActivityRow) => <span className="text-[12px] text-content-3">{formatDate(row.first_seen, digits)}</span> },
    { id: "last", header: t("last seen"), cell: (row: IPActivityRow) => <span className="text-[12px] text-content-3">{formatRelative(row.last_seen, digits)}</span> },
    { id: "status", header: t("common.status"), cell: (row: IPActivityRow) => <Badge tone={TONE[row.status]} dot={row.status === "active"}>{t(row.status)}</Badge> },
  ];
  return (
    <div className="space-y-3">
      {!embedded && (
        <div className="flex items-center gap-2">
          <h1 className="me-auto flex items-center gap-2 text-lg font-bold"><Globe2 size={18} className="text-brand" />{t("monitoring.ipActivity")}</h1>
          <Button variant="ghost" size="sm" onClick={() => query.refetch()}><RefreshCcw size={13} />{t("common.refresh")}</Button>
        </div>
      )}
      {query.isLoading ? <Skeleton className="h-72" /> : query.isError ? (
        <EmptyState title={t("common.loadFailed")} hint={t("common.tryAgain")} />
      ) : (
        <DataTable columns={columns as never} rows={query.data?.items ?? []}
          rowKey={(row: IPActivityRow) => row.id} height={520}
          empty={<EmptyState title={t("monitoring.noIPs")} hint={t("monitoring.noIPsHint")} />} />
      )}
      {!query.isError && <PaginationBar page={page} pageSize={PAGE_SIZE} total={query.data?.total ?? 0} onChange={setPage} />}
    </div>
  );
}
