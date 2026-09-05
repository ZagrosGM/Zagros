// Monitoring · Devices — strict enrolled X-Device-ID/X-HWID rows only.
// Source IP activity is intentionally a separate tab and table.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCcw, Trash2, Wifi } from "lucide-react";
import { useState } from "react";
import { DataTable } from "../components/DataTable";
import { PaginationBar } from "../components/PaginationBar";
import { toast } from "../components/feedback";
import { ConfirmDialog } from "../components/overlays";
import { Badge, Button, EmptyState, Skeleton } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { formatRelative, useDigits } from "../lib/format";
import { useT } from "../lib/i18n";
import type { MonitoringDevice } from "../lib/types";

const PAGE_SIZE = 100;

export default function Devices({ embedded = false }: { embedded?: boolean }) {
  const t = useT();
  const digits = useDigits();
  const client = useQueryClient();
  const [page, setPage] = useState(1);
  const [forgetFor, setForgetFor] = useState<MonitoringDevice | null>(null);
  const list = useQuery({
    queryKey: ["zagros", "monitoring", "devices", page],
    queryFn: () => api.get<{ items: MonitoringDevice[]; total: number; page: number; page_size: number }>(
      `/zagros/monitoring/devices?page=${page}&page_size=${PAGE_SIZE}`),
    refetchInterval: 15000,
    placeholderData: (previous) => previous,
  });
  const forget = useMutation({
    mutationFn: (id: number) => api.delete(`/zagros/monitoring/devices/${id}`),
    onSuccess: () => {
      toast.ok(t("common.deleted"));
      setForgetFor(null);
      client.invalidateQueries({ queryKey: ["zagros", "monitoring", "devices"] });
    },
    onError: (error) => toast.error(error instanceof ApiError ? error.message : t("common.error")),
  });

  const columns = [
    { id: "user", header: t("user"), cell: (row: MonitoringDevice) => <span className="font-medium">{row.username}</span> },
    { id: "device", header: "Device / HWID", cell: (row: MonitoringDevice) => <code className="font-mono text-[11px]" dir="ltr">{row.device}</code> },
    { id: "ip", header: t("last ip"), cell: (row: MonitoringDevice) => <code className="font-mono text-[11px]" dir="ltr">{row.last_ip ?? "—"}</code> },
    { id: "core", header: t("core"), cell: (row: MonitoringDevice) => <span className="text-content-2">{row.core_id ?? "—"}</span> },
    { id: "node", header: t("node"), cell: (row: MonitoringDevice) => <span className="text-content-2">{row.node_name ?? "—"}</span> },
    { id: "seen", header: t("last seen"), cell: (row: MonitoringDevice) => <span className="text-[12px] text-content-3">{formatRelative(row.last_seen, digits)}</span> },
    { id: "status", header: t("common.status"), cell: () => <Badge tone="info">{t("monitoring.enrolled")}</Badge> },
    { id: "action", header: "", width: "82px", cell: (row: MonitoringDevice) => (
      <Button variant="ghost" size="sm" onClick={() => setForgetFor(row)} aria-label={t("common.delete")}><Trash2 size={13} /></Button>
    )},
  ];

  return (
    <div className="space-y-3">
      {!embedded && (
        <div className="flex items-center gap-2">
          <h1 className="me-auto flex items-center gap-2 text-lg font-bold"><Wifi size={18} className="text-brand" />{t("monitoring.devices")}</h1>
          <Button variant="ghost" size="sm" onClick={() => list.refetch()}><RefreshCcw size={13} />{t("common.refresh")}</Button>
        </div>
      )}
      {list.isLoading ? <Skeleton className="h-72" /> : list.isError ? (
        <EmptyState title={t("common.loadFailed")} hint={t("common.tryAgain")} />
      ) : (
        <DataTable columns={columns as never} rows={list.data?.items ?? []}
          rowKey={(row: MonitoringDevice) => row.id} height={520}
          empty={<EmptyState title={t("monitoring.noDevices")} hint={t("monitoring.noDevicesHint")} />} />
      )}
      {!list.isError && <PaginationBar page={page} pageSize={PAGE_SIZE} total={list.data?.total ?? 0} onChange={setPage} />}
      <ConfirmDialog open={!!forgetFor} onClose={() => setForgetFor(null)}
        onConfirm={() => forgetFor && forget.mutate(forgetFor.id)}
        title={`${t("common.delete")} — ${forgetFor?.device ?? ""}`}
        body={t("monitoring.forgetDeviceHint")} danger loading={forget.isPending} />
    </div>
  );
}
