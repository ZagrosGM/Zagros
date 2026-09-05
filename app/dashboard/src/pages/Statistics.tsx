import { useQuery } from "@tanstack/react-query";
import { Activity, ArrowDown, ArrowUp, BarChart3, Cpu, HardDrive, RefreshCcw, Users } from "lucide-react";
import { useState } from "react";
import { DataTable, type Column } from "../components/DataTable";
import { TrafficChart } from "../components/TrafficChart";
import { TrafficRange, trafficRangeQuery, type TrafficRangeValue } from "../components/TrafficRange";
import { Badge, Button, Card, CardHeader, EmptyState, Skeleton, Stat } from "../components/ui";
import { api } from "../lib/api";
import { formatBytes, formatNumber, useDigits } from "../lib/format";
import { useT } from "../lib/i18n";
import type { StatisticsOverview, TrafficByCore, TrafficByNode, TrafficHistory } from "../lib/types";

const initialRange: TrafficRangeValue = { period: "day", start: "", end: "" };

export default function Statistics() {
  const t = useT();
  const digits = useDigits();
  const [range, setRange] = useState(initialRange);
  const overview = useQuery({
    queryKey: ["zagros", "statistics", "overview"],
    queryFn: () => api.get<StatisticsOverview>("/zagros/statistics/overview"),
    staleTime: 30000,
    refetchOnWindowFocus: false,
  });
  const customReady = range.period !== "custom" || Boolean(range.start && range.end);
  const history = useQuery({
    queryKey: ["zagros", "statistics", "history", range],
    queryFn: () => api.get<TrafficHistory>(`/zagros/statistics/traffic-history?${trafficRangeQuery(range)}`),
    enabled: customReady,
    staleTime: 30000,
    refetchOnWindowFocus: false,
  });
  const coreColumns: Column<TrafficByCore>[] = [
    { id: "name", header: t("core"), cell: (row: TrafficByCore) => <div><span className="font-medium">{row.core_name}</span><span className="ms-2"><Badge tone="muted">{row.core_id}</Badge></span></div> },
    { id: "down", header: t("statistics.download"), cell: (row: TrafficByCore) => <span className="tabular-nums">{formatBytes(row.download_bytes, digits)}</span> },
    { id: "up", header: t("statistics.upload"), cell: (row: TrafficByCore) => <span className="tabular-nums">{formatBytes(row.upload_bytes, digits)}</span> },
    { id: "total", header: t("statistics.total"), cell: (row: TrafficByCore) => <span className="font-medium tabular-nums">{formatBytes(row.total_bytes, digits)}</span> },
  ];
  const nodeColumns: Column<TrafficByNode>[] = [
    { id: "name", header: t("node"), cell: (row: TrafficByNode) => <span className="font-medium">{row.node_id == null ? t("Master") : row.node_name}</span> },
    { id: "down", header: t("statistics.download"), cell: (row: TrafficByNode) => <span className="tabular-nums">{formatBytes(row.download_bytes, digits)}</span> },
    { id: "up", header: t("statistics.upload"), cell: (row: TrafficByNode) => <span className="tabular-nums">{formatBytes(row.upload_bytes, digits)}</span> },
    { id: "total", header: t("statistics.total"), cell: (row: TrafficByNode) => <span className="font-medium tabular-nums">{formatBytes(row.total_bytes, digits)}</span> },
  ];
  const data = overview.data;
  return (
    <div className="space-y-5 animate-fade-up">
      <div className="flex items-center gap-2">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight"><BarChart3 size={18} className="text-brand" />{t("nav.statistics")}</h1>
        <Button variant="ghost" size="sm" onClick={() => { overview.refetch(); if (customReady) history.refetch(); }}>
          <RefreshCcw size={13} />{t("common.refresh")}
        </Button>
      </div>

      {overview.isError && <Card><EmptyState title={t("common.loadFailed")} hint={t("common.tryAgain")} /></Card>}
      {!overview.isError && <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 xl:grid-cols-7">
        {overview.isLoading ? Array.from({ length: 7 }).map((_, index) => <Skeleton key={index} className="h-[84px]" />) : (
          <>
            <Stat icon={<Activity size={18} />} label={t("statistics.totalTraffic")} value={formatBytes(data?.total_traffic_bytes ?? 0, digits)} />
            <Stat icon={<ArrowDown size={18} />} label={t("statistics.download")} value={formatBytes(data?.download_bytes ?? 0, digits)} />
            <Stat icon={<ArrowUp size={18} />} tone="warn" label={t("statistics.upload")} value={formatBytes(data?.upload_bytes ?? 0, digits)} />
            <Stat icon={<Users size={18} />} tone="ok" label={t("statistics.activeUsers")} value={formatNumber(data?.active_users ?? 0, digits)} />
            <Stat icon={<Activity size={18} />} tone="ok" label={t("statistics.activeConnections")} value={formatNumber(data?.active_connections ?? 0, digits)} />
            <Stat icon={<HardDrive size={18} />} label={t("statistics.totalNodes")} value={formatNumber(data?.total_nodes ?? 0, digits)} />
            <Stat icon={<Cpu size={18} />} label={t("statistics.totalCores")} value={formatNumber(data?.total_cores ?? 0, digits)} />
          </>
        )}
      </div>}

      <Card>
        <CardHeader title={t("statistics.trafficHistory")} subtitle={t("statistics.aggregateHint")}
          actions={<TrafficRange value={range} onChange={setRange} />} />
        {!customReady ? <EmptyState title={t("statistics.chooseRange")} />
          : history.isLoading ? <Skeleton className="h-64" />
          : history.isError ? <EmptyState title={t("common.loadFailed")} hint={t("common.tryAgain")} />
          : <TrafficChart points={history.data?.points ?? []} />}
      </Card>

      {!overview.isError && <div className="grid gap-4 xl:grid-cols-2">
        <Card className="p-0">
          <div className="p-4 pb-2"><CardHeader title={t("statistics.byNode")} subtitle={t("statistics.aggregateOnly")} /></div>
          <DataTable columns={nodeColumns} rows={data?.traffic_by_node ?? []}
            rowKey={(row: TrafficByNode) => row.node_id ?? "master"}
            empty={<EmptyState title={t("statistics.noNodeTraffic")} />} />
        </Card>
        <Card className="p-0">
          <div className="p-4 pb-2"><CardHeader title={t("statistics.byCore")} subtitle={t("statistics.aggregateOnly")} /></div>
          <DataTable columns={coreColumns} rows={data?.traffic_by_core ?? []}
            rowKey={(row: TrafficByCore) => row.core_id}
            empty={<EmptyState title={t("statistics.noCoreTraffic")} />} />
        </Card>
      </div>}
    </div>
  );
}
