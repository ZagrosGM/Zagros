import { useQuery } from "@tanstack/react-query";
import { BarChart3 } from "lucide-react";
import { useState } from "react";
import { TrafficChart } from "./TrafficChart";
import { TrafficRange, trafficRangeQuery, type TrafficRangeValue } from "./TrafficRange";
import { Drawer } from "./overlays";
import { Badge, Card, CardHeader, EmptyState, Progress, Skeleton } from "./ui";
import { api } from "../lib/api";
import { formatBytes, useDigits } from "../lib/format";
import { useT, useTDynamic } from "../lib/i18n";
import type { User, UserStatisticsOverview, UserTrafficStatistics } from "../lib/types";

export function UserStatisticsDrawer({ user, onClose }: { user: User; onClose: () => void }) {
  const t = useT();
  const td = useTDynamic();
  const digits = useDigits();
  const [range, setRange] = useState<TrafficRangeValue>({ period: "day", start: "", end: "" });
  const username = encodeURIComponent(user.username);
  const overview = useQuery({
    queryKey: ["zagros", "user-statistics", user.username, "overview"],
    queryFn: () => api.get<UserStatisticsOverview>(`/zagros/statistics/users/by-username/${username}`),
    staleTime: 30000,
    refetchOnWindowFocus: false,
  });
  const customReady = range.period !== "custom" || Boolean(range.start && range.end);
  const traffic = useQuery({
    queryKey: ["zagros", "user-statistics", user.username, "traffic", range],
    queryFn: () => api.get<UserTrafficStatistics>(
      `/zagros/statistics/users/by-username/${username}/traffic?${trafficRangeQuery(range)}`),
    enabled: customReady,
    staleTime: 30000,
    refetchOnWindowFocus: false,
  });
  const data = overview.data;
  const percent = data?.usage_percentage;
  return (
    <Drawer open onClose={onClose}
      title={<span className="inline-flex items-center gap-2"><BarChart3 size={16} className="text-brand" />{t("users.usageStatistics")} — {user.username}</span>}>
      <div className="space-y-4">
        <Card>
          <CardHeader title={t("statistics.overview")} actions={data && <Badge tone={data.status === "active" ? "ok" : "muted"}>{td(data.status)}</Badge>} />
          {overview.isLoading ? <Skeleton className="h-40" /> : overview.isError ? (
            <EmptyState title={t("common.loadFailed")} hint={t("common.tryAgain")} />
          ) : (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                {[
                  [t("statistics.totalTraffic"), data?.total_traffic_bytes],
                  [t("statistics.download"), data?.download_bytes],
                  [t("statistics.upload"), data?.upload_bytes],
                  [t("users.limit"), data?.data_limit_bytes],
                  [t("users.used"), data?.used_bytes],
                  [t("statistics.remaining"), data?.remaining_bytes],
                ].map(([label, value]) => (
                  <div key={String(label)} className="rounded-xl bg-surface-2 p-2.5">
                    <p className="text-[10.5px] text-content-3">{label}</p>
                    <p className="mt-1 truncate text-sm font-semibold tabular-nums">
                      {value == null ? t("users.unlimited") : formatBytes(Number(value), digits)}
                    </p>
                  </div>
                ))}
              </div>
              {percent != null && (
                <div>
                  <div className="mb-1 flex justify-between text-[11px] text-content-3"><span>{t("statistics.usagePercentage")}</span><span className="tabular-nums">{digits(percent.toFixed(1))}%</span></div>
                  <Progress value={Math.min(100, percent)} tone={percent >= 100 ? "danger" : percent >= 80 ? "warn" : "brand"} />
                </div>
              )}
            </div>
          )}
        </Card>

        <Card>
          <CardHeader title={t("statistics.trafficOverTime")} />
          <div className="mb-3"><TrafficRange value={range} onChange={setRange} /></div>
          {!customReady ? <EmptyState title={t("statistics.chooseRange")} />
            : traffic.isLoading ? <Skeleton className="h-60" />
            : traffic.isError ? <EmptyState title={t("common.loadFailed")} hint={t("common.tryAgain")} />
            : <TrafficChart points={traffic.data?.points ?? []} />}
        </Card>

        {traffic.data && <>
          <Breakdown title={t("statistics.byCore")} empty={t("statistics.noCoreTraffic")}
            rows={traffic.data.traffic_by_core.map((row) => ({
              key: row.core_id, name: row.core_name, detail: row.core_id,
              download: row.download_bytes, upload: row.upload_bytes, total: row.total_bytes,
            }))} />
          <Breakdown title={t("statistics.byNode")} empty={t("statistics.noNodeTraffic")}
            rows={traffic.data.traffic_by_node.map((row) => ({
              key: String(row.node_id ?? "master"), name: row.node_name,
              download: row.download_bytes, upload: row.upload_bytes, total: row.total_bytes,
            }))} />
        </>}
      </div>
    </Drawer>
  );
}

function Breakdown({ title, empty, rows }: {
  title: string; empty: string;
  rows: Array<{ key: string; name: string; detail?: string; download: number; upload: number; total: number }>;
}) {
  const t = useT();
  const td = useTDynamic();
  const digits = useDigits();
  return (
    <Card>
      <CardHeader title={title} />
      {!rows.length ? <p className="py-5 text-center text-xs text-content-3">{empty}</p> : (
        <div className="divide-y divide-border">
          {rows.map((row) => (
            <div key={row.key} className="py-2.5">
              <div className="mb-1 flex items-center justify-between gap-3"><span className="font-medium">{td(row.name)}</span><span className="font-semibold tabular-nums">{formatBytes(row.total, digits)}</span></div>
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-[10.5px] text-content-3">
                {row.detail && <span>{row.detail}</span>}
                <span>{t("statistics.download")}: {formatBytes(row.download, digits)}</span>
                <span>{t("statistics.upload")}: {formatBytes(row.upload, digits)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
