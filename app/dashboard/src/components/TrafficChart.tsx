import { AreaChart } from "./charts";
import { EmptyState } from "./ui";
import { formatBytes, formatDate, useDigits } from "../lib/format";
import { useT } from "../lib/i18n";
import type { TrafficPoint } from "../lib/types";

export function TrafficChart({ points }: { points: TrafficPoint[] }) {
  const t = useT();
  const digits = useDigits();
  if (!points.length) {
    return <EmptyState title={t("statistics.noTraffic")} hint={t("statistics.noTrafficHint")} />;
  }
  const upload = points.reduce((sum, point) => sum + point.upload_bytes, 0);
  const download = points.reduce((sum, point) => sum + point.download_bytes, 0);
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-2 text-xs">
        <div className="rounded-xl bg-surface-2 p-2.5"><p className="text-content-3">{t("statistics.download")}</p><p className="mt-1 font-semibold tabular-nums">{formatBytes(download, digits)}</p></div>
        <div className="rounded-xl bg-surface-2 p-2.5"><p className="text-content-3">{t("statistics.upload")}</p><p className="mt-1 font-semibold tabular-nums">{formatBytes(upload, digits)}</p></div>
        <div className="rounded-xl bg-surface-2 p-2.5"><p className="text-content-3">{t("statistics.total")}</p><p className="mt-1 font-semibold tabular-nums">{formatBytes(upload + download, digits)}</p></div>
      </div>
      <AreaChart height={180}
        series={[
          points.map((point) => point.download_bytes),
          points.map((point) => point.upload_bytes),
          points.map((point) => point.total_bytes),
        ]}
        colors={["var(--brand)", "var(--warn)", "var(--info)"]}
        labels={[t("statistics.download"), t("statistics.upload"), t("statistics.total")]} />
      <div className="flex justify-between gap-3 text-[10.5px] text-content-3 tabular-nums">
        <span>{formatDate(points[0].bucket_start, digits)}</span>
        <span>{formatDate(points[points.length - 1].bucket_start, digits)}</span>
      </div>
    </div>
  );
}
