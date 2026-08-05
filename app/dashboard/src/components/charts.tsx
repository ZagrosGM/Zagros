// Live charts — hand-rolled SVG (no chart lib): area, donut, sparkline, gauge.
// Values are plain numbers; colors come from design tokens.
import { useId } from "react";

export function AreaChart({ series, height = 120, colors = ["var(--brand)", "var(--info)"], labels }: {
  series: number[][]; height?: number; colors?: string[]; labels?: string[];
}) {
  const id = useId().replace(/:/g, "");
  const w = 600;
  const n = Math.max(series[0]?.length ?? 2, 2);
  const max = Math.max(1, ...series.flat());
  const pathFor = (values: number[]) => {
    const pts = values.map((v, i) => [
      (i / (n - 1)) * w,
      height - 6 - (Math.max(0, v) / max) * (height - 14),
    ]);
    const line = pts.map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
    return { line, area: `${line} L${w},${height} L0,${height} Z` };
  };
  return (
    <div>
      <svg viewBox={`0 0 ${w} ${height}`} className="w-full" preserveAspectRatio="none" role="img">
        <defs>
          {series.map((_, i) => (
            <linearGradient key={i} id={`${id}-g${i}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={colors[i % colors.length]} stopOpacity="0.32" />
              <stop offset="100%" stopColor={colors[i % colors.length]} stopOpacity="0.02" />
            </linearGradient>
          ))}
        </defs>
        {series.map((s, i) => {
          const { line, area } = pathFor(s);
          return (
            <g key={i}>
              <path d={area} fill={`url(#${id}-g${i})`} />
              <path d={line} fill="none" stroke={colors[i % colors.length]} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
            </g>
          );
        })}
      </svg>
      {labels && (
        <div className="mt-2 flex gap-4 text-[11px] text-content-3">
          {labels.map((l, i) => (
            <span key={l} className="inline-flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full" style={{ background: colors[i % colors.length] }} />
              {l}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export function DonutChart({ value, size = 96, thickness = 10, label, tone = "var(--brand)" }: {
  value: number; size?: number; thickness?: number; label?: React.ReactNode; tone?: string;
}) {
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.min(100, Math.max(0, value));
  return (
    <div className="relative inline-grid place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--surface-3)" strokeWidth={thickness} />
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none" stroke={tone} strokeWidth={thickness}
          strokeDasharray={c} strokeDashoffset={c - (pct / 100) * c} strokeLinecap="round"
          className="transition-all duration-700"
        />
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">
        <div>
          <div className="text-lg font-semibold tabular-nums">{Math.round(pct)}%</div>
          {label && <div className="text-[10px] text-content-3">{label}</div>}
        </div>
      </div>
    </div>
  );
}

export function Sparkline({ values, width = 90, height = 26, color = "var(--brand)" }: {
  values: number[]; width?: number; height?: number; color?: string;
}) {
  if (!values.length) return null;
  const max = Math.max(1, ...values);
  const pts = values.map((v, i) => `${(i / Math.max(1, values.length - 1)) * width},${height - 2 - (v / max) * (height - 4)}`);
  return (
    <svg width={width} height={height} aria-hidden>
      <polyline points={pts.join(" ")} fill="none" stroke={color} strokeWidth="1.6" strokeLinejoin="round" />
    </svg>
  );
}
