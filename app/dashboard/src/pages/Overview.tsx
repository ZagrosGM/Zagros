// Overview — live system stats, bandwidth graph (polled), cores + nodes at a glance.
import { useQuery } from "@tanstack/react-query";
import { Activity, ArrowDown, ArrowUp, Cpu, Gauge, MemoryStick, Users as UsersIcon, UserCheck, Wifi } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { AreaChart } from "../components/charts";
import { Badge, Card, CardHeader, Progress, Skeleton, Stat, StatusDot, cn } from "../components/ui";
import { api } from "../lib/api";
import { useDigits, formatBytes, formatDuration, formatNumber, formatSpeed } from "../lib/format";
import { useT } from "../lib/i18n";
import type { CoreView, Node, Snapshot, SystemStats } from "../lib/types";

const SAMPLES = 42;

export default function Overview() {
  const t = useT();
  const digits = useDigits();
  const [bandSeries, setBandSeries] = useState<{ rx: number[]; tx: number[] }>({ rx: [], tx: [] });

  const system = useQuery({
    queryKey: ["system"],
    queryFn: () => api.get<SystemStats>("/system"),
    refetchInterval: 3000,
    placeholderData: (prev) => prev,
  });
  const snapshot = useQuery({
    queryKey: ["zagros", "snapshot"],
    queryFn: () => api.get<Snapshot>("/zagros/dashboard/snapshot"),
    refetchInterval: 8000,
    retry: false, // sudo surface — non-sudo admins see legacy stats only
  });
  const cores = useQuery({
    queryKey: ["zagros", "cores"],
    queryFn: () => api.get<{ cores: CoreView[] }>("/zagros/cores"),
    refetchInterval: 8000,
    retry: false,
  });
  const nodes = useQuery({
    queryKey: ["nodes"],
    queryFn: () => api.get<Node[]>("/nodes"),
    refetchInterval: 10000,
    retry: false,
  });

  const sys = system.data;
  const last = useRef({ rx: 0, tx: 0 });
  useEffect(() => {
    if (!sys) return;
    setBandSeries((prev) => {
      const rx = [...prev.rx, sys.incoming_bandwidth_speed ?? 0].slice(-SAMPLES);
      const tx = [...prev.tx, sys.outgoing_bandwidth_speed ?? 0].slice(-SAMPLES);
      last.current = { rx: sys.incoming_bandwidth ?? 0, tx: sys.outgoing_bandwidth ?? 0 };
      return { rx, tx };
    });
  }, [sys]);

  const loading = system.isLoading;

  return (
    <div className="space-y-5 animate-fade-up">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {loading ? Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-[76px]" />) : (
          <>
            <Stat icon={<UsersIcon size={19} />} label={t("overview.users")}
              value={formatNumber(sys?.total_user ?? snapshot.data?.totals.users ?? 0, digits)}
              sub={`${t("overview.activeUsers")}: ${formatNumber(sys?.users_active ?? snapshot.data?.totals.active_users ?? 0, digits)}`} />
            <Stat icon={<UserCheck size={19} />} tone="ok" label={t("overview.onlineNow")}
              value={formatNumber(snapshot.data?.totals.online_users ?? 0, digits)} />
            <Stat icon={<ArrowDown size={19} />} tone="default" label={t("overview.incoming")}
              value={formatSpeed(sys?.incoming_bandwidth_speed ?? 0, digits)}
              sub={formatBytes(sys?.incoming_bandwidth ?? 0, digits)} />
            <Stat icon={<ArrowUp size={19} />} tone="warn" label={t("overview.outgoing")}
              value={formatSpeed(sys?.outgoing_bandwidth_speed ?? 0, digits)}
              sub={formatBytes(sys?.outgoing_bandwidth ?? 0, digits)} />
          </>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader title={<span className="inline-flex items-center gap-2"><Activity size={16} className="text-brand" />{t("overview.bandwidth")}</span>}
            subtitle={<span className="tabular-nums">↓ {formatSpeed(sys?.incoming_bandwidth_speed ?? 0, digits)} · ↑ {formatSpeed(sys?.outgoing_bandwidth_speed ?? 0, digits)}</span>} />
          {loading ? <Skeleton className="h-[120px]" /> : (
            <AreaChart
              series={[bandSeries.rx, bandSeries.tx]}
              colors={["var(--brand)", "var(--warn)"]}
              labels={[t("overview.incoming"), t("overview.outgoing")]}
            />
          )}
        </Card>

        <Card>
          <CardHeader title={<span className="inline-flex items-center gap-2"><Gauge size={16} className="text-brand" />{t("overview.system")}</span>} />
          {loading ? <Skeleton className="h-[120px]" /> : (
            <div className="space-y-4">
              <div>
                <div className="mb-1 flex justify-between text-[11px] text-content-3">
                  <span className="inline-flex items-center gap-1"><MemoryStick size={12} />{t("overview.memory")}</span>
                  <span className="tabular-nums">{formatBytes(sys?.mem_used ?? 0, digits)} / {formatBytes(sys?.mem_total ?? 0, digits)}</span>
                </div>
                <Progress value={sys?.mem_total ? (sys.mem_used / sys.mem_total) * 100 : 0} />
              </div>
              <div>
                <div className="mb-1 flex justify-between text-[11px] text-content-3">
                  <span className="inline-flex items-center gap-1"><Cpu size={12} />{t("overview.cpu")} ({digits(String(sys?.cpu_cores ?? 0))})</span>
                  <span className="tabular-nums">{digits((sys?.cpu_usage ?? 0).toFixed(0))}%</span>
                </div>
                <Progress value={sys?.cpu_usage ?? 0} tone="warn" />
              </div>
              <div className="flex items-center justify-between border-t border-border pt-3 text-[11px] text-content-3">
                <span>{t("overview.version")}: <span className="font-medium text-content">{sys?.version ?? snapshot.data?.version ?? "—"}</span></span>
                <span>{t("overview.uptime")}: <span className="text-content tabular-nums">{formatDuration(snapshot.data?.uptime_seconds, digits)}</span></span>
              </div>
            </div>
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader
            title={<Link to="/cores" className="inline-flex items-center gap-2 hover:text-brand"><Cpu size={16} className="text-brand" />{t("overview.cores")}</Link>}
            actions={<Link to="/cores"><Badge tone="brand">manage</Badge></Link>} />
          {cores.isLoading ? <Skeleton className="h-20" /> : cores.isError ? (
            <p className="py-6 text-center text-xs text-content-3">Core inventory requires a sudo admin.</p>
          ) : !cores.data?.cores.length ? (
            <p className="py-6 text-center text-xs text-content-3">No cores installed — install one from the Cores page.</p>
          ) : (
            <ul className="divide-y divide-border">
              {cores.data.cores.map((c) => (
                <li key={c.id} className="flex items-center justify-between gap-3 py-2.5">
                  <div className="flex min-w-0 items-center gap-2.5">
                    <StatusDot tone={c.state === "running" ? "ok" : c.state === "error" ? "danger" : "muted"} pulse={c.state === "running"} />
                    <span className="truncate font-medium">{c.name || c.id}</span>
                    <Badge tone="muted">{c.id}</Badge>
                  </div>
                  <div className="flex items-center gap-2 text-[11px] text-content-3">
                    <span className="tabular-nums">{c.core_version ?? "—"}</span>
                    <Badge tone={c.state === "running" ? "ok" : c.enabled ? "info" : "muted"} dot>
                      {c.state}{c.health && c.state === "running" ? ` · ${c.health}` : ""}
                    </Badge>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardHeader
            title={<Link to="/nodes" className="inline-flex items-center gap-2 hover:text-brand"><Wifi size={16} className="text-brand" />{t("overview.nodes")}</Link>}
            actions={<Link to="/nodes"><Badge tone="brand">manage</Badge></Link>} />
          {nodes.isLoading ? <Skeleton className="h-20" /> : nodes.isError || !nodes.data?.length ? (
            <p className="py-6 text-center text-xs text-content-3">Master node only — add remote nodes from the Nodes page.</p>
          ) : (
            <ul className="divide-y divide-border">
              {nodes.data.map((n) => (
                <li key={n.id} className="flex items-center justify-between gap-3 py-2.5">
                  <div className="flex min-w-0 items-center gap-2.5">
                    <StatusDot tone={n.status === "connected" ? "ok" : n.status === "disabled" ? "muted" : "danger"} pulse={n.status === "connected"} />
                    <span className="truncate font-medium">{n.name}</span>
                    <span className="truncate text-[11px] text-content-3">{n.address}:{n.port}</span>
                  </div>
                  <span className={cn("text-[11px] tabular-nums text-content-3")}>{n.xray_version ?? ""}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
