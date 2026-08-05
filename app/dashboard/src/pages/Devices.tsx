// Devices — registered Zagros app devices with forget action.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCcw, Trash2, Wifi } from "lucide-react";
import { useState } from "react";
import { toast } from "../components/feedback";
import { ConfirmDialog } from "../components/overlays";
import { Badge, Button, Card, EmptyState, Skeleton } from "../components/ui";
import { DataTable } from "../components/DataTable";
import { api, ApiError } from "../lib/api";
import { useDigits, formatRelative } from "../lib/format";
import { useT } from "../lib/i18n";
import type { Device } from "../lib/types";

export default function Devices() {
  const t = useT();
  const digits = useDigits();
  const qc = useQueryClient();
  const [forgetFor, setForgetFor] = useState<Device | null>(null);

  const list = useQuery({
    queryKey: ["zagros", "devices"],
    queryFn: () => api.get<{ devices: Device[] }>("/zagros/devices"),
    refetchInterval: 15000,
  });
  const forget = useMutation({
    mutationFn: (id: string) => api.delete(`/zagros/devices/${encodeURIComponent(id)}`),
    onSuccess: () => { toast.ok("device forgotten"); setForgetFor(null); qc.invalidateQueries({ queryKey: ["zagros", "devices"] }); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const cols = [
    {
      id: "dev", header: "device", cell: (d: Device) => (
        <div>
          <span className="font-medium">{d.name || d.device_id}</span>
          <span className="ms-2 text-[11px] text-content-3">{d.platform ?? ""}{d.app_version ? ` · v${d.app_version}` : ""}</span>
        </div>
      ),
    },
    { id: "user", header: "user", cell: (d: Device) => <Badge tone="brand">{d.username ?? `#${d.user_id}`}</Badge> },
    { id: "ip", header: "last ip", cell: (d: Device) => <code className="font-mono text-[11px]" dir="ltr">{d.last_ip ?? "—"}</code> },
    { id: "core", header: "core", cell: (d: Device) => <span className="text-[12px] text-content-2">{d.current_core ?? (d.cores ?? []).join(", ") ?? "—"}</span> },
    { id: "seen", header: "last seen", width: "130px", cell: (d: Device) => <span className="text-[12px] text-content-3">{formatRelative(d.last_seen, digits)}</span> },
    {
      id: "act", header: "", width: "96px",
      cell: (d: Device) => <Button variant="danger" size="sm" onClick={() => setForgetFor(d)}><Trash2 size={12} /> forget</Button>,
    },
  ];

  return (
    <div className="space-y-4 animate-fade-up">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <Wifi size={18} className="text-brand" />{t("nav.devices")}
        </h1>
        <Button variant="ghost" size="sm" onClick={() => list.refetch()}><RefreshCcw size={13} /> {t("common.refresh")}</Button>
      </div>

      {list.isLoading ? <Skeleton className="h-72" /> : (
        <DataTable columns={cols as never} rows={list.data?.devices ?? []} rowKey={(d: Device) => d.device_id} height={560}
          empty={<EmptyState title="No devices yet" hint="Devices register themselves the first time the Zagros app signs in on them." />} />
      )}

      <ConfirmDialog open={!!forgetFor} onClose={() => setForgetFor(null)}
        onConfirm={() => forgetFor && forget.mutate(forgetFor.device_id)}
        title={`forget device — ${forgetFor?.name ?? forgetFor?.device_id ?? ""}`}
        body="The device record is removed; the app re-registers on its next sign-in."
        danger loading={forget.isPending} />
    </div>
  );
}
