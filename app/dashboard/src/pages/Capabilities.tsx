// Capability matrix — renders the canonical implementation-backed contract
// returned by /cores/capability-matrix. No feature/core allow-list lives here.
import { useQuery } from "@tanstack/react-query";
import { Grid3X3 } from "lucide-react";
import { Badge, Card, ErrorState, Skeleton } from "../components/ui";
import { api } from "../lib/api";
import { useT } from "../lib/i18n";
import type { SupportState } from "../lib/types";

interface CapabilityCell {
  state: SupportState;
  detail?: string | null;
}
interface CapabilityMatrixResponse {
  features: string[];
  installed: string[];
  cores: Record<string, Record<string, CapabilityCell>>;
  all: Record<string, Record<string, CapabilityCell>>;
}

const stateLabel: Record<SupportState, string> = {
  supported: "Supported",
  unsupported: "Unsupported",
  environment_limited: "Environment-limited",
  not_installed: "Not-installed",
  not_applicable: "Not-applicable",
};
const stateTone: Record<SupportState, "ok" | "danger" | "warn" | "info" | "muted"> = {
  supported: "ok",
  unsupported: "danger",
  environment_limited: "warn",
  not_installed: "info",
  not_applicable: "muted",
};
const featureLabel = (value: string) => value.replace(/_/g, " ");

export default function Capabilities() {
  const t = useT();
  const matrix = useQuery({
    queryKey: ["zagros", "capability-matrix"],
    queryFn: () => api.get<CapabilityMatrixResponse>("/zagros/cores/capability-matrix"),
  });

  const installed = new Set(matrix.data?.installed ?? []);
  const coreEntries = Object.entries(matrix.data?.cores ?? {});

  return (
    <div className="space-y-4 animate-fade-up">
      <div>
        <h1 className="flex items-center gap-2 text-lg font-bold tracking-tight">
          <Grid3X3 size={18} className="text-brand" />{t("nav.capabilities")}
        </h1>
        <p className="mt-1 text-xs text-content-3">
          One server-backed contract for inbound, outbound, routing, TUN, accounting, delivery, TLS, versions, and native nodes.
        </p>
      </div>

      <Card className="flex flex-wrap gap-2">
        {(Object.keys(stateLabel) as SupportState[]).map((state) => (
          <Badge key={state} tone={stateTone[state]} dot>{stateLabel[state]}</Badge>
        ))}
      </Card>

      {matrix.isLoading && <Skeleton className="h-96 w-full" />}
      {matrix.isError && (
        <Card><ErrorState message={(matrix.error as Error).message} onRetry={() => matrix.refetch()} /></Card>
      )}
      {matrix.data && (
        <Card className="overflow-hidden p-0">
          <div className="overflow-x-auto">
            <table className="min-w-[1180px] w-full border-collapse text-start text-xs">
              <thead>
                <tr className="border-b border-border bg-surface-2 text-content-2">
                  <th className="sticky start-0 z-10 min-w-32 bg-surface-2 px-4 py-3 text-start font-semibold">Core</th>
                  {matrix.data.features.map((feature) => (
                    <th key={feature} className="min-w-40 px-3 py-3 text-start font-semibold capitalize">
                      {featureLabel(feature)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {coreEntries.map(([coreId, cells]) => (
                  <tr key={coreId} className="border-b border-border last:border-0 align-top">
                    <th className="sticky start-0 z-10 bg-surface-1 px-4 py-4 text-start">
                      <span className="block text-sm font-semibold">{coreId}</span>
                      <Badge tone={installed.has(coreId) ? "ok" : "info"}>
                        {installed.has(coreId) ? "installed" : "not installed"}
                      </Badge>
                    </th>
                    {matrix.data.features.map((feature) => {
                      const cell = cells[feature] ?? { state: "not_applicable" as const, detail: "No implementation contract" };
                      const effectiveState: SupportState = installed.has(coreId) || cell.state === "unsupported" || cell.state === "not_applicable"
                        ? cell.state : "not_installed";
                      return (
                        <td key={feature} className="px-3 py-4">
                          <Badge tone={stateTone[effectiveState]} dot>{stateLabel[effectiveState]}</Badge>
                          {cell.detail && <p className="mt-2 leading-5 text-content-3">{cell.detail}</p>}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
