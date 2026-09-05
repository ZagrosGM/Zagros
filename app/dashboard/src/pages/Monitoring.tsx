import { Activity, FileTerminal, Globe2, Monitor, Wifi } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { Tabs } from "../components/ui";
import { useT } from "../lib/i18n";
import Devices from "./Devices";
import IPActivity from "./IPActivity";
import LiveConnections from "./Sessions";
import Logs from "./Logs";

const VALID_TABS = new Set(["connections", "devices", "ips", "logs"]);

export default function Monitoring() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const requested = params.get("tab") ?? "connections";
  const tab = VALID_TABS.has(requested) ? requested : "connections";
  const select = (next: string) => setParams(next === "connections" ? {} : { tab: next }, { replace: true });
  return (
    <div className="space-y-4 animate-fade-up">
      <div className="flex flex-col gap-3 xl:flex-row xl:items-center">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <Monitor size={18} className="text-brand" />{t("nav.monitoring")}
        </h1>
        <Tabs active={tab} onChange={select} tabs={[
          { id: "connections", label: t("monitoring.liveConnections"), icon: <Activity size={13} /> },
          { id: "devices", label: t("monitoring.devices"), icon: <Wifi size={13} /> },
          { id: "ips", label: t("monitoring.ipActivity"), icon: <Globe2 size={13} /> },
          { id: "logs", label: t("nav.logs"), icon: <FileTerminal size={13} /> },
        ]} />
      </div>
      {tab === "connections" && <LiveConnections embedded />}
      {tab === "devices" && <Devices embedded />}
      {tab === "ips" && <IPActivity embedded />}
      {tab === "logs" && <Logs embedded />}
    </div>
  );
}
