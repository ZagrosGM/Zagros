// Settings — panel info + Advanced Mode gate.
// (alpha.7: admins and user templates are no longer second-class Settings
// widgets — both moved to first-class sidebar pages under "Management".)
import { useQuery } from "@tanstack/react-query";
import { Settings as SettingsIcon, TerminalSquare } from "lucide-react";
import { Badge, Card, CardHeader, Skeleton, Switch } from "../components/ui";
import { api } from "../lib/api";
import { useDigits, formatDuration } from "../lib/format";
import { useT } from "../lib/i18n";
import { applyUiState, useUI } from "../stores/ui";
import type { PanelInfo } from "../lib/types";

export default function Settings() {
  const t = useT();
  const digits = useDigits();
  const { advancedMode, setAdvancedMode, theme, locale } = useUI();

  const info = useQuery({ queryKey: ["zagros", "panel-info"], queryFn: () => api.get<PanelInfo>("/zagros/panel/info"), retry: false });

  return (
    <div className="space-y-4 animate-fade-up">
      <h1 className="flex items-center gap-2 text-lg font-bold tracking-tight">
        <SettingsIcon size={18} className="text-brand" />{t("nav.settings")}
      </h1>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="panel" subtitle="identity & runtime (read-only, .env is the source of truth)" />
          {info.isLoading ? <Skeleton className="h-40" /> : info.isError ? (
            <p className="py-4 text-xs text-content-3">requires sudo admin</p>
          ) : (
            <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-[12.5px]">
              <Meta k="version" v={<Badge tone="brand">{info.data!.version}</Badge>} />
              <Meta k="app" v={info.data!.app_name} />
              <Meta k="domain" v={info.data!.domain || "—"} />
              <Meta k="tls mode" v={info.data!.tls_mode} />
              <Meta k="database" v={info.data!.database_driver} />
              <Meta k="uptime" v={formatDuration(info.data!.uptime_seconds, digits)} />
              <Meta k="panel url" v={<span className="break-all" dir="ltr">{info.data!.panel_base_url || "—"}</span>} />
              <Meta k="auth mode" v={info.data!.client_auth_mode} />
            </dl>
          )}
        </Card>

        <Card>
          <CardHeader title={<span className="inline-flex items-center gap-2"><TerminalSquare size={16} className="text-brand" /> Advanced Mode</span>} />
          <p className="text-[12.5px] leading-6 text-content-2">
            Advanced Mode unlocks the in-panel <b>Config Studio</b> raw document editor
            (schema validation + diff preview) and shows the <b>{t("nav.advanced")}</b> entry
            in the sidebar. Everything outside it stays graphical — regular operators
            never touch JSON.
          </p>
          <div className="mt-4 flex items-center gap-2.5">
            <Switch checked={advancedMode} onChange={(v) => { setAdvancedMode(v); applyUiState(theme, locale); }} label="advanced mode" />
            <span className="text-sm">{advancedMode ? "enabled" : "disabled"}</span>
            {advancedMode && <Badge tone="warn" dot>JSON exposed in Advanced page only</Badge>}
          </div>
        </Card>
      </div>
    </div>
  );
}

function Meta({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[10.5px] uppercase tracking-wide text-content-3">{k}</dt>
      <dd className="mt-0.5 truncate text-content">{v}</dd>
    </div>
  );
}
