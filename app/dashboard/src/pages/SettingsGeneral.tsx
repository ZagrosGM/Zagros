// Settings → General — panel info, Panel Network and Advanced Mode.
// (Moved verbatim when Settings gained tabs: this is the tab the
// operator already knows.)
// (: admins and user templates are no longer second-class Settings
// widgets — both moved to first-class sidebar pages under "Management".)
import { useMutation, useQuery } from "@tanstack/react-query";
import { Save, Settings as SettingsIcon, TerminalSquare } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "../components/feedback";
import { Badge, Button, Card, CardHeader, Field, Input, Select, Skeleton, Switch } from "../components/ui";
import { api, ApiError, adminQueryErrorKey } from "../lib/api";
import { useDigits, formatDuration } from "../lib/format";
import { useT } from "../lib/i18n";
import { applyUiState, useUI } from "../stores/ui";
import type { CertificateInfo, PanelInfo, PanelNetworkSettings } from "../lib/types";

interface NetworkApplyAccepted { accepted: boolean; public_url: string; operation_id: string; status: string }
interface NetworkApplyStatus { status: string; message?: string; rolled_back?: boolean; public_url?: string }

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Cross-origin readiness probe. Image loading reveals no API data, sends no
 * credentials, and still requires DNS + a browser-trusted TLS certificate. */
function probeNewOrigin(base: string, operationId: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const image = new Image();
    const timer = window.setTimeout(() => {
      image.src = "";
      reject(new Error("new origin health probe timed out"));
    }, 4000);
    image.onload = () => { window.clearTimeout(timer); resolve(); };
    image.onerror = () => { window.clearTimeout(timer); reject(new Error("not ready")); };
    image.referrerPolicy = "no-referrer";
    image.src = `${base.replace(/\/$/, "")}/api/zagros/network-transition/${operationId}.svg?t=${Date.now()}`;
  });
}

export default function SettingsGeneral() {
  const t = useT();
  const digits = useDigits();
  const { advancedMode, setAdvancedMode, theme, locale } = useUI();

  const info = useQuery({ queryKey: ["zagros", "panel-info"], queryFn: () => api.get<PanelInfo>("/zagros/panel/info"), retry: false });
  const networkQ = useQuery({ queryKey: ["zagros", "panel-network"], queryFn: () => api.get<PanelNetworkSettings>("/zagros/settings/panel-network") });
  const certsQ = useQuery({ queryKey: ["zagros", "certificates"], queryFn: () => api.get<{ certificates: CertificateInfo[] }>("/zagros/certificates") });

  const [network, setNetwork] = useState<PanelNetworkSettings | null>(null);
  const [networkTest, setNetworkTest] = useState<Record<string, unknown> | null>(null);
  const [networkTransition, setNetworkTransition] = useState("");

  useEffect(() => { if (networkQ.data) setNetwork(networkQ.data); }, [networkQ.data]);

  const testNetwork = useMutation({
    mutationFn: () => api.post<Record<string, unknown>>("/zagros/settings/panel-network/test", network),
    onSuccess: (data) => { setNetworkTest(data); toast.ok("panel network configuration is valid"); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });
  const saveNetwork = useMutation({
    mutationFn: () => api.put("/zagros/settings/panel-network", network),
    onSuccess: () => toast.ok(t("common.saved")),
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });
  const applyNetwork = useMutation({
    mutationFn: () => api.post<NetworkApplyAccepted>("/zagros/settings/panel-network/apply", network),
    onSuccess: async (data) => {
      setNetworkTransition(`Applying host settings; waiting for ${data.public_url}…`);
      const deadline = Date.now() + 210_000;
      while (Date.now() < deadline) {
        // While the old origin is alive it can surface an explicit rollback.
        try {
          const status = await api.get<NetworkApplyStatus>(
            `/zagros/settings/panel-network/apply-status?operation_id=${encodeURIComponent(data.operation_id)}`,
          );
          if (status.status === "failed") {
            const message = status.message || "host apply failed";
            setNetworkTransition(status.rolled_back ? `${message} (rolled back)` : message);
            toast.error(message);
            return;
          }
        } catch { /* expected while the old listener is being recreated */ }

        try {
          await probeNewOrigin(data.public_url, data.operation_id);
          setNetworkTransition("New URL is healthy and its TLS connection was accepted by the browser. Redirecting…");
          const destination = `${data.public_url.replace(/\/$/, "")}${window.location.pathname}${window.location.search}${window.location.hash}`;
          window.location.assign(destination);
          return;
        } catch { /* not healthy yet */ }
        await sleep(1000);
      }
      setNetworkTransition("Timed out waiting for the new URL. The browser was not redirected; check apply status and rollback health.");
      toast.error("new panel URL did not become browser-reachable");
    },
    onError: (e) => {
      setNetworkTransition("");
      toast.error(e instanceof ApiError ? e.message : t("common.error"));
    },
  });

  return (
    <div className="space-y-4 animate-fade-up">
      <h1 className="flex items-center gap-2 text-lg font-bold tracking-tight">
        <SettingsIcon size={18} className="text-brand" />{t("nav.settings")}
      </h1>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title={t("panel")} subtitle={t("identity & runtime (read-only, .env is the source of truth)")} />
          {info.isLoading ? <Skeleton className="h-40" /> : info.isError ? (
            <p className="py-4 text-xs text-content-3">{t(adminQueryErrorKey(info.error))}</p>
          ) : (
            <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-[12.5px]">
              <Meta k={t("version")} v={<Badge tone="brand">{info.data!.version}</Badge>} />
              <Meta k={t("app")} v={info.data!.app_name} />
              <Meta k={t("domain")} v={info.data!.domain || "—"} />
              <Meta k={t("tls mode")} v={info.data!.tls_mode} />
              <Meta k={t("database")} v={info.data!.database_driver} />
              <Meta k={t("uptime")} v={formatDuration(info.data!.uptime_seconds, digits)} />
              <Meta k={t("panel url")} v={<span className="break-all" dir="ltr">{info.data!.panel_base_url || "—"}</span>} />
              <Meta k={t("auth mode")} v={info.data!.client_auth_mode} />
            </dl>
          )}
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader title={t("Panel Network")} subtitle={t("validated host binding and managed TLS certificate")} />
          {networkQ.isError ? (
            <p className="py-4 text-xs text-content-3">{t(adminQueryErrorKey(networkQ.error))}</p>
          ) : !network ? <Skeleton className="h-56" /> : (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <Field label={t("panel domain")}><Input value={network.domain ?? ""} onChange={(e) => setNetwork({ ...network, domain: e.target.value || null })} dir="ltr" placeholder="panel.example.com" /></Field>
              <Field label={t("public port")}><Input type="number" min={1} max={65535} value={network.port} onChange={(e) => setNetwork({ ...network, port: Number(e.target.value) || 8000 })} dir="ltr" /></Field>
              <Field label={t("protocol")}><Select value={network.scheme} onChange={(e) => setNetwork({ ...network, scheme: e.target.value as "http" | "https" })}><option value="http">HTTP</option><option value="https">HTTPS</option></Select></Field>
              <Field label={t("bind address")}><Input value={network.bind_address} onChange={(e) => setNetwork({ ...network, bind_address: e.target.value })} dir="ltr" /></Field>
              <Field label={t("trusted proxies")} hint={t("comma-separated CIDRs")}><Input value={network.trusted_proxies.join(", ")} onChange={(e) => setNetwork({ ...network, trusted_proxies: e.target.value.split(",").map((v) => v.trim()).filter(Boolean) })} dir="ltr" placeholder="10.0.0.0/8" /></Field>
              <Field label={t("TLS certificate")} hint={t("required for HTTPS")}><Select value={network.tls_certificate_id ?? ""} onChange={(e) => setNetwork({ ...network, tls_certificate_id: e.target.value || null })}><option value="">{t("None (HTTP only)")}</option>{(certsQ.data?.certificates ?? []).filter((c) => c.has_key && !c.expired).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</Select></Field>
              <label className="flex items-center gap-2.5 text-sm text-content-2"><Switch checked={network.hsts} onChange={(v) => setNetwork({ ...network, hsts: v })} label={t("HSTS")} />{t("HSTS")}</label>
              <label className="flex items-center gap-2.5 text-sm text-content-2"><Switch checked={network.redirect_http_to_https} onChange={(v) => setNetwork({ ...network, redirect_http_to_https: v })} label={t("redirect HTTP to HTTPS")} />{t("Redirect HTTP → HTTPS")}</label>
              <div className="flex flex-wrap items-end gap-2 sm:col-span-2 lg:col-span-3">
                <Button variant="secondary" onClick={() => testNetwork.mutate()} loading={testNetwork.isPending}>{t("test configuration")}</Button>
                <Button variant="secondary" onClick={() => saveNetwork.mutate()} loading={saveNetwork.isPending}><Save size={14} />{t("save desired state")}</Button>
                <Button onClick={() => applyNetwork.mutate()} loading={applyNetwork.isPending}>{t("apply with rollback")}</Button>
              </div>
              {networkTransition && <p role="status" className="rounded-xl border border-brand/30 bg-brand-soft px-3 py-2 text-xs text-content-2 sm:col-span-2 lg:col-span-3">{networkTransition}</p>}
              {networkTest && <pre className="max-h-48 overflow-auto rounded-xl bg-surface p-3 text-[10px] text-content-2 sm:col-span-2 lg:col-span-3" dir="ltr">{JSON.stringify(networkTest, null, 2)}</pre>}
            </div>
          )}
        </Card>

        <Card>
          <CardHeader title={<span className="inline-flex items-center gap-2"><TerminalSquare size={16} className="text-brand" /> Advanced Mode</span>} />
          <p className="text-[12.5px] leading-6 text-content-2">{t("Advanced Mode unlocks the in-panel")}<b>{t("Config Studio")}</b>{t("raw document editor (schema validation + diff preview) and shows the")}<b>{t("nav.advanced")}</b>{t("entry in the sidebar. Everything outside it stays graphical — regular operators never touch JSON.")}</p>
          <div className="mt-4 flex items-center gap-2.5">
            <Switch checked={advancedMode} onChange={(v) => { setAdvancedMode(v); applyUiState(theme, locale); }} label={t("advanced mode")} />
            <span className="text-sm">{advancedMode ? "enabled" : "disabled"}</span>
            {advancedMode && <Badge tone="warn" dot>{t("JSON exposed in Advanced page only")}</Badge>}
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
