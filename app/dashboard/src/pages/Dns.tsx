// DNS — structured resolver editing (template, resolvers, DoH/DoT, fallback,
// cache) mapped onto the core's config document via studio patch ops.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Globe, Plus, Save, ShieldCheck, Trash2, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "../components/feedback";
import { Badge, Button, Card, CardHeader, EmptyState, Field, Input, Select, Skeleton, Switch } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useT , useTDynamic } from "../lib/i18n";
import type { CoreView } from "../lib/types";

interface DnsServer { address: string; domains?: string; detour?: string }
interface DnsModel {
  servers: DnsServer[];
  disable_cache: boolean;
  fallback: string;
  strategy: string;
}

const TEMPLATES: Record<string, DnsModel> = {
  clean: {
    servers: [{ address: "https://dns.google/dns-query" }, { address: "tls://1.1.1.1" }, { address: "1.1.1.1" }],
    disable_cache: false, fallback: "1.1.1.1", strategy: "ipv4_only",
  },
  iran: {
    servers: [
      { address: "https://dns.google/dns-query", domains: "geosite:category-ir" },
      { address: "10.202.10.202", domains: "" },
      { address: "10.202.10.102", domains: "" },
    ],
    disable_cache: false, fallback: "10.202.10.202", strategy: "ipv4_only",
  },
  privacy: {
    servers: [{ address: "https://dns.quad9.net/dns-query" }, { address: "tls://9.9.9.9" }],
    disable_cache: true, fallback: "9.9.9.9", strategy: "prefer_ipv4",
  },
};

const STRATEGIES = ["ipv4_only", "ipv6_only", "prefer_ipv4", "prefer_ipv6"];

export default function Dns() {
  const t = useT();
  const td = useTDynamic();
  const qc = useQueryClient();
  const [coreId, setCoreId] = useState("");
  const [model, setModel] = useState<DnsModel | null>(null);
  const [dirty, setDirty] = useState(false);

  const cores = useQuery({ queryKey: ["zagros", "cores"], queryFn: () => api.get<{ cores: CoreView[] }>("/zagros/cores") });
  const effectiveCore = coreId || cores.data?.cores[0]?.id || "";

  const raw = useQuery({
    queryKey: ["zagros", "studio", "raw", effectiveCore],
    queryFn: () => api.get<{ json: string }>(`/zagros/studio/${effectiveCore}/raw`),
    enabled: !!effectiveCore,
  });

  // decode current dns section from the document (core-native shape differs;
  // xray: dns{servers:[...]}; sing-box: dns{servers:[{address, detour?}]})
  useEffect(() => {
    if (!raw.data?.json) return;
    try {
      const doc = JSON.parse(raw.data.json) as { dns?: Record<string, unknown> };
      const d = doc.dns;
      if (!d) { setModel(TEMPLATES.clean); setDirty(false); return; }
      const servers: DnsServer[] = Array.isArray(d.servers)
        ? (d.servers as unknown[]).map((s) => typeof s === "string"
          ? { address: s }
          : { address: String((s as { address?: unknown }).address ?? ""), domains: String((s as { domains?: unknown }).domains ?? "") || undefined })
        : [];
      setModel({
        servers,
        disable_cache: Boolean(d.disable_cache ?? d.disableCache ?? false),
        fallback: "",
        strategy: String(d.strategy ?? d.query_strategy ?? "prefer_ipv4"),
      });
      setDirty(false);
    } catch { setModel(TEMPLATES.clean); }
  }, [raw.data, effectiveCore]);

  const save = useMutation({
    mutationFn: async () => {
      if (!model) return;
      const doc = model.servers.some((s) => s.domains)
        ? { servers: model.servers.map((s) => s.domains ? { address: s.address, domains: s.domains.split(",").map((x) => x.trim()).filter(Boolean) } : s.address), disable_cache: model.disable_cache, strategy: model.strategy }
        : { servers: model.servers.map((s) => s.address), disable_cache: model.disable_cache, strategy: model.strategy };
      const ops = [{ op: "replace", path: "/dns", value: doc }];
      const preview = await api.post<{ valid: boolean; errors: string[] }>(`/zagros/studio/${effectiveCore}/preview`, { operations: ops });
      if (!preview.valid) throw new ApiError(422, preview.errors.join("; ") || "schema rejected the dns section");
      return api.post(`/zagros/studio/${effectiveCore}/apply`, { operations: ops });
    },
    onSuccess: () => {
      toast.ok(t("common.saved")); setDirty(false);
      qc.invalidateQueries({ queryKey: ["zagros", "studio", "raw", effectiveCore] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const health = useMemo(() => {
    if (!model) return null;
    const doh = model.servers.filter((s) => s.address.startsWith("https://")).length;
    const dot = model.servers.filter((s) => s.address.startsWith("tls://")).length;
    const plain = model.servers.length - doh - dot;
    return { doh, dot, plain, encrypted: doh + dot };
  }, [model]);

  return (
    <div className="space-y-4 animate-fade-up">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <Globe size={18} className="text-brand" />{t("nav.dns")}
          {dirty && <Badge tone="warn" dot>unsaved</Badge>}
        </h1>
        <Field label={t("core")}>
          <Select value={effectiveCore} onChange={(e) => setCoreId(e.target.value)} className="w-40">
            {(cores.data?.cores ?? []).map((c) => <option key={c.id} value={c.id}>{c.id}</option>)}
            {!cores.data?.cores?.length && <option value="">—</option>}
          </Select>
        </Field>
        <Button size="sm" onClick={() => save.mutate()} loading={save.isPending} disabled={!dirty || !effectiveCore}>
          <Save size={13} /> {t("common.save")}
        </Button>
      </div>

      {!effectiveCore ? (
        <Card><EmptyState title={t("Install a core first")} /></Card>
      ) : raw.isLoading || !model ? (
        <Skeleton className="h-72" />
      ) : (
        <div className="grid gap-4 lg:grid-cols-3">
          <Card className="lg:col-span-2">
            <CardHeader title={t("resolvers")} subtitle={t("queried top-down; optionally pinned to domains")}
              actions={<Button size="sm" variant="secondary" onClick={() => { setModel({ ...model, servers: [...model.servers, { address: "" }] }); setDirty(true); }}><Plus size={13} />{t("resolver")}</Button>} />
            <div className="space-y-2.5">
              {model.servers.map((s, i) => (
                <div key={i} className="grid gap-2 rounded-xl border border-border p-3 sm:grid-cols-[1fr_200px_36px]">
                  <Input value={s.address} dir="ltr" placeholder="https://dns.google/dns-query · tls://1.1.1.1 · 8.8.8.8"
                    onChange={(e) => { const servers = [...model.servers]; servers[i] = { ...s, address: e.target.value }; setModel({ ...model, servers }); setDirty(true); }} />
                  <Input value={s.domains ?? ""} dir="ltr" placeholder="domains (optional) geosite:ir"
                    onChange={(e) => { const servers = [...model.servers]; servers[i] = { ...s, domains: e.target.value }; setModel({ ...model, servers }); setDirty(true); }} />
                  <Button variant="ghost" size="icon" aria-label={t("remove resolver")}
                    onClick={() => { setModel({ ...model, servers: model.servers.filter((_, xi) => xi !== i) }); setDirty(true); }}>
                    <Trash2 size={14} />
                  </Button>
                </div>
              ))}
              {model.servers.length === 0 && <p className="py-4 text-center text-xs text-content-3">{t("no resolvers — add one or apply a template")}</p>}
            </div>

            <div className="mt-5 grid gap-4 border-t border-border pt-4 sm:grid-cols-3">
              <Field label={t("fallback resolver")} hint={t("used when all others time out")}>
                <Input value={model.fallback} dir="ltr" placeholder="1.1.1.1"
                  onChange={(e) => { setModel({ ...model, fallback: e.target.value }); setDirty(true); }} />
              </Field>
              <Field label={t("resolution strategy")}>
                <Select value={model.strategy} onChange={(e) => { setModel({ ...model, strategy: e.target.value }); setDirty(true); }}>
                  {STRATEGIES.map((s) => <option key={s} value={s}>{s}</option>)}
                </Select>
              </Field>
              <Field label={t("cache")} hint={t("core-side answer cache")}>
                <div className="flex h-9 items-center gap-2.5">
                  <Switch checked={!model.disable_cache} onChange={(v) => { setModel({ ...model, disable_cache: !v }); setDirty(true); }} label={t("cache")} />
                  <span className="text-xs text-content-2">{model.disable_cache ? "off" : "on"}</span>
                </div>
              </Field>
            </div>
          </Card>

          <div className="space-y-4">
            <Card>
              <CardHeader title={t("health")} subtitle={t("shape of the resolver set")} />
              <div className="space-y-2.5 text-[13px]">
                <HealthRow ok={health!.encrypted > 0}
                  label={t("{doh} DoH + {dot} DoT encrypted", { doh: health!.doh, dot: health!.dot })}
                  detail={health!.encrypted > 0 ? t("plaintext spoofing resistant") : t("all resolvers are plaintext")} />
                <HealthRow ok={model.servers.length >= 2}
                  label={t("{count} resolver(s)", { count: model.servers.length })}
                  detail={model.servers.length >= 2 ? t("redundant") : t("single point of failure")} />
                <HealthRow ok={!model.servers.some((s) => !s.address.trim())} label={t("no empty entries")} detail="" />
              </div>
            </Card>
            <Card>
              <CardHeader title={t("templates")} subtitle={t("replace the resolver set")} />
              <div className="grid gap-2">
                {(Object.keys(TEMPLATES) as (keyof typeof TEMPLATES)[]).map((k) => (
                  <button key={k} onClick={() => { setModel(structuredClone(TEMPLATES[k])); setDirty(true); }}
                    className="rounded-xl border border-border p-3 text-start transition-colors hover:border-brand">
                    <p className="text-[13px] font-semibold capitalize">{td(k)}</p>
                    <p className="mt-0.5 text-[11px] text-content-3">
                      {k === "clean" ? t("Google DoH + Cloudflare DoT — sane default")
                        : k === "iran" ? t("Shecan (403) fallback for IR split-routing")
                        : t("Quad9 filtering, cache disabled")}
                    </p>
                  </button>
                ))}
              </div>
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}

function HealthRow({ ok, label, detail }: { ok: boolean; label: string; detail: string }) {
  return (
    <div className="flex items-start gap-2.5 rounded-xl border border-border p-3">
      {ok ? <CheckCircle2 size={16} className="mt-0.5 text-ok" /> : <XCircle size={16} className="mt-0.5 text-warn" />}
      <div>
        <p className="font-medium">{label}</p>
        {detail && <p className="text-[11px] text-content-3">{detail}</p>}
      </div>
    </div>
  );
}
