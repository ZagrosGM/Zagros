// Routing — graphical Rule Builder with drag & drop ordering + save / dry
// preview / one-click deploy. Zero JSON (advanced users live in Advanced Mode).
import { DndContext, PointerSensor, closestCenter, useSensor, useSensors, type DragEndEvent } from "@dnd-kit/core";
import { SortableContext, arrayMove, useSortable, verticalListSortingStrategy } from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, GripVertical, Plus, Rocket, Route as RouteIcon, Save, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "../components/feedback";
import { Dialog } from "../components/overlays";
import { Badge, Button, Card, CardHeader, EmptyState, Field, Input, Select, Switch, cn } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useT } from "../lib/i18n";
import type { OutboundsResponse, RoutePreview, RoutingRule } from "../lib/types";

const ACTIONS = ["allow", "block", "route_to", "redirect", "dns", "fake_dns", "dns_override"] as const;
const GEO_DEFAULT = ["ir", "cn", "ru", "us", "de", "ae", "tr", "private"];
const PROTOCOL_HINT = ["http", "tls", "quic", "bittorrent"];
const NETWORKS = ["tcp", "udp", "tcp,udp"];

function emptyRule(priority: number): RoutingRule {
  return { name: "", matcher: {}, action: "block", outbound: null, redirect_to: null, dns_server: null, priority, enabled: true };
}

export default function Routing() {
  const t = useT();
  const qc = useQueryClient();
  const [rules, setRules] = useState<RoutingRule[]>([]);
  const [editIdx, setEditIdx] = useState<number | null>(null);
  const [dirty, setDirty] = useState(false);
  const [preview, setPreview] = useState<RoutePreview | null>(null);

  const load = useQuery({
    queryKey: ["zagros", "routing"],
    queryFn: () => api.get<{ rules: RoutingRule[] }>("/zagros/routing/rules"),
  });
  const outbounds = useQuery({
    queryKey: ["zagros", "outbounds"],
    queryFn: () => api.get<OutboundsResponse>("/zagros/outbounds"),
    staleTime: 30000,
  });

  useEffect(() => {
    if (load.data) setRules(load.data.rules);
  }, [load.data]);

  const markDirty = (next: RoutingRule[]) => { setRules(next); setDirty(true); };

  const save = useMutation({
    mutationFn: () => api.put("/zagros/routing/rules", { rules }),
    onSuccess: () => { toast.ok(t("common.saved")); setDirty(false); qc.invalidateQueries({ queryKey: ["zagros", "routing"] }); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });
  const dryRun = useMutation({
    mutationFn: () => api.post<RoutePreview>("/zagros/routing/preview", { rules }),
    onSuccess: (data) => setPreview(data),
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });
  const deploy = useMutation({
    mutationFn: () => api.post<{ saved: boolean; report?: unknown }>("/zagros/routing/deploy", { rules }),
    onSuccess: () => { toast.ok("deployed to all routing-capable cores"); setDirty(false); qc.invalidateQueries({ queryKey: ["zagros", "routing"] }); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 6 } }));
  const onDragEnd = (e: DragEndEvent) => {
    if (!e.over || e.active.id === e.over.id) return;
    const from = rules.findIndex((r) => r.name === e.active.id);
    const to = rules.findIndex((r) => r.name === e.over!.id);
    if (from < 0 || to < 0) return;
    markDirty(arrayMove(rules, from, to).map((r, i) => ({ ...r, priority: (i + 1) * 10 })));
  };

  const outboundNames = useMemo(() => (outbounds.data?.outbounds ?? [])
    .filter((o) => {
      const capability = outbounds.data?.capabilities?.[o.kind];
      return o.enabled && capability?.state === "supported" && capability.tun;
    })
    .map((o) => o.name), [outbounds.data]);
  const nonTunOutbounds = useMemo(() => (outbounds.data?.outbounds ?? [])
    .filter((o) => o.enabled && outbounds.data?.capabilities?.[o.kind]?.tun === false)
    .map((o) => ({ name: o.name, reason: outbounds.data?.capabilities?.[o.kind]?.reason })), [outbounds.data]);

  return (
    <div className="space-y-4 animate-fade-up">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <RouteIcon size={18} className="text-brand" />{t("nav.routing")}
          {dirty && <Badge tone="warn" dot>unsaved</Badge>}
        </h1>
        <Button variant="secondary" size="sm" onClick={() => dryRun.mutate()} loading={dryRun.isPending} disabled={!rules.length}>
          <Eye size={13} /> {t("common.preview")}
        </Button>
        <Button variant="secondary" size="sm" onClick={() => save.mutate()} loading={save.isPending} disabled={!dirty}>
          <Save size={13} /> {t("common.save")}
        </Button>
        <Button size="sm" onClick={() => deploy.mutate()} loading={deploy.isPending} disabled={!rules.length}>
          <Rocket size={13} /> {t("common.deploy")}
        </Button>
        <Button size="sm" variant="secondary" onClick={() => setEditIdx(-1) /* -1 = new */}>
          <Plus size={13} /> rule
        </Button>
      </div>

      <p className="text-xs text-content-3">
        Rules are evaluated by priority, first match wins. Drag cards to reorder — priorities renumber automatically (10, 20, 30…).
      </p>
      <p className="rounded-xl border border-warn/30 bg-warn-soft px-3 py-2 text-[11px] text-warn">
        SoftEther architecture: L2TP, SSTP and native sessions in one SoftEther instance share a single Virtual Hub/TAP source subnet. They must use one shared egress decision; different per-transport outbounds are rejected before Save/Deploy. Separate decisions require separate SoftEther instances/hubs.
      </p>
      {nonTunOutbounds.length > 0 && (
        <div className="rounded-xl border border-warn/30 bg-warn-soft px-3 py-2 text-[11px] text-warn">
          Application-only outbounds are excluded from policy TUN targets: {nonTunOutbounds.map((o) => o.name).join(", ")}.
          {nonTunOutbounds.some((o) => o.reason) && <span> {nonTunOutbounds.find((o) => o.reason)?.reason}</span>}
        </div>
      )}

      {load.isLoading ? null : rules.length === 0 ? (
        <Card>
          <EmptyState
            title="No routing rules"
            hint={'Example: IF inbound is "reality-in" AND country is IR THEN route through "warp-up" outbound.'}
            action={<Button size="sm" onClick={() => setEditIdx(-1)}><Plus size={13} /> create rule</Button>}
          />
        </Card>
      ) : (
        <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={onDragEnd}>
          <SortableContext items={rules.map((r) => r.name)} strategy={verticalListSortingStrategy}>
            <div className="space-y-2.5">
              {rules.map((r, i) => (
                <RuleCard
                  key={r.name || `rule-${i}`}
                  rule={r}
                  onEdit={() => setEditIdx(i)}
                  onToggle={(v) => markDirty(rules.map((x, xi) => xi === i ? { ...x, enabled: v } : x))}
                  onDelete={() => markDirty(rules.filter((_, xi) => xi !== i))}
                />
              ))}
            </div>
          </SortableContext>
        </DndContext>
      )}

      {preview && (
        <Card>
          <CardHeader title="Dry preview — what every core would accept" subtitle="nothing was sent to the cores" />
          <div className="space-y-3">
            {Object.entries(preview.results ?? {}).map(([core, res]) => (
              <div key={core} className="rounded-xl border border-border p-3.5">
                <div className="mb-2 flex items-center gap-2">
                  <Badge tone="brand">{core}</Badge>
                  <span className="text-[11px] text-content-3">
                    {res.applied?.length ?? 0} applicable · {res.unsupported?.length ?? 0} unsupported
                  </span>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {res.applied?.map((n) => <Badge key={n} tone="ok">{n}</Badge>)}
                  {res.unsupported?.map((g) => (
                    <Badge key={g.rule} tone="warn">{g.rule}: {g.reason}</Badge>
                  ))}
                </div>
              </div>
            ))}
            {Object.keys(preview.results ?? {}).length === 0 && (
              <p className="text-xs text-content-3">No routing-capable core is installed — the matrix is empty.</p>
            )}
          </div>
        </Card>
      )}

      {editIdx !== null && (
        <RuleDialog
          rule={editIdx >= 0 ? rules[editIdx] : emptyRule((rules.length + 1) * 10)}
          outbounds={outboundNames}
          existingNames={rules.filter((_, i) => i !== editIdx).map((r) => r.name)}
          onClose={() => setEditIdx(null)}
          onSave={(r) => {
            markDirty(editIdx >= 0 ? rules.map((x, i) => i === editIdx ? r : x) : [...rules, r]);
            setEditIdx(null);
          }}
        />
      )}
    </div>
  );
}

function RuleCard({ rule, onEdit, onToggle, onDelete }: {
  rule: RoutingRule; onEdit: () => void; onToggle: (v: boolean) => void; onDelete: () => void;
}) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id: rule.name });
  return (
    <div
      ref={setNodeRef}
      style={{ transform: CSS.Transform.toString(transform), transition }}
      className={cn("card flex items-center gap-3 p-3.5", isDragging && "z-10 shadow-pop border-brand", !rule.enabled && "opacity-60")}
    >
      <button {...attributes} {...listeners} aria-label="drag to reorder"
        className="cursor-grab touch-none rounded-lg p-1.5 text-content-3 hover:bg-surface-2 hover:text-content active:cursor-grabbing">
        <GripVertical size={15} />
      </button>
      <Badge tone="muted" >#{rule.priority}</Badge>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-semibold">{rule.name || "(unnamed)"}</span>
          <Badge tone={rule.action === "block" ? "danger" : rule.action === "route_to" ? "brand" : "info"}>
            {rule.action}{rule.outbound ? ` → ${rule.outbound}` : rule.redirect_to ? ` → ${rule.redirect_to}` : rule.dns_server ? ` → ${rule.dns_server}` : ""}
          </Badge>
        </div>
        <MatcherSummary rule={rule} />
      </div>
      <Switch checked={rule.enabled} onChange={onToggle} label="enabled" />
      <Button variant="ghost" size="sm" onClick={onEdit}>edit</Button>
      <Button variant="ghost" size="icon" onClick={onDelete} aria-label="delete rule"><Trash2 size={14} /></Button>
    </div>
  );
}

function MatcherSummary({ rule }: { rule: RoutingRule }) {
  const m = rule.matcher ?? {};
  const chips: string[] = [];
  if (m.inbounds?.length) chips.push(`inbound ∈ {${m.inbounds.join(", ")}}`);
  if (m.domains?.length) chips.push(`domains: ${m.domains.slice(0, 3).join(", ")}${m.domains.length > 3 ? "…" : ""}`);
  if (m.domain_suffixes?.length) chips.push(`suffix: ${m.domain_suffixes.slice(0, 2).join(", ")}`);
  if (m.geoips?.length) chips.push(`country ∈ {${m.geoips.join(", ").toUpperCase()}}`);
  if (m.ciders?.length) chips.push(`ip: ${m.ciders.slice(0, 2).join(", ")}`);
  if (m.ports?.length) chips.push(`port ${m.ports.join(", ")}`);
  if (m.protocols?.length) chips.push(`proto: ${m.protocols.join(", ")}`);
  if (m.networks?.length) chips.push(`net: ${m.networks.join(", ")}`);
  if (m.process_names?.length) chips.push(`proc: ${m.process_names.join(", ")}`);
  return (
    <p className="mt-1 truncate text-[11px] text-content-3">
      {chips.length ? chips.join("   ·   ") : "matches ALL traffic"}
    </p>
  );
}

// List editor for chip-style values (domains, geoips…)
function ChipField({ label, values, onChange, placeholder, datalist }: {
  label: string; values: string[]; onChange: (v: string[]) => void; placeholder?: string; datalist?: string[];
}) {
  const [text, setText] = useState("");
  const id = `dl-${label.replace(/\W+/g, "-")}`;
  const add = () => {
    const v = text.trim().toLowerCase();
    if (v && !values.includes(v)) onChange([...values, v]);
    setText("");
  };
  return (
    <Field label={label}>
      <div className="flex flex-wrap items-center gap-1.5 rounded-xl border border-border p-2">
        {values.map((v) => (
          <span key={v} className="inline-flex items-center gap-1 rounded-lg bg-surface-3 px-2 py-1 text-[11px]">
            {v}
            <button type="button" aria-label={`remove ${v}`} onClick={() => onChange(values.filter((x) => x !== v))}
              className="text-content-3 hover:text-danger">×</button>
          </span>
        ))}
        <input
          value={text}
          list={datalist ? id : undefined}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); add(); } }}
          onBlur={add}
          placeholder={placeholder ?? "type + Enter"}
          className="min-w-[7rem] flex-1 bg-transparent px-1 py-1 text-xs outline-none placeholder:text-content-3"
        />
        {datalist && <datalist id={id}>{datalist.map((d) => <option key={d} value={d} />)}</datalist>}
      </div>
    </Field>
  );
}

function RuleDialog({ rule, outbounds, existingNames, onClose, onSave }: {
  rule: RoutingRule; outbounds: string[]; existingNames: string[];
  onClose: () => void; onSave: (r: RoutingRule) => void;
}) {
  const t = useT();
  const [r, setR] = useState<RoutingRule>(structuredClone(rule));
  const [error, setError] = useState("");
  const m = r.matcher ?? {};

  const setMatcher = (patch: Partial<RoutingRule["matcher"]>) =>
    setR({ ...r, matcher: { ...m, ...patch } });

  const needsOutbound = r.action === "route_to";
  const needsRedirect = r.action === "redirect";
  const needsDns = r.action === "dns" || r.action === "dns_override" || r.action === "fake_dns";

  const validate = () => {
    if (!r.name.trim()) return "name is required";
    if (existingNames.includes(r.name.trim())) return `a rule named "${r.name.trim()}" already exists`;
    if (needsOutbound && !r.outbound) return "route_to needs a target outbound";
    if (needsRedirect && !r.redirect_to) return "redirect needs a target address";
    if (needsDns && !r.dns_server) return "dns action needs a dns server";
    return "";
  };

  return (
    <Dialog open onClose={onClose} title={existingNames.includes(r.name) || rule.name ? `edit — ${rule.name || "rule"}` : "new rule"}
      wide
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button onClick={() => {
            const err = validate();
            if (err) return setError(err);
            onSave({ ...r, name: r.name.trim() });
          }}>{t("common.save")}</Button>
        </>
      }>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="rule name" required>
          <Input value={r.name} onChange={(e) => setR({ ...r, name: e.target.value })} placeholder="iran-via-warp" />
        </Field>
        <Field label="priority" hint="lower = evaluated earlier (Dragging cards renumbers)">
          <Input type="number" value={r.priority} onChange={(e) => setR({ ...r, priority: Number(e.target.value) || 100 })} />
        </Field>

        <div className="sm:col-span-2 grid gap-4 rounded-xl border border-border p-3.5">
          <p className="text-[11px] font-semibold uppercase tracking-wide text-content-3">IF — matchers (all must match)</p>
          <ChipField label="inbound tags" values={m.inbounds ?? []} onChange={(v) => setMatcher({ inbounds: v })}
            placeholder="reality-in" />
          <ChipField label="domains / geosites" values={m.domains ?? []} onChange={(v) => setMatcher({ domains: v })}
            placeholder="geosite:category-ir / example.com" />
          <div className="grid gap-4 sm:grid-cols-2">
            <ChipField label="country (GeoIP)" values={m.geoips ?? []} onChange={(v) => setMatcher({ geoips: v })}
              datalist={GEO_DEFAULT} placeholder="ir" />
            <ChipField label="protocol" values={m.protocols ?? []} onChange={(v) => setMatcher({ protocols: v })}
              datalist={PROTOCOL_HINT} placeholder="bittorrent" />
            <ChipField label="target CIDR" values={m.ciders ?? []} onChange={(v) => setMatcher({ ciders: v })}
              placeholder="geoip:private / 1.2.3.0/24" />
            <ChipField label="ports" values={m.ports ?? []} onChange={(v) => setMatcher({ ports: v })}
              placeholder="53 / 1000-2000" />
            <Field label="network">
              <Select value={(m.networks ?? []).join(",")} onChange={(e) => setMatcher({ networks: e.target.value ? [e.target.value] : [] })}>
                <option value="">any</option>
                {NETWORKS.map((n) => <option key={n} value={n}>{n}</option>)}
              </Select>
            </Field>
            <ChipField label="process names" values={m.process_names ?? []} onChange={(v) => setMatcher({ process_names: v })}
              placeholder="chrome.exe (sing-box only)" />
          </div>
        </div>

        <div className="sm:col-span-2 grid gap-4 rounded-xl border border-border p-3.5 sm:grid-cols-2">
          <p className="text-[11px] font-semibold uppercase tracking-wide text-content-3 sm:col-span-2">THEN — action</p>
          <Field label="action" required>
            <Select value={r.action} onChange={(e) => setR({ ...r, action: e.target.value as RoutingRule["action"] })}>
              {ACTIONS.map((a) => <option key={a} value={a}>{a}</option>)}
            </Select>
          </Field>
          {needsOutbound && (
            <Field label="target outbound" required>
              <Select value={r.outbound ?? ""} onChange={(e) => setR({ ...r, outbound: e.target.value || null })}>
                <option value="">— choose —</option>
                {outbounds.map((o) => <option key={o} value={o}>{o}</option>)}
              </Select>
            </Field>
          )}
          {needsRedirect && (
            <Field label="redirect to" required>
              <Input value={r.redirect_to ?? ""} onChange={(e) => setR({ ...r, redirect_to: e.target.value || null })} placeholder="127.0.0.1:8080" dir="ltr" />
            </Field>
          )}
          {needsDns && (
            <Field label="dns server" required>
              <Input value={r.dns_server ?? ""} onChange={(e) => setR({ ...r, dns_server: e.target.value || null })} placeholder="https://dns.google/dns-query" dir="ltr" />
            </Field>
          )}
          <label className="flex items-center gap-2.5 text-sm text-content-2">
            <Switch checked={r.enabled} onChange={(v) => setR({ ...r, enabled: v })} label="enabled" />
            rule active
          </label>
        </div>
      </div>
      {error && <p role="alert" className="mt-3 rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}
