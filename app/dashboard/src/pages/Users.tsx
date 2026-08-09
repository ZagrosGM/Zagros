// Users — full management: virtualized table, advanced filters, inline status,
// bulk actions, create/edit dialog (access mode = subscription link OR
// application login), per-user quick actions. No JSON anywhere.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Ban, Check, ChevronDown, Copy, Dices, ExternalLink, Filter, Link2, MoreHorizontal,
  Plus, RefreshCcw, Search, Trash2, UserPlus, Users as UsersIcon,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { DataTable, type Column } from "../components/DataTable";
import { toast } from "../components/feedback";
import { ConfirmDialog, Dialog, RowMenu } from "../components/overlays";
import { Badge, Button, Card, EmptyState, Field, Input, Progress, Select, Switch, Tooltip, cn } from "../components/ui";
import CoreAccessPicker from "../components/CoreAccessPicker";
import { api, ApiError } from "../lib/api";
import { copyText } from "../lib/clipboard";
import { XRAY_CORE_ID, allCoreAccess, allLegacySelected } from "../lib/inboundTree";
import { randomUsername } from "../lib/username";
import { useDigits, formatBytes, formatDate, formatRelative, usagePercent } from "../lib/format";
import { useT } from "../lib/i18n";
import type { User, UsersResponse, UserStatus, UserTemplate , InboundCatalogGroup } from "../lib/types";

const STATUS_TONE: Record<UserStatus, "ok" | "muted" | "warn" | "danger" | "info"> = {
  active: "ok", disabled: "muted", limited: "warn", expired: "danger", on_hold: "info",
};
const ALL_STATUSES: UserStatus[] = ["active", "disabled", "limited", "expired", "on_hold"];

interface UserForm {
  username: string;
  note: string;
  status: UserStatus;
  dataLimitGB: string;
  /** global device limit as text ("" / "0" = unlimited), all cores combined */
  deviceLimit: string;
  expireDate: string;
  /** alpha.7: creation mode — from a template, or manual inbound picking */
  mode: "template" | "manual";
  templateId: number | null;
  /** protocol -> selected tags ([] = every inbound of the protocol) */
  inbounds: Record<string, string[]>;
  /** multi-core grants: core_id -> inbound tags ([] revokes that core) */
  coreAccess: Record<string, string[]>;
  telegramId: string;
}

const emptyForm: UserForm = {
  username: "", note: "", status: "active", dataLimitGB: "", deviceLimit: "", expireDate: "",
  mode: "manual", templateId: null, inbounds: {}, coreAccess: {}, telegramId: "",
};

/** The legacy API sends subscription_url as a RELATIVE /sub/... path (never
 * as the `sub_url` the older UI code read — that mismatch silently broke the
 * copy action). Make it absolute against the serving origin. */
function absolutizeSub(path: string | null | undefined): string | null {
  if (!path) return null;
  if (/^https?:\/\//i.test(path)) return path;
  return `${window.location.origin}${path.startsWith("/") ? path : `/${path}`}`;
}

/** Per-row one-click subscription link copy with a tooltip (α7.1, item 7):
 *  visible without opening the overflow menu, disabled when the user has no
 *  link instead of failing late. */
function CopySubButton({ u, copySub }: { u: User; copySub: (u: User) => void }) {
  const t = useT();
  const [done, setDone] = useState(false);
  const hasLink = absolutizeSub(u.subscription_url ?? u.sub_url) !== null;
  return (
    <Tooltip label={done ? t("common.copied") : t("users.copySub")}>
      <button
        type="button"
        aria-label={t("users.copySub")}
        disabled={!hasLink}
        onClick={() => { copySub(u); setDone(true); setTimeout(() => setDone(false), 1600); }}
        className="rounded-lg p-1.5 text-content-3 hover:bg-surface-3 hover:text-content disabled:pointer-events-none disabled:opacity-40"
      >
        {done ? <Check size={15} className="text-ok" /> : <Link2 size={15} />}
      </button>
    </Tooltip>
  );
}

export default function Users() {
  const t = useT();
  const digits = useDigits();
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [ownerFilter, setOwnerFilter] = useState<string>("all");
  const [showFilters, setShowFilters] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [dialog, setDialog] = useState<{ mode: "create" } | { mode: "edit"; user: User } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<User | null>(null);
  // α7.2: the row menu is portal-mounted (RowMenu) → track the anchor element
  const [menu, setMenu] = useState<{ user: User; anchor: HTMLElement } | null>(null);

  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["users", search, statusFilter, ownerFilter],
    queryFn: () => {
      const p = new URLSearchParams();
      if (search) p.set("search", search);
      if (statusFilter !== "all") p.set("status", statusFilter);
      if (ownerFilter !== "all") p.set("admin", ownerFilter);
      const qs = p.toString();
      return api.get<UsersResponse>(`/users${qs ? `?${qs}` : ""}`);
    },
    placeholderData: (prev) => prev,
  });
  // item 14: real multi-core online signal (core sessions/presence; never
  // a UI guess). unknown = some core failed its read, so "no session" is
  // not asserted as "offline".
  const onlineQ = useQuery({
    queryKey: ["users-online"],
    queryFn: () => api.get<{ states: Record<string, "online" | "offline" | "unknown">; collect_ts?: number; failed_cores: string[] }>("/zagros/users/online"),
    refetchInterval: 15000,
  });
  const onlineMap = onlineQ.data?.states ?? {};
  const templatesQ = useQuery({
    queryKey: ["user_templates"],
    queryFn: () => api.get<UserTemplate[]>("/user_template"),
    staleTime: 30000,
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: ["users"] });

  const setStatus = useMutation({
    mutationFn: ({ username, status }: { username: string; status: UserStatus }) =>
      api.put(`/user/${username}`, { status }),
    onSuccess: () => { toast.ok(t("common.saved")); invalidate(); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });
  const deleteUser = useMutation({
    mutationFn: (username: string) => api.delete(`/user/${username}`),
    onSuccess: () => { toast.ok(t("common.deleted")); setConfirmDelete(null); invalidate(); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });
  const resetUsage = useMutation({
    mutationFn: (username: string) => api.post(`/user/${username}/reset`),
    onSuccess: () => { toast.ok("usage reset"); invalidate(); },
  });
  const revokeSub = useMutation({
    mutationFn: (username: string) => api.post(`/user/${username}/revoke_sub`),
    onSuccess: () => { toast.ok("subscription revoked"); invalidate(); },
  });

  const users = useMemo(() => data?.users ?? [], [data]);
  const owners = useMemo(() => [...new Set(users.map((u) => u.admin).filter(Boolean))] as string[], [users]);
  const catalogQ = useQuery({
    queryKey: ["zagros", "inbounds-catalog"],
    queryFn: () => api.get<{ groups: InboundCatalogGroup[] }>("/zagros/inbounds"),
  });
  const templates = useMemo(() => templatesQ.data ?? [], [templatesQ.data]);

  const bulk = async (action: "activate" | "disable" | "delete") => {
    const names = [...selected];
    setSelected(new Set());
    let failures = 0;
    for (const username of names) {
      try {
        if (action === "delete") await api.delete(`/user/${username}`);
        else await api.put(`/user/${username}`, { status: action === "activate" ? "active" : "disabled" });
      } catch { failures++; }
    }
    if (failures) toast.error(`${failures} ${t("common.error").toLowerCase()}`);
    else toast.ok(t("common.saved"));
    invalidate();
  };

  // α7.2 (item 16): copyText falls back to execCommand on plain-HTTP panels
  // where navigator.clipboard does not exist at all; report the real result.
  const copySub = async (u: User) => {
    const link = absolutizeSub(u.subscription_url ?? u.sub_url);
    if (!link) return toast.error("no subscription link");
    (await copyText(link)) ? toast.ok(t("common.copied")) : toast.error(t("common.error"));
  };

  const allChecked = users.length > 0 && users.every((u) => selected.has(u.username));

  const columns: Column<User>[] = [
    {
      id: "sel", width: "38px", header: (
        <input type="checkbox" aria-label="Select all" checked={allChecked}
          onChange={(e) => setSelected(e.target.checked ? new Set(users.map((u) => u.username)) : new Set())} />
      ),
      cell: (u) => (
        <input type="checkbox" aria-label={`select ${u.username}`} checked={selected.has(u.username)}
          onClick={(e) => e.stopPropagation()}
          onChange={(e) => {
            const next = new Set(selected);
            e.target.checked ? next.add(u.username) : next.delete(u.username);
            setSelected(next);
          }} />
      ),
    },
    {
      id: "user", header: t("users.title"), cell: (u) => (
        <div className="flex min-w-0 items-center gap-2.5">
          {/* item 15: the account-status lamp is gone — one presence dot only:
              online = session on ≥1 core (green), offline = no session and
              every online-capable core answered (gray), unknown = a core
              failed its read OR the deployment has no online API at all
              (gray + honest title). Account status lives in its own column. */}
          <span
            role="img"
            aria-label={`presence ${onlineMap[u.username] ?? "unknown"}`}
            title={onlineMap[u.username] === "online"
              ? "online (session on ≥1 core)"
              : onlineMap[u.username] === "offline"
                ? "offline (no session on any online-capable core)"
                : (onlineQ.data?.failed_cores?.length
                    ? `presence unknown (${onlineQ.data.failed_cores.join(", ")} failed its read)`
                    : "presence unknown (no online-capable core on this deployment)")}
            className={`inline-block h-2 w-2 shrink-0 rounded-full ${onlineMap[u.username] === "online" ? "bg-ok" : "bg-content-3/50"}`}
          />
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="truncate font-medium">{u.username}</span>
              {u.app_username && <Badge tone="info">app</Badge>}
            </div>
            {u.core_access && Object.keys(u.core_access).length > 0 && (
              <div className="mt-0.5 flex flex-wrap gap-1">
                {Object.entries(u.core_access).map(([core, tags]) => (
                  <Badge key={core} tone="brand">{core} · {tags.length}</Badge>
                ))}
              </div>
            )}
            {u.note && <p className="truncate text-[11px] text-content-3">{u.note}</p>}
          </div>
        </div>
      ),
    },
    {
      id: "status", header: t("common.status"), width: "130px",
      cell: (u) => (
        <button
          className="inline-flex items-center gap-1"
          title="toggle active/disabled"
          onClick={(e) => { e.stopPropagation(); setStatus.mutate({ username: u.username, status: u.status === "active" ? "disabled" : "active" }); }}
        >
          <Badge tone={STATUS_TONE[u.status]} dot>{u.status}</Badge>
          <ChevronDown size={12} className="text-content-3" />
        </button>
      ),
    },
    {
      id: "usage", header: t("users.used"), width: "180px",
      cell: (u) => {
        const pct = usagePercent(u);
        return (
          <div className="w-full">
            <div className="mb-1 flex justify-between gap-2 text-[11px] tabular-nums">
              <span>{formatBytes(u.used_traffic, digits)}</span>
              <span className="text-content-3">{u.data_limit ? formatBytes(u.data_limit, digits) : "∞"}</span>
            </div>
            <Progress value={pct} tone={pct > 90 ? "danger" : pct > 70 ? "warn" : "brand"} />
          </div>
        );
      },
    },
    { id: "expire", header: t("users.expire"), width: "130px", cell: (u) => <span className="text-[12px] tabular-nums text-content-2">{formatDate(u.expire, digits)}</span> },
    { id: "owner", header: t("users.admin"), width: "110px", cell: (u) => {
        const owner = u.admin == null ? "—" : typeof u.admin === "string" ? u.admin : u.admin.username ?? "—";
        return <span className="text-[12px] text-content-2">{owner}</span>;
      } },
    { id: "online", header: t("users.lastOnline"), width: "120px", cell: (u) => <span className="text-[12px] text-content-3">{formatRelative(u.online_at, digits)}</span> },
    {
      id: "actions", header: "", width: "82px",
      cell: (u) => (
        <div className="relative flex items-center justify-end gap-0.5" onClick={(e) => e.stopPropagation()}>
          <CopySubButton u={u} copySub={copySub} />
          <button aria-label="actions"
            onClick={(e) => setMenu((m) => (m?.user.username === u.username ? null : { user: u, anchor: e.currentTarget }))}
            className="rounded-lg p-1.5 text-content-3 hover:bg-surface-3 hover:text-content">
            <MoreHorizontal size={16} />
          </button>
        </div>
      ),
    },
  ];

  // One portal-mounted menu instance for the whole table (never clipped).
  const mu = menu?.user;
  const rowMenu = (
    <RowMenu open={!!menu} anchor={menu?.anchor ?? null} onClose={() => setMenu(null)}>
      {mu && (
        <>
          <MenuItem icon={<ExternalLink size={14} />} label={t("common.edit")} onClick={() => { setMenu(null); setDialog({ mode: "edit", user: mu }); }} />
          <MenuItem icon={<Copy size={14} />} label={t("users.copySub")} onClick={() => { setMenu(null); copySub(mu); }} />
          <MenuItem icon={<RefreshCcw size={14} />} label={t("users.resetUsage")} onClick={() => { setMenu(null); resetUsage.mutate(mu.username); }} />
          <MenuItem icon={<Link2 size={14} />} label={t("users.revokeSub")} onClick={() => { setMenu(null); revokeSub.mutate(mu.username); }} />
          <div className="my-1 border-t border-border" />
          <MenuItem icon={<Trash2 size={14} />} label={t("common.delete")} danger
            onClick={() => { setMenu(null); setConfirmDelete(mu); }} />
        </>
      )}
    </RowMenu>
  );

  return (
    <div className="space-y-4 animate-fade-up">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <UsersIcon size={18} className="text-brand" />{t("users.title")}
          <span className="text-xs font-normal text-content-3 tabular-nums">({digits(String(data?.total ?? 0))})</span>
        </h1>
        <div className="relative">
          <Search size={14} className="absolute start-3 top-1/2 -translate-y-1/2 text-content-3" />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder={t("common.search")}
            className="w-52 ps-8" aria-label="search users" />
        </div>
        <Button variant={showFilters ? "secondary" : "ghost"} size="sm" onClick={() => setShowFilters((v) => !v)}>
          <Filter size={14} /> <span className="hidden sm:inline">filters</span>
        </Button>
        <Button variant="ghost" size="icon" onClick={() => refetch()} aria-label={t("common.refresh")}>
          <RefreshCcw size={15} className={cn(isFetching && "animate-spin")} />
        </Button>
        <Button size="sm" onClick={() => setDialog({ mode: "create" })}><UserPlus size={14} />{t("users.new")}</Button>
      </div>

      {showFilters && (
        <Card className="flex flex-wrap items-end gap-3 p-3.5">
          <Field label={t("users.filter.status")}>
            <Select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="w-36">
              <option value="all">{t("common.all")}</option>
              {ALL_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
            </Select>
          </Field>
          <Field label={t("users.filter.owner")}>
            <Select value={ownerFilter} onChange={(e) => setOwnerFilter(e.target.value)} className="w-36">
              <option value="all">{t("common.all")}</option>
              {owners.map((o) => <option key={o} value={o}>{o}</option>)}
            </Select>
          </Field>
          {(statusFilter !== "all" || ownerFilter !== "all") && (
            <Button variant="ghost" size="sm" onClick={() => { setStatusFilter("all"); setOwnerFilter("all"); }}>reset</Button>
          )}
        </Card>
      )}

      {selected.size > 0 && (
        <Card className="flex items-center gap-3 border-brand/40 bg-brand-soft/40 p-3">
          <span className="text-xs font-medium text-brand tabular-nums">{digits(String(selected.size))} {t("users.bulkSelected")}</span>
          <div className="ms-auto flex gap-1.5">
            <Button size="sm" variant="secondary" onClick={() => bulk("activate")}><Check size={13} />{t("users.enableSelected")}</Button>
            <Button size="sm" variant="secondary" onClick={() => bulk("disable")}><Ban size={13} />{t("users.disableSelected")}</Button>
            <Button size="sm" variant="danger" onClick={() => bulk("delete")}><Trash2 size={13} />{t("users.deleteSelected")}</Button>
          </div>
        </Card>
      )}

      {isError ? (
        <Card><EmptyState title={(error as Error).message} /></Card>
      ) : (
        <DataTable
          columns={columns}
          rows={users}
          rowKey={(u) => u.username}
          loading={isLoading}
          virtual
          height={620}
          onRowClick={(u) => setDialog({ mode: "edit", user: u })}
          empty={<EmptyState title={search || statusFilter !== "all" ? "No users match the current filter" : "No users yet"}
            action={!search && statusFilter === "all" ? <Button size="sm" onClick={() => setDialog({ mode: "create" })}><Plus size={14} />{t("users.new")}</Button> : undefined} />}
        />
      )}
      {rowMenu}

      {dialog && (
        <UserDialog
          mode={dialog.mode}
          user={"user" in dialog ? dialog.user : undefined}
          catalog={catalogQ.data?.groups ?? []}
          templates={templates}
          onClose={() => setDialog(null)}
          onSaved={() => { setDialog(null); invalidate(); }}
        />
      )}

      <ConfirmDialog
        open={!!confirmDelete}
        onClose={() => setConfirmDelete(null)}
        onConfirm={() => confirmDelete && deleteUser.mutate(confirmDelete.username)}
        title={`${t("common.delete")} — ${confirmDelete?.username ?? ""}`}
        body={t("users.deleteConfirm")}
        danger
        loading={deleteUser.isPending}
      />
    </div>
  );
}

function MenuItem({ icon, label, onClick, danger }: { icon: React.ReactNode; label: string; onClick: () => void; danger?: boolean }) {
  return (
    <button onClick={onClick}
      className={cn("flex w-full items-center gap-2.5 px-3.5 py-2 text-[13px] transition-colors",
        danger ? "text-danger hover:bg-danger-soft" : "text-content-2 hover:bg-surface-2 hover:text-content")}>
      {icon}{label}
    </button>
  );
}

// ---------------------------------------------------------------- dialog ---

function PortalLinkSection({ username }: { username: string }) {
  const t = useT();
  const [link, setLink] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const info = useQuery({
    queryKey: ["zagros", "panel-info"],
    queryFn: () => api.get<{ panel_base_url?: string | null; domain?: string | null }>("/zagros/panel/info"),
  });
  const issue = async () => {
    setBusy(true);
    try {
      const r = await api.post<{ path: string }>(`/zagros/users/by-username/${encodeURIComponent(username)}/subscription-token`, {});
      const base = (info.data?.panel_base_url || (info.data?.domain ? `https://${info.data.domain}` : "")) || window.location.origin;
      setLink(`${base}${r.path}`);
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t("common.error"));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="sm:col-span-2 rounded-xl border border-brand/30 bg-brand-soft/20 p-3">
      <p className="mb-1.5 text-[11px] font-medium text-brand">
        {t("users.subPortalHint")}
      </p>
      <div className="flex items-center gap-2">
        {link ? (
          <>
            <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-content-2" dir="ltr">{link}</code>
            <Button variant="secondary" size="sm" onClick={async () => (await copyText(link)) ? toast.ok(t("common.copied")) : toast.error(t("common.error"))}>
              <Copy size={13} /> {t("common.copy")}
            </Button>
          </>
        ) : (
          <Button variant="secondary" size="sm" onClick={issue} loading={busy}>
            <Link2 size={13} /> issue portal link
          </Button>
        )}
      </div>
    </div>
  );
}

function UserDialog({ mode, user, catalog, templates, onClose, onSaved }: {
  mode: "create" | "edit"; user?: User;
  catalog: InboundCatalogGroup[]; templates: UserTemplate[];
  onClose: () => void; onSaved: () => void;
}) {
  const t = useT();
  const [form, setForm] = useState<UserForm>(() => {
    if (mode === "edit" && user) {
      return {
        ...emptyForm,
        username: user.username, note: user.note ?? "", status: user.status,
        dataLimitGB: user.data_limit ? String(user.data_limit / 1024 ** 3) : "",
        deviceLimit: user.device_limit ? String(user.device_limit) : "",
        expireDate: user.expire ? new Date(user.expire * 1000).toISOString().slice(0, 10) : "",
        inbounds: user.proxies
          ? Object.fromEntries(Object.keys(user.proxies).map((p) => [p, user.inbounds?.[p] ?? []]))
          : {},
        coreAccess: structuredClone(user.core_access ?? {}),
        telegramId: user.telegram_id ? String(user.telegram_id) : "",
      };
    }
    return emptyForm;
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const qc = useQueryClient();
  // α7.2 (item 12): username generator state
  const [genLen, setGenLen] = useState(8);
  const [genBusy, setGenBusy] = useState(false);

  const chosen = Object.keys(form.inbounds);
  const subUrl = absolutizeSub(user?.subscription_url ?? user?.sub_url);

  // α7.2 (item 11): on CREATE everything is pre-selected once the catalog
  // arrives (without clobbering a template pre-fill or admin edits).
  const prefilled = useRef(false);
  useEffect(() => {
    if (mode !== "create" || prefilled.current || !catalog.length) return;
    prefilled.current = true;
    setForm((f) => {
      const xg = catalog.find((g) => g.core_id === XRAY_CORE_ID);
      return {
        ...f,
        inbounds: Object.keys(f.inbounds).length ? f.inbounds : (xg ? allLegacySelected(xg) : f.inbounds),
        coreAccess: Object.keys(f.coreAccess).length ? f.coreAccess : allCoreAccess(catalog),
      };
    });
  }, [mode, catalog]);

  // α7.2 (item 12): letters+digits at a configurable length, verified unique
  // against the real user API before filling the field.
  const generateUsername = async () => {
    setGenBusy(true);
    try {
      for (let attempt = 0; attempt < 8; attempt++) {
        const name = randomUsername(genLen);
        try {
          await api.get(`/user/${encodeURIComponent(name)}`);
          continue; // taken — regenerate
        } catch (e) {
          if (e instanceof ApiError && e.status === 404) {
            setForm((f) => ({ ...f, username: name }));
            return;
          }
          throw e; // real failure (500, network…) — surface it honestly
        }
      }
      toast.error("could not find a free username — try again");
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t("common.error"));
    } finally {
      setGenBusy(false);
    }
  };

  // Template pre-fill (mode 1): data limit, expiry, username affixes and
  // the template's inbound sets flow into the form in one click.
  const applyTemplate = (id: number | null) => {
    const tp = templates.find((x) => x.id === id);
    if (!tp) return setForm({ ...form, templateId: id });
    setForm({
      ...form,
      templateId: id,
      dataLimitGB: tp.data_limit ? String(tp.data_limit / 1024 ** 3) : "",
      expireDate: tp.expire_duration
        ? new Date(Date.now() + tp.expire_duration * 1000).toISOString().slice(0, 10)
        : "",
      inbounds: structuredClone(tp.inbounds ?? {}),
      coreAccess: { ...form.coreAccess, ...structuredClone(tp.core_access ?? {}) },
    });
  };

  const save = async () => {
    setBusy(true); setError("");
    const data_limit = form.dataLimitGB ? Math.round(parseFloat(form.dataLimitGB) * 1024 ** 3) : null;
    const device_limit = form.deviceLimit ? Math.max(0, parseInt(form.deviceLimit, 10) || 0) : null;
    const expire = form.expireDate ? Math.floor(new Date(form.expireDate + "T23:59:59").getTime() / 1000) : null;
    const proxySettings: Record<string, Record<string, unknown>> = {};
    const inboundSel: Record<string, string[]> = {};
    for (const p of chosen) {
      proxySettings[p] = {};
      inboundSel[p] = form.inbounds[p] ?? [];
    }
    try {
      if (mode === "create") {
        await api.post("/user", {
          username: form.username.trim(), status: form.status,
          data_limit, device_limit, expire,
          note: form.note || null,
          proxies: proxySettings,
          inbounds: inboundSel,
          data_limit_reset_strategy: "no_reset",
          telegram_id: form.telegramId ? Number(form.telegramId) : null,
          ...(Object.values(form.coreAccess).some((tags) => tags.length)
            ? { core_access: Object.fromEntries(Object.entries(form.coreAccess).filter(([, tags]) => tags.length)) }
            : {}),
        });
        toast.ok(`${form.username} created`);
      } else if (user) {
        const body: Record<string, unknown> = {
          status: form.status, data_limit, device_limit, expire, note: form.note || null,
          telegram_id: form.telegramId ? Number(form.telegramId) : null,
        };
        if (chosen.length) { body.proxies = proxySettings; body.inbounds = inboundSel; }
        if (Object.keys(form.coreAccess).length || Object.keys(user.core_access ?? {}).length) {
          body.core_access = form.coreAccess;
        }
        await api.put(`/user/${user.username}`, body);
        toast.ok(t("common.saved"));
      }
      qc.invalidateQueries({ queryKey: ["users"] });
      onSaved();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t("common.error"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open onClose={onClose}
      title={mode === "create" ? t("users.new") : `${t("common.edit")} — ${user?.username}`}
      wide
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button onClick={save} loading={busy}
            disabled={(mode === "create" && !form.username.trim()) || chosen.length === 0}>
            {t("common.save")}
          </Button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="username" required
          hint={mode === "create" ? "letters + digits — or generate a random one" : undefined}>
          <div className={mode === "create"
            ? "grid grid-cols-[minmax(0,1fr)_4rem_auto] items-center gap-2"
            : ""}>
            <Input id="username" value={form.username} disabled={mode === "edit"} autoComplete="off"
              /* grid tracks, not flex: the <input>'s intrinsic width made the
                 flex row overflow INTO the status select (clicks on generate
                 landed on the select — caught by the browser gate) */
              onChange={(e) => setForm({ ...form, username: e.target.value })} />
            {mode === "create" && (
              <>
                <Input type="number" min={4} max={32} value={genLen} aria-label="username length"
                  title="generated username length (4–32)"
                  className="w-16"
                  onChange={(e) => setGenLen(Math.max(4, Math.min(32, parseInt(e.target.value, 10) || 8)))} />
                <Button type="button" variant="secondary" size="sm" onClick={generateUsername}
                  loading={genBusy} title="generate a unique random username">
                  <Dices size={14} /> generate
                </Button>
              </>
            )}
          </div>
        </Field>
        <Field label={t("common.status")}>
          <Select value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value as UserStatus })}>
            {ALL_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
          </Select>
        </Field>
        <Field label={`${t("users.limit")} (GB)`} hint="empty = unlimited">
          <Input id="dataLimit" type="number" min="0" step="0.1" value={form.dataLimitGB}
            onChange={(e) => setForm({ ...form, dataLimitGB: e.target.value })} />
        </Field>
        <Field label={t("users.deviceLimit")} hint={t("users.deviceLimitHint")}>
          <Input id="deviceLimit" type="number" min="0" step="1" value={form.deviceLimit}
            onChange={(e) => setForm({ ...form, deviceLimit: e.target.value })} />
        </Field>
        <Field label={t("users.expire")} hint="empty = never">
          <Input type="date" value={form.expireDate}
            onChange={(e) => setForm({ ...form, expireDate: e.target.value })} />
        </Field>

        {mode === "create" && (
          <div className="sm:col-span-2">
            <Field label={t("users.template")}>
              <div className="grid grid-cols-2 gap-2">
                {(["template", "manual"] as const).map((m) => (
                  <button key={m} type="button"
                    onClick={() => setForm({ ...form, mode: m, templateId: m === "manual" ? null : form.templateId })}
                    className={cn("rounded-xl border px-3 py-2.5 text-start transition-colors",
                      form.mode === m ? "border-brand bg-brand-soft" : "border-border hover:border-border-strong")}>
                    <span className="block text-[13px] font-medium">
                      {m === "template" ? t("users.mode.template") : t("users.mode.manual")}
                    </span>
                    <span className="mt-1 block text-[11px] text-content-3">
                      {m === "template"
                        ? "pre-filled limits + inbound sets"
                        : t("users.mode.manualHint")}
                    </span>
                  </button>
                ))}
              </div>
            </Field>
          </div>
        )}

        {mode === "create" && form.mode === "template" && (
          <div className="sm:col-span-2">
            <Field label={t("users.template")} required hint={templates.length === 0 ? "no templates yet — create one in Templates" : undefined}>
              <Select value={form.templateId ?? ""} onChange={(e) => applyTemplate(e.target.value ? Number(e.target.value) : null)}>
                <option value="">— choose a template —</option>
                {templates.map((tp) => (
                  <option key={tp.id} value={tp.id}>
                    {tp.name} · {tp.data_limit ? `${(tp.data_limit / 1024 ** 3).toFixed(0)}GB` : "∞"} · {tp.expire_duration ? `${Math.round(tp.expire_duration / 86400)}d` : "no expiry"}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
        )}

        <div className="sm:col-span-2">
          <Field label={t("users.protocols")}
            hint={chosen.length === 0
              ? "select at least one protocol on the xray row — accounts on other cores share this user's quota, expiry and status"
              : `${chosen.length} protocol${chosen.length > 1 ? "s" : ""} on xray · every selected core gets a real account`}>
            <CoreAccessPicker
              groups={catalog}
              value={form.coreAccess}
              onChange={(next) => setForm({ ...form, coreAccess: next })}
              xrayValue={form.inbounds}
              onXrayChange={(next) => setForm({ ...form, inbounds: next })}
            />
          </Field>
        </div>

        <Field label={t("users.telegramId")}>
          <Input type="number" value={form.telegramId} onChange={(e) => setForm({ ...form, telegramId: e.target.value })} />
        </Field>
        <div className="sm:col-span-2">
          <Field label={t("users.note")}>
            <Input value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} />
          </Field>
        </div>

        {mode === "edit" && subUrl && (
          <div className="sm:col-span-2 rounded-xl border border-border bg-surface-2 p-3">
            <p className="mb-1.5 text-[11px] font-medium text-content-3">{t("users.qr")} — every core, one link</p>
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-content-2" dir="ltr">{subUrl}</code>
              <Button variant="secondary" size="sm" onClick={async () => (await copyText(subUrl)) ? toast.ok(t("common.copied")) : toast.error(t("common.error"))}>
                <Copy size={13} /> {t("common.copy")}
              </Button>
            </div>
          </div>
        )}

        {mode === "edit" && user && <PortalLinkSection username={user.username} />}
      </div>
      {error && <p role="alert" className="mt-3 rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}
