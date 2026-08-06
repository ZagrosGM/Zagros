// Users — full management: virtualized table, advanced filters, inline status,
// bulk actions, create/edit dialog (access mode = subscription link OR
// application login), per-user quick actions. No JSON anywhere.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Ban, Check, ChevronDown, Copy, ExternalLink, Filter, Link2, MoreHorizontal,
  Plus, QrCode, RefreshCcw, Search, Trash2, UserPlus, Users as UsersIcon,
} from "lucide-react";
import { useMemo, useRef, useState } from "react";
import { DataTable, type Column } from "../components/DataTable";
import { toast } from "../components/feedback";
import { ConfirmDialog, Dialog } from "../components/overlays";
import { Badge, Button, Card, EmptyState, Field, Input, Progress, Select, StatusDot, Switch, cn } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useDigits, formatBytes, formatDate, formatRelative, usagePercent } from "../lib/format";
import { useT } from "../lib/i18n";
import type { User, UsersResponse, UserStatus } from "../lib/types";

const STATUS_TONE: Record<UserStatus, "ok" | "muted" | "warn" | "danger" | "info"> = {
  active: "ok", disabled: "muted", limited: "warn", expired: "danger", on_hold: "info",
};
const ALL_STATUSES: UserStatus[] = ["active", "disabled", "limited", "expired", "on_hold"];

interface UserForm {
  username: string;
  note: string;
  status: UserStatus;
  dataLimitGB: string;
  expireDate: string;
  protocols: Record<string, boolean>;
  authMode: "subscription" | "app";
  appUsername: string;
  telegramId: string;
}

const emptyForm = (protocols: string[]): UserForm => ({
  username: "", note: "", status: "active", dataLimitGB: "", expireDate: "",
  protocols: Object.fromEntries(protocols.map((p) => [p, false])),
  authMode: "subscription", appUsername: "", telegramId: "",
});

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
  const [menuFor, setMenuFor] = useState<string | null>(null);

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
  // legacy API: inbounds grouped by protocol → we consume the protocol keys
  const inboundsQ = useQuery({
    queryKey: ["inbounds"],
    queryFn: () => api.get<Record<string, unknown[]>>("/inbounds"),
    retry: false, staleTime: 60000,
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
  // grouped response: Record<protocol, inbound[]> — we only need the protocol keys
  const protocols = useMemo(() => Object.keys(inboundsQ.data ?? {}), [inboundsQ.data]);

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

  const copySub = (u: User) => {
    if (!u.sub_url) return toast.error("no subscription link");
    navigator.clipboard.writeText(u.sub_url).then(() => toast.ok(t("common.copied")), () => toast.error(t("common.error")));
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
          <StatusDot tone={u.status === "active" ? "ok" : u.status === "disabled" ? "muted" : u.status === "limited" ? "warn" : "danger"} />
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="truncate font-medium">{u.username}</span>
              {u.app_username && <Badge tone="info">app</Badge>}
            </div>
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
      id: "actions", header: "", width: "44px",
      cell: (u) => (
        <div className="relative" onClick={(e) => e.stopPropagation()}>
          <button aria-label="actions" onClick={() => setMenuFor(menuFor === u.username ? null : u.username)}
            className="rounded-lg p-1.5 text-content-3 hover:bg-surface-3 hover:text-content">
            <MoreHorizontal size={16} />
          </button>
          {menuFor === u.username && (
            <>
              <div className="fixed inset-0 z-30" onClick={() => setMenuFor(null)} />
              <div className="absolute end-0 top-8 z-40 w-48 overflow-hidden rounded-xl border border-border-strong bg-surface-1 py-1 shadow-pop">
                <MenuItem icon={<ExternalLink size={14} />} label={t("common.edit")} onClick={() => { setMenuFor(null); setDialog({ mode: "edit", user: u }); }} />
                <MenuItem icon={<Copy size={14} />} label={t("users.qr")} onClick={() => { setMenuFor(null); copySub(u); }} />
                <MenuItem icon={<RefreshCcw size={14} />} label={t("users.resetUsage")} onClick={() => { setMenuFor(null); resetUsage.mutate(u.username); }} />
                <MenuItem icon={<Link2 size={14} />} label={t("users.revokeSub")} onClick={() => { setMenuFor(null); revokeSub.mutate(u.username); }} />
                <div className="my-1 border-t border-border" />
                <MenuItem icon={<Trash2 size={14} />} label={t("common.delete")} danger
                  onClick={() => { setMenuFor(null); setConfirmDelete(u); }} />
              </div>
            </>
          )}
        </div>
      ),
    },
  ];

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

      {dialog && (
        <UserDialog
          mode={dialog.mode}
          user={"user" in dialog ? dialog.user : undefined}
          protocols={protocols}
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

function UserDialog({ mode, user, protocols, onClose, onSaved }: {
  mode: "create" | "edit"; user?: User; protocols: string[];
  onClose: () => void; onSaved: () => void;
}) {
  const t = useT();
  const digit = useDigits();
  const [form, setForm] = useState<UserForm>(() => {
    if (mode === "edit" && user) {
      const userProtos = user.proxies ? Object.keys(user.proxies) : [];
      return {
        username: user.username, note: user.note ?? "", status: user.status,
        dataLimitGB: user.data_limit ? String(user.data_limit / 1024 ** 3) : "",
        expireDate: user.expire ? new Date(user.expire * 1000).toISOString().slice(0, 10) : "",
        protocols: Object.fromEntries(protocols.map((p) => [p, userProtos.includes(p)])),
        authMode: user.app_username ? "app" : "subscription",
        appUsername: user.app_username ?? "",
        telegramId: user.telegram_id ? String(user.telegram_id) : "",
      };
    }
    return emptyForm(protocols);
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const qc = useQueryClient();

  const chosen = Object.entries(form.protocols).filter(([, v]) => v).map(([k]) => k);

  const subUrl = user?.sub_url ?? null;

  const save = async () => {
    setBusy(true); setError("");
    const data_limit = form.dataLimitGB ? Math.round(parseFloat(form.dataLimitGB) * 1024 ** 3) : null;
    const expire = form.expireDate ? Math.floor(new Date(form.expireDate + "T23:59:59").getTime() / 1000) : null;
    const proxySettings: Record<string, Record<string, unknown>> = {};
    for (const p of chosen) proxySettings[p] = {};
    try {
      if (mode === "create") {
        await api.post("/user", {
          username: form.username.trim(), status: form.status,
          data_limit, expire,
          note: form.note || null,
          proxies: proxySettings,
          inbounds: {},
          data_limit_reset_strategy: "no_reset",
          telegram_id: form.telegramId ? Number(form.telegramId) : null,
          app_username: form.authMode === "app" && form.appUsername ? form.appUsername : null,
        });
        toast.ok(`${form.username} created`);
      } else if (user) {
        const body: Record<string, unknown> = {
          status: form.status, data_limit, expire, note: form.note || null,
          telegram_id: form.telegramId ? Number(form.telegramId) : null,
        };
        if (chosen.length) body.proxies = proxySettings;
        if (form.authMode === "app" && form.appUsername) body.app_username = form.appUsername;
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
          <Button onClick={save} loading={busy} disabled={mode === "create" && !form.username.trim()}>
            {t("common.save")}
          </Button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="username" required>
          <Input id="username" value={form.username} disabled={mode === "edit"} autoComplete="off"
            onChange={(e) => setForm({ ...form, username: e.target.value })} />
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
        <Field label={t("users.expire")} hint="empty = never">
          <Input type="date" value={form.expireDate}
            onChange={(e) => setForm({ ...form, expireDate: e.target.value })} />
        </Field>

        <div className="sm:col-span-2">
          <Field label={t("users.protocols")} hint={protocols.length === 0 ? "no inbounds configured yet" : `${chosen.length || 0}/${protocols.length}`}>
            <div className="flex flex-wrap gap-2 rounded-xl border border-border p-3">
              {protocols.length === 0 && <span className="text-xs text-content-3">—</span>}
              {protocols.map((p) => (
                <button
                  key={p} type="button"
                  onClick={() => setForm({ ...form, protocols: { ...form.protocols, [p]: !form.protocols[p] } })}
                  className={cn(
                    "rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors",
                    form.protocols[p]
                      ? "border-brand bg-brand-soft text-brand"
                      : "border-border-strong text-content-2 hover:border-brand/50",
                  )}
                >
                  {p}
                </button>
              ))}
            </div>
          </Field>
        </div>

        <div className="sm:col-span-2">
          <Field label={t("users.authMode")}>
            <div className="grid grid-cols-2 gap-2">
              {(["subscription", "app"] as const).map((m) => (
                <button
                  key={m} type="button"
                  onClick={() => setForm({ ...form, authMode: m })}
                  className={cn(
                    "rounded-xl border px-3 py-2.5 text-start transition-colors",
                    form.authMode === m ? "border-brand bg-brand-soft" : "border-border hover:border-border-strong",
                  )}
                >
                  <span className="flex items-center gap-2 text-[13px] font-medium">
                    {m === "subscription" ? <Link2 size={14} /> : <QrCode size={14} />}
                    {m === "subscription" ? t("users.authMode.sub") : t("users.authMode.app")}
                  </span>
                  <span className="mt-1 block text-[11px] text-content-3">
                    {m === "subscription"
                      ? "client apps import a tokenized link"
                      : "the Zagros app signs in with credentials"}
                  </span>
                </button>
              ))}
            </div>
          </Field>
        </div>

        {form.authMode === "app" && (
          <Field label={t("users.appUsername")}>
            <Input value={form.appUsername} onChange={(e) => setForm({ ...form, appUsername: e.target.value })} />
          </Field>
        )}
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
            <p className="mb-1.5 text-[11px] font-medium text-content-3">{t("users.qr")}</p>
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-content-2" dir="ltr">{subUrl}</code>
              <Button variant="secondary" size="sm" onClick={() => navigator.clipboard.writeText(subUrl).then(() => toast.ok(t("common.copied")))}>
                <Copy size={13} /> {t("common.copy")}
              </Button>
            </div>
          </div>
        )}
      </div>
      {error && <p role="alert" className="mt-3 rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}
