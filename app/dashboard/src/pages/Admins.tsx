// Admins — first-class management page (moved out of Settings in alpha.7).
// Full CRUD + governance caps per admin: max users, account expiry,
// traffic-allocation budget and traffic-consumption cap (the backend
// enforces all four transaction-safely; this page is their control room).
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Ban, Check, Crown, Eraser, MoreHorizontal, Pencil, Plus, RefreshCcw,
  ShieldCheck, Trash2, UserCog,
} from "lucide-react";
import { useMemo, useState } from "react";
import { DataTable, type Column } from "../components/DataTable";
import { toast } from "../components/feedback";
import { ConfirmDialog, Dialog } from "../components/overlays";
import { Badge, Button, Card, EmptyState, ErrorState, Field, Input, Progress, Skeleton, Switch, cn } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useDigits, formatBytes, formatDate, formatRelative } from "../lib/format";
import { useT } from "../lib/i18n";
import type { AdminUser } from "../lib/types";

interface AdminForm {
  username: string;
  password: string;
  is_sudo: boolean;
  telegram_id: string;
  discord_webhook: string;
  max_users: string;
  expire_at: string;
  traffic_alloc_limit_gb: string;
  traffic_consume_limit_gb: string;
}

const emptyForm: AdminForm = {
  username: "", password: "", is_sudo: false, telegram_id: "", discord_webhook: "",
  max_users: "", expire_at: "", traffic_alloc_limit_gb: "", traffic_consume_limit_gb: "",
};

const gbToBytes = (v: string) => (v && Number(v) > 0 ? Math.round(Number(v) * 1024 ** 3) : null);
const bytesToGb = (v?: number | null) => (v ? String(Math.round((v / 1024 ** 3) * 100) / 100) : "");

export default function Admins() {
  const t = useT();
  const digits = useDigits();
  const qc = useQueryClient();
  const [dialog, setDialog] = useState<{ mode: "create" } | { mode: "edit"; admin: AdminUser } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<AdminUser | null>(null);
  const [menuFor, setMenuFor] = useState<string | null>(null);

  const admins = useQuery({
    queryKey: ["admins"],
    queryFn: () => api.get<AdminUser[]>("/admins"),
  });
  const invalidate = () => qc.invalidateQueries({ queryKey: ["admins"] });

  const deleteAdmin = useMutation({
    mutationFn: (username: string) => api.delete(`/admin/${username}`),
    onSuccess: () => { toast.ok(t("common.deleted")); setConfirmDelete(null); invalidate(); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });
  const usersAction = useMutation({
    mutationFn: ({ username, action }: { username: string; action: "disable" | "activate" }) =>
      api.post(`/admin/${username}/users/${action}`),
    onSuccess: (_d, v) => { toast.ok(`${v.username}: users ${v.action}d`); invalidate(); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });
  const resetUsage = useMutation({
    mutationFn: (username: string) => api.post(`/admin/usage/reset/${username}`),
    onSuccess: () => { toast.ok("usage counter reset"); invalidate(); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const rows = useMemo(() => admins.data ?? [], [admins.data]);

  const columns: Column<AdminUser>[] = [
    {
      id: "admin", header: t("nav.admins"), cell: (a) => (
        <div className="flex min-w-0 items-center gap-2.5">
          <div className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-brand-soft text-brand">
            {a.is_sudo ? <Crown size={14} /> : <UserCog size={14} />}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="truncate font-medium">{a.username}</span>
              {a.is_sudo && <Badge tone="brand">sudo</Badge>}
              {a.expire_at && new Date(a.expire_at).getTime() <= Date.now() && (
                <Badge tone="danger" dot>expired</Badge>
              )}
            </div>
            <p className="truncate text-[11px] text-content-3">
              {a.created_at ? `since ${formatRelative(a.created_at, digits)}` : "—"}
            </p>
          </div>
        </div>
      ),
    },
    {
      id: "users", header: t("admins.users"), width: "130px", cell: (a) => {
        const count = a.users_count ?? 0;
        const pct = a.max_users ? Math.min(100, (count / a.max_users) * 100) : 0;
        return (
          <div className="w-full">
            <div className="mb-1 flex justify-between gap-2 text-[11px] tabular-nums">
              <span>{digits(String(count))}</span>
              <span className="text-content-3">{a.max_users ? digits(String(a.max_users)) : "∞"}</span>
            </div>
            {a.max_users ? <Progress value={pct} tone={pct >= 100 ? "danger" : pct >= 80 ? "warn" : "brand"} /> : null}
          </div>
        );
      },
    },
    {
      id: "usage", header: t("admins.usageLifetime"), width: "200px", cell: (a) => {
        const used = a.users_lifetime_usage ?? 0;
        const pct = a.traffic_consume_limit ? Math.min(100, (used / a.traffic_consume_limit) * 100) : 0;
        return (
          <div className="w-full">
            <div className="mb-1 flex justify-between gap-2 text-[11px] tabular-nums">
              <span title="consumed">{formatBytes(used, digits)}</span>
              <span className="text-content-3" title="consumption cap">
                {a.traffic_consume_limit ? formatBytes(a.traffic_consume_limit, digits) : "∞"}
              </span>
            </div>
            {a.traffic_consume_limit ? (
              <Progress value={pct} tone={pct >= 100 ? "danger" : pct >= 80 ? "warn" : "ok"} />
            ) : null}
            <p className="mt-1 text-[10px] text-content-3 tabular-nums">
              alloc: {formatBytes(a.users_allocated_traffic ?? 0, digits)}
              {a.traffic_alloc_limit ? ` / ${formatBytes(a.traffic_alloc_limit, digits)}` : " / ∞"}
            </p>
          </div>
        );
      },
    },
    {
      id: "expire", header: t("admins.expireAt"), width: "120px",
      cell: (a) => <span className="text-[12px] tabular-nums text-content-2">{a.expire_at ? formatDate(a.expire_at, digits) : "∞"}</span>,
    },
    {
      id: "actions", header: "", width: "44px",
      cell: (a) => (
        <div className="relative" onClick={(e) => e.stopPropagation()}>
          <button aria-label="actions" onClick={() => setMenuFor(menuFor === a.username ? null : a.username)}
            className="rounded-lg p-1.5 text-content-3 hover:bg-surface-3 hover:text-content">
            <MoreHorizontal size={16} />
          </button>
          {menuFor === a.username && (
            <>
              <div className="fixed inset-0 z-30" onClick={() => setMenuFor(null)} />
              <div className="absolute end-0 top-8 z-40 w-52 overflow-hidden rounded-xl border border-border-strong bg-surface-1 py-1 shadow-pop">
                <MenuItem icon={<Pencil size={14} />} label={t("common.edit")} onClick={() => { setMenuFor(null); setDialog({ mode: "edit", admin: a }); }} />
                <MenuItem icon={<Ban size={14} />} label="disable all users" onClick={() => { setMenuFor(null); usersAction.mutate({ username: a.username, action: "disable" }); }} />
                <MenuItem icon={<Check size={14} />} label="activate all users" onClick={() => { setMenuFor(null); usersAction.mutate({ username: a.username, action: "activate" }); }} />
                <MenuItem icon={<Eraser size={14} />} label="reset usage counter" onClick={() => { setMenuFor(null); resetUsage.mutate(a.username); }} />
                {!a.is_sudo && (
                  <>
                    <div className="my-1 border-t border-border" />
                    <MenuItem icon={<Trash2 size={14} />} label={t("common.delete")} danger
                      onClick={() => { setMenuFor(null); setConfirmDelete(a); }} />
                  </>
                )}
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
          <ShieldCheck size={18} className="text-brand" />{t("nav.admins")}
          <span className="text-xs font-normal text-content-3 tabular-nums">({rows.length})</span>
        </h1>
        <Button variant="ghost" size="icon" onClick={() => admins.refetch()} aria-label={t("common.refresh")}>
          <RefreshCcw size={15} className={cn(admins.isFetching && "animate-spin")} />
        </Button>
        <Button size="sm" onClick={() => setDialog({ mode: "create" })}><Plus size={14} />{t("admins.new")}</Button>
      </div>

      {admins.isLoading ? (
        <Card><Skeleton className="h-56" /></Card>
      ) : admins.isError ? (
        <Card><ErrorState message={(admins.error as Error).message} onRetry={() => admins.refetch()} /></Card>
      ) : (
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(a) => a.username}
          loading={false}
          onRowClick={(a) => setDialog({ mode: "edit", admin: a })}
          empty={<EmptyState
            title="No admins yet"
            hint="Panel operators beyond the CLI bootstrap admin appear here."
            action={<Button size="sm" onClick={() => setDialog({ mode: "create" })}><Plus size={14} />{t("admins.new")}</Button>} />}
        />
      )}

      {dialog && (
        <AdminDialog
          mode={dialog.mode}
          admin={"admin" in dialog ? dialog.admin : undefined}
          onClose={() => setDialog(null)}
          onSaved={() => { setDialog(null); invalidate(); }}
        />
      )}

      <ConfirmDialog
        open={!!confirmDelete}
        onClose={() => setConfirmDelete(null)}
        onConfirm={() => confirmDelete && deleteAdmin.mutate(confirmDelete.username)}
        title={`${t("common.delete")} — ${confirmDelete?.username ?? ""}`}
        body={t("admins.deleteConfirm")}
        danger
        loading={deleteAdmin.isPending}
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

function AdminDialog({ mode, admin, onClose, onSaved }: {
  mode: "create" | "edit"; admin?: AdminUser; onClose: () => void; onSaved: () => void;
}) {
  const t = useT();
  const [form, setForm] = useState<AdminForm>(() => {
    if (mode === "edit" && admin) {
      return {
        username: admin.username, password: "", is_sudo: admin.is_sudo,
        telegram_id: admin.telegram_id ? String(admin.telegram_id) : "",
        discord_webhook: admin.discord_webhook ?? "",
        max_users: admin.max_users ? String(admin.max_users) : "",
        expire_at: admin.expire_at ? admin.expire_at.slice(0, 10) : "",
        traffic_alloc_limit_gb: bytesToGb(admin.traffic_alloc_limit),
        traffic_consume_limit_gb: bytesToGb(admin.traffic_consume_limit),
      };
    }
    return emptyForm;
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const save = async () => {
    setBusy(true); setError("");
    const governance = {
      max_users: form.max_users ? Number(form.max_users) : null,
      expire_at: form.expire_at ? new Date(`${form.expire_at}T23:59:59`).toISOString() : null,
      traffic_alloc_limit: gbToBytes(form.traffic_alloc_limit_gb),
      traffic_consume_limit: gbToBytes(form.traffic_consume_limit_gb),
    };
    try {
      if (mode === "create") {
        await api.post("/admin", {
          username: form.username.trim(),
          password: form.password,
          is_sudo: form.is_sudo,
          telegram_id: form.telegram_id ? Number(form.telegram_id) : null,
          discord_webhook: form.discord_webhook || null,
          ...governance,
        });
        toast.ok(`${form.username} created`);
      } else if (admin) {
        await api.put(`/admin/${admin.username}`, {
          is_sudo: form.is_sudo,
          password: form.password || null,
          telegram_id: form.telegram_id ? Number(form.telegram_id) : null,
          discord_webhook: form.discord_webhook || null,
          ...governance,
        });
        toast.ok(t("common.saved"));
      }
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
      title={mode === "create" ? t("admins.new") : `${t("common.edit")} — ${admin?.username}`}
      subtitle="governance caps are enforced instantly on the server — login, user creation and edits all respect them"
      wide
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button onClick={save} loading={busy}
            disabled={!form.username.trim() || (mode === "create" && !form.password)}>
            {t("common.save")}
          </Button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="username" required>
          <Input value={form.username} disabled={mode === "edit"} autoComplete="off"
            onChange={(e) => setForm({ ...form, username: e.target.value })} />
        </Field>
        <Field label={mode === "create" ? "password" : "new password (empty = keep)"} required={mode === "create"}>
          <Input type="password" value={form.password} autoComplete="new-password"
            onChange={(e) => setForm({ ...form, password: e.target.value })} />
        </Field>
        <Field label={t("users.telegramId")}>
          <Input type="number" value={form.telegram_id}
            onChange={(e) => setForm({ ...form, telegram_id: e.target.value })} />
        </Field>
        <Field label="discord webhook">
          <Input value={form.discord_webhook} dir="ltr" placeholder="https://discord.com/api/webhooks/…"
            onChange={(e) => setForm({ ...form, discord_webhook: e.target.value })} />
        </Field>

        <div className="sm:col-span-2 mt-1 rounded-xl border border-border p-3.5">
          <p className="mb-3 text-[11px] font-semibold uppercase tracking-wide text-content-3">governance limits</p>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t("admins.maxUsers")} hint="empty = unlimited — the admin can't create users past this cap">
              <Input type="number" min="0" value={form.max_users}
                onChange={(e) => setForm({ ...form, max_users: e.target.value })} />
            </Field>
            <Field label={t("admins.expireAt")} hint="empty = never — after this date the admin can't log in or manage anything">
              <Input type="date" value={form.expire_at}
                onChange={(e) => setForm({ ...form, expire_at: e.target.value })} />
            </Field>
            <Field label={`${t("admins.allocLimit")} (GB)`}
              hint="cap on the SUM of data limits this admin can grant (empty = unlimited)">
              <Input type="number" min="0" step="0.1" value={form.traffic_alloc_limit_gb}
                onChange={(e) => setForm({ ...form, traffic_alloc_limit_gb: e.target.value })} />
            </Field>
            <Field label={`${t("admins.consumeLimit")} (GB)`}
              hint="cap on REAL consumed traffic — crossing it suspends all of the admin's users (never deletes)">
              <Input type="number" min="0" step="0.1" value={form.traffic_consume_limit_gb}
                onChange={(e) => setForm({ ...form, traffic_consume_limit_gb: e.target.value })} />
            </Field>
          </div>
        </div>

        <label className="flex items-center gap-2.5 text-sm text-content-2">
          <Switch checked={form.is_sudo} onChange={(v) => setForm({ ...form, is_sudo: v })} label="sudo" />
          sudo — full panel access
        </label>
      </div>
      {error && <p role="alert" className="mt-3 rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}
