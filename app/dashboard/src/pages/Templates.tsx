// Templates — first-class page (moved out of Settings in alpha.7).
// User templates pre-fill data limit, expiry, username affixes and the
// per-protocol inbound sets used by "create user from template".
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LayoutTemplate, MoreHorizontal, Pencil, Plus, RefreshCcw, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "../components/feedback";
import { ConfirmDialog, Dialog } from "../components/overlays";
import { Badge, Button, Card, EmptyState, ErrorState, Field, Input, Skeleton, cn } from "../components/ui";
import CoreAccessPicker from "../components/CoreAccessPicker";
import { api, ApiError } from "../lib/api";
import { useDigits, formatBytes } from "../lib/format";
import { useT } from "../lib/i18n";
import type { UserTemplate, InboundCatalogGroup } from "../lib/types";

type InboundsGrouped = Record<string, { tag: string; port?: number | string; protocol?: string }[]>;

interface TemplateForm {
  name: string;
  dataLimitGB: string;
  expireDays: string;
  username_prefix: string;
  username_suffix: string;
  /** protocol -> selected tags ([] = every inbound of that protocol) */
  inbounds: Record<string, string[]>;
  /** multi-core grants: core_id -> inbound tags */
  coreAccess: Record<string, string[]>;
}

const emptyForm: TemplateForm = {
  name: "", dataLimitGB: "", expireDays: "", username_prefix: "", username_suffix: "", inbounds: {}, coreAccess: {},
};

export default function Templates() {
  const t = useT();
  const digits = useDigits();
  const qc = useQueryClient();
  const [dialog, setDialog] = useState<{ mode: "create" } | { mode: "edit"; template: UserTemplate } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<UserTemplate | null>(null);
  const [menuFor, setMenuFor] = useState<number | null>(null);

  const templates = useQuery({
    queryKey: ["user_templates"],
    queryFn: () => api.get<UserTemplate[]>("/user_template"),
  });
  const inboundsQ = useQuery({
    queryKey: ["inbounds"],
    queryFn: () => api.get<InboundsGrouped>("/inbounds"),
    staleTime: 60000,
  });
  const catalogQ = useQuery({
    queryKey: ["zagros", "inbounds-catalog"],
    queryFn: () => api.get<{ groups: InboundCatalogGroup[] }>("/zagros/inbounds"),
  });
  const invalidate = () => qc.invalidateQueries({ queryKey: ["user_templates"] });

  const deleteTemplate = useMutation({
    mutationFn: (id: number) => api.delete(`/user_template/${id}`),
    onSuccess: () => { toast.ok(t("common.deleted")); setConfirmDelete(null); invalidate(); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const rows = useMemo(() => templates.data ?? [], [templates.data]);

  return (
    <div className="space-y-4 animate-fade-up">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <LayoutTemplate size={18} className="text-brand" />{t("nav.templates")}
          <span className="text-xs font-normal text-content-3 tabular-nums">({rows.length})</span>
        </h1>
        <Button variant="ghost" size="icon" onClick={() => templates.refetch()} aria-label={t("common.refresh")}>
          <RefreshCcw size={15} className={cn(templates.isFetching && "animate-spin")} />
        </Button>
        <Button size="sm" onClick={() => setDialog({ mode: "create" })}><Plus size={14} />{t("templates.new")}</Button>
      </div>

      {templates.isLoading ? (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">{[1, 2, 3].map((i) => <Skeleton key={i} className="h-40" />)}</div>
      ) : templates.isError ? (
        <Card><ErrorState message={(templates.error as Error).message} onRetry={() => templates.refetch()} /></Card>
      ) : rows.length === 0 ? (
        <Card>
          <EmptyState
            title="No templates yet"
            hint="Templates pre-fill data limit, expiry and inbound sets when creating users."
            action={<Button size="sm" onClick={() => setDialog({ mode: "create" })}><Plus size={14} />{t("templates.new")}</Button>}
          />
        </Card>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {rows.map((tp) => {
            const protocols = Object.keys(tp.inbounds ?? {});
            return (
              <Card key={tp.id}>
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <h3 className="truncate text-sm font-semibold">{tp.name}</h3>
                    <p className="mt-0.5 text-[11px] text-content-3 tabular-nums">
                      {tp.data_limit ? formatBytes(tp.data_limit, digits) : "∞ data"}
                      {" · "}
                      {tp.expire_duration ? `${digits(String(Math.round(tp.expire_duration / 86400)))}d` : "∞ time"}
                      {(tp.username_prefix || tp.username_suffix)
                        ? ` · ${tp.username_prefix ?? ""}…${tp.username_suffix ?? ""}` : ""}
                    </p>
                  </div>
                  <div className="relative" onClick={(e) => e.stopPropagation()}>
                    <button aria-label="actions" onClick={() => setMenuFor(menuFor === tp.id ? null : tp.id)}
                      className="rounded-lg p-1.5 text-content-3 hover:bg-surface-3 hover:text-content">
                      <MoreHorizontal size={16} />
                    </button>
                    {menuFor === tp.id && (
                      <>
                        <div className="fixed inset-0 z-30" onClick={() => setMenuFor(null)} />
                        <div className="absolute end-0 top-8 z-40 w-44 overflow-hidden rounded-xl border border-border-strong bg-surface-1 py-1 shadow-pop">
                          <MenuBtn icon={<Pencil size={14} />} label={t("common.edit")} onClick={() => { setMenuFor(null); setDialog({ mode: "edit", template: tp }); }} />
                          <MenuBtn icon={<Trash2 size={14} />} label={t("common.delete")} danger onClick={() => { setMenuFor(null); setConfirmDelete(tp); }} />
                        </div>
                      </>
                    )}
                  </div>
                </div>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {protocols.length === 0 ? (
                    <Badge tone="muted">all inbounds</Badge>
                  ) : protocols.slice(0, 6).map((p) => {
                    const tags = tp.inbounds[p];
                    return <Badge key={p} tone="info">{tags.length ? `${p} (${tags.length})` : p}</Badge>;
                  })}
                  {protocols.length > 6 && <Badge tone="muted">+{protocols.length - 6}</Badge>}
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {dialog && (
        <TemplateDialog
          mode={dialog.mode}
          template={"template" in dialog ? dialog.template : undefined}
          inbounds={inboundsQ.data ?? {}}
          catalog={catalogQ.data?.groups ?? []}
          onClose={() => setDialog(null)}
          onSaved={() => { setDialog(null); invalidate(); }}
        />
      )}

      <ConfirmDialog
        open={!!confirmDelete}
        onClose={() => setConfirmDelete(null)}
        onConfirm={() => confirmDelete && deleteTemplate.mutate(confirmDelete.id)}
        title={`${t("common.delete")} — ${confirmDelete?.name ?? ""}`}
        body={t("templates.deleteConfirm")}
        danger
        loading={deleteTemplate.isPending}
      />
    </div>
  );
}

function MenuBtn({ icon, label, onClick, danger }: { icon: React.ReactNode; label: string; onClick: () => void; danger?: boolean }) {
  return (
    <button onClick={onClick}
      className={cn("flex w-full items-center gap-2.5 px-3.5 py-2 text-[13px] transition-colors",
        danger ? "text-danger hover:bg-danger-soft" : "text-content-2 hover:bg-surface-2 hover:text-content")}>
      {icon}{label}
    </button>
  );
}

// ---------------------------------------------------------------- dialog ---

function TemplateDialog({ mode, template, inbounds, catalog, onClose, onSaved }: {
  mode: "create" | "edit"; template?: UserTemplate;
  inbounds: InboundsGrouped; catalog: InboundCatalogGroup[];
  onClose: () => void; onSaved: () => void;
}) {
  const t = useT();
  const [form, setForm] = useState<TemplateForm>(() => {
    if (mode === "edit" && template) {
      return {
        name: template.name ?? "",
        dataLimitGB: template.data_limit ? String(template.data_limit / 1024 ** 3) : "",
        expireDays: template.expire_duration ? String(Math.round(template.expire_duration / 86400)) : "",
        username_prefix: template.username_prefix ?? "",
        username_suffix: template.username_suffix ?? "",
        inbounds: structuredClone(template.inbounds ?? {}),
        coreAccess: structuredClone(template.core_access ?? {}),
      };
    }
    return emptyForm;
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const protocols = Object.keys(inbounds);
  const toggleProtocol = (p: string) => {
    const next = { ...form.inbounds };
    if (p in next) delete next[p];
    else next[p] = []; // [] = every inbound of the protocol
    setForm({ ...form, inbounds: next });
  };
  const toggleTag = (p: string, tag: string) => {
    const cur = new Set(form.inbounds[p] ?? []);
    cur.has(tag) ? cur.delete(tag) : cur.add(tag);
    setForm({ ...form, inbounds: { ...form.inbounds, [p]: [...cur] } });
  };

  const save = async () => {
    setBusy(true); setError("");
    const body = {
      name: form.name.trim(),
      data_limit: form.dataLimitGB ? Math.round(parseFloat(form.dataLimitGB) * 1024 ** 3) : 0,
      expire_duration: form.expireDays ? Math.round(parseFloat(form.expireDays) * 86400) : 0,
      username_prefix: form.username_prefix || null,
      username_suffix: form.username_suffix || null,
      inbounds: form.inbounds,
      core_access: form.coreAccess,
    };
    try {
      if (mode === "create") {
        await api.post("/user_template", body);
        toast.ok(`${form.name} created`);
      } else if (template) {
        await api.put(`/user_template/${template.id}`, body);
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
      title={mode === "create" ? t("templates.new") : `${t("common.edit")} — ${template?.name}`}
      subtitle="inbound sets apply to every protocol the core offers — leave a protocol out to exclude it"
      wide
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button onClick={save} loading={busy} disabled={!form.name.trim()}>{t("common.save")}</Button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("common.name")} required>
          <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </Field>
        <div className="grid grid-cols-2 gap-4">
          <Field label={`${t("templates.dataLimit")} (GB)`} hint="0 = unlimited">
            <Input type="number" min="0" step="0.1" value={form.dataLimitGB}
              onChange={(e) => setForm({ ...form, dataLimitGB: e.target.value })} />
          </Field>
          <Field label={t("templates.expireDuration")} hint="0 = never">
            <Input type="number" min="0" value={form.expireDays}
              onChange={(e) => setForm({ ...form, expireDays: e.target.value })} />
          </Field>
        </div>
        <Field label="username prefix">
          <Input value={form.username_prefix} onChange={(e) => setForm({ ...form, username_prefix: e.target.value })} />
        </Field>
        <Field label="username suffix">
          <Input value={form.username_suffix} onChange={(e) => setForm({ ...form, username_suffix: e.target.value })} />
        </Field>

        <Field label="other cores — include inbounds from ANY core in this template"
          hint="users created from this template get real accounts on every selected core">
          <CoreAccessPicker
            groups={catalog}
            value={form.coreAccess}
            onChange={(next) => setForm({ ...form, coreAccess: next })}
          />
        </Field>

        <div className="sm:col-span-2">
          <Field label={t("users.protocols")} hint={`${Object.keys(form.inbounds).length}/${protocols.length} — no selection = all inbounds of the chosen protocols`}>
            <div className="space-y-2.5 rounded-xl border border-border p-3">
              {protocols.length === 0 && <span className="text-xs text-content-3">no inbounds configured yet</span>}
              {protocols.map((p) => {
                const enabled = p in form.inbounds;
                const tags = inbounds[p] ?? [];
                const selected = new Set(form.inbounds[p] ?? []);
                return (
                  <div key={p} className={cn("rounded-xl border p-2.5 transition-colors",
                    enabled ? "border-brand/50 bg-brand-soft/30" : "border-border")}>
                    <button type="button" onClick={() => toggleProtocol(p)}
                      className={cn("flex w-full items-center justify-between text-[13px] font-medium",
                        enabled ? "text-brand" : "text-content-2 hover:text-content")}>
                      <span className="inline-flex items-center gap-2">
                        <span className={cn("h-2 w-2 rounded-full", enabled ? "bg-brand" : "bg-content-3")} />
                        {p}
                      </span>
                      <span className="text-[11px] font-normal text-content-3">
                        {enabled ? (selected.size ? `${selected.size}/${tags.length} tags` : "all tags") : `${tags.length} tags`}
                      </span>
                    </button>
                    {enabled && tags.length > 1 && (
                      <div className="mt-2 flex flex-wrap gap-1.5 border-t border-border pt-2">
                        {tags.map((tag) => {
                          const name = tag.tag;
                          const on = selected.has(name);
                          return (
                            <button key={name} type="button" onClick={() => toggleTag(p, name)}
                              className={cn("rounded-lg border px-2.5 py-1 text-[11px] transition-colors",
                                on ? "border-brand bg-brand-soft text-brand"
                                   : "border-border-strong text-content-2 hover:border-brand/50")}>
                              {name}
                            </button>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </Field>
        </div>
      </div>
      {error && <p role="alert" className="mt-3 rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}
