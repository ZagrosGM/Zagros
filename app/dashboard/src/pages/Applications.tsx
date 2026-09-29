// Applications — white-label reseller apps: create/list, per-app detail
// (public keys, bound users, one-time activation tickets, launcher icon)
// and the white-label build trigger + history. Leaf dialogs stay dumb:
// every action refetches its own query so the panel is the source of truth.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, ImagePlus, Plus, RefreshCw, Rocket, ShieldX, Trash2 } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { useEffect, useRef, useState } from "react";
import { DataTable, type Column } from "../components/DataTable";
import { toast } from "../components/feedback";
import { Dialog } from "../components/overlays";
import { Badge, Button, Card, CardHeader, CopyButton, EmptyState, ErrorState, Field, Input, Select, Skeleton, cn } from "../components/ui";
import { api, ApiError, download, getToken } from "../lib/api";
import { formatBytes, formatDate } from "../lib/format";
import { useT } from "../lib/i18n";

const API_BASE = (import.meta.env.VITE_BASE_API || "/api/").replace(/\/$/, "");
const APP_QK = ["zagros", "applications"];

interface AppListItem {
  id: number; public_id: string; owner_admin_id: number; name: string;
  status: string; api_base_url: string; default_lang: string;
  active_signing_kid: string | null; active_config_kid: string | null;
}
interface AppDetail extends AppListItem {
  branding: Record<string, unknown>;
}
interface GrantItem {
  user_id: number; username: string; status: string;
  granted_at: string | null;
}
interface KeySlot { kid: string; public_key: string }
interface AppKeys { signing: KeySlot | null; config: KeySlot | null }
interface IconMeta {
  sha256: string; size_bytes: number; width: number; height: number;
  mime: string; updated_at: string | null;
  android_pack_sha256?: string | null; android_pack_bytes?: number | null;
}
interface BuildTarget {
  platform: string; arch: string; artifact: string; status: string;
}
interface BuildArtifact {
  platform: string; arch: string; artifact: string; filename: string;
  rel_path: string; sha256: string; size_bytes: number;
}
interface BuildItem {
  public_id: string; version: string | null; build_number: number | null;
  status: string; progress: number | null; created_at: string | null;
  targets: BuildTarget[]; artifacts: BuildArtifact[];
  failure_code?: string | null; failure_message?: string | null;
}
interface CredentialItem {
  public_id: string; kind: string; label: string; revoked: boolean;
}
interface BootstrapResult {
  application_id: string; name: string; status: string;
  signing_key_id: string; signing_public_key: string;
  config_key_id: string; config_public_key: string;
}
interface TicketResult { activation_ticket: string; expires_at: string;
  enrollment_url?: string | null }

function statusTone(status: string): "ok" | "warn" | "danger" | "muted" {
  if (status === "active" || status === "succeeded") return "ok";
  if (status === "revoked" || status === "failed" || status === "cancelled") return "danger";
  if (status === "queued" || status === "running") return "warn";
  return "muted";
}

function errMsg(e: unknown, fallback: string): string {
  return e instanceof ApiError ? e.message : fallback;
}

/** Resolve a legacy username to its platform user_id (grant/ticket bodies need the id). */
async function resolveUserId(username: string): Promise<number> {
  const overview = await api.get<{ user_id: number }>(
    `/zagros/users/by-username/${encodeURIComponent(username)}/application-overview`);
  return overview.user_id;
}

export default function Applications() {
  const t = useT();
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const listQ = useQuery({
    queryKey: APP_QK,
    queryFn: () => api.get<AppListItem[]>("/zagros/applications"),
  });

  const columns: Column<AppListItem>[] = [
    { id: "name", header: t("apps.name"), cell: (a) => (
      <button type="button" className="font-medium text-brand hover:underline" onClick={() => setSelected(a.public_id)}>
        {a.name}
      </button>
    ) },
    { id: "status", header: t("apps.status"), width: "110px", cell: (a) => (
      <Badge tone={statusTone(a.status)}>{a.status}</Badge>
    ) },
    { id: "api", header: t("apps.apiBaseUrl"), cell: (a) => (
      <code className="block max-w-[280px] truncate text-[11px]" dir="ltr" title={a.api_base_url}>{a.api_base_url}</code>
    ) },
    { id: "lang", header: t("apps.defaultLang"), width: "90px", cell: (a) => (
      <span className="text-[12px] text-content-2">{a.default_lang}</span>
    ) },
    { id: "actions", header: "", width: "120px", cell: (a) => (
      <div className="flex justify-end gap-1">
        <Button type="button" size="sm" variant="ghost" onClick={() => setSelected(a.public_id)}>
          {t("common.edit")}
        </Button>
      </div>
    ) },
  ];

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader
          title={t("apps.title")}
          subtitle={t("apps.subtitle")}
          actions={
            <div className="flex gap-2">
              <Button type="button" size="sm" variant="secondary" onClick={() => void listQ.refetch()} loading={listQ.isFetching}>
                <RefreshCw size={13} />{t("common.refresh")}
              </Button>
              <Button type="button" size="sm" onClick={() => setCreateOpen(true)}>
                <Plus size={13} />{t("apps.create")}
              </Button>
            </div>
          }
        />
        {listQ.isLoading ? (
          <div className="space-y-2 p-4"><Skeleton className="h-10" /><Skeleton className="h-10" /><Skeleton className="h-10" /></div>
        ) : listQ.isError ? (
          <div className="p-4"><ErrorState message={errMsg(listQ.error, t("common.loadFailed"))} onRetry={() => void listQ.refetch()} /></div>
        ) : (listQ.data ?? []).length === 0 ? (
          <div className="p-4">
            <EmptyState title={t("apps.empty")} hint={t("apps.emptyHint")}
              action={<Button type="button" size="sm" onClick={() => setCreateOpen(true)}><Plus size={13} />{t("apps.create")}</Button>} />
          </div>
        ) : (
          <DataTable columns={columns} rows={listQ.data ?? []} rowKey={(a) => a.public_id} />
        )}
      </Card>

      {createOpen && (
        <CreateDialog onClose={() => setCreateOpen(false)} onCreated={(id) => {
          setCreateOpen(false);
          void qc.invalidateQueries({ queryKey: APP_QK });
          setSelected(id);
        }} />
      )}
      {selected && (
        <DetailDialog publicId={selected} onClose={() => setSelected(null)} onChanged={() => {
          void qc.invalidateQueries({ queryKey: APP_QK });
        }} />
      )}
    </div>
  );
}

// ------------------------------------------------------------------ create ---

function CreateDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (id: string) => void }) {
  const t = useT();
  const [name, setName] = useState("");
  const [apiBaseUrl, setApiBaseUrl] = useState(
    typeof window !== "undefined" ? window.location.origin : "https://");
  const [defaultLang, setDefaultLang] = useState("en");
  const [bootstrap, setBootstrap] = useState<BootstrapResult | null>(null);

  const create = useMutation({
    mutationFn: () => api.post<BootstrapResult>("/zagros/applications", {
      name: name.trim(), api_base_url: apiBaseUrl.trim(), default_lang: defaultLang,
    }),
    onSuccess: (data) => { setBootstrap(data); toast.ok(t("apps.created")); },
    onError: (e) => toast.error(errMsg(e, t("common.error"))),
  });

  return (
    <Dialog open onClose={onClose} title={t("apps.create")}
      footer={bootstrap ? (
        <Button type="button" onClick={() => onCreated(bootstrap.application_id)}>{t("common.confirm")}</Button>
      ) : (
        <>
          <Button type="button" variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button type="button" onClick={() => create.mutate()} loading={create.isPending}
            disabled={!name.trim() || !apiBaseUrl.trim()}>{t("common.create")}</Button>
        </>
      )}>
      {bootstrap ? (
        <div className="space-y-2">
          <p className="text-[12px] text-content-2">
            <code dir="ltr">{bootstrap.application_id}</code>
          </p>
          {([["signing", bootstrap.signing_key_id, bootstrap.signing_public_key],
            ["config", bootstrap.config_key_id, bootstrap.config_public_key]] as const).map(([slot, kid, pub]) => (
            <div key={slot} className="rounded-lg border border-line/60 px-2.5 py-2">
              <div className="flex items-center justify-between gap-2">
                <p className="text-[11px] text-content-3">{slot} · <code dir="ltr">{kid}</code></p>
                <CopyButton text={pub} />
              </div>
              <code className="mt-1 block break-all text-[11px]" dir="ltr">{pub}</code>
            </div>
          ))}
        </div>
      ) : (
        <div className="space-y-3">
          <Field label={t("apps.name")} required>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="ResellerApp" />
          </Field>
          <Field label={t("apps.apiBaseUrl")} hint={t("apps.apiBaseUrlHint")} required>
            <Input value={apiBaseUrl} onChange={(e) => setApiBaseUrl(e.target.value)} dir="ltr" placeholder="https://panel.example.com" />
          </Field>
          <Field label={t("apps.defaultLang")}>
            <Select value={defaultLang} onChange={(e) => setDefaultLang(e.target.value)}>
              <option value="en">English</option>
              <option value="fa">فارسی</option>
            </Select>
          </Field>
          <p className="text-[11px] text-content-3">{t("apps.ownerAuto")}</p>
        </div>
      )}
    </Dialog>
  );
}

// ------------------------------------------------------------------ detail ---

function DetailDialog({ publicId, onClose, onChanged }: {
  publicId: string; onClose: () => void; onChanged: () => void;
}) {
  const t = useT();
  const qc = useQueryClient();
  const detailQ = useQuery({
    queryKey: [...APP_QK, publicId],
    queryFn: () => api.get<AppDetail>(`/zagros/applications/${publicId}`),
  });
  const app = detailQ.data ?? null;
  const active = app?.status === "active";

  const revoke = useMutation({
    mutationFn: () => api.post(`/zagros/applications/${publicId}/revoke`, {}),
    onSuccess: () => {
      toast.ok(t("apps.revoked"));
      onChanged();
      void qc.invalidateQueries({ queryKey: [...APP_QK, publicId] });
    },
    onError: (e) => toast.error(errMsg(e, t("common.error"))),
  });

  return (
    <Dialog open onClose={onClose} wide
      title={app ? app.name : publicId}
      subtitle={app && (
        <span className="flex flex-wrap items-center gap-2">
          <Badge tone={statusTone(app.status)}>{app.status}</Badge>
          <code className="text-[11px]" dir="ltr">{app.public_id}</code>
          <CopyButton text={app.public_id} />
        </span>
      )}
      headerActions={app && active ? (
        <Button type="button" size="sm" variant="danger"
          loading={revoke.isPending}
          onClick={() => { if (window.confirm(t("apps.revokeConfirm"))) revoke.mutate(); }}>
          <ShieldX size={13} />{t("apps.revokeApp")}
        </Button>
      ) : undefined}>
      {detailQ.isLoading ? (
        <div className="space-y-2"><Skeleton className="h-16" /><Skeleton className="h-16" /><Skeleton className="h-16" /></div>
      ) : detailQ.isError || !app ? (
        <ErrorState message={errMsg(detailQ.error, t("common.loadFailed"))} onRetry={() => void detailQ.refetch()} />
      ) : (
        <div className="space-y-4">
          <div className="grid gap-2 text-[12px] sm:grid-cols-2">
            <div><p className="text-[11px] text-content-3">{t("apps.apiBaseUrl")}</p>
              <code className="break-all text-[11px]" dir="ltr">{app.api_base_url}</code></div>
            <div><p className="text-[11px] text-content-3">{t("apps.defaultLang")}</p>
              <p>{app.default_lang}</p></div>
          </div>
          <IconSection app={app} disabled={!active} />
          <KeysSection publicId={publicId} />
          <GrantsSection publicId={publicId} disabled={!active} />
          <TicketsSection publicId={publicId} disabled={!active} />
          <BuildsSection app={app} disabled={!active} />
        </div>
      )}
    </Dialog>
  );
}

// --------------------------------------------------------------------- icon ---

function IconSection({ app, disabled }: { app: AppDetail; disabled: boolean }) {
  const t = useT();
  const qc = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [iconUrl, setIconUrl] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const meta = (app.branding?.icon ?? null) as IconMeta | null;

  useEffect(() => {
    if (!meta) { setIconUrl(null); return; }
    let alive = true;
    let url: string | null = null;
    const token = getToken();
    fetch(`${API_BASE}/zagros/applications/${app.public_id}/icon`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }).then((r) => (r.ok ? r.blob() : null)).then((blob) => {
      if (blob && alive) { url = URL.createObjectURL(blob); setIconUrl(url); }
    }).catch(() => {});
    return () => { alive = false; if (url) URL.revokeObjectURL(url); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [app.public_id, meta?.sha256, nonce]);

  const refresh = () => {
    setNonce((n) => n + 1);
    void qc.invalidateQueries({ queryKey: [...APP_QK, app.public_id] });
  };
  const upload = useMutation({
    mutationFn: async (file: File) => {
      const body = new FormData();
      body.append("file", file, file.name);
      return api.post<IconMeta>(`/zagros/applications/${app.public_id}/icon`, body);
    },
    onSuccess: () => { toast.ok(t("apps.iconUploaded")); refresh(); },
    onError: (e) => toast.error(errMsg(e, t("common.error"))),
  });
  const remove = useMutation({
    mutationFn: () => api.delete(`/zagros/applications/${app.public_id}/icon`),
    onSuccess: () => { toast.ok(t("apps.iconDeleted")); setIconUrl(null); refresh(); },
    onError: (e) => toast.error(errMsg(e, t("common.error"))),
  });

  return (
    <section className="rounded-xl border border-border bg-surface-2 p-3">
      <p className="text-xs font-medium">{t("apps.icon")}</p>
      <p className="mb-2 text-[11px] text-content-3">{t("apps.iconHint")}</p>
      <div className="flex items-center gap-3">
        {iconUrl ? (
          <img src={iconUrl} alt="" className="h-16 w-16 rounded-xl border border-border object-cover" />
        ) : (
          <div className="flex h-16 w-16 items-center justify-center rounded-xl border border-dashed border-border-strong text-content-3">
            <ImagePlus size={20} />
          </div>
        )}
        <div className="min-w-0 flex-1">
          {meta ? (
            <p className="text-[11px] text-content-2" dir="ltr">
              {meta.width}×{meta.height} · {formatBytes(meta.size_bytes)} · {meta.sha256.slice(0, 12)}…
              {meta.android_pack_bytes != null && (
                <> · pack {formatBytes(meta.android_pack_bytes)}</>
              )}
            </p>
          ) : (
            <p className="text-[11px] text-content-3">{t("apps.noIcon")}</p>
          )}
          <input ref={fileRef} type="file" accept="image/png,.png" className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              e.target.value = "";
              if (file) upload.mutate(file);
            }} />
          <div className="mt-1.5 flex gap-2">
            <Button type="button" size="sm" variant="secondary" disabled={disabled}
              loading={upload.isPending} onClick={() => fileRef.current?.click()}>
              {t("apps.uploadIcon")}
            </Button>
            {meta && (
              <Button type="button" size="sm" variant="ghost" disabled={disabled}
                loading={remove.isPending} onClick={() => remove.mutate()}>
                <Trash2 size={13} />{t("common.delete")}
              </Button>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

// --------------------------------------------------------------------- keys ---

function KeysSection({ publicId }: { publicId: string }) {
  const t = useT();
  const keysQ = useQuery({
    queryKey: [...APP_QK, publicId, "keys"],
    queryFn: () => api.get<AppKeys>(`/zagros/applications/${publicId}/keys`),
  });
  return (
    <section className="rounded-xl border border-border bg-surface-2 p-3">
      <p className="text-xs font-medium">{t("apps.keys")}</p>
      <p className="mb-2 text-[11px] text-content-3">{t("apps.keysHint")}</p>
      {keysQ.isLoading ? <Skeleton className="h-12" />
        : keysQ.isError || !keysQ.data ? (
          <ErrorState message={errMsg(keysQ.error, t("common.loadFailed"))} onRetry={() => void keysQ.refetch()} />
        ) : (
          <div className="space-y-1.5">
            {(["signing", "config"] as const).map((slot) => {
              const key = keysQ.data![slot];
              return (
                <div key={slot} className="rounded-lg border border-line/60 px-2.5 py-2">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-[11px] text-content-3">
                      {slot} · <code dir="ltr">{key?.kid ?? t("apps.unknown")}</code>
                    </p>
                    {key && <CopyButton text={key.public_key} />}
                  </div>
                  {key && <code className="mt-1 block break-all text-[11px]" dir="ltr">{key.public_key}</code>}
                </div>
              );
            })}
          </div>
        )}
    </section>
  );
}

// ------------------------------------------------------------------- grants ---

function GrantsSection({ publicId, disabled }: { publicId: string; disabled: boolean }) {
  const t = useT();
  const qc = useQueryClient();
  const [username, setUsername] = useState("");
  const grantsQ = useQuery({
    queryKey: [...APP_QK, publicId, "grants"],
    queryFn: () => api.get<GrantItem[]>(`/zagros/applications/${publicId}/grants`),
  });
  const grant = useMutation({
    mutationFn: async (name: string) => {
      let userId: number;
      try {
        userId = await resolveUserId(name);
      } catch {
        throw new Error(t("apps.userResolveFailed"));
      }
      return api.post(`/zagros/applications/${publicId}/grants`, { user_id: userId });
    },
    onSuccess: () => {
      toast.ok(t("apps.granted"));
      setUsername("");
      void qc.invalidateQueries({ queryKey: [...APP_QK, publicId, "grants"] });
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : t("common.error")),
  });
  const unbind = useMutation({
    mutationFn: (userId: number) =>
      api.post(`/zagros/applications/${publicId}/grants/${userId}/revoke`, {}),
    onSuccess: () => {
      toast.ok(t("apps.grantRevoked"));
      void qc.invalidateQueries({ queryKey: [...APP_QK, publicId, "grants"] });
    },
    onError: (e) => toast.error(errMsg(e, t("common.error"))),
  });

  return (
    <section className="rounded-xl border border-border bg-surface-2 p-3">
      <p className="text-xs font-medium">{t("apps.grants")}</p>
      <div className="mb-2 mt-2 flex gap-2">
        <Input value={username} onChange={(e) => setUsername(e.target.value)}
          placeholder={t("apps.grantUsername")} disabled={disabled}
          onKeyDown={(e) => { if (e.key === "Enter" && username.trim()) grant.mutate(username.trim()); }} />
        <Button type="button" size="sm" variant="secondary" disabled={disabled || !username.trim()}
          loading={grant.isPending} onClick={() => grant.mutate(username.trim())}>
          {t("apps.grant")}
        </Button>
      </div>
      {grantsQ.isLoading ? <Skeleton className="h-10" />
        : grantsQ.isError ? (
          <ErrorState message={errMsg(grantsQ.error, t("common.loadFailed"))} onRetry={() => void grantsQ.refetch()} />
        ) : (grantsQ.data ?? []).length === 0 ? (
          <p className="py-1 text-center text-[11px] text-content-3">{t("apps.noGrants")}</p>
        ) : (
          <div className="space-y-1.5">
            {(grantsQ.data ?? []).map((g) => (
              <div key={g.user_id} className="flex items-center justify-between gap-2 rounded-lg border border-line/60 px-2.5 py-1.5">
                <div className="min-w-0">
                  <p className="truncate text-[12px] font-medium">{g.username}</p>
                  <p className="text-[10.5px] text-content-3">
                    {g.status}{g.granted_at ? ` · ${formatDate(g.granted_at)}` : ""}
                  </p>
                </div>
                <Button type="button" size="sm" variant="ghost" disabled={disabled}
                  loading={unbind.isPending} onClick={() => unbind.mutate(g.user_id)}>
                  <Trash2 size={13} />{t("apps.revokeGrant")}
                </Button>
              </div>
            ))}
          </div>
        )}
    </section>
  );
}

// ------------------------------------------------------------------ tickets ---

function TicketsSection({ publicId, disabled }: { publicId: string; disabled: boolean }) {
  const t = useT();
  const [username, setUsername] = useState("");
  const [ttl, setTtl] = useState("600");
  const [issued, setIssued] = useState<TicketResult | null>(null);
  const issue = useMutation({
    mutationFn: async () => {
      let userId: number;
      try {
        userId = await resolveUserId(username.trim());
      } catch {
        throw new Error(t("apps.userResolveFailed"));
      }
      return api.post<TicketResult>(`/zagros/applications/${publicId}/activation-tickets`, {
        user_id: userId, ttl_seconds: Number(ttl),
      });
    },
    onSuccess: (data) => { setIssued(data); toast.ok(t("apps.ticketIssued")); },
    onError: (e) => toast.error(e instanceof Error ? e.message : t("common.error")),
  });

  return (
    <section className="rounded-xl border border-border bg-surface-2 p-3">
      <p className="text-xs font-medium">{t("apps.tickets")}</p>
      <p className="mb-2 text-[11px] text-content-3">{t("apps.ticketsHint")}</p>
      <div className="flex gap-2">
        <Input value={username} onChange={(e) => setUsername(e.target.value)}
          placeholder={t("apps.grantUsername")} disabled={disabled} />
        <Select value={ttl} onChange={(e) => setTtl(e.target.value)} disabled={disabled}
          aria-label={t("apps.ttl")}>
          <option value="300">5m</option>
          <option value="600">10m</option>
          <option value="1800">30m</option>
          <option value="3600">1h</option>
        </Select>
        <Button type="button" size="sm" variant="secondary" disabled={disabled || !username.trim()}
          loading={issue.isPending} onClick={() => issue.mutate()}>
          {t("apps.issueTicket")}
        </Button>
      </div>
      {issued && (
        <div className="mt-2 space-y-1.5 rounded-lg border border-warn/40 bg-warn/5 p-2.5">
          <div className="flex items-center justify-between gap-2">
            <p className="text-[11px] text-content-3">
              {t("apps.ttl")}: <span dir="ltr">{formatDate(issued.expires_at)}</span>
            </p>
            <CopyButton text={issued.activation_ticket} />
          </div>
          <code className="block break-all text-[11px]" dir="ltr">{issued.activation_ticket}</code>
          {issued.enrollment_url && (
            <div className="flex items-start gap-2.5 rounded-lg bg-surface-1 p-2">
              <QRCodeSVG value={issued.enrollment_url} size={112} level="M"
                bgColor="transparent" fgColor="currentColor"
                aria-label={t("apps.enrollmentQr")} />
              <div className="min-w-0 flex-1">
                <p className="text-[11px] font-medium">{t("apps.enrollmentQr")}</p>
                <p className="mb-1.5 text-[10.5px] text-content-3">{t("apps.enrollmentQrHint")}</p>
                <CopyButton text={issued.enrollment_url} />
              </div>
            </div>
          )}
          <div className="flex justify-end">
            <Button type="button" size="sm" variant="ghost" onClick={() => setIssued(null)}>
              {t("common.close")}
            </Button>
          </div>
        </div>
      )}
    </section>
  );
}

// ------------------------------------------------------------------- builds ---

function BuildsSection({ app, disabled }: { app: AppDetail; disabled: boolean }) {
  const t = useT();
  const qc = useQueryClient();
  const [triggerOpen, setTriggerOpen] = useState(false);
  const [detailId, setDetailId] = useState<string | null>(null);
  const buildsQ = useQuery({
    queryKey: [...APP_QK, app.public_id, "builds"],
    queryFn: () => api.get<{ items: BuildItem[]; total: number }>(
      `/zagros/builds?application_id=${encodeURIComponent(app.public_id)}&limit=20`),
    refetchInterval: 15_000,
  });

  const saveArtifact = async (build: BuildItem, art: BuildArtifact) => {
    try {
      await download(
        `/zagros/builds/${build.public_id}/artifacts/${art.platform}/${art.arch}/${encodeURIComponent(art.filename)}`,
        art.filename);
    } catch (e) {
      toast.error(errMsg(e, t("common.error")));
    }
  };

  return (
    <section className="rounded-xl border border-border bg-surface-2 p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <p className="text-xs font-medium">{t("apps.builds")}</p>
        <Button type="button" size="sm" disabled={disabled} onClick={() => setTriggerOpen(true)}>
          <Rocket size={13} />{t("apps.triggerBuild")}
        </Button>
      </div>
      {buildsQ.isLoading ? <Skeleton className="h-10" />
        : buildsQ.isError ? (
          <ErrorState message={errMsg(buildsQ.error, t("common.loadFailed"))} onRetry={() => void buildsQ.refetch()} />
        ) : (buildsQ.data?.items ?? []).length === 0 ? (
          <p className="py-1 text-center text-[11px] text-content-3">{t("apps.noBuilds")}</p>
        ) : (
          <div className="space-y-1.5">
            {(buildsQ.data?.items ?? []).map((b) => (
              <div key={b.public_id} onClick={() => setDetailId(b.public_id)}
                className="cursor-pointer rounded-lg border border-line/60 px-2.5 py-2 transition-colors hover:border-brand/60">
                <div className="flex items-center justify-between gap-2">
                  <p className="truncate text-[12px] font-medium" dir="ltr">
                    {b.version ?? b.public_id}
                    {b.build_number != null && <span className="text-content-3"> #{b.build_number}</span>}
                  </p>
                  <Badge tone={statusTone(b.status)}>{b.status}</Badge>
                </div>
                <p className="mt-0.5 text-[10.5px] text-content-3" dir="ltr">
                  {(b.targets ?? []).map((tg) => `${tg.platform}/${tg.arch}/${tg.artifact}`).join(" · ")}
                  {b.created_at ? ` — ${formatDate(b.created_at)}` : ""}
                </p>
                {(b.artifacts ?? []).length > 0 && (
                  <div className="mt-1 space-y-1">
                    {(b.artifacts ?? []).map((art) => (
                      <div key={art.rel_path} className="flex items-center justify-between gap-2">
                        <code className="min-w-0 truncate text-[11px]" dir="ltr" title={art.sha256}>
                          {art.filename} · {formatBytes(art.size_bytes)}
                        </code>
                        <Button type="button" size="sm" variant="ghost"
                          onClick={() => void saveArtifact(b, art)}>
                          <Download size={13} />
                        </Button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      {triggerOpen && (
        <TriggerBuildDialog app={app} onClose={() => setTriggerOpen(false)} onQueued={() => {
          setTriggerOpen(false);
          void qc.invalidateQueries({ queryKey: [...APP_QK, app.public_id, "builds"] });
        }} />
      )}
      {detailId && (
        <BuildDetailDialog app={app} buildId={detailId} onClose={() => setDetailId(null)} />
      )}
    </section>
  );
}

interface TargetRow { platform: string; arch: string; artifact: string }

const PLATFORM_ARTIFACTS: Record<string, string[]> = {
  android: ["apk", "aab"],
  windows: ["zip"],
  linux: ["tar.gz"],
  macos: ["tar.gz"],
  ios: ["ipa"],
};

const PLATFORM_ARCHES: Record<string, string[]> = {
  android: ["armeabi-v7a", "arm64-v8a", "x86_64"],
  ios: ["arm64"],
  windows: ["x64", "arm64"],
  linux: ["x64", "arm64"],
  macos: ["arm64", "x64"],
};

interface ExternalProbe {
  reachable: boolean; host_key_pin: string | null; os_pretty: string | null;
  cores: number | null; mem_avail_mb: number | null; mem_total_mb: number | null;
  swap_total_mb: number | null; disk_free_mb: number | null; is_root: boolean;
  toolchain: Record<string, boolean>; message: string | null;
}

function BuildDetailDialog({ app, buildId, onClose }: {
  app: AppDetail; buildId: string; onClose: () => void;
}) {
  const t = useT();
  const detailQ = useQuery({
    queryKey: [...APP_QK, app.public_id, "build", buildId],
    queryFn: () => api.get<BuildItem>(`/zagros/builds/${buildId}`),
    refetchInterval: (q) => {
      const cur = q.state.data;
      return cur && (cur.status === "queued" || cur.status === "running")
        ? 5000 : false;
    },
  });
  const b = detailQ.data;
  const saveArtifact = async (art: BuildArtifact) => {
    try {
      await download(
        `/zagros/builds/${buildId}/artifacts/${art.platform}/${art.arch}/${encodeURIComponent(art.filename)}`,
        art.filename);
    } catch (e) {
      toast.error(errMsg(e, t("common.error")));
    }
  };
  return (
    <Dialog open onClose={onClose} wide title={t("apps.buildDetail")}
      subtitle={<code className="text-[11px]" dir="ltr">{buildId}</code>}
      footer={<Button type="button" variant="ghost" onClick={onClose}>{t("common.close")}</Button>}>
      {detailQ.isLoading || !b ? <Skeleton className="h-24" /> : (
        <div className="space-y-4">
          <div className="flex items-center justify-between gap-2">
            <p className="text-sm font-semibold" dir="ltr">
              {b.version ?? b.public_id}
              {b.build_number != null && <span className="text-content-3"> #{b.build_number}</span>}
            </p>
            <Badge tone={statusTone(b.status)}>{b.status}</Badge>
          </div>
          {b.created_at && (
            <p className="text-[11px] text-content-3" dir="ltr">{formatDate(b.created_at)}</p>
          )}
          {b.status === "failed" && (
            <div className="rounded-lg border border-danger/30 bg-danger/10 p-2.5">
              <p className="text-[11px] font-medium text-danger">{t("apps.buildFailure")}</p>
              <p className="mt-1 break-words font-mono text-[10.5px] text-danger/90" dir="ltr">
                {b.failure_message || b.failure_code || "-"}
              </p>
            </div>
          )}
          <div>
            <p className="mb-1 text-[12px] font-medium">{t("apps.buildTargets")}</p>
            <div className="space-y-1">
              {(b.targets ?? []).map((tg) => (
                <div key={`${tg.platform}-${tg.arch}-${tg.artifact}`}
                  className="flex items-center justify-between rounded-lg border border-line/60 px-2.5 py-1.5 text-[11.5px]"
                  dir="ltr">
                  <span className="font-mono">{tg.platform}/{tg.arch} · {tg.artifact}</span>
                  <Badge tone={statusTone(tg.status)}>{tg.status}</Badge>
                </div>
              ))}
            </div>
          </div>
          <div>
            <p className="mb-1 text-[12px] font-medium">{t("apps.artifacts")}</p>
            {(b.artifacts ?? []).length === 0 ? (
              <p className="py-2 text-center text-[11px] text-content-3">{t("apps.noArtifacts")}</p>
            ) : (
              <div className="space-y-1">
                {(b.artifacts ?? []).map((art) => (
                  <div key={art.rel_path}
                    className="flex items-center justify-between gap-2 rounded-lg border border-line/60 px-2.5 py-1.5">
                    <div className="min-w-0">
                      <code className="block truncate text-[11.5px]" dir="ltr" title={art.sha256}>{art.filename}</code>
                      <span className="text-[10px] text-content-3" dir="ltr">
                        {art.platform}/{art.arch} · {formatBytes(art.size_bytes)} · sha256:{art.sha256.slice(0, 12)}…
                      </span>
                    </div>
                    <Button type="button" size="sm" onClick={() => void saveArtifact(art)}>
                      <Download size={13} />{t("apps.download")}
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </Dialog>
  );
}

function TriggerBuildDialog({ app, onClose, onQueued }: {
  app: AppDetail; onClose: () => void; onQueued: () => void;
}) {
  const t = useT();
  const keysQ = useQuery({
    queryKey: [...APP_QK, app.public_id, "keys"],
    queryFn: () => api.get<AppKeys>(`/zagros/applications/${app.public_id}/keys`),
  });
  const credsQ = useQuery({
    queryKey: ["zagros", "build-credentials"],
    queryFn: () => api.get<{ items?: CredentialItem[] } | CredentialItem[]>("/zagros/build-credentials"),
  });
  const creds: CredentialItem[] = Array.isArray(credsQ.data)
    ? credsQ.data
    : (credsQ.data?.items ?? []);

  // wizard mode: simple (default) hides repos/revisions + raw config
  const [mode, setMode] = useState<"simple" | "advanced">("simple");
  // build location: master (default) or an external SSH host
  const [location, setLocation] = useState<"master" | "external">("master");

  const [version, setVersion] = useState("1.0.0");
  const [sourceRepo, setSourceRepo] = useState("https://github.com/ZagrosGM/Zagros-VPN");
  const [sourceRevision, setSourceRevision] = useState("");
  const [sdkRepo, setSdkRepo] = useState("https://github.com/ZagrosGM/Zagros-VPN-SDK");
  const [sdkRevision, setSdkRevision] = useState("");
  const [targets, setTargets] = useState<TargetRow[]>([
    { platform: "android", arch: "arm64-v8a", artifact: "apk" },
  ]);
  const shaOk = (s: string) => /^[0-9a-f]{40}$/i.test(s.trim());
  const [credIds, setCredIds] = useState<string[]>([]);
  const [configText, setConfigText] = useState<string | null>(null);
  const keys = keysQ.data;

  // external host fields + probe state
  const [extHost, setExtHost] = useState("");
  const [extPort, setExtPort] = useState("22");
  const [extUser, setExtUser] = useState("root");
  const [extPass, setExtPass] = useState("");
  const [extKey, setExtKey] = useState("");
  const [probe, setProbe] = useState<ExternalProbe | null>(null);
  const [pinConfirmed, setPinConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const probeMut = useMutation({
    mutationFn: () => api.post<ExternalProbe>("/zagros/builds/external-host-probe", {
      host: extHost.trim(),
      port: Number(extPort) || 22,
      username: extUser.trim(),
      password: extPass,
      private_key: extKey.trim(),
    }),
    onSuccess: (r) => {
      setProbe(r);
      setPinConfirmed(false);
      if (!r.reachable) toast.error(r.message || t("apps.probeFail"));
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : t("common.error")),
  });

  useEffect(() => {
    if (configText === null && keys) {
      const slug = (app.name.toLowerCase().replace(/[^a-z0-9]+/g, "") || "app").slice(0, 32);
      setConfigText(JSON.stringify({
        display_name: app.name,
        default_locale: app.default_lang,
        application_api_base_url: app.api_base_url,
        application_id: app.public_id,
        application_name: app.name,
        application_status: app.status,
        config_key_id: keys.config?.kid ?? "",
        config_public_key: keys.config?.public_key ?? "",
        signing_key_id: keys.signing?.kid ?? "",
        signing_public_key: keys.signing?.public_key ?? "",
        android_application_id: `com.zagros.${slug}`,
        android_application_label: app.name,
      }, null, 2));
    }
  }, [keys, configText, app]);

  const resolvedRevisions = mode === "advanced"
    || (shaOk(sourceRevision) && shaOk(sdkRevision));

  async function submit() {
    if (submitting) return;
    if (location === "external" && (!probe?.reachable || !pinConfirmed)) return;
    setSubmitting(true);
    try {
      let repo = sourceRepo.trim();
      let revision = sourceRevision.trim();
      let sdkR = sdkRepo.trim();
      let sdkRev = sdkRevision.trim();
      if (mode === "simple") {
        const r = await api.post<{ source: { repo: string; revision: string }; sdk_source: { repo: string; revision: string } }>(
          "/zagros/builds/resolve-source", {});
        repo = r.source.repo; revision = r.source.revision;
        sdkR = r.sdk_source.repo; sdkRev = r.sdk_source.revision;
      }
      const credentialIds = [...credIds];
      if (location === "external") {
        const material: Record<string, unknown> = {
          host: extHost.trim(),
          port: Number(extPort) || 22,
          username: extUser.trim(),
          host_key_pin: probe?.host_key_pin ?? "",
        };
        if (extPass) material.password = extPass;
        if (extKey.trim()) material.private_key = extKey.trim();
        const cred = await api.post<{ public_id: string }>("/zagros/build-credentials", {
          scope: "application",
          owner_ref: app.public_id,
          kind: "ssh_password",
          label: `build-host ${extHost.trim()}`,
          material,
        });
        credentialIds.push(cred.public_id);
      }
      let buildConfig: Record<string, unknown>;
      try {
        buildConfig = JSON.parse(configText ?? "{}") as Record<string, unknown>;
      } catch {
        throw new Error(t("apps.invalidJson"));
      }
      await api.post(`/zagros/applications/${app.public_id}/builds`, {
        version: version.trim(),
        source_repo: repo,
        source_revision: revision,
        sdk_source_repo: sdkR,
        sdk_source_revision: sdkRev,
        targets: targets.filter((tg) => tg.platform.trim() && tg.arch.trim() && tg.artifact.trim()),
        credential_ids: credentialIds,
        build_config: buildConfig,
      });
      toast.ok(t("apps.buildQueued"));
      onQueued();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t("common.error"));
    } finally {
      setSubmitting(false);
    }
  }

  const setTarget = (i: number, patch: Partial<TargetRow>) =>
    setTargets((rows) => rows.map((row, j) => (j === i ? { ...row, ...patch } : row)));

  const archesFor = (platform: string) => PLATFORM_ARCHES[platform] ?? [];

  const locationBlock = (
    <div className="mt-3">
      <p className="mb-1 text-[12px] font-medium">{t("apps.buildLocation")}</p>
      <div className="grid gap-2 sm:grid-cols-2">
        {([
          { id: "master", label: t("apps.locMaster"), hint: t("apps.locMasterHint") },
          { id: "external", label: t("apps.locExternal"), hint: t("apps.locExternalHint") },
        ] as const).map((opt) => (
          <button key={opt.id} type="button"
            onClick={() => setLocation(opt.id)}
            className={cn("rounded-xl border p-2.5 text-start transition-colors",
              location === opt.id
                ? "border-brand bg-brand/10"
                : "border-border bg-surface-1 hover:border-border-strong")}>
            <span className="flex items-center gap-2 text-[12.5px] font-medium">
              <input type="radio" className="accent-brand" checked={location === opt.id} readOnly />
              {opt.label}
            </span>
            <span className="mt-1 block text-[11px] text-content-3">{opt.hint}</span>
          </button>
        ))}
      </div>
      {location === "external" && (
        <div className="mt-3 rounded-xl border border-border bg-surface-1 p-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label={t("apps.extHost")} required>
              <Input value={extHost} onChange={(e) => setExtHost(e.target.value)} dir="ltr"
                placeholder="203.0.113.10" />
            </Field>
            <Field label={t("apps.extPort")}>
              <Input value={extPort} onChange={(e) => setExtPort(e.target.value)} dir="ltr"
                inputMode="numeric" placeholder="22" />
            </Field>
            <Field label={t("apps.extUsername")} required>
              <Input value={extUser} onChange={(e) => setExtUser(e.target.value)} dir="ltr"
                placeholder="root" />
            </Field>
            <Field label={t("apps.extPassword")}>
              <Input type="password" value={extPass} onChange={(e) => setExtPass(e.target.value)} dir="ltr" />
            </Field>
            {mode === "advanced" && (
              <Field label={t("apps.extKey")} hint=" ">
                <textarea value={extKey} onChange={(e) => setExtKey(e.target.value)} dir="ltr"
                  spellCheck={false} rows={3}
                  className="w-full rounded-lg border border-border bg-surface-1 p-2 font-mono text-[11px] text-content outline-none focus:border-brand" />
              </Field>
            )}
          </div>
          <div className="mt-2 flex items-center gap-2">
            <Button type="button" size="sm" variant="secondary"
              disabled={!extHost.trim() || !extUser.trim() || probeMut.isPending}
              onClick={() => probeMut.mutate()}>
              <RefreshCw size={13} className={probeMut.isPending ? "animate-spin" : ""} />
              {probeMut.isPending ? t("apps.probeTesting") : t("apps.testConnection")}
            </Button>
            {probe?.reachable && (
              <span className="text-[11.5px] font-medium text-green-500">✓ {t("apps.probeOk")}</span>
            )}
          </div>
          {probe?.reachable && (
            <div className="mt-3 space-y-2">
              <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11.5px] sm:grid-cols-3">
                {probe.os_pretty && (
                  <span className="text-content-2">{t("apps.probeOs")}: <b className="text-content">{probe.os_pretty}</b></span>
                )}
                {probe.cores !== null && (
                  <span className="text-content-2">{t("apps.probeCores")}: <b className="text-content">{probe.cores}</b></span>
                )}
                {probe.mem_avail_mb !== null && (
                  <span className="text-content-2">{t("apps.probeMem")}: <b className="text-content">{probe.mem_avail_mb}MB</b>{probe.swap_total_mb ? ` (+${probe.swap_total_mb}MB ${t("apps.probeSwap")})` : ""}</span>
                )}
                {probe.disk_free_mb !== null && (
                  <span className="text-content-2">{t("apps.probeDisk")}: <b className="text-content">{probe.disk_free_mb}MB</b></span>
                )}
                <span className="text-content-2">{t("apps.probeRoot")}: <b className="text-content">{probe.is_root ? "✓" : "✗"}</b></span>
                {Object.entries(probe.toolchain).map(([k, v]) => (
                  <span key={k} className="text-content-2">{k}: <b className={v ? "text-green-500" : "text-amber-500"}>{v ? "✓" : "install"}</b></span>
                ))}
              </div>
              {probe.host_key_pin && (
                <div>
                  <code className="block break-all rounded-lg border border-border bg-surface-1 p-2 font-mono text-[10.5px]" dir="ltr">
                    {probe.host_key_pin}
                  </code>
                  <label className="mt-1 flex items-center gap-2 text-[11.5px]">
                    <input type="checkbox" className="accent-brand"
                      checked={pinConfirmed}
                      onChange={(e) => setPinConfirmed(e.target.checked)} />
                    {t("apps.pinConfirm")}
                  </label>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );

  return (
    <Dialog open onClose={onClose} wide title={t("apps.triggerBuild")}
      subtitle={<code className="text-[11px]" dir="ltr">{app.public_id}</code>}
      footer={
        <>
          <Button type="button" variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button type="button" onClick={() => void submit()} loading={submitting}
            disabled={!version.trim() || targets.length === 0
              || (mode === "advanced" && (!shaOk(sourceRevision) || !shaOk(sdkRevision)))
              || (location === "external" && (!probe?.reachable || !pinConfirmed))}>
            <Rocket size={13} />{t("apps.triggerBuild")}
          </Button>
        </>
      }>
      <div className="mb-3 grid grid-cols-2 gap-1 rounded-xl border border-border bg-surface-1 p-1">
        {([["simple", t("apps.modeSimple")], ["advanced", t("apps.modeAdvanced")]] as const).map(
          ([id, label]) => (
            <button key={id} type="button" onClick={() => setMode(id)}
              className={cn("h-8 rounded-lg text-xs font-medium transition-colors",
                mode === id ? "bg-brand text-brand-content shadow-sm" : "text-content-2 hover:text-content")}>
              {label}
            </button>
          ))}
      </div>
      {mode === "simple" && (
        <p className="mb-3 rounded-lg border border-border/60 bg-surface-1 p-2 text-[11px] text-content-3">
          {t("apps.wizardHint")}
        </p>
      )}
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label={t("apps.version")} required>
          <Input value={version} onChange={(e) => setVersion(e.target.value)} dir="ltr" />
        </Field>
        {mode === "advanced" && (
          <>
            <Field label={t("apps.sourceRepo")} required>
              <Input value={sourceRepo} onChange={(e) => setSourceRepo(e.target.value)} dir="ltr"
                placeholder="https://github.com/…" />
            </Field>
            <Field label={t("apps.sourceRevision")} hint={t("apps.revisionHint")} required>
              <Input value={sourceRevision} onChange={(e) => setSourceRevision(e.target.value)} dir="ltr"
                placeholder="40-hex commit SHA" />
            </Field>
            <Field label={t("apps.sdkRepo")}>
              <Input value={sdkRepo} onChange={(e) => setSdkRepo(e.target.value)} dir="ltr"
                placeholder="https://github.com/…" />
            </Field>
            <Field label={t("apps.sdkRevision")} hint={t("apps.revisionHint")} required>
              <Input value={sdkRevision} onChange={(e) => setSdkRevision(e.target.value)} dir="ltr"
                placeholder="40-hex commit SHA" />
            </Field>
          </>
        )}
        <div>
          <p className="mb-1 text-[12px] font-medium">{t("apps.credentials")}</p>
          <p className="mb-1 text-[10.5px] leading-4 text-content-3">{t("apps.credentialsHint")}</p>
          {credsQ.isLoading ? <Skeleton className="h-8" />
            : creds.length === 0 ? (
              <p className="py-2 text-[11px] text-content-3">{t("apps.noCredentials")}</p>
            ) : (
              <div className="max-h-28 space-y-1 overflow-auto rounded-lg border border-line/60 p-2">
                {creds.filter((c) => !c.revoked).map((c) => (
                  <label key={c.public_id} className="flex items-center gap-2 text-[12px]">
                    <input type="checkbox" className="accent-brand"
                      checked={credIds.includes(c.public_id)}
                      onChange={(e) => setCredIds((ids) => e.target.checked
                        ? [...ids, c.public_id]
                        : ids.filter((id) => id !== c.public_id))} />
                    <span className="truncate">{c.label}</span>
                    <span className="text-[10.5px] text-content-3">({c.kind})</span>
                  </label>
                ))}
              </div>
            )}
        </div>
      </div>
      <div className="mt-3">
        <div className="mb-1 flex items-center justify-between">
          <p className="text-[12px] font-medium">{t("apps.targets")}</p>
          <Button type="button" size="sm" variant="ghost"
            onClick={() => setTargets((rows) => [...rows, { platform: "android", arch: "arm64-v8a", artifact: "apk" }])}>
            <Plus size={13} />{t("apps.addTarget")}
          </Button>
        </div>
        <div className="space-y-1.5">
          {targets.map((tg, i) => (
            <div key={i} className="grid grid-cols-[1fr_1fr_1fr_auto] gap-2">
              <Select value={tg.platform} dir="ltr" aria-label={t("apps.targetPlatform")}
                onChange={(e) => {
                  const platform = e.target.value;
                  const arches = archesFor(platform);
                  const arts = PLATFORM_ARTIFACTS[platform] ?? ["apk"];
                  setTarget(i, {
                    platform,
                    arch: arches.includes(tg.arch) ? tg.arch : (arches[0] ?? ""),
                    artifact: arts.includes(tg.artifact) ? tg.artifact : arts[0],
                  });
                }}>
                {Object.keys(PLATFORM_ARCHES).map((p) => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </Select>
              <Select value={tg.arch} dir="ltr" aria-label={t("apps.targetArch")}
                onChange={(e) => setTarget(i, { arch: e.target.value })}>
                {archesFor(tg.platform).map((a) => (
                  <option key={a} value={a}>{a}</option>
                ))}
              </Select>
              <Select value={tg.artifact} dir="ltr" aria-label={t("apps.targetArtifact")}
                onChange={(e) => setTarget(i, { artifact: e.target.value })}
                disabled={(PLATFORM_ARTIFACTS[tg.platform] ?? ["apk"]).length <= 1}>
                {(PLATFORM_ARTIFACTS[tg.platform] ?? ["apk"]).map((a) => (
                  <option key={a} value={a}>{a}</option>
                ))}
              </Select>
              <Button type="button" size="sm" variant="ghost" aria-label="remove target"
                disabled={targets.length <= 1}
                onClick={() => setTargets((rows) => rows.filter((_, j) => j !== i))}>
                <Trash2 size={13} />
              </Button>
            </div>
          ))}
        </div>
      </div>
      {locationBlock}
      <div className="mt-3">
        {mode === "advanced" ? (
          <Field label={t("apps.buildConfig")} hint={t("apps.buildConfigHint")}>
            {configText === null ? <Skeleton className="h-32" /> : (
              <textarea value={configText} onChange={(e) => setConfigText(e.target.value)}
                dir="ltr" spellCheck={false}
                className="min-h-32 w-full rounded-lg border border-border bg-surface-1 p-2 font-mono text-[11px] leading-5 text-content outline-none focus:border-brand" />
            )}
          </Field>
        ) : (
          <p className="rounded-lg border border-border/60 bg-surface-1 p-2 text-[11px] text-content-3">
            {t("apps.configAutoHint")}
          </p>
        )}
      </div>
    </Dialog>
  );
}
