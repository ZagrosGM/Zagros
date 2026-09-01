// Certificates — visual inventory, PEM import (pair validated), self-signed
// generation, delete. ACME (Let's Encrypt) is REAL here: issuance/renewal/
// delete run the host ACME client (certbot/acme.sh/lego) — an unavailable
// client or a failed run is shown honestly, never as a fake success.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileKey2, Globe, KeyRound, Plus, RefreshCcw, RotateCw, ShieldCheck, Trash2, Upload } from "lucide-react";
import { useState } from "react";
import { toast } from "../components/feedback";
import { ConfirmDialog, Dialog } from "../components/overlays";
import { Badge, Button, Card, CardHeader, EmptyState, Field, Input, Select, Skeleton, Switch, Textarea, cn } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useDigits, formatDate } from "../lib/format";
import { useT , useTDynamic } from "../lib/i18n";
import type { CertificateInfo } from "../lib/types";

const expiryTone = (c: CertificateInfo) => c.expired ? "danger" : c.days_left <= 14 ? "warn" : "ok";

type AcmeProvider = { id: string; name: string; path: string };
type AcmeEntry = {
  domain: string; provider: string | null; email: string | null;
  issued_at: string | null; renewed_at: string | null;
  cert_path: string; key_path: string;
  days_left: number | null; expired: boolean | null; renew_due: boolean | null;
};
type AcmeState = {
  available: boolean; status: string; providers: AcmeProvider[]; entries: AcmeEntry[];
};

export default function Certificates() {
  const t = useT();
  const digits = useDigits();
  const qc = useQueryClient();
  const [dialog, setDialog] = useState<"import" | "selfsigned" | null>(null);
  const [deleteFor, setDeleteFor] = useState<CertificateInfo | null>(null);

  const list = useQuery({
    queryKey: ["zagros", "certificates"],
    queryFn: () => api.get<{ certificates: CertificateInfo[]; acme: { available: boolean; status: string } }>("/zagros/certificates"),
  });
  // ACME reality: detected host clients + every ACME-managed entry. Owned by
  // the page so the grid can also mark ACME-managed names (their delete must
  // flow through the ACME endpoint for provider cleanup).
  const acme = useQuery({
    queryKey: ["zagros", "certificates", "acme"],
    queryFn: () => api.get<AcmeState>("/zagros/certificates/acme"),
  });
  const acmeNames = new Set((acme.data?.entries ?? []).map((e) => e.domain));
  const del = useMutation({
    // item 18: address by the STABLE inventory id (reaches core-materialized
    // certs too) — cleared on each list; fall back to the plain managed name
    mutationFn: (c: CertificateInfo) => api.delete(`/zagros/certificates/${encodeURIComponent(c.id || c.name)}`),
    onSuccess: () => { toast.ok(t("common.deleted")); setDeleteFor(null); qc.invalidateQueries({ queryKey: ["zagros", "certificates"] }); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  const certs = list.data?.certificates ?? [];

  return (
    <div className="space-y-4 animate-fade-up">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <ShieldCheck size={18} className="text-brand" />{t("nav.certificates")}
        </h1>
        <Button variant="ghost" size="sm" onClick={() => list.refetch()}><RefreshCcw size={13} /> {t("common.refresh")}</Button>
        <Button variant="secondary" size="sm" onClick={() => setDialog("import")}><Upload size={13} />{t("import PEM")}</Button>
        <Button size="sm" onClick={() => setDialog("selfsigned")}><KeyRound size={13} />{t("self-signed")}</Button>
      </div>

      <AcmeSection state={acme.data} loading={acme.isLoading} />

      {list.isLoading ? (
        <div className="grid gap-3 md:grid-cols-2">{[1, 2].map((i) => <Skeleton key={i} className="h-36" />)}</div>
      ) : certs.length === 0 ? (
        <Card>
          <EmptyState title={t("No certificates")}
            hint={t("Import an existing PEM pair or generate a self-signed certificate for LAN/test setups.")}
            action={<div className="flex gap-2">
              <Button size="sm" variant="secondary" onClick={() => setDialog("import")}><Upload size={13} /> import</Button>
              <Button size="sm" onClick={() => setDialog("selfsigned")}><KeyRound size={13} />{t("self-signed")}</Button>
            </div>} />
        </Card>
      ) : (
        <div className="grid gap-3 md:grid-cols-2">
          {certs.map((c) => (
            <Card key={c.name}>
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <h3 className="truncate text-sm font-semibold">{c.name}</h3>
                    {acmeNames.has(c.name) && <Badge tone="info">ACME</Badge>}
                    {c.self_signed && <Badge tone="warn">{t("self-signed")}</Badge>}
                    {!c.has_key && <Badge tone="danger">cert only</Badge>}
                  </div>
                  <p className="mt-1 truncate text-[11px] text-content-3">CN: {c.subject || "—"} · issuer: {c.issuer || "—"}</p>
                </div>
                <Badge tone={expiryTone(c) as never} dot>
                  {c.expired ? t("expired") : t("{days}d left", { days: c.days_left })}
                </Badge>
              </div>
              <div className="mt-3 grid grid-cols-2 gap-2 text-[11px] text-content-3">
                <span>{t("issued {date}", { date: formatDate(c.not_before, digits) })}</span>
                <span>{t("expires {date}", { date: formatDate(c.not_after, digits) })}</span>
              </div>
              <div className="mt-3 flex items-center justify-between border-t border-border pt-3">
                <code className="font-mono text-[10px] text-content-3" dir="ltr">{c.serial ? `serial ${c.serial.slice(0, 18)}…` : ""}</code>
                {acmeNames.has(c.name) ? (
                  // ACME-managed: bare store delete is refused by the API
                  // (409) — deletion belongs to the ACME section so provider
                  // cleanup runs and is reported
                  <span className="text-[10px] text-content-3">{t("managed by ACME — delete below")}</span>
                ) : (
                  <Button variant="ghost" size="icon" aria-label={t("delete {name}", { name: c.name })} onClick={() => setDeleteFor(c)}><Trash2 size={14} /></Button>
                )}
              </div>
            </Card>
          ))}
        </div>
      )}

      {dialog === "import" && <ImportDialog onClose={() => setDialog(null)} />}
      {dialog === "selfsigned" && <SelfSignedDialog onClose={() => setDialog(null)} />}

      <ConfirmDialog open={!!deleteFor} onClose={() => setDeleteFor(null)}
        onConfirm={() => deleteFor && del.mutate(deleteFor)}
        title={`delete certificate — ${deleteFor?.name ?? ""}`}
        body="Cores pointing at these files will fail their next restart until re-pointed."
        danger loading={del.isPending} />
    </div>
  );
}

function ImportDialog({ onClose }: { onClose: () => void }) {
  const t = useT();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [certPem, setCertPem] = useState("");
  const [keyPem, setKeyPem] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const missing = !(name.trim() && certPem.includes("BEGIN CERTIFICATE") && keyPem.includes("PRIVATE KEY"));
  return (
    <Dialog open onClose={onClose} title={t("import certificate")} wide
      subtitle={t("the pair is validated — a mismatched key is refused before anything lands on disk")}
      footer={<>
        <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
        <Button loading={busy} disabled={missing} onClick={async () => {
          setBusy(true); setError("");
          try {
            await api.post("/zagros/certificates/import", { name: name.trim(), cert_pem: certPem, key_pem: keyPem });
            toast.ok("certificate imported");
            qc.invalidateQueries({ queryKey: ["zagros", "certificates"] });
            onClose();
          } catch (e) { setError(e instanceof ApiError ? e.message : t("common.error")); } finally { setBusy(false); }
        }}><Upload size={13} /> import</Button>
      </>}>
      <div className="space-y-4">
        <Field label="name" required hint="stored under <data>/certs/&lt;name&gt;/ as fullchain.pem + key.pem">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="panel.example.com" dir="ltr" />
        </Field>
        <Field label={t("certificate chain (PEM)")} required>
          <Textarea rows={6} value={certPem} onChange={(e) => setCertPem(e.target.value)} dir="ltr" className="font-mono text-[11px]"
            placeholder="-----BEGIN CERTIFICATE-----&#10;…(fullchain.pem, leaf first)…" />
        </Field>
        <Field label={t("private key (PEM)")} required>
          <Textarea rows={5} value={keyPem} onChange={(e) => setKeyPem(e.target.value)} dir="ltr" className="font-mono text-[11px]"
            placeholder="-----BEGIN PRIVATE KEY-----" />
        </Field>
        {error && <p role="alert" className="rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
      </div>
    </Dialog>
  );
}

function SelfSignedDialog({ onClose }: { onClose: () => void }) {
  const t = useT();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [cn, setCn] = useState("");
  const [days, setDays] = useState(365);
  const [sans, setSans] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <Dialog open onClose={onClose} title={t("generate self-signed certificate")}
      subtitle={t("RSA-2048 with SANs — for LAN/testing; browsers will warn (expected)")}
      footer={<>
        <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
        <Button loading={busy} disabled={!name.trim() || !cn.trim()} onClick={async () => {
          setBusy(true); setError("");
          try {
            await api.post("/zagros/certificates/self-signed", {
              name: name.trim(), common_name: cn.trim(), days,
              san_dns: sans.split(",").map((s) => s.trim()).filter(Boolean),
            });
            toast.ok("certificate generated");
            qc.invalidateQueries({ queryKey: ["zagros", "certificates"] });
            onClose();
          } catch (e) { setError(e instanceof ApiError ? e.message : t("common.error")); } finally { setBusy(false); }
        }}><KeyRound size={13} /> generate</Button>
      </>}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="name" required><Input value={name} onChange={(e) => setName(e.target.value)} placeholder="lab-cert" dir="ltr" /></Field>
        <Field label={t("common name (CN)")} required><Input value={cn} onChange={(e) => setCn(e.target.value)} placeholder="panel.lan" dir="ltr" /></Field>
        <Field label={t("validity (days)")}><Input type="number" min={1} max={3650} value={days} onChange={(e) => setDays(Number(e.target.value))} /></Field>
        <Field label={t("extra SAN hostnames")} hint={t("comma separated")}>
          <Input value={sans} onChange={(e) => setSans(e.target.value)} placeholder="panel.lan, 192.168.1.10" dir="ltr" />
        </Field>
      </div>
      {error && <p role="alert" className="mt-3 rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}

function AcmeSection({ state, loading }: { state?: AcmeState; loading: boolean }) {
  const t = useT();
  const td = useTDynamic();
  const qc = useQueryClient();
  const digits = useDigits();
  const [issueOpen, setIssueOpen] = useState(false);
  const [deleteFor, setDeleteFor] = useState<AcmeEntry | null>(null);
  const invalidate = () => qc.invalidateQueries({ queryKey: ["zagros", "certificates"] });

  const renew = useMutation({
    mutationFn: (domain: string) => api.post<{ ok: boolean; message: string }>(`/zagros/certificates/acme/${encodeURIComponent(domain)}/renew`, {}),
    onSuccess: (r) => { toast.ok(r.message || t("common.saved")); invalidate(); },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });
  const remove = useMutation({
    mutationFn: (domain: string) => api.delete<{ ok: boolean; provider_cleanup: string | null }>(`/zagros/certificates/acme/${encodeURIComponent(domain)}`),
    onSuccess: (r) => {
      toast.ok(r.provider_cleanup ? `deleted — ${r.provider_cleanup}` : t("common.deleted"));
      setDeleteFor(null); invalidate();
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  if (loading) return <Skeleton className="h-24" />;
  const available = !!state?.available;
  const entries = state?.entries ?? [];

  return (
    <Card className="space-y-3 border-dashed">
      <div className="flex flex-wrap items-center gap-3">
        <div className="grid h-10 w-10 place-items-center rounded-xl bg-info-soft text-info"><FileKey2 size={17} /></div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium">{t("ACME / Let's Encrypt")}</p>
          <p className="text-[11px] text-content-3">{td(state?.status)}</p>
        </div>
        <Badge tone={(available ? "ok" : "muted") as never} dot>{available ? t("operational") : t("unavailable")}</Badge>
        {available && <Button size="sm" onClick={() => setIssueOpen(true)}><Globe size={13} />{t("issue certificate")}</Button>}
      </div>

      {!available && (
        <p className="rounded-xl border border-border px-3 py-2 text-[11px] leading-relaxed text-content-3">{t("automatic issuance needs an ACME client on this host (certbot, acme.sh or lego). The official panel image ships certbot; on a manual install run")}<code className="font-mono" dir="ltr">apt install certbot</code>{t("and reopen this page. PEM import and self-signed certificates work regardless.")}</p>
      )}

      {available && entries.length === 0 && (
        <p className="text-[11px] text-content-3">{t("no ACME-managed certificates yet — issuance deploys into the managed store below, and a background job renews entries within 30 days of expiry.")}</p>
      )}

      {entries.length > 0 && (
        <div className="divide-y divide-border rounded-xl border border-border">
          {entries.map((e) => (
            <div key={e.domain} className="flex flex-wrap items-center gap-2 px-3 py-2">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="truncate text-xs font-semibold" dir="ltr">{e.domain}</span>
                  {e.provider && <Badge tone="info">{e.provider}</Badge>}
                  <Badge tone={(e.expired ? "danger" : e.renew_due ? "warn" : "ok") as never} dot>
                    {e.expired ? t("expired") : e.days_left != null ? t("{days}d left", { days: e.days_left }) : t("status unknown")}
                  </Badge>
                  {!e.expired && !!e.renew_due && <Badge tone="warn">renewal due</Badge>}
                </div>
                <p className="mt-0.5 truncate font-mono text-[10px] text-content-3" dir="ltr">
                  {e.cert_path}
                  {e.renewed_at ? ` · ${t("renewed {date}", { date: formatDate(e.renewed_at, digits) })}` : e.issued_at ? ` · ${t("issued {date}", { date: formatDate(e.issued_at, digits) })}` : ""}
                </p>
              </div>
              <Button variant="ghost" size="sm" loading={renew.isPending && renew.variables === e.domain}
                onClick={() => renew.mutate(e.domain)}><RotateCw size={12} />{t("renew")}</Button>
              <Button variant="ghost" size="icon" aria-label={t("delete ACME {domain}", { domain: e.domain })} onClick={() => setDeleteFor(e)}><Trash2 size={13} /></Button>
            </div>
          ))}
        </div>
      )}

      {issueOpen && <AcmeIssueDialog providers={state?.providers ?? []} onClose={() => setIssueOpen(false)} />}
      <ConfirmDialog open={!!deleteFor} onClose={() => setDeleteFor(null)}
        onConfirm={() => deleteFor && remove.mutate(deleteFor.domain)}
        title={`delete ACME certificate — ${deleteFor?.domain ?? ""}`}
        body="Removes the managed files and best-effort cleans up the provider's own copy (the result is reported). Cores pointing at these files fail their next restart until re-pointed."
        danger loading={remove.isPending} />
    </Card>
  );
}

function AcmeIssueDialog({ providers, onClose }: { providers: AcmeProvider[]; onClose: () => void }) {
  const t = useT();
  const qc = useQueryClient();
  const [domain, setDomain] = useState("");
  const [email, setEmail] = useState("");
  const [provider, setProvider] = useState("auto");
  const [force, setForce] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const d = domain.trim().toLowerCase();
  // front-door sanity only — the backend validates authoritatively (idna,
  // wildcard/IP refusal, duplicate entries, the lego email requirement)
  const invalid = !d || d.includes("*") || !d.includes(".") || d.includes("/") || d.includes(" ");
  return (
    <Dialog open onClose={busy ? () => {} : onClose} title={t("issue certificate (ACME)")}
      subtitle={t("standalone HTTP-01: DNS for this domain must resolve to THIS host and port 80 must be free. A failed run returns the client's own error tail — nothing is green-lit unless the CA really issued.")}
      footer={<>
        <Button variant="ghost" disabled={busy} onClick={onClose}>{t("common.cancel")}</Button>
        <Button loading={busy} disabled={invalid} onClick={async () => {
          setBusy(true); setError("");
          try {
            const r = await api.post<{ ok: boolean; message: string }>("/zagros/certificates/acme/issue", {
              domain: d, email: email.trim() || null, provider: provider === "auto" ? null : provider, force,
            });
            toast.ok(r.message || "certificate issued");
            qc.invalidateQueries({ queryKey: ["zagros", "certificates"] });
            onClose();
          } catch (e) { setError(e instanceof ApiError ? e.message : t("common.error")); } finally { setBusy(false); }
        }}><Globe size={13} /> {busy ? "issuing — can take ~30s" : "issue"}</Button>
      </>}>
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("domain")} required hint={t("a public hostname pointing at this server — wildcards need DNS-01 and are refused here")}>
            <Input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="panel.example.com" dir="ltr" autoFocus />
          </Field>
          <Field label={t("contact email")} hint={t("expiry notices from Let's Encrypt; required when the provider is lego")}>
            <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="admin@example.com" dir="ltr" />
          </Field>
        </div>
        <Field label="ACME client" hint={t("auto = first detected on this host")}>
          <Select value={provider} onChange={(e) => setProvider(e.target.value)}>
            <option value="auto">auto detect</option>
            {providers.map((p) => <option key={p.id} value={p.id}>{p.name} — {p.path}</option>)}
          </Select>
        </Field>
        <Switch checked={force} onChange={setForce} label={t("re-issue even if this domain is already ACME-managed (converges onto the same entry — no duplicates)")} />
        {error && <p role="alert" className="max-h-36 overflow-auto whitespace-pre-wrap rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 font-mono text-[11px] text-danger">{error}</p>}
      </div>
    </Dialog>
  );
}
