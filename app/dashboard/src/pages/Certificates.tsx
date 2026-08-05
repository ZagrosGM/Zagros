// Certificates — visual inventory, PEM import (pair validated), self-signed
// generation, delete. ACME/Let's Encrypt is honestly labeled Roadmap.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileKey2, KeyRound, Plus, RefreshCcw, ShieldCheck, Trash2, Upload } from "lucide-react";
import { useState } from "react";
import { toast } from "../components/feedback";
import { ConfirmDialog, Dialog } from "../components/overlays";
import { Badge, Button, Card, CardHeader, EmptyState, Field, Input, Skeleton, Textarea, cn } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useDigits, formatDate } from "../lib/format";
import { useT } from "../lib/i18n";
import type { CertificateInfo } from "../lib/types";

const expiryTone = (c: CertificateInfo) => c.expired ? "danger" : c.days_left <= 14 ? "warn" : "ok";

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
  const del = useMutation({
    mutationFn: (name: string) => api.delete(`/zagros/certificates/${encodeURIComponent(name)}`),
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
        <Button variant="secondary" size="sm" onClick={() => setDialog("import")}><Upload size={13} /> import PEM</Button>
        <Button size="sm" onClick={() => setDialog("selfsigned")}><KeyRound size={13} /> self-signed</Button>
      </div>

      <Card className="flex items-center gap-3 border-dashed">
        <div className="grid h-10 w-10 place-items-center rounded-xl bg-info-soft text-info"><FileKey2 size={17} /></div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium">ACME / Let's Encrypt</p>
          <p className="text-[11px] text-content-3">{list.data?.acme?.status ?? "roadmap — automatic issuance & renewal is planned; import PEM or self-signed works today."}</p>
        </div>
        <Badge tone="info">{t("common.roadmap")}</Badge>
      </Card>

      {list.isLoading ? (
        <div className="grid gap-3 md:grid-cols-2">{[1, 2].map((i) => <Skeleton key={i} className="h-36" />)}</div>
      ) : certs.length === 0 ? (
        <Card>
          <EmptyState title="No certificates"
            hint="Import an existing PEM pair or generate a self-signed certificate for LAN/test setups."
            action={<div className="flex gap-2">
              <Button size="sm" variant="secondary" onClick={() => setDialog("import")}><Upload size={13} /> import</Button>
              <Button size="sm" onClick={() => setDialog("selfsigned")}><KeyRound size={13} /> self-signed</Button>
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
                    {c.self_signed && <Badge tone="warn">self-signed</Badge>}
                    {!c.has_key && <Badge tone="danger">cert only</Badge>}
                  </div>
                  <p className="mt-1 truncate text-[11px] text-content-3">CN: {c.subject_cn || "—"} · issuer: {c.issuer_cn || "—"}</p>
                </div>
                <Badge tone={expiryTone(c) as never} dot>
                  {c.expired ? "expired" : `${c.days_left}d left`}
                </Badge>
              </div>
              <div className="mt-3 grid grid-cols-2 gap-2 text-[11px] text-content-3">
                <span>issued {formatDate(c.not_before, digits)}</span>
                <span>expires {formatDate(c.not_after, digits)}</span>
              </div>
              <div className="mt-3 flex items-center justify-between border-t border-border pt-3">
                <code className="font-mono text-[10px] text-content-3" dir="ltr">{c.serial ? `serial ${c.serial.slice(0, 18)}…` : ""}</code>
                <Button variant="ghost" size="icon" aria-label={`delete ${c.name}`} onClick={() => setDeleteFor(c)}><Trash2 size={14} /></Button>
              </div>
            </Card>
          ))}
        </div>
      )}

      {dialog === "import" && <ImportDialog onClose={() => setDialog(null)} />}
      {dialog === "selfsigned" && <SelfSignedDialog onClose={() => setDialog(null)} />}

      <ConfirmDialog open={!!deleteFor} onClose={() => setDeleteFor(null)}
        onConfirm={() => deleteFor && del.mutate(deleteFor.name)}
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
    <Dialog open onClose={onClose} title="import certificate" wide
      subtitle="the pair is validated — a mismatched key is refused before anything lands on disk"
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
        <Field label="certificate chain (PEM)" required>
          <Textarea rows={6} value={certPem} onChange={(e) => setCertPem(e.target.value)} dir="ltr" className="font-mono text-[11px]"
            placeholder="-----BEGIN CERTIFICATE-----&#10;…(fullchain.pem, leaf first)…" />
        </Field>
        <Field label="private key (PEM)" required>
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
    <Dialog open onClose={onClose} title="generate self-signed certificate"
      subtitle="RSA-2048 with SANs — for LAN/testing; browsers will warn (expected)"
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
        <Field label="common name (CN)" required><Input value={cn} onChange={(e) => setCn(e.target.value)} placeholder="panel.lan" dir="ltr" /></Field>
        <Field label="validity (days)"><Input type="number" min={1} max={3650} value={days} onChange={(e) => setDays(Number(e.target.value))} /></Field>
        <Field label="extra SAN hostnames" hint="comma separated">
          <Input value={sans} onChange={(e) => setSans(e.target.value)} placeholder="panel.lan, 192.168.1.10" dir="ltr" />
        </Field>
      </div>
      {error && <p role="alert" className="mt-3 rounded-xl border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}
