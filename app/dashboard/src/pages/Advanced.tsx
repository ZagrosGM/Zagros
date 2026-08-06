// Advanced Mode (in-panel Config Studio) — VISUAL by default (alpha.7):
// the tree editor covers objects/arrays/scalars without ever showing raw
// JSON; "raw document" and "patch operations" stay available as explicit
// pro modes. Schema validation + diff preview + apply are shared by all.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Eye, Plus, Rocket, TerminalSquare, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { JsonTree } from "../components/JsonTree";
import { toast } from "../components/feedback";
import { Badge, Button, Card, CardHeader, Input, Select, Textarea, cn } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useT } from "../lib/i18n";
import { useUI } from "../stores/ui";
import type { CoreView, StudioPatchOp } from "../lib/types";

interface PreviewOut { core_id: string; valid: boolean; errors: string[]; diff: string; document?: unknown }
type EditMode = "tree" | "raw" | "ops";

export default function Advanced() {
  const t = useT();
  const qc = useQueryClient();
  const { advancedMode } = useUI();
  const [coreId, setCoreId] = useState("");
  const [mode, setMode] = useState<EditMode>("tree");
  const [rawText, setRawText] = useState("");
  const [ops, setOps] = useState<StudioPatchOp[]>([]);
  const [dirty, setDirty] = useState(false);
  const [preview, setPreview] = useState<PreviewOut | null>(null);

  const cores = useQuery({ queryKey: ["zagros", "cores"], queryFn: () => api.get<{ cores: CoreView[] }>("/zagros/cores") });
  const effectiveCore = coreId || cores.data?.cores[0]?.id || "";

  const raw = useQuery({
    queryKey: ["zagros", "studio", "raw", effectiveCore],
    queryFn: () => api.get<{ json: string }>(`/zagros/studio/${effectiveCore}/raw`),
    enabled: !!effectiveCore && advancedMode,
  });
  useEffect(() => { if (raw.data?.json) { setRawText(raw.data.json); setDirty(false); setPreview(null); } }, [raw.data, effectiveCore]);

  const opsFromRaw = (): StudioPatchOp[] | string => {
    try {
      const doc = JSON.parse(rawText);
      return [{ op: "replace", path: "", value: doc }];
    } catch (e) {
      return `invalid JSON: ${(e as Error).message}`;
    }
  };

  const doPreview = useMutation({
    mutationFn: async (operations: StudioPatchOp[]) =>
      api.post<PreviewOut>(`/zagros/studio/${effectiveCore}/preview`, { operations }),
    onSuccess: (r) => setPreview(r),
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });
  const doApply = useMutation({
    mutationFn: async (operations: StudioPatchOp[]) =>
      api.post<PreviewOut>(`/zagros/studio/${effectiveCore}/apply`, { operations }),
    onSuccess: (r) => {
      if (r.valid) {
        toast.ok("applied — document saved and core notified");
        setDirty(false); setPreview(null);
        qc.invalidateQueries({ queryKey: ["zagros", "studio", "raw", effectiveCore] });
        qc.invalidateQueries({ queryKey: ["inbounds"] });
      } else {
        setPreview(r);
        toast.error(r.errors.join("; ") || "schema rejected the change");
      }
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : t("common.error")),
  });

  if (!advancedMode) {
    return (
      <Card>
        <CardHeader title={<span className="inline-flex items-center gap-2"><TerminalSquare size={16} className="text-brand" /> {t("nav.advanced")}</span>} />
        <p className="text-sm text-content-2">
          Advanced Mode is off. Enable it from <b>Settings → Advanced Mode</b> to open the in-panel Config Studio.
        </p>
      </Card>
    );
  }

  const run = (fn: (ops: StudioPatchOp[]) => void) => {
    const operations = mode === "raw" ? opsFromRaw() : ops;
    if (typeof operations === "string") return toast.error(operations);
    if (!operations.length) return toast.error("no operations to send");
    fn(operations);
  };

  return (
    <div className="space-y-4 animate-fade-up">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <TerminalSquare size={18} className="text-brand" /> {t("nav.advanced")}
          <Badge tone={mode === "tree" ? "ok" : "warn"} dot>{mode === "tree" ? "visual" : "pro — JSON"}</Badge>
          {dirty && <Badge tone="info" dot>modified</Badge>}
        </h1>
        <Select value={effectiveCore} onChange={(e) => setCoreId(e.target.value)} className="w-40" aria-label="core">
          {(cores.data?.cores ?? []).map((c) => <option key={c.id} value={c.id}>{c.id}</option>)}
          {!cores.data?.cores?.length && <option value="">— install a core —</option>}
        </Select>
        <Select value={mode} onChange={(e) => setMode(e.target.value as EditMode)} className="w-44" aria-label="edit mode">
          <option value="tree">visual tree (default)</option>
          <option value="raw">raw document — pro</option>
          <option value="ops">patch operations — pro</option>
        </Select>
        <Button variant="secondary" size="sm" onClick={() => run((o) => doPreview.mutate(o))} loading={doPreview.isPending} disabled={!effectiveCore}>
          <Eye size={13} /> validate & diff
        </Button>
        <Button size="sm" onClick={() => run((o) => doApply.mutate(o))} loading={doApply.isPending} disabled={!effectiveCore}>
          <Rocket size={13} /> apply
        </Button>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card className="p-3">
          {mode === "tree" ? (() => {
            let doc: unknown = null;
            let parseError: string | null = null;
            try { doc = JSON.parse(rawText); } catch (e) { parseError = (e as Error).message; }
            return parseError ? (
              <div className="p-2 text-[12px] text-danger">
                <p className="mb-2 font-medium">the document isn't valid JSON right now — fix it in raw mode:</p>
                <code className="text-[11px]">{parseError}</code>
              </div>
            ) : (
              <div className="h-[66vh] overflow-auto">
                <JsonTree
                  document={doc as never}
                  onChange={(next) => { setRawText(JSON.stringify(next, null, 2)); setDirty(true); }}
                />
              </div>
            );
          })() : mode === "raw" ? (
            <Textarea
              value={rawText}
              onChange={(e) => { setRawText(e.target.value); setDirty(true); }}
              spellCheck={false}
              dir="ltr"
              className="h-[66vh] resize-none border-0 bg-transparent font-mono text-[11.5px] leading-5 focus:outline-none"
            />
          ) : (
            <div className="space-y-2.5 p-1.5">
              <p className="text-[11px] text-content-3">RFC-6902 patch ops against the current document — precise, validated, and diffed before apply.</p>
              {ops.map((op, i) => (
                <div key={i} className="grid gap-2 rounded-xl border border-border p-2.5 sm:grid-cols-[110px_1fr_1fr_36px]">
                  <Select value={op.op} onChange={(e) => setOps(ops.map((x, xi) => xi === i ? { ...x, op: e.target.value } : x))}>
                    {["add", "remove", "replace", "move", "copy", "test"].map((o) => <option key={o} value={o}>{o}</option>)}
                  </Select>
                  <Input value={op.path} dir="ltr" placeholder="/path/pointer"
                    onChange={(e) => setOps(ops.map((x, xi) => xi === i ? { ...x, path: e.target.value } : x))} />
                  <Textarea rows={1} value={typeof op.value === "string" ? op.value : JSON.stringify(op.value ?? null)} dir="ltr" placeholder="value (JSON)"
                    className="font-mono text-[11px]"
                    onChange={(e) => {
                      let v: unknown = e.target.value;
                      try { v = JSON.parse(e.target.value); } catch { /* keep string */ }
                      setOps(ops.map((x, xi) => xi === i ? { ...x, value: v } : x));
                    }} />
                  <Button variant="ghost" size="icon" aria-label="remove op" onClick={() => setOps(ops.filter((_, xi) => xi !== i))}><Trash2 size={13} /></Button>
                </div>
              ))}
              <Button variant="secondary" size="sm" onClick={() => setOps([...ops, { op: "replace", path: "/" }])}><Plus size={13} /> operation</Button>
            </div>
          )}
        </Card>

        <Card className="p-3">
          <div className="flex items-center gap-2 px-1.5 pb-2 text-[11px] text-content-3">
            {preview ? (
              preview.valid
                ? <><CheckCircle2 size={13} className="text-ok" /> schema-valid — diff of the proposed change</>
                : <><AlertTriangle size={13} className="text-danger" /> rejected</>
            ) : "validate & diff to inspect the change before it touches the core"}
          </div>
          {preview && !preview.valid && preview.errors.length > 0 && (
            <ul className="mb-2 space-y-1 rounded-xl border border-danger/30 bg-danger-soft p-3 text-[11.5px] text-danger">
              {preview.errors.map((e, i) => <li key={i}>• {e}</li>)}
            </ul>
          )}
          <pre dir="ltr" className={cn(
            "h-[58vh] overflow-auto rounded-xl p-3 font-mono text-[11px] leading-5",
            preview ? (preview.valid ? "bg-surface text-content-2" : "bg-surface text-danger/80") : "bg-surface text-content-3",
          )}>
            {preview?.diff || "// no diff yet"}
          </pre>
        </Card>
      </div>
    </div>
  );
}
