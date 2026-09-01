// Logs — per-core live log tail (polled), with search + line-count control.
import { useQuery } from "@tanstack/react-query";
import { FileTerminal, RefreshCcw, Search } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Badge, Button, Card, Field, Input, Select } from "../components/ui";
import { api } from "../lib/api";
import { useT } from "../lib/i18n";
import type { CoreView } from "../lib/types";

export default function Logs() {
  const t = useT();
  const [coreId, setCoreId] = useState("");
  const [lines, setLines] = useState(300);
  const [filter, setFilter] = useState("");
  const [follow, setFollow] = useState(true);
  const boxRef = useRef<HTMLPreElement>(null);

  const cores = useQuery({ queryKey: ["zagros", "cores"], queryFn: () => api.get<{ cores: CoreView[] }>("/zagros/cores") });
  const effectiveCore = coreId || cores.data?.cores[0]?.id || "";

  const logs = useQuery({
    queryKey: ["zagros", "core-logs", effectiveCore, lines],
    queryFn: () => api.get<{ lines: string[] }>(`/zagros/cores/${effectiveCore}/logs?lines=${lines}`),
    enabled: !!effectiveCore,
    refetchInterval: 2500,
    placeholderData: (prev) => prev,
  });

  const shown = useMemo(() => {
    const all = logs.data?.lines ?? [];
    const f = filter.trim().toLowerCase();
    return f ? all.filter((l) => l.toLowerCase().includes(f)) : all;
  }, [logs.data, filter]);

  useEffect(() => {
    if (follow) boxRef.current?.scrollTo({ top: boxRef.current.scrollHeight });
  }, [shown, follow]);

  return (
    <div className="flex h-full flex-col space-y-4 animate-fade-up">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="me-auto flex items-center gap-2 text-lg font-bold tracking-tight">
          <FileTerminal size={18} className="text-brand" />{t("nav.logs")}
          {effectiveCore && <Badge tone="brand">{effectiveCore}</Badge>}
        </h1>
        <Select value={effectiveCore} onChange={(e) => setCoreId(e.target.value)} className="w-40" aria-label={t("core")}>
          {(cores.data?.cores ?? []).map((c) => <option key={c.id} value={c.id}>{c.id}</option>)}
          {!cores.data?.cores?.length && <option value="">{t("— install a core —")}</option>}
        </Select>
        <Select value={String(lines)} onChange={(e) => setLines(Number(e.target.value))} className="w-28" aria-label={t("lines")}>
          {[100, 300, 500, 1000].map((n) => <option key={n} value={n}>{n}</option>)}
        </Select>
        <div className="relative">
          <Search size={13} className="absolute start-2.5 top-1/2 -translate-y-1/2 text-content-3" />
          <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder={t("filter…")} className="w-44 ps-7" aria-label={t("filter logs")} />
        </div>
        <Button variant={follow ? "secondary" : "ghost"} size="sm" onClick={() => setFollow((v) => !v)}>{t("follow")}</Button>
        <Button variant="ghost" size="sm" onClick={() => logs.refetch()}><RefreshCcw size={13} /></Button>
      </div>

      <Card className="min-h-0 flex-1 p-0">
        <pre
          ref={boxRef}
          className="h-[62vh] overflow-auto rounded-2xl p-4 font-mono text-[11.5px] leading-5 text-content-2"
          dir="ltr"
        >
          {!effectiveCore
            ? "// install a core to read its logs"
            : shown.join("\n") || (filter ? `// no lines match "${filter}"` : "// no output yet")}
        </pre>
      </Card>
    </div>
  );
}
