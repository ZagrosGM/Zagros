// Command palette — Ctrl/⌘+K: jump anywhere, quick actions, searchable.
import { AnimatePresence, motion } from "framer-motion";
import { ArrowRight, CornerDownLeft, Search } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { cn } from "./ui";

export interface Command {
  id: string;
  title: string;
  hint?: string;
  section?: string;
  run: () => void;
}

export function useCommands(extra: Command[]): Command[] {
  const navigate = useNavigate();
  return useMemo(() => [
    ...["", "users", "subscriptions", "nodes", "cores", "routing", "outbounds", "inbounds", "dns", "certificates", "sessions", "devices", "logs", "marketplace", "settings", "advanced"].map((p) => ({
      id: `go-${p || "overview"}`,
      title: p ? `Go to ${p[0].toUpperCase()}${p.slice(1)}` : "Go to Overview",
      hint: `/${p}`,
      section: "Navigate",
      run: () => navigate(`/${p}`),
    })),
    ...extra,
  ], [extra, navigate]);
}

export function CommandPalette({ open, onClose, commands }: {
  open: boolean; onClose: () => void; commands: Command[];
}) {
  const [q, setQ] = useState("");
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const results = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return commands.slice(0, 18);
    return commands.filter((c) =>
      `${c.title} ${c.hint ?? ""} ${c.section ?? ""}`.toLowerCase().includes(needle)).slice(0, 18);
  }, [q, commands]);

  useEffect(() => {
    if (open) { setQ(""); setCursor(0); setTimeout(() => inputRef.current?.focus(), 40); }
  }, [open]);
  useEffect(() => setCursor(0), [q]);

  useEffect(() => {
    if (!open) return;
    const h = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key === "ArrowDown") { e.preventDefault(); setCursor((c) => Math.min(results.length - 1, c + 1)); }
      if (e.key === "ArrowUp") { e.preventDefault(); setCursor((c) => Math.max(0, c - 1)); }
      if (e.key === "Enter" && results[cursor]) { results[cursor].run(); onClose(); }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [open, results, cursor, onClose]);

  useEffect(() => {
    listRef.current?.querySelector(`[data-idx="${cursor}"]`)?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  let lastSection = "";

  return (
    <AnimatePresence>
      {open && (
        <motion.div className="fixed inset-0 z-[80] flex items-start justify-center pt-[14vh]"
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
          <div className="absolute inset-0 bg-black/55 backdrop-blur-sm" onClick={onClose} />
          <motion.div
            initial={{ opacity: 0, y: -10, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.98, transition: { duration: 0.14 } }}
            className="glass relative w-full max-w-lg overflow-hidden rounded-2xl border border-border-strong shadow-pop"
            role="dialog" aria-label="Command palette"
          >
            <div className="flex items-center gap-2.5 border-b border-border px-4">
              <Search size={16} className="shrink-0 text-content-3" />
              <input
                ref={inputRef}
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Search everywhere…"
                className="h-12 w-full bg-transparent text-sm outline-none placeholder:text-content-3"
              />
              <span className="kbd">esc</span>
            </div>
            <div ref={listRef} className="max-h-[46vh] overflow-y-auto p-1.5">
              {results.length === 0 && <p className="px-3 py-8 text-center text-xs text-content-3">No matches.</p>}
              {results.map((c, i) => {
                const header = c.section && c.section !== lastSection ? (lastSection = c.section) : null;
                return (
                  <div key={c.id}>
                    {header && <p className="px-3 pb-1 pt-2.5 text-[10px] font-semibold uppercase tracking-wider text-content-3">{header}</p>}
                    <button
                      data-idx={i}
                      onClick={() => { c.run(); onClose(); }}
                      onMouseEnter={() => setCursor(i)}
                      className={cn(
                        "flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-start text-sm transition-colors",
                        i === cursor ? "bg-brand-soft text-brand" : "text-content-2",
                      )}
                    >
                      <span className="truncate">{c.title}</span>
                      <span className="ms-3 flex shrink-0 items-center gap-2 text-[11px] text-content-3">
                        {c.hint}
                        {i === cursor ? <CornerDownLeft size={12} /> : <ArrowRight size={12} className="opacity-0" />}
                      </span>
                    </button>
                  </div>
                );
              })}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
