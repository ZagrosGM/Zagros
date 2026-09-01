// JsonTree — the visual Config-Studio editor: collapsible
// objects/arrays, inline scalar editing, add/remove nodes, drag-free row
// ops — zero raw JSON in Normal mode. Changes write back a JSON document
// that the Studio's validate/diff/apply pipeline consumes unchanged.
import { Braces, Brackets, ChevronDown, ChevronRight, Hash, Plus, ToggleLeft, Trash2, Type } from "lucide-react";
import { useState } from "react";
import { Button, Input, Select, cn } from "./ui";

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

const TYPE_OF = (v: Json): string =>
  v === null ? "null" : Array.isArray(v) ? "array" : typeof v;

const TYPE_ICON: Record<string, React.ReactNode> = {
  object: <Braces size={12} className="text-brand" />,
  array: <Brackets size={12} className="text-info" />,
  string: <Type size={12} className="text-ok" />,
  number: <Hash size={12} className="text-warn" />,
  boolean: <ToggleLeft size={12} className="text-warn" />,
  null: <span className="text-content-3">∅</span>,
};

const EMPTY_OF: Record<string, Json> = {
  string: "", number: 0, boolean: false, null: null, object: {}, array: [],
};

function ScalarEditor({ value, onChange }: { value: Json; onChange: (v: Json) => void }) {
  const type = TYPE_OF(value);
  if (type === "boolean") {
    return (
      <Select value={String(value)} onChange={(e) => onChange(e.target.value === "true")} className="h-7 w-24 text-[11.5px]">
        <option value="true">true</option>
        <option value="false">false</option>
      </Select>
    );
  }
  if (type === "number") {
    return (
      <Input type="number" dir="ltr" className="h-7 w-36 text-[11.5px] tabular-nums"
        value={String(value)}
        onChange={(e) => onChange(e.target.value === "" ? 0 : Number(e.target.value))} />
    );
  }
  if (type === "null") {
    return <span className="text-[11.5px] italic text-content-3">null</span>;
  }
  return (
    <Input dir="ltr" className="h-7 min-w-40 flex-1 font-mono text-[11.5px]"
      value={String(value)}
      onChange={(e) => onChange(e.target.value)} />
  );
}

function TypeConvert({ current, onPick }: { current: string; onPick: (t: string) => void }) {
  return (
    <Select value="" onChange={(e) => e.target.value && onPick(e.target.value)}
      className="h-7 w-16 text-[10.5px] opacity-0 transition-opacity group-hover:opacity-100"
      title={`type: ${current} — convert`}>
      <option value="">⇄</option>
      {Object.keys(EMPTY_OF).filter((t) => t !== current).map((t) => (
        <option key={t} value={t}>{t}</option>
      ))}
    </Select>
  );
}

interface NodeProps {
  value: Json;
  onChange: (v: Json) => void;
  depth: number;
  label?: string | number;
  onDelete?: () => void;
}

function Node({ value, onChange, depth, label, onDelete }: NodeProps) {
  const [open, setOpen] = useState(depth < 2);
  const [adding, setAdding] = useState(false);
  const [newKey, setNewKey] = useState("");
  const [newType, setNewType] = useState("string");
  const type = TYPE_OF(value);
  const composite = type === "object" || type === "array";
  const entries: [string | number, Json][] = type === "object"
    ? Object.keys(value as object).map((k) => [k, (value as Record<string, Json>)[k]])
    : type === "array" ? (value as Json[]).map((v, i) => [i, v]) : [];

  const setChild = (key: string | number, child: Json) => {
    if (type === "object") onChange({ ...(value as Record<string, Json>), [key]: child });
    else if (type === "array") onChange((value as Json[]).map((v, i) => i === key ? child : v));
  };
  const removeChild = (key: string | number) => {
    if (type === "object") {
      const next = { ...(value as Record<string, Json>) };
      delete next[key];
      onChange(next);
    } else if (type === "array") {
      onChange((value as Json[]).filter((_, i) => i !== key));
    }
  };
  const addChild = () => {
    if (type === "object" && !newKey.trim()) return;
    if (type === "object") {
      onChange({ ...(value as Record<string, Json>), [newKey.trim()]: EMPTY_OF[newType] });
    } else if (type === "array") {
      onChange([...(value as Json[]), EMPTY_OF[newType]]);
    }
    setNewKey(""); setNewType("string"); setAdding(false);
    setOpen(true);
  };

  return (
    <div className={cn("group", depth > 0 && "ms-4 border-s border-border/60 ps-3")}>
      <div className="flex min-h-7 items-center gap-1.5 py-0.5">
        {composite ? (
          <button onClick={() => setOpen(!open)} aria-label={open ? "collapse" : "expand"}
            className="grid h-5 w-5 shrink-0 place-items-center rounded text-content-3 hover:bg-surface-2 hover:text-content">
            {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          </button>
        ) : <span className="w-5 shrink-0" />}
        <span className="shrink-0">{TYPE_ICON[type]}</span>
        {label !== undefined && (
          <span className="shrink-0 font-mono text-[11.5px] font-medium text-content-2" dir="ltr">
            {typeof label === "string" ? `"${label}"` : `[${label}]`}
          </span>
        )}
        {composite ? (
          <span className="text-[10.5px] text-content-3">
            {type === "array" ? `${entries.length} items` : `${entries.length} keys`}
          </span>
        ) : (
          <ScalarEditor value={value} onChange={onChange} />
        )}
        <TypeConvert current={type} onPick={(t) => onChange(EMPTY_OF[t])} />
        {composite && (
          <Button variant="ghost" size="icon" aria-label="add child"
            className="h-6 w-6 opacity-0 transition-opacity group-hover:opacity-100"
            onClick={() => setAdding(!adding)}>
            <Plus size={12} />
          </Button>
        )}
        {onDelete && (
          <Button variant="ghost" size="icon" aria-label="delete node"
            className="h-6 w-6 opacity-0 transition-opacity group-hover:opacity-100 hover:text-danger"
            onClick={onDelete}>
            <Trash2 size={12} />
          </Button>
        )}
      </div>
      {composite && open && (
        <div>
          {adding && (
            <div className="ms-4 mb-1 flex items-center gap-1.5 border-s border-brand/40 ps-3 py-1">
              {type === "object" && (
                <Input dir="ltr" placeholder="key" className="h-7 w-36 text-[11.5px]"
                  value={newKey} onChange={(e) => setNewKey(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && addChild()} />
              )}
              <Select value={newType} onChange={(e) => setNewType(e.target.value)} className="h-7 w-24 text-[11.5px]">
                {Object.keys(EMPTY_OF).map((t) => <option key={t} value={t}>{t}</option>)}
              </Select>
              <Button size="sm" variant="secondary" className="h-7 px-2.5 text-[11px]" onClick={addChild}>add</Button>
              <Button size="sm" variant="ghost" className="h-7 px-2.5 text-[11px]" onClick={() => setAdding(false)}>cancel</Button>
            </div>
          )}
          {entries.length === 0 && !adding && (
            <p className="ms-4 border-s border-border/60 ps-3 py-1 text-[10.5px] italic text-content-3">
              empty {type}
            </p>
          )}
          {entries.map(([key, child]) => (
            <Node
              key={key} value={child} label={key} depth={depth + 1}
              onChange={(v) => setChild(key, v)}
              onDelete={() => removeChild(key)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export function JsonTree({ document, onChange }: {
  document: Json; onChange: (doc: Json) => void;
}) {
  return (
    <div className="rounded-xl bg-surface p-2" dir="ltr">
      <Node value={document} onChange={onChange} depth={0} label="$" />
    </div>
  );
}
