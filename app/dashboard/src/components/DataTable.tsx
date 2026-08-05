// DataTable — pro table: sticky header, optional virtualization, skeleton rows.
import { useVirtualizer } from "@tanstack/react-virtual";
import { useRef, type ReactNode } from "react";
import { cn, Skeleton } from "./ui";

export interface Column<T> {
  id: string;
  header: ReactNode;
  cell: (row: T, index: number) => ReactNode;
  className?: string;
  width?: string;
}

export function DataTable<T>({
  columns, rows, rowKey, loading, empty, virtual = false, height = 560, onRowClick, estimate = 52,
}: {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T, index: number) => string | number;
  loading?: boolean;
  empty?: ReactNode;
  virtual?: boolean;
  height?: number;
  onRowClick?: (row: T, index: number) => void;
  estimate?: number;
}) {
  const parentRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => estimate,
    overscan: 12,
    enabled: virtual,
  });

  const header = (
    <div role="row" className="sticky top-0 z-10 flex border-b border-border bg-surface-1/95 backdrop-blur">
      {columns.map((c) => (
        <div key={c.id} role="columnheader" style={c.width ? { width: c.width, flex: "none" } : undefined}
          className={cn("flex-1 px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wide text-content-3", c.className)}>
          {c.header}
        </div>
      ))}
    </div>
  );

  if (loading) {
    return (
      <div className="card overflow-hidden" style={{ height }}>
        {header}
        <div className="space-y-2 p-3">
          {Array.from({ length: 9 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
        </div>
      </div>
    );
  }

  if (!rows.length) {
    return (
      <div className="card overflow-hidden" style={{ minHeight: 260 }}>
        {header}
        {empty}
      </div>
    );
  }

  return (
    <div ref={parentRef} className="card overflow-auto" style={{ height }}>
      {header}
      <div style={virtual ? { height: virtualizer.getTotalSize(), position: "relative" } : undefined}>
        {(virtual ? virtualizer.getVirtualItems() : rows.map((row, index) => ({ index, start: 0, key: index, row, size: 0 })))
          .map((vi) => {
            const index = (vi as { index: number }).index;
            const row = rows[index];
            if (!row) return null;
            return (
              <div
                key={virtual ? (vi as { key: React.Key }).key : rowKey(row, index)}
                role="row"
                onClick={onRowClick ? () => onRowClick(row, index) : undefined}
                className={cn(
                  "flex items-center border-b border-border/60 transition-colors hover:bg-surface-2/60",
                  onRowClick && "cursor-pointer",
                )}
                style={virtual ? {
                  position: "absolute", top: 0, left: 0, width: "100%",
                  transform: `translateY(${(vi as { start: number }).start}px)`,
                } : undefined}
              >
                {columns.map((c) => (
                  <div key={c.id} role="cell" style={c.width ? { width: c.width, flex: "none" } : undefined}
                    className={cn("flex-1 truncate px-4 py-3 text-[13px]", c.className)}>
                    {c.cell(row, index)}
                  </div>
                ))}
              </div>
            );
          })}
      </div>
    </div>
  );
}
