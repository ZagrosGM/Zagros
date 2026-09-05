import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "./ui";
import { useDigits } from "../lib/format";

export function PaginationBar({ page, pageSize, total, onChange }: {
  page: number; pageSize: number; total: number; onChange: (page: number) => void;
}) {
  const digits = useDigits();
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (total <= pageSize && page === 1) return null;
  return (
    <div className="flex flex-wrap items-center justify-end gap-2 text-xs text-content-3">
      <span className="me-auto tabular-nums">
        {digits(String(total))} total · {digits(String(page))} / {digits(String(pages))}
      </span>
      <Button variant="ghost" size="icon" disabled={page <= 1}
        onClick={() => onChange(Math.max(1, page - 1))} aria-label="Previous page">
        <ChevronLeft size={15} />
      </Button>
      <Button variant="ghost" size="icon" disabled={page >= pages}
        onClick={() => onChange(Math.min(pages, page + 1))} aria-label="Next page">
        <ChevronRight size={15} />
      </Button>
    </div>
  );
}
