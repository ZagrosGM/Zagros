// Design-system primitives — every page composes these; nothing restyles per page.
import { clsx } from "clsx";
import { forwardRef, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";
import { AlertTriangle, Loader2, PackageOpen } from "lucide-react";
import { copyText } from "../lib/clipboard";

export const cn = (...args: Parameters<typeof clsx>) => clsx(...args);

// ---------------------------------------------------------------- Button ---
type Variant = "primary" | "secondary" | "ghost" | "danger" | "outline";
const variants: Record<Variant, string> = {
  primary: "bg-brand text-brand-content hover:bg-brand-strong shadow-sm",
  secondary: "bg-surface-3 text-content hover:bg-surface-2 border border-border-strong",
  ghost: "text-content-2 hover:bg-surface-2 hover:text-content",
  danger: "bg-danger/15 text-danger hover:bg-danger/25 border border-danger/30",
  outline: "border border-border-strong text-content hover:border-brand hover:text-brand",
};
const sizes = { sm: "h-8 px-3 text-xs gap-1.5", md: "h-9 px-4 text-sm gap-2", icon: "h-8 w-8" };

export const Button = forwardRef<HTMLButtonElement, ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant; size?: keyof typeof sizes; loading?: boolean;
}>(({ variant = "primary", size = "md", loading, className, children, disabled, ...rest }, ref) => (
  <button
    ref={ref}
    disabled={disabled || loading}
    className={cn(
      "inline-flex select-none items-center justify-center rounded-xl font-medium transition-all",
      "active:scale-[0.98] disabled:pointer-events-none disabled:opacity-50",
      variants[variant], sizes[size], className,
    )}
    {...rest}
  >
    {loading && <Loader2 size={15} className="animate-spin" />}
    {children}
  </button>
));
Button.displayName = "Button";

// ------------------------------------------------------------------ Card ---
export function Card({ className, children, ...rest }: { className?: string; children: ReactNode } & React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("card p-5", className)} {...rest}>{children}</div>;
}

export function CardHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-4 flex items-start justify-between gap-3">
      <div>
        <h3 className="text-[15px] font-semibold">{title}</h3>
        {subtitle && <p className="mt-0.5 text-xs text-content-3">{subtitle}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

// ----------------------------------------------------------------- Badge ---
const tones = {
  ok: "bg-ok-soft text-ok",
  warn: "bg-warn-soft text-warn",
  danger: "bg-danger-soft text-danger",
  info: "bg-info-soft text-info",
  brand: "bg-brand-soft text-brand",
  muted: "bg-surface-3 text-content-2",
} as const;
export function Badge({ tone = "muted", children, dot }: { tone?: keyof typeof tones; children: ReactNode; dot?: boolean }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[11px] font-medium", tones[tone])}>
      {dot && <span className="h-1.5 w-1.5 rounded-full bg-current" />}
      {children}
    </span>
  );
}

// ---------------------------------------------------------------- Inputs ---
export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement> & { invalid?: boolean }>(
  ({ className, invalid, ...rest }, ref) => (
    <input
      ref={ref}
      className={cn(
        "h-9 w-full rounded-xl border bg-surface-1 px-3 text-sm text-content placeholder:text-content-3",
        "transition-colors hover:border-border-strong focus:border-brand focus:outline-none",
        invalid ? "border-danger" : "border-border",
        className,
      )}
      {...rest}
    />
  ),
);
Input.displayName = "Input";

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...rest }, ref) => (
    <textarea
      ref={ref}
      className={cn(
        "w-full rounded-xl border border-border bg-surface-1 px-3 py-2 text-sm text-content placeholder:text-content-3",
        "transition-colors hover:border-border-strong focus:border-brand focus:outline-none",
        className,
      )}
      {...rest}
    />
  ),
);
Textarea.displayName = "Textarea";

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(
  ({ className, children, ...rest }, ref) => (
    <select
      ref={ref}
      className={cn(
        "h-9 w-full appearance-none rounded-xl border border-border bg-surface-1 px-3 pe-8 text-sm text-content",
        "cursor-pointer transition-colors hover:border-border-strong focus:border-brand focus:outline-none",
        "bg-[url('data:image/svg+xml;charset=utf-8,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%2212%22 height=%2212%22 viewBox=%220 0 24 24%22 fill=%22none%22 stroke=%22%238a99ab%22 stroke-width=%223%22%3E%3Cpath d=%22m6 9 6 6 6-6%22/%3E%3C/svg%3E')] bg-[position:right_0.7rem_center] bg-no-repeat",
        "[dir=rtl]&:bg-[position:left_0.7rem_center]",
        className,
      )}
      {...rest}
    >
      {children}
    </select>
  ),
);
Select.displayName = "Select";

export function Field({ label, hint, error, children, required }: {
  label: ReactNode; hint?: ReactNode; error?: string; children: ReactNode; required?: boolean;
}) {
  return (
    <label className="block">
      <span className="mb-1.5 flex items-center gap-1 text-xs font-medium text-content-2">
        {label}{required && <span className="text-danger">*</span>}
      </span>
      {children}
      {error ? <span className="mt-1 block text-[11px] text-danger">{error}</span>
        : hint ? <span className="mt-1 block text-[11px] text-content-3">{hint}</span> : null}
    </label>
  );
}

// ---------------------------------------------------------------- Switch ---
export function Switch({ checked, onChange, disabled, label }: {
  checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; label?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        "relative h-5 w-9 shrink-0 rounded-full transition-colors disabled:opacity-40",
        checked ? "bg-brand" : "bg-surface-3 border border-border-strong",
      )}
    >
      <span className={cn(
        "absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-all",
        checked ? "start-[18px]" : "start-0.5",
      )} />
    </button>
  );
}

// ----------------------------------------------------------------- Misc ---
export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={cn("skeleton", className)} />;
}

export function EmptyState({ title, hint, action, icon }: { title?: ReactNode; hint?: ReactNode; action?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-14 text-center">
      <div className="mb-1 grid h-12 w-12 place-items-center rounded-2xl bg-surface-2 text-content-3">
        {icon ?? <PackageOpen size={22} />}
      </div>
      <p className="text-sm font-medium text-content-2">{title ?? "Nothing here yet"}</p>
      {hint && <p className="max-w-sm text-xs text-content-3">{hint}</p>}
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-14 text-center">
      <AlertTriangle className="text-warn" size={26} />
      <p className="max-w-md text-sm text-content-2">{message}</p>
      {onRetry && <Button variant="secondary" size="sm" onClick={onRetry}>Retry</Button>}
    </div>
  );
}

export function StatusDot({ tone, pulse }: { tone: "ok" | "warn" | "danger" | "muted"; pulse?: boolean }) {
  const c = { ok: "bg-ok", warn: "bg-warn", danger: "bg-danger", muted: "bg-content-3" }[tone];
  return (
    <span className="relative inline-flex h-2 w-2">
      {pulse && <span className={cn("absolute inline-flex h-full w-full animate-ping rounded-full opacity-60", c)} />}
      <span className={cn("relative inline-flex h-2 w-2 rounded-full", c)} />
    </span>
  );
}

export function Progress({ value, tone = "brand", className }: { value: number; tone?: "brand" | "ok" | "warn" | "danger"; className?: string }) {
  const colors = { brand: "bg-brand", ok: "bg-ok", warn: "bg-warn", danger: "bg-danger" };
  return (
    <div className={cn("h-1.5 w-full overflow-hidden rounded-full bg-surface-3", className)}>
      <div className={cn("h-full rounded-full transition-all", colors[tone])} style={{ width: `${Math.min(100, Math.max(0, value))}%` }} />
    </div>
  );
}

export function Stat({ label, value, sub, icon, tone = "default" }: {
  label: ReactNode; value: ReactNode; sub?: ReactNode; icon?: ReactNode; tone?: "default" | "ok" | "warn" | "danger";
}) {
  const iconTone = { default: "bg-brand-soft text-brand", ok: "bg-ok-soft text-ok", warn: "bg-warn-soft text-warn", danger: "bg-danger-soft text-danger" }[tone];
  return (
    <div className="card flex items-center gap-4 p-4">
      {icon && <div className={cn("grid h-11 w-11 shrink-0 place-items-center rounded-xl", iconTone)}>{icon}</div>}
      <div className="min-w-0">
        <p className="truncate text-xs text-content-3">{label}</p>
        <p className="mt-0.5 truncate text-xl font-semibold tabular-nums">{value}</p>
        {sub && <p className="mt-0.5 truncate text-[11px] text-content-3">{sub}</p>}
      </div>
    </div>
  );
}

export function Tabs({ tabs, active, onChange }: { tabs: { id: string; label: ReactNode; icon?: ReactNode }[]; active: string; onChange: (id: string) => void }) {
  return (
    <div role="tablist" className="flex max-w-full items-center gap-1 overflow-x-auto rounded-2xl border border-border bg-surface-1 p-1">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={active === t.id}
          onClick={() => onChange(t.id)}
          className={cn(
            "flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl px-3.5 py-1.5 text-xs font-medium transition-colors",
            active === t.id ? "bg-brand-soft text-brand" : "text-content-2 hover:text-content",
          )}
        >
          {t.icon}{t.label}
        </button>
      ))}
    </div>
  );
}

// --------------------------------------------------------------- Tooltip ---
/** Minimal accessible tooltip: hover/focus reveals, ESC/blur hides.
 *  Positioned so table row actions can explain icon-only buttons. */
export function Tooltip({ label, children, className }: { label: ReactNode; children: ReactNode; className?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <span className={cn("relative inline-flex", className)}
      onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)} onBlur={() => setOpen(false)}>
      {children}
      <span role="tooltip"
        className={cn(
          "pointer-events-none absolute bottom-full start-1/2 z-50 mb-1.5 -translate-x-1/2 whitespace-nowrap rounded-lg border border-border-strong bg-surface-1 px-2 py-1 text-[11px] font-medium text-content shadow-pop transition-opacity rtl:translate-x-1/2",
          open ? "opacity-100" : "opacity-0",
        )}>
        {label}
      </span>
    </span>
  );
}

export function CopyButton({ text, copiedLabel = "Copied!", copyLabel = "Copy" }: { text: string; copiedLabel?: string; copyLabel?: string }) {
  const [done, setDone] = useStateBool();
  return (
    <Button variant="ghost" size="sm" onClick={async () => {
      // α7.2: copyText works without a secure context (plain-HTTP panels).
      if (await copyText(text)) setDone();
    }}>
      {done ? copiedLabel : copyLabel}
    </Button>
  );
}

function useStateBool(): [boolean, () => void] {
  const [v, setV] = useState(false);
  return [v, () => { setV(true); setTimeout(() => setV(false), 1600); }];
}
