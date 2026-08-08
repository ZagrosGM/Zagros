// Dialog + Drawer — portal-mounted, scroll-locked overlays.
//
// alpha.7 fix (the "black band at the bottom of the page" bug): the old
// implementation rendered the backdrop as `absolute inset-0` INSIDE a
// scrollable grid container. The moment dialog content exceeded the
// viewport height — exactly what the New-User dialog does — the grid row
// grew past 100vh, the container scrolled, and the backdrop (one viewport
// tall) stayed at the top: everything below it rendered on the bare page
// background while the body kept scrolling behind. New contract:
//   * both layers portal into <body> — no stacking-context surprises from
//     transformed ancestors anywhere in the shell;
//   * backdrop is its own `position: fixed` layer — it ALWAYS covers the
//     full viewport at every scroll position;
//   * the scroll container is `fixed inset-0 overflow-y-auto` and the
//     dialog itself is capped to the dynamic viewport (`max-h-[100dvh]`)
//     so mobile URL-bar resizing never uncovers a strip;
//   * the body is scroll-locked while ANY overlay is open (with
//     scrollbar-width compensation so the shell doesn't jump).
import { AnimatePresence, motion } from "framer-motion";
import { X } from "lucide-react";
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { cn, Button } from "./ui";

function useEscape(onClose: () => void, active: boolean) {
  useEffect(() => {
    if (!active) return;
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [active, onClose]);
}

// Reference-counted body scroll lock (nested overlays stay safe) with
// layout-shift compensation for the removed scrollbar.
let lockCount = 0;
function useBodyScrollLock(active: boolean) {
  useEffect(() => {
    if (!active) return;
    const body = document.body;
    if (lockCount === 0) {
      const scrollbar = window.innerWidth - document.documentElement.clientWidth;
      body.dataset.prevOverflow = body.style.overflow;
      body.dataset.prevPaddingRight = body.style.paddingRight;
      body.style.overflow = "hidden";
      if (scrollbar > 0) body.style.paddingRight = `${scrollbar}px`;
    }
    lockCount += 1;
    return () => {
      lockCount -= 1;
      if (lockCount === 0) {
        body.style.overflow = body.dataset.prevOverflow ?? "";
        body.style.paddingRight = body.dataset.prevPaddingRight ?? "";
      }
    };
  }, [active]);
}

function Backdrop({ onClose }: { onClose: () => void }) {
  return (
    <div
      // FULL-viewport sibling layer — impervious to container scrolling.
      className="fixed inset-0 z-[70] bg-black/55 backdrop-blur-sm"
      onClick={onClose}
      aria-hidden
    />
  );
}

export function Dialog({ open, onClose, title, subtitle, headerActions, children, footer, wide }: {
  open: boolean; onClose: () => void; title: ReactNode; subtitle?: ReactNode;
  headerActions?: ReactNode;
  children: ReactNode; footer?: ReactNode; wide?: boolean;
}) {
  useEscape(onClose, open);
  useBodyScrollLock(open);
  const panelRef = useRef<HTMLDivElement>(null);
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  useEffect(() => {
    if (open) setTimeout(() => panelRef.current?.querySelector<HTMLElement>("input,select,textarea,button:not([aria-label=Close])")?.focus(), 60);
  }, [open]);
  if (!mounted) return null;
  return createPortal(
    <AnimatePresence>
      {open && (
        <>
          <motion.div key="bd" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <Backdrop onClose={onClose} />
          </motion.div>
          <motion.div
            key="scroller"
            className="fixed inset-0 z-[71] grid place-items-center overflow-y-auto overscroll-contain p-4"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          >
            <motion.div
              ref={panelRef}
              role="dialog" aria-modal="true"
              initial={{ opacity: 0, y: 18, scale: 0.97 }}
              animate={{ opacity: 1, y: 0, scale: 1, transition: { type: "spring", stiffness: 380, damping: 30 } }}
              exit={{ opacity: 0, y: 10, scale: 0.97, transition: { duration: 0.15 } }}
              className={cn(
                "card relative my-auto flex max-h-[calc(100dvh-2rem)] w-full flex-col p-5 shadow-pop",
                wide ? "max-w-3xl" : "max-w-lg",
              )}
            >
              <div className="mb-4 flex shrink-0 items-start justify-between gap-4">
                <div>
                  <h2 className="text-base font-semibold">{title}</h2>
                  {subtitle && <p className="mt-0.5 text-xs text-content-3">{subtitle}</p>}
                </div>
                <div className="flex items-center gap-2.5">
                  {headerActions}
                  <button onClick={onClose} aria-label="Close" className="rounded-lg p-1.5 text-content-3 hover:bg-surface-2 hover:text-content">
                    <X size={16} />
                  </button>
                </div>
              </div>
              <div className="min-h-0 flex-1 overflow-y-auto pe-1">{children}</div>
              {footer && <div className="mt-5 flex shrink-0 justify-end gap-2 border-t border-border pt-4">{footer}</div>}
            </motion.div>
          </motion.div>
        </>
      )}
    </AnimatePresence>,
    document.body,
  );
}

export function Drawer({ open, onClose, title, children, footer }: {
  open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; footer?: ReactNode;
}) {
  useEscape(onClose, open);
  useBodyScrollLock(open);
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted) return null;
  return createPortal(
    <AnimatePresence>
      {open && (
        <>
          <motion.div key="bd" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <Backdrop onClose={onClose} />
          </motion.div>
          <motion.div
            key="panel"
            role="dialog" aria-modal="true"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-[71] pointer-events-none"
          >
            <motion.div
              initial={{ x: "100%" }} animate={{ x: 0 }} exit={{ x: "100%" }}
              transition={{ type: "spring", stiffness: 320, damping: 34 }}
              className="pointer-events-auto absolute inset-y-0 end-0 flex h-[100dvh] w-full max-w-xl flex-col border-s border-border bg-surface-1 shadow-pop"
            >
              <div className="flex shrink-0 items-center justify-between border-b border-border p-4">
                <h2 className="text-sm font-semibold">{title}</h2>
                <button onClick={onClose} aria-label="Close" className="rounded-lg p-1.5 text-content-3 hover:bg-surface-2 hover:text-content">
                  <X size={16} />
                </button>
              </div>
              <div className="min-h-0 flex-1 overflow-y-auto p-4">{children}</div>
              {footer && <div className="shrink-0 border-t border-border p-4">{footer}</div>}
            </motion.div>
          </motion.div>
        </>
      )}
    </AnimatePresence>,
    document.body,
  );
}

export function ConfirmDialog({ open, onClose, onConfirm, title, body, confirmLabel, danger, loading }: {
  open: boolean; onClose: () => void; onConfirm: () => void; title: ReactNode; body?: ReactNode;
  confirmLabel?: string; danger?: boolean; loading?: boolean;
}) {
  return (
    <Dialog open={open} onClose={onClose} title={title}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant={danger ? "danger" : "primary"} onClick={onConfirm} loading={loading}>
            {confirmLabel ?? "Confirm"}
          </Button>
        </>
      }>
      {body && <p className="text-sm text-content-2">{body}</p>}
    </Dialog>
  );
}

// ------------------------------------------------------------- RowMenu ---
//
// alpha.7.2 (item 16): the old per-row ⋯ menu was `absolute` INSIDE the
// table's scroll container (`card overflow-auto`, fixed height). Anything
// overflowing that box got clipped — the menu opened but was invisible,
// which read as "the ⋯ button does nothing". No absolute-in-container
// popover can ever fix that, so RowMenu portals into <body> and positions
// itself with `position: fixed` from the anchor's bounding rect:
//   * never clipped by ANY ancestor (scroll box, transform, stacking ctx);
//   * flips above the anchor when the viewport bottom is too close;
//   * closes on outside pointerdown, Escape, and any scroll (the anchor
//     would move out from under the menu — closing matches every major
//     design system and is virtualized-table-safe);
//   * z-[80]: above dialogs (z-[71]) so pickers can use it inside modals.
export function RowMenu({ open, anchor, onClose, children, width = 192 }: {
  open: boolean;
  /** The element the menu is anchored to (e.g. the ⋯ button). */
  anchor: HTMLElement | null;
  onClose: () => void;
  children: ReactNode;
  /** Menu width in px (measured offsets need real CSS values). */
  width?: number;
}) {
  const menuRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ top: number; left: number; up: boolean } | null>(null);
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  useEscape(onClose, open);

  // Place from the anchor rect BEFORE paint (no flicker). Re-run whenever
  // the menu content height could have changed (open transition, width).
  useLayoutEffect(() => {
    if (!open || !anchor) { setPos(null); return; }
    const r = anchor.getBoundingClientRect();
    const mh = menuRef.current?.offsetHeight ?? 220;
    const gap = 6;
    let top = r.bottom + gap;
    let up = false;
    if (top + mh > window.innerHeight - 8 && r.top - mh - gap > 8) {
      up = true;
      top = r.top - mh - gap;
    }
    const left = Math.min(Math.max(8, r.right - width), window.innerWidth - width - 8);
    setPos({ top, left, up });
  }, [open, anchor, width, children]);

  useEffect(() => {
    if (!open) return;
    const onPointer = (e: PointerEvent) => {
      const target = e.target as Node;
      if (menuRef.current?.contains(target)) return;
      if (anchor?.contains(target)) return;
      onClose();
    };
    const onScroll = () => onClose();
    document.addEventListener("pointerdown", onPointer, true);
    window.addEventListener("resize", onScroll);
    window.addEventListener("scroll", onScroll, true); // capture: container scrolls too
    return () => {
      document.removeEventListener("pointerdown", onPointer, true);
      window.removeEventListener("resize", onScroll);
      window.removeEventListener("scroll", onScroll, true);
    };
  }, [open, anchor, onClose]);

  if (!mounted) return null;
  return createPortal(
    <AnimatePresence>
      {open && (
        <motion.div
          ref={menuRef}
          role="menu"
          initial={{ opacity: 0, scale: 0.96, y: pos?.up ? 4 : -4 }}
          animate={{ opacity: 1, scale: 1, y: 0, transition: { duration: 0.12 } }}
          exit={{ opacity: 0, scale: 0.97, transition: { duration: 0.08 } }}
          style={{
            position: "fixed",
            top: pos?.top ?? -9999,
            left: pos?.left ?? -9999,
            width,
            transformOrigin: pos?.up ? "bottom right" : "top right",
          }}
          className="z-[80] overflow-hidden rounded-xl border border-border-strong bg-surface-1 py-1 shadow-pop"
        >
          {children}
        </motion.div>
      )}
    </AnimatePresence>,
    document.body,
  );
}
