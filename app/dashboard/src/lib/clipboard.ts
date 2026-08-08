// Clipboard copy that works on EVERY panel deployment (alpha.7.2, item 16).
//
// The bug: panels are typically served over plain HTTP on a LAN/VPN; there
// `navigator.clipboard` is UNDEFINED (secure-context-only API), so
// `navigator.clipboard.writeText(...)` throws a TypeError synchronously and
// the click does literally nothing — exactly the reported "Subscription
// Copy doesn't work".
//
// Contract: secure Clipboard API first; documented execCommand fallback
// otherwise (still supported by every browser for this exact use case).
export async function copyText(text: string): Promise<boolean> {
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // permission denied etc. — fall through to the legacy path
    }
  }
  if (typeof document === "undefined") return false;
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.insetInlineStart = "-9999px";
    ta.style.top = "0";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}
