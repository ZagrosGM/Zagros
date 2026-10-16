// f-branding-1: operator white-labeling, applied at runtime.
// One public query (GET /api/zagros/branding — no auth needed) shared by the
// whole app: sidebar name/logo/tagline, login screen, tab title, favicon and
// the --brand accent family. NULL fields keep the stock Zagros look.
import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";

export interface Branding {
  panel_name?: string | null;
  panel_tagline?: string | null;
  name_fa?: string | null;
  name_en?: string | null;
  tagline_fa?: string | null;
  tagline_en?: string | null;
  logo_url?: string | null;
  favicon_url?: string | null;
  accent_color?: string | null;
  show_powered_by?: boolean | null;
}

const DEFAULT_FAVICON = "./statics/zagros.svg";

export function useBranding() {
  const q = useQuery({
    queryKey: ["zagros", "branding"],
    queryFn: () => api.get<Branding>("/zagros/branding"),
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
  const branding = q.data ?? {};

  useEffect(() => {
    const root = document.documentElement;
    // accent: swap the --brand family from one hex (soft/strong derive via
    // color-mix so dark/light both stay readable)
    if (branding.accent_color) {
      root.style.setProperty("--brand", branding.accent_color);
      root.style.setProperty("--brand-strong", branding.accent_color);
      root.style.setProperty(
        "--brand-soft", `color-mix(in srgb, ${branding.accent_color} 14%, transparent)`);
    }
    // favicon
    const link = document.querySelector<HTMLLinkElement>(
      "link[rel~='icon']") ?? document.head.appendChild(
      Object.assign(document.createElement("link"), { rel: "icon" }));
    if (link) link.href = branding.favicon_url || DEFAULT_FAVICON;
    return () => {
      if (branding.accent_color) {
        root.style.removeProperty("--brand");
        root.style.removeProperty("--brand-strong");
        root.style.removeProperty("--brand-soft");
      }
    };
  }, [branding.accent_color, branding.favicon_url]);

  return branding;
}

/** Brand name for the ACTIVE locale (per-language override beats global). */
export function brandName(b: Branding, locale: string): string {
  const override = locale === "fa" ? (b.name_fa ?? b.name_en) : (b.name_en ?? b.name_fa);
  return override || b.panel_name || "Zagros";
}

export function brandTagline(b: Branding, locale: string): string | null {
  const override = locale === "fa" ? (b.tagline_fa ?? b.tagline_en)
    : (b.tagline_en ?? b.tagline_fa);
  return override || b.panel_tagline || null;
}

export function brandLogo(b: Branding): string {
  return b.logo_url || "./statics/zagros.svg";
}
