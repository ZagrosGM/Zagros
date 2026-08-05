import { create } from "zustand";
import { persist } from "zustand/middleware";

export type Theme = "dark" | "light";
export type Locale = "en" | "fa";

interface UiState {
  theme: Theme;
  locale: Locale;
  sidebarCollapsed: boolean;
  advancedMode: boolean;
  setTheme: (t: Theme) => void;
  setLocale: (l: Locale) => void;
  toggleSidebar: () => void;
  setAdvancedMode: (v: boolean) => void;
}

export const useUI = create<UiState>()(
  persist(
    (set) => ({
      theme: "dark",
      locale: "en",
      sidebarCollapsed: false,
      advancedMode: false,
      setTheme: (theme) => set({ theme }),
      setLocale: (locale) => set({ locale }),
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      setAdvancedMode: (advancedMode) => set({ advancedMode }),
    }),
    {
      name: "zagros.ui",
      onRehydrateStorage: () => (state) => {
        applyUiState(state?.theme ?? "dark", state?.locale ?? "en");
      },
    },
  ),
);

export function applyUiState(theme: Theme, locale: Locale) {
  const root = document.documentElement;
  root.classList.toggle("dark", theme === "dark");
  root.classList.toggle("light", theme === "light");
  root.setAttribute("dir", locale === "fa" ? "rtl" : "ltr");
  root.setAttribute("lang", locale);
}
