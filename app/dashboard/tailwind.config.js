/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Zagros identity — driven by CSS custom properties (see tokens.css)
        surface: "var(--surface)",
        "surface-1": "var(--surface-1)",
        "surface-2": "var(--surface-2)",
        "surface-3": "var(--surface-3)",
        border: "var(--border)",
        "border-strong": "var(--border-strong)",
        content: "var(--content)",
        "content-2": "var(--content-2)",
        "content-3": "var(--content-3)",
        brand: "var(--brand)",
        "brand-strong": "var(--brand-strong)",
        "brand-soft": "var(--brand-soft)",
        "brand-content": "var(--brand-content)",
        ok: "var(--ok)",
        "ok-soft": "var(--ok-soft)",
        warn: "var(--warn)",
        "warn-soft": "var(--warn-soft)",
        danger: "var(--danger)",
        "danger-soft": "var(--danger-soft)",
        info: "var(--info)",
        "info-soft": "var(--info-soft)",
      },
      fontFamily: {
        sans: [
          "Inter", "Vazirmatn", "system-ui", "-apple-system", "Segoe UI",
          "Roboto", "sans-serif",
        ],
        mono: ["'JetBrains Mono'", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      borderRadius: {
        xl: "0.875rem",
        "2xl": "1.125rem",
      },
      boxShadow: {
        card: "0 1px 2px rgb(0 0 0 / 0.05), 0 1px 6px -1px rgb(0 0 0 / 0.05)",
        pop: "0 8px 30px -6px rgb(0 0 0 / 0.25), 0 2px 8px -2px rgb(0 0 0 / 0.1)",
      },
      keyframes: {
        shimmer: { "100%": { transform: "translateX(100%)" } },
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(6px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        pulse2: { "50%": { opacity: "0.55" } },
      },
      animation: {
        "fade-up": "fade-up .35s cubic-bezier(.21,1.02,.73,1) both",
        pulse2: "pulse2 2s cubic-bezier(.4,0,.6,1) infinite",
      },
    },
  },
  plugins: [],
};
