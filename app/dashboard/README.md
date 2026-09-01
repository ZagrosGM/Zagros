# Zagros Dashboard (unified panel)

The **single** management interface of Zagros — a React 18 + TypeScript SPA
written from scratch for the multi-core platform.

- **Stack:** React 18, Vite 5, Tailwind CSS 3 (design-token driven),
  react-router 6 (hash routing — works on every deployment shape),
  TanStack Query + Virtual, lucide icons, hand-rolled SVG charts
  (no analytics SDK), dnd-kit for routing-rule reordering.
- **Surfaces:** Overview, Users, Subscriptions, Nodes, Cores (full
  lifecycle), Routing (graphical Rule Builder, drag & drop, dry preview,
  deploy), Outbounds, Inbounds (per-protocol wizard), DNS, Certificates,
  Sessions, Devices, Logs, Marketplace (honest roadmap), Settings, and
  **Advanced Mode** (in-panel Config Studio — the only JSON surface).
- **Theming:** dark + light via CSS custom properties; RTL (فارسی) + LTR.
- **Backend:** legacy admin API (`/api/*`) plus the unified Zagros admin
  API (`/api/zagros/*`) — no mocks, no placeholders, everything wired.

## Development

```bash
npm ci
VITE_BASE_API=http://127.0.0.1:8000/api/ npm run dev
```

## Build (what the Dockerfile and the backend fallback builder run)

```bash
npm run build   # tsc + vite build → build/ (index.html + 404.html + statics/)
```

`build/` is git-ignored: CI and `docker build` produce the bundle
deterministically; the backend mounts `build/` at `DASHBOARD_PATH`
(`/dashboard/` by default) and `build/statics` at `/statics/`.
