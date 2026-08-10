import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The panel is served under DASHBOARD_PATH (default /dashboard/) by the
// FastAPI app; assets are emitted to `<outDir>/statics` and referenced from
// the site root (the backend also mounts /statics). Keep this identical to
// the plumbing in app/dashboard/__init__.py.
export default defineConfig({
  plugins: [react()],
  preview: {
    // Agent/dev previews are served behind an ephemeral reverse-proxy host.
    // Production assets remain FastAPI-served; this affects `vite preview` only.
    allowedHosts: true,
  },
  build: {
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        manualChunks: {
          react: ["react", "react-dom", "react-router-dom"],
          query: ["@tanstack/react-query"],
        },
      },
    },
  },
});
