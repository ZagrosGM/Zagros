import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The panel is served under DASHBOARD_PATH (default /dashboard/) by the
// FastAPI app; assets are emitted to `<outDir>/statics` and referenced
// relative to index.html. Relative assets avoid colliding with the configurable
// root-level subscription route and work under every DASHBOARD_PATH.
export default defineConfig({
  base: "./",
  plugins: [react()],
  server: {
    // Arena/remote development previews arrive through an ephemeral host.
    allowedHosts: true,
  },
  preview: {
    // Agent/dev previews are served behind an ephemeral reverse-proxy host.
    // Production assets remain FastAPI-served; this affects `vite preview` only.
    allowedHosts: true,
  },
  build: {
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        // Vite 8/Rolldown accepts the function form; the previous Rollup
        // object form is no longer part of OutputOptions. Preserve the same
        // stable vendor split without deprecated build-tool types.
        manualChunks(id) {
          if (/node_modules\/(react|react-dom|react-router|react-router-dom)\//.test(id)) {
            return "react";
          }
          if (id.includes("/node_modules/@tanstack/react-query/")) {
            return "query";
          }
          return undefined;
        },
      },
    },
  },
});
