// SPA affordance: python's StaticFiles(html=True) serves 404.html for
// unknown paths, so client-side routes like /dashboard/users deep-link
// correctly. The backend's own bundle builder does the same copy — this is
// the same step for the Docker image build (idempotent).
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const outDir = join(dirname(fileURLToPath(import.meta.url)), "..", "build");
const indexHtml = join(outDir, "index.html");
if (existsSync(indexHtml)) {
  copyFileSync(indexHtml, join(outDir, "404.html"));
  console.log("postbuild: 404.html created for SPA deep links");
} else {
  console.error("postbuild: build/index.html missing — run vite build first");
  process.exit(1);
}
mkdirSync(outDir, { recursive: true });
