import { execSync } from "node:child_process";
import { cpSync, createReadStream, existsSync, rmSync, statSync } from "node:fs";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import react from "@astrojs/react";
import sitemap from "@astrojs/sitemap";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "astro/config";

const root = dirname(fileURLToPath(import.meta.url));
const docsRoot = join(root, "../docs");
const docsDist = join(docsRoot, "dist");
const docsPublic = resolve(root, "public/docs");
const building = process.env.npm_lifecycle_event === "build";
if (building || !existsSync(join(docsPublic, "index.html"))) {
  if (!existsSync(join(docsRoot, "node_modules/astro"))) {
    execSync("npm ci", { cwd: docsRoot, stdio: "inherit" });
  }
  execSync("npm run build", { cwd: docsRoot, stdio: "inherit" });
  // Replace generated docs so removed pages and old search assets cannot survive a rebuild.
  rmSync(docsPublic, { recursive: true, force: true });
  cpSync(docsDist, docsPublic, { recursive: true });
}

const docsTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json",
  ".txt": "text/plain; charset=utf-8",
  ".webp": "image/webp",
  ".png": "image/png",
  ".woff2": "font/woff2",
};

function docsRequestPath(url = "") {
  const pathname = decodeURIComponent(url.split("?")[0]);
  if (pathname !== "/docs" && !pathname.startsWith("/docs/")) return null;
  let rel = pathname.slice("/docs".length);
  if (rel === "" || rel.endsWith("/")) rel = `${rel}index.html`.replace(/^\//, "");
  else if (!extname(rel)) rel = `${rel.replace(/^\//, "")}/index.html`;
  else rel = rel.replace(/^\//, "");
  const file = resolve(docsPublic, normalize(rel));
  const docsRootPath = docsPublic.endsWith("/") ? docsPublic : `${docsPublic}/`;
  if (!file.startsWith(docsRootPath)) return null;
  return existsSync(file) && statSync(file).isFile() ? file : null;
}

function attachDocs(server) {
  server.middlewares.use((req, res, next) => {
    const file = docsRequestPath(req.url);
    if (!file) return next();
    res.setHeader("Content-Type", docsTypes[extname(file)] ?? "application/octet-stream");
    createReadStream(file).pipe(res);
  });
}

function docsDevPlugin() {
  return {
    name: "insidia-docs",
    configureServer: attachDocs,
    configurePreviewServer: attachDocs,
  };
}

export default defineConfig({
  site: "https://www.insidialabs.com",
  output: "static",
  trailingSlash: "always",
  redirects: {
    "/licenses": "/credits",
  },
  integrations: [react(), sitemap()],
  vite: {
    plugins: [tailwindcss(), docsDevPlugin()],
  },
});
