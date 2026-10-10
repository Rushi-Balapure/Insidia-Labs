import { execSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import react from "@astrojs/react";
import sitemap from "@astrojs/sitemap";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "astro/config";

const root = dirname(fileURLToPath(import.meta.url));
const videoOut = join(root, "video/out");
const videoPublic = join(root, "public/video");
const videoFiles = [
  "howto.mp4",
  "howto.webm",
  "howto.vtt",
  "howto.jpg",
  "film.mp4",
  "film.webm",
  "film.vtt",
  "film.jpg",
  "film-chapters.vtt",
];
const docsRoot = join(root, "../docs");
const docsDist = join(docsRoot, "dist");
const docsPublic = join(root, "public/docs");
const building = process.env.npm_lifecycle_event === "build";
if (building || !existsSync(join(docsPublic, "index.html"))) {
  execSync("npm run build", { cwd: docsRoot, stdio: "inherit" });
  cpSync(docsDist, docsPublic, { recursive: true });
}

if (existsSync(videoOut)) {
  mkdirSync(videoPublic, { recursive: true });
  for (const name of videoFiles) {
    const from = join(videoOut, name);
    if (existsSync(from)) cpSync(from, join(videoPublic, name));
  }
}

export default defineConfig({
  site: "https://insidialabs.com",
  output: "static",
  redirects: {
    "/licenses": "/credits",
  },
  integrations: [react(), sitemap()],
  vite: {
    plugins: [tailwindcss()],
  },
});
