import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const origin = "https://site.example";

async function htmlFiles(directory) {
  const found = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) found.push(...await htmlFiles(file));
    else if (entry.name.endsWith(".html")) found.push(file);
  }
  return found;
}

async function fileAt(root, pathname) {
  const file = path.resolve(root, `.${decodeURIComponent(pathname)}`);
  if (!file.startsWith(`${root}${path.sep}`) && file !== root) return null;
  for (const candidate of [file, path.join(file, "index.html")]) {
    try {
      if ((await stat(candidate)).isFile()) return candidate;
    } catch (error) {
      if (error.code !== "ENOENT" && error.code !== "ENOTDIR") throw error;
    }
  }
  return null;
}

async function html(file, cache) {
  if (!cache.has(file)) cache.set(file, await readFile(file, "utf8"));
  return cache.get(file);
}

export async function checkBuiltLinks(directory) {
  const root = path.resolve(directory);
  const cache = new Map();
  const issues = [];
  const pages = await htmlFiles(root);
  for (const file of pages) {
    const route = `/${path.relative(root, file).split(path.sep).join("/").replace(/index\.html$/, "")}`;
    const content = await html(file, cache);
    for (const [, reference] of content.matchAll(/\b(?:href|src|poster)="([^"]+)"/g)) {
      const url = new URL(reference.replaceAll("&amp;", "&"), `${origin}${route}`);
      if (url.origin !== origin) continue;
      const destination = await fileAt(root, url.pathname);
      let issue = destination ? "" : "missing file or route";
      if (destination?.endsWith(".html") && url.hash) {
        const id = decodeURIComponent(url.hash.slice(1));
        const markup = await html(destination, cache);
        if (!markup.includes(`id="${id}"`) && !markup.includes(`name="${id}"`)) issue = "missing anchor";
      }
      if (issue) issues.push(`${route}: ${reference} (${issue})`);
    }
  }
  return { pages: pages.length, issues };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await checkBuiltLinks(process.argv[2] || "dist");
  if (result.issues.length) {
    result.issues.forEach((issue) => console.error(issue));
    process.exitCode = 1;
  } else console.log(`built links and assets ok (${result.pages} pages)`);
}
