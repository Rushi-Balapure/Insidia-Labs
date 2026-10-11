import { readdir, readFile, access } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

async function files(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const found = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      found.push(...(await files(full)));
    } else if (entry.name.endsWith(".md") || entry.name.endsWith(".mdx")) {
      found.push(full);
    }
  }
  return found;
}

/** Resolve published /docs/ routes to their Markdown sources. */
export async function targetExists(root, file, target) {
  if (/^(?:https?:|mailto:|#)/.test(target)) return true;
  const pathname = target.split(/[?#]/)[0];
  let candidates;
  if (pathname === "/docs" || pathname.startsWith("/docs/")) {
    const slug = pathname.slice(5).replace(/^\/+|\/+$/g, "");
    const stem = path.resolve(root, slug || "index");
    candidates = [`${stem}.md`, `${stem}.mdx`, path.join(stem, "index.md"), path.join(stem, "index.mdx")];
  } else {
    candidates = [path.resolve(path.dirname(file), pathname)];
  }
  for (const candidate of candidates) {
    try {
      await access(candidate);
      return true;
    } catch (error) {
      if (error.code !== "ENOENT" && error.code !== "ENOTDIR") throw error;
    }
  }
  return false;
}

async function main() {
  const root = path.resolve("src/content/docs");
  let failed = false;
  for (const file of await files(root)) {
    const text = await readFile(file, "utf8");
    for (const match of text.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)) {
      if (await targetExists(root, file, match[1])) continue;
      console.error(`${file} links to missing ${match[1]}`);
      failed = true;
    }
  }
  if (failed) process.exitCode = 1;
  else console.log("docs links ok");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
