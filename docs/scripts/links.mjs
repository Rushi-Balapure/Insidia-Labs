import { readdir, readFile, access } from "node:fs/promises";
import path from "node:path";

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

const root = path.resolve("src/content/docs");
let failed = false;
for (const file of await files(root)) {
  const text = await readFile(file, "utf8");
  for (const match of text.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)) {
    const target = match[1];
    if (target.startsWith("http") || target.startsWith("#") || target.startsWith("mailto:")) {
      continue;
    }
    const resolved = path.resolve(path.dirname(file), target.split("#")[0]);
    try {
      await access(resolved);
    } catch {
      console.error(`${file} links to missing ${target}`);
      failed = true;
    }
  }
}
if (failed) {
  process.exit(1);
}
