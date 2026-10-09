import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";

const patterns = [
  { name: "aws-access-key", re: /AKIA[0-9A-Z]{16}/ },
  { name: "openai-key", re: /sk-[A-Za-z0-9]{20,}/ },
  { name: "github-token", re: /ghp_[A-Za-z0-9]{20,}/ },
  { name: "private-key", re: /-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/ },
  { name: "slack-token", re: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
];

const roots = process.argv.slice(2);
if (roots.length === 0) roots.push("src", "public");

const extensions = new Set([
  ".html",
  ".js",
  ".mjs",
  ".css",
  ".svg",
  ".txt",
  ".xml",
  ".json",
  ".astro",
  ".ts",
  ".tsx",
  ".md",
]);

async function files(dir) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const found = [];
  for (const entry of entries) {
    if (entry.name === "node_modules" || entry.name === ".astro") continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) found.push(...(await files(full)));
    else if (extensions.has(path.extname(entry.name))) found.push(full);
  }
  return found;
}

let failed = false;
for (const root of roots) {
  const info = await stat(root).catch(() => null);
  if (!info) continue;
  const list = info.isDirectory() ? await files(root) : [root];
  for (const file of list) {
    const text = await readFile(file, "utf8");
    for (const pattern of patterns) {
      if (pattern.re.test(text)) {
        console.error(`${file} contains ${pattern.name}`);
        failed = true;
      }
    }
  }
}

if (failed) process.exit(1);
console.log(`secrets ok (${roots.join(", ")})`);
