import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

const banned = [
  "garak",
  "promptfoo",
  "pyrit",
  "deepteam",
  "nuclei",
  "dalfox",
  "owasp zap",
  "vllm",
  "llama.cpp",
  "ollama",
];

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
  const text = (await readFile(file, "utf8")).toLowerCase();
  for (const word of banned) {
    if (text.includes(word)) {
      console.error(`${file} contains forbidden name: ${word}`);
      failed = true;
    }
  }
}
if (failed) {
  process.exit(1);
}
