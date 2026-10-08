import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

const patterns = [
  { name: "aws-access-key", re: /AKIA[0-9A-Z]{16}/ },
  { name: "openai-key", re: /sk-[A-Za-z0-9]{20,}/ },
  { name: "github-token", re: /ghp_[A-Za-z0-9]{20,}/ },
  { name: "private-key", re: /-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/ },
  { name: "slack-token", re: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
];

async function files(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const found = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) found.push(...(await files(full)));
    else if (entry.name.endsWith(".md") || entry.name.endsWith(".mdx")) found.push(full);
  }
  return found;
}

const root = path.resolve("src/content/docs");
let failed = false;
for (const file of await files(root)) {
  const text = await readFile(file, "utf8");
  for (const pattern of patterns) {
    if (pattern.re.test(text)) {
      console.error(`${file} contains ${pattern.name}`);
      failed = true;
    }
  }
}

if (failed) process.exit(1);
console.log("docs secrets ok");
