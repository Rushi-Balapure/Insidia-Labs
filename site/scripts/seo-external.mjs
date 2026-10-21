import { readFile } from "node:fs/promises";
import path from "node:path";
import Validator from "@adobe/structured-data-validator";
import WebAutoExtractor from "@marbec/web-auto-extractor";
import { htmlFiles, inspectPage } from "./seo.mjs";

const root = path.resolve(process.argv[2] ?? "dist");
const vocabularyUrl = "https://schema.org/version/latest/schemaorg-all-https.jsonld";
async function vocabulary() {
  if (process.argv[3]) return JSON.parse(await readFile(process.argv[3], "utf8"));
  const response = await fetch(vocabularyUrl);
  if (!response.ok) throw new Error(`Schema.org vocabulary request failed: ${response.status}`);
  return response.json();
}

const validator = new Validator(await vocabulary());
const extractor = new WebAutoExtractor();
const issues = [];
let pages = 0;
let structured = 0;
for (const file of await htmlFiles(root)) {
  const route = `/${path.relative(root, file).split(path.sep).join("/").replace(/index\.html$/, "")}`;
  const html = await readFile(file, "utf8");
  const page = inspectPage(html, route);
  if (page.noindex || page.redirect) continue;
  pages++;
  if (page.graph.length) structured++;
  const results = await validator.validate(extractor.parse(html));
  issues.push(...results.map(({ severity, issueMessage, path: field }) => ({
    route, severity, message: issueMessage, field,
  })));
}
const report = {
  tool: "@adobe/structured-data-validator", version: "1.7.0",
  extractor: "@marbec/web-auto-extractor@2.1.0", vocabulary: vocabularyUrl,
  pages, structured,
  errors: issues.filter((issue) => issue.severity === "ERROR").length,
  warnings: issues.filter((issue) => issue.severity === "WARNING").length,
  issues,
};
console.log(JSON.stringify(report, null, 2));
if (report.errors) process.exitCode = 1;
