import { existsSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "parse5";

const origin = "https://www.insidialabs.com";
const attr = (node, name) => node?.attrs?.find((item) => item.name === name)?.value;
const text = (node) => node?.value ?? (node?.childNodes ?? []).map(text).join("");

function elements(node) {
  return [node, ...(node.childNodes ?? []).flatMap(elements)];
}

export async function htmlFiles(root) {
  const files = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const file = path.join(root, entry.name);
    if (entry.isDirectory()) files.push(...await htmlFiles(file));
    else if (entry.name.endsWith(".html")) files.push(file);
  }
  return files;
}

export function inspectPage(html, route) {
  const nodes = elements(parse(html));
  const tags = (name) => nodes.filter((node) => node.tagName === name);
  const metas = tags("meta");
  const meta = (key) => metas.find((node) => (attr(node, "name") ?? attr(node, "property")) === key);
  const canonicals = tags("link").filter((node) => attr(node, "rel") === "canonical");
  const noindex = /\bnoindex\b/.test(attr(meta("robots"), "content") ?? "");
  const redirect = metas.some((node) => attr(node, "http-equiv")?.toLowerCase() === "refresh");
  const issues = [];
  const graph = [];
  for (const script of tags("script").filter((node) => attr(node, "type") === "application/ld+json")) {
    try {
      const data = JSON.parse(text(script));
      graph.push(...(data["@graph"] ?? [data]));
    } catch (error) {
      issues.push(`invalid JSON-LD: ${error.message}`);
    }
  }
  const title = text(tags("title")[0]);
  const description = attr(meta("description"), "content");
  if (!title) issues.push("missing title");
  if (!description && !redirect) issues.push("missing description");
  if (tags("h1").length !== 1 && !redirect) issues.push("expected one H1");
  if (attr(tags("html")[0], "lang") !== "en" && !redirect) issues.push("missing English language declaration");
  const canonical = attr(canonicals[0], "href");
  if (!noindex && !redirect) checkIndexable({ tags, meta, canonicals, canonical, route, graph, issues });
  if (route.endsWith("404.html") && !noindex) issues.push("404 must be noindex");
  return { route, title, description, canonical, noindex, redirect, graph, issues };
}

function checkIndexable({ tags, meta, canonicals, canonical, route, graph, issues }) {
  if (canonicals.length !== 1 || canonical !== new URL(route, origin).href) issues.push("canonical must match the public URL");
  for (const key of ["og:title", "og:description", "og:image", "twitter:card", "twitter:image"]) {
    if (!attr(meta(key), "content")) issues.push(`missing ${key}`);
  }
  if (attr(meta("og:url"), "content") !== canonical) issues.push("og:url differs from canonical");
  for (const type of ["Organization", "WebSite", "WebPage", ...(route === "/" ? ["SoftwareApplication", "FAQPage"] : ["BreadcrumbList"])]) {
    if (!graph.some((node) => node["@type"] === type)) issues.push(`missing ${type} schema`);
  }
  if (route.startsWith("/docs/") && !graph.some((node) => node["@type"] === "TechArticle")) issues.push("missing TechArticle schema");
  for (const faq of graph.filter((node) => node["@type"] === "FAQPage")) {
    const body = text(tags("body")[0]).replace(/\s+/g, " ");
    for (const question of faq.mainEntity ?? []) {
      if (![question.name, question.acceptedAnswer?.text].every((answer) => answer && body.includes(answer.replace(/\s+/g, " ")))) {
        issues.push("FAQ schema must match rendered questions and answers");
      }
    }
  }
}

async function checkDiscovery(root, pages, issues) {
  const urls = new Set();
  for (const sitemap of ["sitemap-0.xml", "docs/sitemap-0.xml"]) {
    const xml = await readFile(path.join(root, sitemap), "utf8");
    for (const [, url] of xml.matchAll(/<loc>([^<]+)<\/loc>/g)) urls.add(url);
  }
  const expected = new Set(pages.filter((page) => !page.noindex && !page.redirect).map((page) => new URL(page.route, origin).href));
  for (const url of expected) if (!urls.has(url)) issues.push(`sitemap missing ${url}`);
  for (const url of urls) if (!expected.has(url)) issues.push(`sitemap contains noncanonical or nonindexable URL: ${url}`);
  const robots = await readFile(path.join(root, "robots.txt"), "utf8");
  for (const sitemap of ["/sitemap-index.xml", "/docs/sitemap-index.xml"]) {
    if (!robots.includes(`Sitemap: ${origin}${sitemap}`)) issues.push(`robots missing ${sitemap}`);
  }
  if (/^Disallow:\s*\/\s*$/mi.test(robots)) issues.push("robots blocks the site");
  for (const file of ["llms.txt", "llms-full.txt", "docs/llms.txt"]) {
    if (!existsSync(path.join(root, file))) { issues.push(`missing ${file}`); continue; }
    const guide = await readFile(path.join(root, file), "utf8");
    if (guide.includes("https://docs.insidialabs.com")) issues.push(`${file} uses the obsolete docs host`);
    for (const [, url] of guide.matchAll(/\]\((https:\/\/www\.insidialabs\.com[^)]+)\)/g)) {
      const pathname = new URL(url).pathname;
      if (!existsSync(path.join(root, pathname, "index.html")) && !existsSync(path.join(root, pathname))) issues.push(`${file} links to missing ${pathname}`);
    }
  }
}

export async function checkBuiltSeo(directory) {
  const root = path.resolve(directory);
  const pages = [];
  for (const file of await htmlFiles(root)) {
    const route = `/${path.relative(root, file).split(path.sep).join("/").replace(/index\.html$/, "")}`;
    pages.push(inspectPage(await readFile(file, "utf8"), route));
  }
  const issues = pages.flatMap((page) => page.issues.map((issue) => `${page.route}: ${issue}`));
  for (const field of ["title", "description"]) {
    const seen = new Set();
    for (const page of pages.filter((item) => !item.noindex && !item.redirect)) {
      if (seen.has(page[field])) issues.push(`${page.route}: duplicate ${field}`);
      seen.add(page[field]);
    }
  }
  await checkDiscovery(root, pages, issues);
  const indexable = pages.filter((page) => !page.noindex && !page.redirect);
  return { pages: pages.length, indexable: indexable.length, structured: indexable.filter((page) => page.graph.length).length, issues };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await checkBuiltSeo(process.argv[2] ?? "dist");
  console.log(JSON.stringify(result, null, 2));
  if (result.issues.length) process.exitCode = 1;
}
