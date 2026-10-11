import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { targetExists } from "../../docs/scripts/links.mjs";
import { checkBuiltLinks } from "./links.mjs";

describe("documentation links", () => {
  let root;
  let source;
  beforeAll(async () => {
    root = await mkdtemp(path.join(tmpdir(), "insidia-doc-links-"));
    await mkdir(path.join(root, "start"));
    await writeFile(path.join(root, "index.md"), "Overview");
    source = path.join(root, "start", "install.md");
    await writeFile(source, "Install");
    await writeFile(path.join(root, "start", "quickstart.mdx"), "Quickstart");
  });
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it("accepts published routes, extensions, and fragments", async () => {
    for (const target of ["/docs", "/docs/", "/docs/start/install/", "/docs/start/quickstart/#run", "../index.md"]) {
      expect(await targetExists(root, source, target), target).toBe(true);
    }
  });
  it("rejects missing routes and files", async () => {
    for (const target of ["/docs/start/missing/", "missing.md"]) {
      expect(await targetExists(root, source, target), target).toBe(false);
    }
  });
  it("leaves external URLs and local anchors to their respective checkers", async () => {
    for (const target of ["https://example.com", "mailto:a@example.com", "#install"]) {
      expect(await targetExists(root, source, target), target).toBe(true);
    }
  });
});

describe("built site links and assets", () => {
  let root;
  beforeAll(async () => {
    root = await mkdtemp(path.join(tmpdir(), "insidia-built-links-"));
    await mkdir(path.join(root, "docs"));
    await writeFile(path.join(root, "docs", "index.html"), '<h1 id="overview">Docs</h1>');
    await writeFile(path.join(root, "icon.svg"), "<svg></svg>");
  });
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it("resolves pages, relative assets, and fragment destinations", async () => {
    await writeFile(path.join(root, "index.html"), '<a href="/docs/#overview">Docs</a><img src="icon.svg"><a href="https://example.com">External</a>');
    expect(await checkBuiltLinks(root)).toEqual({ pages: 2, issues: [] });
  });
  it("fails for missing routes, assets, and anchors", async () => {
    await writeFile(path.join(root, "index.html"), '<a href="/missing/">Missing</a><video poster="missing.jpg"></video><a href="/docs/#missing">Docs</a>');
    const result = await checkBuiltLinks(root);
    expect(result.issues).toHaveLength(3);
    expect(result.issues.filter((issue) => issue.includes("missing file or route"))).toHaveLength(2);
    expect(result.issues.filter((issue) => issue.includes("missing anchor"))).toHaveLength(1);
  });
});
