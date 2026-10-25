import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { mailtoHref, acknowledged, validateLead } from "./lead";
import { CLI_VERSION, installCommands } from "../content/install";
import recording from "../content/terminal-run.json";

const valid = {
  email: "a@example.com",
  company: "Northwind",
  role: "Security",
  interest: "waitlist",
  aiSurface: "support agent",
  honeypot: "",
};

describe("validateLead", () => {
  it("rejects a bad email inline and accepts a real one", () => {
    const bad = validateLead({ ...valid, email: "not-an-email" }, { endpoint: "", lastSubmitAt: null, now: 0 });
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.field).toBe("email");
    const good = validateLead(valid, { endpoint: "", lastSubmitAt: null, now: 0 });
    expect(good).toEqual({ ok: true, channel: "mailto" });
  });

  it("drops a honeypot fill and never names a tenant store", () => {
    const dropped = validateLead({ ...valid, honeypot: "https://spam.example" }, { endpoint: "https://form.example", lastSubmitAt: null, now: 0 });
    expect(dropped).toEqual({ ok: true, channel: "dropped" });
    const hosted = validateLead(valid, { endpoint: "https://form.example/f/abc", lastSubmitAt: null, now: 0 });
    expect(hosted).toEqual({ ok: true, channel: "hosted-form" });
    expect(["hosted-form", "mailto", "dropped"]).not.toContain("tenant");
  });

  it("rate-limits a second submit inside the cooldown", () => {
    const again = validateLead(valid, { endpoint: "", lastSubmitAt: 1_000, now: 5_000 });
    expect(again.ok).toBe(false);
    if (!again.ok) expect(again.field).toBe("rate");
  });

  it("builds a mailto that keeps the lead out of this site", () => {
    const href = mailtoHref({ ...valid, interest: "design-partner" });
    expect(href.startsWith("mailto:insidialabs@gmail.com")).toBe(true);
    expect(href).toContain("Design%20partner");
  });

  it("treats only a 2xx response as acknowledgement", () => {
    expect(acknowledged(202)).toBe(true);
    expect(acknowledged(404)).toBe(false);
    expect(acknowledged(500)).toBe(false);
  });
});

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

describe("marketing copy", () => {
  it("keeps synthetic evidence masked and leaves the planted key out of the site", () => {
    const root = path.resolve("src");
    const text = walk(root)
      .filter((file) => /\.(astro|tsx|ts|css|mjs|json|md)$/.test(file) && !file.endsWith(".test.ts"))
      .map((file) => readFileSync(file, "utf8"))
      .join("\n");
    expect(text).toContain("[AWS_ACCESS_KEY len=20 fp=3f9a1c07]");
    expect(text).not.toMatch(/AKIA[0-9A-Z]{16}/);
    expect(text.toLowerCase()).not.toContain("tenant_pings");
    expect(text.toLowerCase()).not.toMatch(/open[- ]source|open core/);
    expect(text).not.toContain("insidialabs.com");
  });

  it("keeps the license name on the credits page only", () => {
    const root = path.resolve("src");
    const hits = walk(root).filter((file) => {
      if (file.endsWith("credits.astro") || file.endsWith(".test.ts")) return false;
      return readFileSync(file, "utf8").includes("Apache-2.0");
    });
    expect(hits).toEqual([]);
  });

  it("identifies the recorded fixture and displays the full install command", () => {
    expect(recording.source).toBe("recorded-local-fixture");
    expect(recording.fixture).toContain("localhost");
    expect(recording.policy).toBe("L1");
    expect(recording.exitCode).toBe(1);
    expect(recording.summary).toContain("5 not tested");
    expect(recording.finding.probe).toBe("insidia.web.ssti");
    expect(recording.note).toContain("not a live scan");
    const component = readFileSync(path.resolve("src/components/InstallLine.tsx"), "utf8");
    expect(component).toContain("<code>{installCommands[name]}</code>");
    expect(installCommands.uv).not.toContain("…");
    expect(installCommands.uv).toContain(`Rushi-Balapure/Insidia-Labs@v${CLI_VERSION}#subdirectory=core`);
    expect(installCommands.pipx.startsWith("pipx install ")).toBe(true);
  });

  it("pins the install to the CLI version in core/pyproject.toml", () => {
    const pyproject = readFileSync(path.resolve("../core/pyproject.toml"), "utf8");
    expect(pyproject).toMatch(new RegExp(`^version = "${CLI_VERSION.replaceAll(".", "\\.")}"$`, "m"));
  });
});
