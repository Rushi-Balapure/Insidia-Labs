import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { TRACKED_PATHS, analyticsEnabled, assertTrackedPath, pageUrl } from "./analytics";

describe("analyticsEnabled", () => {
  it("stays off in development", () => {
    expect(analyticsEnabled({ production: false })).toBe(false);
  });

  it("turns on in production without an analytics id", () => {
    expect(analyticsEnabled({ production: true })).toBe(true);
  });

  it("stays off when the disable flag is set", () => {
    for (const disabled of ["1", "true", "YES", "on", " TRUE "]) {
      expect(analyticsEnabled({ production: true, disabled })).toBe(false);
    }
    expect(analyticsEnabled({ production: true, disabled: "0" })).toBe(true);
  });
});

describe("pageUrl", () => {
  it("records the marketing homepage as /site", () => {
    expect(pageUrl("https://insidialabs.com/?utm=launch#install", TRACKED_PATHS.site)).toBe(
      "https://insidialabs.com/site",
    );
  });

  it("records the documentation home on its own path", () => {
    expect(pageUrl("https://insidialabs.com/docs/?q=scan#run", TRACKED_PATHS.documentation)).toBe(
      "https://insidialabs.com/documentation",
    );
  });
});

describe("assertTrackedPath", () => {
  it("accepts the two tracked routes", () => {
    expect(assertTrackedPath(TRACKED_PATHS.site)).toBe("/site");
    expect(assertTrackedPath(TRACKED_PATHS.documentation)).toBe("/documentation");
  });

  it("rejects every other route", () => {
    expect(() => assertTrackedPath("/pricing")).toThrow(/only runs on/);
    expect(() => assertTrackedPath("/docs/start/install/")).toThrow(/only runs on/);
  });
});

describe("analytics mounts", () => {
  it("tracks the marketing homepage and the documentation home", () => {
    const home = readFileSync(new URL("../pages/index.astro", import.meta.url), "utf8");
    const layout = readFileSync(new URL("../layouts/Base.astro", import.meta.url), "utf8");
    const docs = readFileSync(new URL("../../../docs/src/content/docs/index.mdx", import.meta.url), "utf8");
    expect(home).toContain("<PageAnalytics path={TRACKED_PATHS.site} />");
    expect(layout).not.toContain("PageAnalytics");
    expect(docs).toContain("<PageAnalytics path={TRACKED_PATHS.documentation} />");
  });
});

describe("analytics copies", () => {
  it("keeps the docs helper aligned with the site helper", () => {
    const site = readFileSync(new URL("./analytics.ts", import.meta.url), "utf8");
    const docs = readFileSync(new URL("../../../docs/src/lib/analytics.ts", import.meta.url), "utf8");
    expect(docs).toBe(site);
  });

  it("keeps the docs component aligned with the site component", () => {
    for (const name of ["PageAnalytics.astro", "AnalyticsBeacon.astro"]) {
      const site = readFileSync(new URL(`../components/${name}`, import.meta.url), "utf8");
      const docs = readFileSync(new URL(`../../../docs/src/components/${name}`, import.meta.url), "utf8");
      expect(docs).toBe(site);
    }
  });
});
