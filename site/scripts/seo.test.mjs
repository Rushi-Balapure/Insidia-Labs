import { describe, expect, it } from "vitest";
import { inspectPage } from "./seo.mjs";

describe("built SEO regression checks", () => {
  it("rejects redirecting canonical hosts and incomplete social metadata", () => {
    const result = inspectPage('<html lang="en"><head><title>Install</title><meta name="description" content="Install Insidia"><link rel="canonical" href="https://old.example/install/"></head><body><h1>Install</h1></body></html>', "/install/");
    expect(result.issues).toContain("canonical must match the public URL");
    expect(result.issues).toContain("missing twitter:image");
    expect(result.issues).toContain("missing BreadcrumbList schema");
  });

  it("reports malformed JSON-LD instead of skipping it", () => {
    const result = inspectPage('<script type="application/ld+json">{invalid}</script>', "/");
    expect(result.issues.some((issue) => issue.startsWith("invalid JSON-LD:"))).toBe(true);
  });

  it("requires noindex on error pages and excludes their schema requirements", () => {
    const html = '<html lang="en"><head><title>Not found</title><meta name="description" content="Missing page"><meta name="robots" content="noindex, follow"></head><body><h1>Not found</h1></body></html>';
    expect(inspectPage(html, "/404.html").issues).toEqual([]);
    expect(inspectPage(html.replace('content="noindex, follow"', 'content="index"'), "/404.html").issues).toContain("404 must be noindex");
  });

  it("rejects FAQ answers that do not appear in the page body", () => {
    const data = { "@type": "FAQPage", mainEntity: [{ name: "Is it free?", acceptedAnswer: { text: "Yes, forever." } }] };
    const result = inspectPage(`<script type="application/ld+json">${JSON.stringify(data)}</script><h1>Product</h1>`, "/");
    expect(result.issues).toContain("FAQ schema must match rendered questions and answers");
  });
});
