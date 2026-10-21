import { describe, expect, it } from "vitest";
import { pageGraph, serializeJsonLd } from "./seo";

const site = new URL("https://site.example/");

describe("structured page metadata", () => {
  it("keeps script-closing text inert while preserving the JSON value", () => {
    const value = { description: '</script><script>alert("test")</script>' };
    const output = serializeJsonLd(value);
    expect(output).not.toContain("<");
    expect(JSON.parse(output)).toEqual(value);
  });

  it("links a documentation article to its page, publisher, and real breadcrumbs", () => {
    const graph = pageGraph(site, {
      path: "/docs/start/install/", title: "Install", description: "Install Insidia", documentation: true,
    })["@graph"] as Record<string, unknown>[];
    const article = graph.find((node) => node["@type"] === "TechArticle");
    expect(article?.mainEntityOfPage).toEqual({ "@id": "https://site.example/docs/start/install/#webpage" });
    expect(article?.publisher).toEqual({ "@id": "https://site.example/#organization" });
    const breadcrumb = graph.find((node) => node["@type"] === "BreadcrumbList");
    expect(breadcrumb?.itemListElement).toEqual([
      { "@type": "ListItem", position: 1, name: "Insidia Labs", item: site.href },
      { "@type": "ListItem", position: 2, name: "Documentation", item: "https://site.example/docs/" },
      { "@type": "ListItem", position: 3, name: "Install", item: "https://site.example/docs/start/install/" },
    ]);
  });
});
