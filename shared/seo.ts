type SchemaNode = Record<string, unknown>;

interface PageMetadata {
  path: string;
  title: string;
  description: string;
  documentation?: boolean;
}

/** Escape HTML delimiters before placing JSON inside a script element. */
export function serializeJsonLd(value: unknown): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

function siteNodes(site: URL): SchemaNode[] {
  return [
    {
      "@type": "Organization", "@id": new URL("/#organization", site).href,
      name: "Insidia Labs", url: site.href,
      logo: new URL("/android-chrome-512.png", site).href,
      email: "insidialabs@gmail.com",
      sameAs: ["https://github.com/Rushi-Balapure/Insidia-Labs"],
    },
    {
      "@type": "WebSite", "@id": new URL("/#website", site).href,
      name: "Insidia Labs", url: site.href, inLanguage: "en",
      publisher: { "@id": new URL("/#organization", site).href },
    },
  ];
}

function breadcrumb(site: URL, page: PageMetadata, canonical: string): SchemaNode {
  const items = [{ name: "Insidia Labs", item: site.href }];
  if (page.documentation && page.path !== "/docs/") {
    items.push({ name: "Documentation", item: new URL("/docs/", site).href });
  }
  items.push({ name: page.title, item: canonical });
  return {
    "@type": "BreadcrumbList", "@id": `${canonical}#breadcrumb`,
    itemListElement: items.map((item, index) => ({
      "@type": "ListItem", position: index + 1, ...item,
    })),
  };
}

export function pageGraph(site: URL, page: PageMetadata): SchemaNode {
  const canonical = new URL(page.path, site).href;
  const organization = { "@id": new URL("/#organization", site).href };
  const nodes: SchemaNode[] = [...siteNodes(site), {
    "@type": "WebPage", "@id": `${canonical}#webpage`, url: canonical,
    name: page.title, description: page.description, inLanguage: "en",
    isPartOf: { "@id": new URL("/#website", site).href },
    publisher: organization,
    ...(page.path !== "/" ? { breadcrumb: { "@id": `${canonical}#breadcrumb` } } : {}),
    ...(page.documentation ? { mainEntity: { "@id": `${canonical}#article` } } : {}),
  }];
  if (page.path !== "/") nodes.push(breadcrumb(site, page, canonical));
  if (page.documentation) nodes.push({
    "@type": "TechArticle", "@id": `${canonical}#article`,
    headline: page.title, description: page.description, inLanguage: "en",
    url: canonical, mainEntityOfPage: { "@id": `${canonical}#webpage` },
    author: organization, publisher: organization, isAccessibleForFree: true,
    image: new URL("/og-image.png", site).href,
    about: { "@type": "SoftwareApplication", name: "Insidia", url: site.href },
  });
  return { "@context": "https://schema.org", "@graph": nodes };
}
