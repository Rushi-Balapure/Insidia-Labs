# SEO and answer-engine audit

Measured on 2026-10-21 against the production builds before and after this
branch. The baseline source is commit `26c3f92` (see the machine-readable
audit for the full, verified revision). These are local build measurements;
this branch has not been deployed.

## Results

| Check | Before | After |
| --- | --- | --- |
| Google Lighthouse 13.0.3, mobile SEO, homepage | 100/100 | 100/100 |
| Google Lighthouse 13.0.3, mobile SEO, quickstart docs | 100/100 | 100/100 |
| Adobe validator: pages with structured data | 1/23 | 23/23 |
| Adobe validator: errors / warnings | 0 / 0 | 0 / 0 |
| Canonical URLs matching the live preferred host | 0/23 | 23/23 |
| Local metadata / discovery regression checks | 210 issues | 0 issues |
| Screenshot, text, and layout comparison | Baseline | 8/8 identical |

Adobe's `@adobe/structured-data-validator@1.7.0` used
`@marbec/web-auto-extractor@2.1.0` and the Schema.org vocabulary downloaded
on the audit date. It validated the actual built HTML, including JSON-LD
references. Zero baseline errors only describes the single page that already
had schema; it does not mean the other 22 pages were described.

Lighthouse already passed the basic SEO audits. Its score does not measure
search rankings, topic relevance, schema completeness, or AI citations.
The 210-to-zero figure is the repository's own regression checklist, **not**
an external SEO or AEO score. The independent tools are Lighthouse and Adobe's
validator. Google's hosted PageSpeed Insights API was also attempted but
returned HTTP 429 (`RESOURCE_EXHAUSTED`); no hosted score was obtained.

Visual comparisons cover `/`, `/pricing/`, `/film/`, and
`/docs/start/quickstart/` at 1440×1000 and 390×844. They use Chromium,
dark mode, reduced motion, fixed GitHub star responses, and disabled analytics
requests. All eight pairs have identical full-page PNG bytes, visible text,
and page dimensions. CSS, typography, page structure, and visible copy are
unchanged.

The compact evidence is in [audits/2026-10-21.json](audits/2026-10-21.json).

## What changed

- Both site configurations, social URLs, structured data, robots declarations,
  and sitemaps use `https://www.insidialabs.com`. The live apex domain returned
  a permanent 308 redirect to `www` during the audit. Directory routes keep
  trailing slashes in Astro and Vercel.
- Marketing pages have descriptive, distinct search titles and descriptions.
  Documentation descriptions explain each guide's purpose without changing
  its visible title or content. Docs now have social-preview images.
- Every indexable page describes its publisher, website, and canonical page.
  Interior pages have breadcrumbs using real public URLs. Docs add linked
  `TechArticle` metadata. The homepage retains its software offer and FAQ
  data, now linked to stable entity IDs. FAQ answers come from the same array
  as the visible accordion. No ratings, testimonials, or availability dates
  were invented. Error pages stay `noindex` and get no page schema.
- `/llms.txt` and `/docs/llms.txt` share the corrected guide. It distinguishes
  available L1 checks from planned L2/L3 and Cloud, and explains scope,
  model costs, and current limitations. `/llms-full.txt` is generated from
  published Markdown docs with source URLs; it excludes the error page.
  New docs and content edits are picked up on the next build.
- Public pages allow large image previews and full text/video snippets.
  Existing robots rules allow search and answer-engine crawlers.

## Search intent by route

These are content themes, not measured keyword volumes or ranking promises.

| Route | Primary intent |
| --- | --- |
| `/` | AI security testing for apps and agents |
| `/launch/` | Install the Insidia CLI and agent skill |
| `/pricing/` | Free CLI features and Cloud availability |
| `/benchmark/` | Scan coverage, baseline policy, benchmark limitations |
| `/security/` | Scan authorization, local data handling, disclosure |
| `/film/` | Security scan walkthrough and transcript |
| `/credits/` | Integrated security engines and licenses |
| `/changelog/` | CLI development and release notes |
| `/docs/start/quickstart/` | Run a first local L1 scan |
| `/docs/reference/cli/` | CLI commands, flags, and exit codes |

## Reproduce

From `site/`, with Node.js 22 and the locked dependencies:

```bash
npm ci
npm test
npm run build
npm run seo
npm run links
npm run seo:external
```

The external validator fetches the current vocabulary by default. For a
repeatable offline run, download a snapshot and pass its filename:

```bash
curl -fsSL https://schema.org/version/latest/schemaorg-all-https.jsonld -o /tmp/schemaorg.json
node scripts/seo-external.mjs dist /tmp/schemaorg.json
```

For Lighthouse, start `npm run preview -- --port 4322` in one terminal.
In another terminal, run these audits with Chrome installed:

```bash
npx --yes lighthouse@13.0.3 http://127.0.0.1:4322/ --only-categories=seo --chrome-flags="--headless" --output=json --output-path=/tmp/insidia-home-seo.json
npx --yes lighthouse@13.0.3 http://127.0.0.1:4322/docs/start/quickstart/ --only-categories=seo --chrome-flags="--headless" --output=json --output-path=/tmp/insidia-docs-seo.json
```

The recorded audits used localhost static servers with both marketing and
docs assets, Chromium 151, and Lighthouse's default mobile SEO settings.
The temporary test environment additionally needed Chrome's `--no-sandbox`
and `--disable-dev-shm-usage` flags. Those flags are not site configuration.

## After deployment

1. Check the apex-to-`www` redirect and representative canonical pages,
   `/robots.txt`, both sitemap indexes, `/llms.txt`, and `/llms-full.txt`
   on the live host. Confirm the CDN permits the intended crawlers.
2. Submit `/sitemap-index.xml` and `/docs/sitemap-index.xml` in verified Google
   Search Console and Bing Webmaster Tools properties. Inspect the homepage
   and quickstart URL for indexability and canonical selection.
3. Validate the live homepage with Google's Rich Results Test and the Schema.org
   validator. Schema validity does not guarantee rich-result eligibility;
   the site does not qualify for Google's government/health FAQ display.
4. Track impressions, clicks, indexed pages, and query/page performance over
   the following 28 days. Record AI-search referrals and citations separately;
   these were not measurable from an undeployed branch.

There is no universal AEO score being claimed here. Google's
[AI features guidance](https://developers.google.com/search/docs/appearance/ai-features)
uses normal SEO requirements, accessible textual content, and structured data
that agrees with the page. It explicitly says special AI files or schema are
not required. `llms.txt` is an additional discovery convenience, not evidence
of ranking or citation gains. See also
[Lighthouse's scoring limits](https://developer.chrome.com/docs/lighthouse/seo/meta-description)
and [Google's FAQ eligibility](https://developers.google.com/search/docs/appearance/structured-data/faqpage).
