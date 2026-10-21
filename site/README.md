# Marketing site deployment

The site is static Astro. `npm run build` also builds the sibling `docs/`
project and copies its output into `public/docs/`, so one Vercel project serves
both the marketing site and `/docs/`.

Both projects import dependency-free SEO helpers from `../shared/`.
The docs project builds with only its own dependencies installed.

## Check locally

From `site/`, with Node.js 22:

```bash
npm ci
npm test
npm run build
npm run links
npm run seo
node scripts/secrets.mjs dist
```

The build installs the docs dependencies with `npm ci` when needed. The
static build succeeds with no environment variables. Web Analytics is included
in production builds and stays off in the development server. See [Web Analytics](#web-analytics).

`npm run seo` checks the built marketing pages and docs for canonical URLs,
unique metadata, social images, structured data, visible FAQ answers, sitemap
coverage, and AI documentation links. CI runs it after the build.
`npm run seo:external` independently validates structured data with Adobe's
validator and the current Schema.org vocabulary (network access required).
See [SEO and answer-engine audit](SEO.md) for measurements and reproduction steps.

## Deploy through Vercel's GitHub integration

1. Commit and push the site changes, including every file in `public/video/`.
2. Open <https://vercel.com/new>, connect GitHub, and import
   `Rushi-Balapure/Insidia-Labs`.
3. Select these project settings:

   | Setting | Value |
   | --- | --- |
   | Framework Preset | Astro |
   | Root Directory | `site` |
   | Install Command | `npm ci` |
   | Build Command | `npm run build` |
   | Output Directory | `dist` |
   | Node.js Version | `22.x` |

Vercel runs `npm ci` with `NODE_ENV=production`, which skips devDependencies.
`@tailwindcss/vite` and `tailwindcss` are dependencies because the build
imports them. `allowScripts` in `site/package.json` and `docs/package.json`
lets `esbuild` and `sharp` run their install scripts. npm 12 blocks those
scripts otherwise, and `npm ci` exits 1 when `strict-allow-scripts` is on.

4. Enable **Include source files outside of the Root Directory in the Build
   Step**. The build needs `../docs/` and `../shared/`. If this option is only available after
   import, save it under **Settings → Build and Deployment → Root Directory**
   and redeploy.
5. Deploy. Confirm **Settings → Environments → Production → Branch Tracking**
   uses `main` for production deployments.
6. On the generated Vercel URL, check `/`, `/film/`, `/docs/`, and
   `/docs/start/install/`. Play both videos and enable captions. The film page
   should have eight chapters and a transcript.

`vercel.json` already defines Astro, the build command, `dist`, and the
`/licenses` redirect. The site uses Astro's static output; it does not need a
server adapter. Subsequent pushes to the production branch trigger deployments.

## Connect insidialabs.com

1. Open the Vercel project, then **Settings → Domains**.
2. Add `insidialabs.com` and `www.insidialabs.com`. Configure `insidialabs.com`
   to redirect to `www.insidialabs.com`, matching the live deployment and the
   canonical URLs in both Astro configurations. Vercel's `trailingSlash: true`
   keeps directory URLs consistent with the generated sitemaps.
3. At your DNS provider, enter the exact records Vercel displays for each domain.
   Replace conflicting records for those names; preserve email/MX records.
4. Wait for both domains to verify and HTTPS to become available. Repeat the
   route and video checks on `https://insidialabs.com`.

The settings above follow Vercel's [build configuration](https://vercel.com/docs/builds/configure-a-build),
[monorepo access](https://vercel.com/docs/monorepos/monorepo-faq), and
[custom domain](https://vercel.com/docs/domains/working-with-domains/add-a-domain)
documentation.

## Web Analytics

Vercel Web Analytics and Speed Insights run on two pages:

| Page a visitor opens | Path recorded in Vercel |
| --- | --- |
| Marketing homepage (`/`) | `/site` |
| Documentation home (`/docs/`) | `/documentation` |

Visitors open `/docs/`. `/documentation` is the recorded path, not a separate
page. The homepage is recorded as `/site`. Visitors open `/`; `/site` is not a
separate page. Pricing,
changelog, film, and the other documentation articles do not load the script.

A page view includes the aggregate panels Vercel builds from it: visitors,
unique visitors, top pages, referrers, countries, devices, browsers, and
operating systems. Speed Insights adds Core Web Vitals for those same two
paths. Vercel’s model is cookieless. Visitors are counted from a hash of the
request, not from a cookie or an account. No custom events are sent. The CLI
and `report.html` do not include this script.

Collection happens on a Vercel deployment. The scripts are
`/_vercel/insights/script.js` and `/_vercel/speed-insights/script.js`, which
Vercel serves after you enable the features. A local build and any host other
than Vercel do not receive the events.

Enable it:

1. In the Vercel project, open **Analytics** and enable **Web Analytics**.
   Enable **Speed Insights** for the vitals panels.
2. No analytics ID, DSN, or API key is required for Vercel-hosted deployments.
   Leave `PUBLIC_VERCEL_ANALYTICS_DISABLED` unset (or set it to `0`). The docs
   build reads the same environment because `npm run build` builds `docs/` first.
3. Redeploy. Visits to the homepage show up as `/site`. Visits to the
   documentation home show up as `/documentation`, so that page’s views and
   unique visitors are their own row under Top Pages.

The [Hobby plan](https://vercel.com/docs/analytics/limits-and-pricing) includes
50,000 Web Analytics events per month across the team and a one-month reporting
window. Basic visitor and page-view metrics do not require a paid plan. Custom
events require Pro or Enterprise. Speed Insights is a separate feature and is
not required for visitor counts.

Turn both scripts off by setting `PUBLIC_VERCEL_ANALYTICS_DISABLED=1`, then
redeploy. Disabling Web Analytics in the Vercel project stops Web Analytics
collection as well. The legacy analytics ID variables remain optional.

After deployment, visit `/` or `/docs/` with browser ad blocking disabled for
the site. In DevTools → Network, confirm `/_vercel/insights/script.js` loads
successfully and a page-view request to `/_vercel/insights/view` succeeds.
Check the project's **Analytics** tab with the production environment selected
and a date range including today. If the script returns 404, enable Web
Analytics and redeploy; see [Vercel's troubleshooting guide](https://vercel.com/docs/analytics/troubleshooting).

## Homepage components

The homepage uses local Astro components for the terminal, the three scan
steps, copy controls, and the FAQ accordion. Its visual patterns draw on
[Magic UI Terminal](https://magicui.design/docs/components/terminal) and
[React Bits Logo Loop](https://reactbits.dev/animations/logo-loop), adapted to
the existing site without adding component-library dependencies.

`src/content/terminal-run.json` contains a sanitized summary and selected rows
from a CLI scan recorded on 2026-10-20 at commit `c07405f`. The target was an
intentionally vulnerable arithmetic renderer bound to localhost. The scan
found `insidia.web.ssti`, exited 1, and reported five checks as not tested.
The terminal labels it as a fixture recording; it is not a live scan or a
claim of accuracy on independent apps. No raw prompts, credentials, or finding
evidence are included. Preserve that provenance when updating the recording.

The terminal animation runs once and can be replayed. The scan steps sit side
by side: the first command types to completion, then the second, then the
third. Logo motion can be paused and stops when reduced motion is requested;
the terminal and the step commands then show their complete text immediately.

## Video assets

`public/video/` is versioned so CI and Vercel receive the MP4/WebM files,
posters, captions, chapters, and transcripts. The current videos are approved
drafts with placeholder scan data. Their draft watermark remains visible.

Local rendering in `video/out/` is ignored and is not copied into the site
automatically. After real scan data replaces the placeholder session, render
final assets from `site/video/`:

```bash
npm ci
npx playwright install chromium
node render.mjs howto film --publish
```

Rendering requires system `ffmpeg`. `--publish` refuses placeholder data.
Review the resulting assets in `public/video/`, rerun the site checks, and
commit them together. The film page reads its transcript from that directory.
