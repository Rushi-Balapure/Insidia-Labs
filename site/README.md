# Marketing site deployment

The site is static Astro. `npm run build` also builds the sibling `docs/`
project and copies its output into `public/docs/`, so one Vercel project serves
both the marketing site and `/docs/`.

## Check locally

From `site/`, with Node.js 22:

```bash
npm ci
npm test
npm run build
npm run links
node scripts/secrets.mjs dist
```

The build installs the docs dependencies with `npm ci` when needed. The
static build succeeds with no environment variables. Web Analytics stays off
until `PUBLIC_VERCEL_ANALYTICS_ID` is set. See [Web Analytics](#web-analytics).

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
imports them. `site/.npmrc` sets `include=dev` so that same command still
installs the other devDependencies.

4. Enable **Include source files outside of the Root Directory in the Build
   Step**. The build needs `../docs/`. If this option is only available after
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
2. Add `insidialabs.com` and `www.insidialabs.com`. Configure `www` to redirect
   to `insidialabs.com`, matching the canonical URL in `astro.config.mjs`.
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
2. Copy the Web Analytics DSN into `PUBLIC_VERCEL_ANALYTICS_ID` for Production
   and Preview. `site/.env.example` and `docs/.env.example` list the variable.
   The docs build reads the same environment because `npm run build` builds
   `docs/` first.
3. Redeploy. Visits to the homepage show up as `/site`. Visits to the
   documentation home show up as `/documentation`, so that page’s views and
   unique visitors are their own row under Top Pages.

Turn it off by setting `PUBLIC_VERCEL_ANALYTICS_DISABLED=1`, or by clearing
`PUBLIC_VERCEL_ANALYTICS_ID`, then redeploy. Disabling Web Analytics in the
Vercel project stops collection as well.

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
