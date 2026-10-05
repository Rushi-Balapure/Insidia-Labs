# Phase W — Marketing website

> **v6. Built, rework pending.** The Astro site on `phase-w-marketing-site` is live as a brochure: brand kit applied, HTML demos, waitlist. Rework it for the open-core plan before the repo is the public face of the project. Lead with the CLI (`uv tool install` from GitHub), the agent prompt, and the benchmark. Credit the engines. Make Insidia Cloud the second call to action. Remove the engine-name denylist from `site/scripts/denylist.mjs` and from CI; keep the secret and real-data checks. Videos follow [22-website-video-scripts.md](22-website-video-scripts.md).

Depends on: nothing in the build tracks.
Parent: [00-master-plan.md](00-master-plan.md). Related: [04-phase2-dashboard.md](04-phase2-dashboard.md) (the hosted dashboard), [15-customer-docs.md](15-customer-docs.md).

## Why this exists
The CLI is not shipped yet. The site explains the problem, shows the open-source install that is coming, and collects design partners. It is a brochure with a lead form, not the application. No scanning runs here and no customer account exists here.

## Reference
Model the structure and motion on [arguslabs.in](https://www.arguslabs.in/): a dark, technical landing page with an animated data-flow hero, a strip of "works with" logos, inline product-UI mockups, a three-step "what it does" story, a security section, a changelog, an FAQ accordion, and a final call to action. We copy the **shape and the feel**, not the copy, and our product story is AI-plus-classic security, not agent observability.

## Hard constraints
- **Credit the engines.** garak, promptfoo, PyRIT, ZAP, Nuclei, and the rest are named where the product story needs them, with links. The architecture graphic shows the engines, the Insidia gap modules, and Insidia Cloud as an optional box. The old engine-name denylist is removed. A check still fails the build if a planted secret or a real customer string appears.
- **Honest claims only.** Pre-product, we do not invent customer testimonials, logos, or metrics. Argus's "by the numbers" counters and tweet wall are illustrative; ours either stay empty until real, or are framed as the industry problem with cited sources, not as our results. A "design partner" quote appears only once we have a real one and they consent.
- **apple-design and the brand kit.** The site follows `.agents/skills/apple-design/SKILL.md`: Motion (MIT), critically damped springs, `transform`/`opacity` only, `prefers-reduced-motion` and `prefers-reduced-transparency` honored, light and dark themes. Type is Sora from the kit.
- **Lead data is customer-derived.** An email typed into the waitlist is PII. Do not store it in plaintext in our product database. Use a dedicated mechanism (see "Lead capture") that keeps marketing leads out of the tenant database entirely.

## Branding kit (applied)
The approved kit (mark v2, 4 Oct 2026) is in the repo at `brand/`. The site copies it into tokens and logo slots:
- Colors, radii, and the gradient are tokens in `site/src/design/tokens.css` and `site/src/design/tokens.ts`, taken from `brand/kit/colors`. Navy `#101028` is the dark background. Buttons use navy text on Orange `#ED7B39` (white on orange fails WCAG).
- `<Logo/>` swaps the outlined horizontal lockup: white wordmark on dark, navy wordmark on light. Below 48 px the simplified mark is the favicon. Do not recolor or redraw the mark.
- Wordmark and UI type use Sora 400 and 600, self-hosted from the kit (OFL), with the system font stack as fallback.

## Stack and location
A new top-level `site/` (separate from `dashboard/` the app and `docs/` the Starlight docs):
- **Astro (MIT)** for a static, SEO-friendly, fast marketing site, the same ecosystem as the Starlight docs. React islands only where interaction is needed (the hero animation, the FAQ accordion, the lead form). This keeps the page static-first and cheap to host.
- **Tailwind** and the shared design tokens; **Motion (MIT)** for the hero data-flow animation and scroll reveals.
- **Hosting: Vercel.** A static export deployed to Vercel on the apex domain, independent of the product cluster (see "Hosting and the deployment split"). The app lives on `app.` and the docs on `docs.`.

```
site/
  astro.config.mjs
  src/
    design/            tokens.css, tokens.ts (brand kit)
    components/
      Logo.astro
      DataFlowHero.tsx       the animated hero (Motion)
      MockDashboard/         HTML/CSS product mockups (see below)
      Section*.astro         feature, security, changelog, FAQ, CTA
      LeadForm.tsx           waitlist + book-a-call
    pages/
      index.astro
      pricing.astro          "Request access" / early-access tiers, no live checkout
      security.astro
      changelog.astro
    content/                 changelog entries, FAQ entries (markdown)
  public/                    og image, favicon (from the kit when it lands)
```

## Page structure (adapted from the reference)
1. **Top bar.** Logo, anchors (How it works, What it finds, Security, Docs, Pricing), and two CTAs: **Join the waitlist** and **Book a call**. Translucent, content scrolls under it.
2. **Hero with the data-flow animation.** Headline on the seam that is our differentiator: an AI attack that becomes a classic exploit. Subhead, then CTAs (Book a call, Watch the demo, Read the docs). The animation is the centerpiece, specified below.
3. **"Works with" strip.** The target types we test, shown as neutral category chips (chat apps, RAG, agents and MCP, multi-agent, web, REST/GraphQL/gRPC APIs, codebases). A separate strip credits the engines by name.
4. **Three-step story** (the reference's detect / explain / fix), each with an inline product mockup:
   - **Attacks both layers.** AI red-teaming and classic AppSec in one run: prompt injection, jailbreaks, RAG and memory, agent tool misuse, plus SQLi, XSS, SSRF, BOLA/IDOR, auth. Mockup: the scan launcher with Standard/Thorough coverage.
   - **Proves the chain.** The pentest agent chains a prompt injection into a backend exploit and confirms it with an oracle, not a guess. Mockup: the attack-path graph and a finding with a cross-validated badge.
   - **Maps to what you report.** Findings carry OWASP LLM and Agentic, ATLAS, and classic web/API ids, exportable as a report. Mockup: the control-coverage matrix / report preview.
5. **The problem, honestly.** Where the reference uses a wall of tweets, we use a short, sourced framing of why one-sided tools miss the AI-to-classic seam. Cited claims only; no fabricated quotes.
6. **Security section.** Three cards matching our real posture: runs in our cloud with per-org envelope encryption, secrets redacted before storage, your findings are never training data. Links to a short security page.
7. **Changelog.** Markdown-driven, starts with "Private beta open" style entries that are true.
8. **FAQ accordion.** What it tests, direct vs runner connection, data handling, pricing model, timeline to access.
9. **Final CTA + footer.** Waitlist, book a call, docs, and the legal "Open-source licenses" link counsel may require (licenses only, no component descriptions; see [00-master-plan.md](00-master-plan.md#attribution-register)).

## The data-flow animation
A looping, reduced-motion-aware diagram that tells the differentiator in one glance:
- Nodes: **Target** (a chat/agent/app) → the engines and Insidia modules → **Findings**, with a second path showing the chain: a prompt-injection token entering the agent, flowing into a tool call, and lighting up a backend exploit node.
- A packet/token travels the edges on a critically damped timeline; nodes pulse when the token arrives; the exploit node flips to a severity badge at the end, then the loop resets.
- Only `transform` and `opacity` animate. Under `prefers-reduced-motion` it becomes a static labeled diagram with a single fade. Under `prefers-reduced-transparency` the node materials are solid.
- Built with Motion in a single React island (`DataFlowHero.tsx`). Engine names are allowed on labels.

## Product demo mockups (HTML, based on the Phase 2 dashboard)
The user wants Argus-style product screenshots generated in HTML from how the dashboard will look. These are **presentational mockups**, not the real app:
- Live HTML/CSS components under `site/src/components/MockDashboard/`, styled with the shared apple-design tokens so they match the eventual product and restyle automatically when the branding kit lands.
- Screens to mock: the **CLI report** (Phase 1), then the hosted dashboard from [04-phase2-dashboard.md](04-phase2-dashboard.md): the **scan launcher**, the **live view** (per-family progress, engine names), the **findings triage**, the **attack-path graph**, and a **benchmark score**.
- Evidence shown is synthetic, with secrets rendered only as masked tokens (`[AWS_ACCESS_KEY len=20 fp=3f9a1c07]`). Engines are named.
- Because they share tokens with `dashboard/src/design/`, these mockups double as an early visual prototype for Phase 2. They are static (no API, no data fetching) and carry a clear "representative UI" note so we are not implying a shipped product.

## Lead capture
- **Waitlist:** email plus optional company and role. **Book a call:** a scheduling link (Cal.com, AGPL-free hosted, or a simple mailto fallback) — no scheduler code in our stack.
- Leads must not land in the product's tenant database. Options, in order of preference: a hosted form/CRM endpoint (e.g. a form provider or a dedicated marketing table in a separate store), with the submission encrypted in transit and access limited to the growth owner. If we ever persist a lead in our own infrastructure, it goes in a separate marketing store, never in the tenant tables, and the email is stored encrypted, following the same no-plaintext-PII rule as [14-database-schema.md](14-database-schema.md).
- Basic anti-spam (honeypot field, rate limit, hCaptcha/Turnstile if needed). A double-opt-in confirmation email is preferred so we hold only confirmed addresses.
- No third-party marketing trackers that leak visitor data; if analytics are needed, use a privacy-respecting, cookieless option and disclose it.

## Hosting and the deployment split
Your understanding is right, and it is a deliberate separation:
- **Marketing site (`site/`, this phase): Vercel.** It is a static Astro bundle with no brain, no scanners, no tenant database, and no customer accounts. The only server interaction is the lead form, which posts to a hosted form/CRM endpoint (see "Lead capture"), not to our product backend. It can go live immediately and scale on Vercel's CDN while the product is still being built.
- **Product dashboard + brain (`dashboard/` + `engine/`, Phases 1–2 onward): our own server cluster.** The brain (FastAPI control plane, Celery workers, RabbitMQ, Valkey, Postgres, hub, egress proxy, model service) runs on Kubernetes in our cloud, as in [00-master-plan.md](00-master-plan.md#stack-and-deployment). The dashboard SPA is served alongside the brain on `app.` and talks to that API. It is **not** on Vercel, because it needs to sit next to the brain, the encrypted tenant database, and the fixed egress IPs, and because customer vulnerability data never transits a third-party platform.
- **Three hosts, three jobs:** the apex domain is the Vercel marketing site, `app.` is the dashboard on our cluster, and `docs.` is the Starlight docs (static, can also be on Vercel or our CDN). The site links out to `app.` and `docs.`; it never embeds the app or calls the brain.
- **Why the split matters:** keeping the lead-gen site off our product infrastructure means a public, high-traffic, frequently-changed marketing surface shares nothing with the system that holds customers' unfixed vulnerabilities. A compromise or misconfiguration of the Vercel site cannot reach the brain, the tenant database, or any customer data.

## SEO and performance
- Server-rendered static HTML, semantic headings, per-page title and meta description, Open Graph and Twitter cards (OG image from the kit), `sitemap.xml`, `robots.txt`, and JSON-LD `Organization`/`SoftwareApplication`.
- Lighthouse: performance, accessibility, best-practices, and SEO all green on the hero page. Images are compressed and lazy-loaded; the animation island is deferred and does not block first paint.
- WCAG 2.2 AA: keyboard-operable nav and FAQ, visible focus, contrast from the kit verified, the animation pausable/escapable.

## Out of scope
Sign-up, login, real scans, billing/checkout (pricing shows "request access" tiers only), the admin console, and any live product data. Those are Phases 2 and 10. This site hands a warm lead to a human.

## Tests
- **Secrets:** a check over the built `site/` output fails on a planted secret or a real customer string. Engine names pass.
- **Accessibility:** axe scan with zero serious issues; reduced-motion and reduced-transparency snapshots of the hero; keyboard-only pass through nav, FAQ, and the lead form.
- **Lead form:** valid submit succeeds, invalid email is rejected inline, the honeypot and rate limit block a bot, and no lead value is written to the tenant database (asserted).
- **Performance:** Lighthouse budget check in CI on the built site.
- **No-secret / no-real-data:** the mockups render only synthetic content; a test asserts no real token or customer string appears in the bundle.

## Exit
- The site builds statically and **deploys to Vercel**; `app.` (dashboard on our cluster) and `docs.` links resolve. The site shares no infrastructure with the brain or the tenant database.
- The animated data-flow hero runs and degrades correctly under reduced motion and transparency.
- The HTML demos render the CLI report and, where they show the hosted dashboard, name the engines. Secrets stay masked.
- Waitlist and book-a-call both work and keep leads out of the tenant database.
- The secret check, accessibility, and Lighthouse checks pass in CI. The engine-name denylist is gone.
- The branding kit (colors + logo) is applied through tokens and the logo slot.

## Risks
- **Over-promising.** Marketing copy can outrun what the product does. Keep claims to what the phases above will actually ship; the coverage story is generated from reality, not hand-waved.
- **Leaking secrets.** A screenshot can include a real key. The secret check over the built output is the guard. Naming an engine is intended.
- **Lead PII.** A marketing form is the easiest place to accidentally collect PII into the wrong store. Keep leads out of the product database by design.
- **Placeholder branding shipping.** Guard the exit so the real kit is applied before launch.
