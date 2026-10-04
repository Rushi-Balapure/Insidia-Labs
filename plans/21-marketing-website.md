# Phase W — Marketing website (lead capture, ships before the product)

Depends on: nothing in the build tracks. It reuses the apple-design tokens that Phase 2 will formalize, but it does not depend on any scanner.
Parent: [00-master-plan.md](00-master-plan.md). Related: [04-phase2-dashboard.md](04-phase2-dashboard.md) (the real dashboard the mockups imitate), [15-customer-docs.md](15-customer-docs.md) (the docs site this links to).

## Why this exists now
The product is months of phases away. A public site that explains the problem and captures interested teams lets us build a waitlist, book design-partner calls, and test the message while the brain is still being built. It is a brochure with a lead form, not the application. No scanning runs here, no customer account exists here, and no engine is ever named.

## Reference
Model the structure and motion on [arguslabs.in](https://www.arguslabs.in/): a dark, technical landing page with an animated data-flow hero, a strip of "works with" logos, inline product-UI mockups, a three-step "what it does" story, a security section, a changelog, an FAQ accordion, and a final call to action. We copy the **shape and the feel**, not the copy, and our product story is AI-plus-classic security, not agent observability.

## Hard constraints (same masking rules as every customer surface)
- **No engine names, ever.** garak, promptfoo, PyRIT, ZAP, Nuclei, Strix, vLLM, llama.cpp, and the rest never appear in markup, copy, alt text, image files, structured data, or the JS bundle. Any architecture graphic shows a single **Insidia Labs Engine** box between the customer's target and the findings. The Phase 6 denylist CI (see [00-master-plan.md](00-master-plan.md#confidentiality-of-the-stack)) runs against this site's built output too.
- **Honest claims only.** Pre-product, we do not invent customer testimonials, logos, or metrics. Argus's "by the numbers" counters and tweet wall are illustrative; ours either stay empty until real, or are framed as the industry problem with cited sources, not as our results. A "design partner" quote appears only once we have a real one and they consent.
- **apple-design.** The site follows `.agents/skills/apple-design/SKILL.md` like the dashboard: Motion (MIT) for animation, critically damped springs, `transform`/`opacity` only, `prefers-reduced-motion` and `prefers-reduced-transparency` honored, system font stack, light and dark themes.
- **Lead data is customer-derived.** An email typed into the waitlist is PII. Do not store it in plaintext in our product database. Use a dedicated mechanism (see "Lead capture") that keeps marketing leads out of the tenant database entirely.

## Branding kit (pending)
The color kit and logo kit are coming from the user. Until they arrive:
- Build every color, radius, shadow, and the logo as a **token**, not a literal, in `site/src/design/tokens.css` (and a matching `tokens.ts`). Use neutral placeholders (a dark technical palette close to the reference) so the layout is real but swapping the kit is a one-file change.
- The logo is a single `<Logo/>` component reading from one SVG slot per theme. No raster logos baked into sections.
- Do not ship the placeholder palette to production. "Apply the branding kit" is an explicit exit item below.

## Stack and location
A new top-level `site/` (separate from `dashboard/` the app and `docs/` the Starlight docs):
- **Astro (MIT)** for a static, SEO-friendly, fast marketing site, the same ecosystem as the Starlight docs. React islands only where interaction is needed (the hero animation, the FAQ accordion, the lead form). This keeps the page static-first and cheap to host.
- **Tailwind** and the shared design tokens; **Motion (MIT)** for the hero data-flow animation and scroll reveals.
- **Hosting: Vercel.** A static export deployed to Vercel on the apex domain, independent of the product cluster (see "Hosting and the deployment split"). The app lives on `app.` and the docs on `docs.`.

```
site/
  astro.config.mjs
  src/
    design/            tokens.css, tokens.ts (placeholders until the kit lands)
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
3. **"Works with" strip.** The target types we test, shown as neutral category chips (chat apps, RAG, agents and MCP, multi-agent, web, REST/GraphQL/gRPC APIs, codebases), not vendor logos, and never engine names.
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
- Nodes: **Target** (a chat/agent/app) → **Insidia Labs Engine** (one box) → **Findings**, with a second path showing the chain: a prompt-injection token entering the agent, flowing into a tool call, and lighting up a backend exploit node.
- A packet/token travels the edges on a critically damped timeline; nodes pulse when the token arrives; the exploit node flips to a severity badge at the end, then the loop resets.
- Only `transform` and `opacity` animate. Under `prefers-reduced-motion` it becomes a static labeled diagram with a single fade. Under `prefers-reduced-transparency` the node materials are solid.
- Built with Motion in a single React island (`DataFlowHero.tsx`); no engine names on any node, edge, or label.

## Product demo mockups (HTML, based on the Phase 2 dashboard)
The user wants Argus-style product screenshots generated in HTML from how the dashboard will look. These are **presentational mockups**, not the real app:
- Live HTML/CSS components under `site/src/components/MockDashboard/`, styled with the shared apple-design tokens so they match the eventual product and restyle automatically when the branding kit lands.
- Screens to mock, drawn from [04-phase2-dashboard.md](04-phase2-dashboard.md): the **scan launcher** (coverage Standard/Thorough/Custom with estimated attempts, cost, duration), the **live view** (per-family progress, "Insidia Labs Engine module N"), the **findings triage** (severity, AI vs web track, cross-validated badge, redacted evidence), the **attack-path graph** (target → engine → tool → backend), and a **report / coverage matrix** preview.
- Every label is masked: "Insidia Labs Engine module N", never a real engine. Evidence shown is synthetic, with secrets rendered only as masked tokens (`[AWS_ACCESS_KEY len=20 fp=3f9a1c07]`), exactly as the real UI will.
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
- Server-rendered static HTML, semantic headings, per-page title and meta description, Open Graph and Twitter cards (OG image from the kit), `sitemap.xml`, `robots.txt`, and JSON-LD `Organization`/`Product` with no engine names.
- Lighthouse: performance, accessibility, best-practices, and SEO all green on the hero page. Images are compressed and lazy-loaded; the animation island is deferred and does not block first paint.
- WCAG 2.2 AA: keyboard-operable nav and FAQ, visible focus, contrast from the kit verified, the animation pausable/escapable.

## Out of scope
Sign-up, login, real scans, billing/checkout (pricing shows "request access" tiers only), the admin console, and any live product data. Those are Phases 2 and 10. This site hands a warm lead to a human.

## Tests
- **Denylist:** the Phase 6 name denylist runs over the built `site/` output (HTML, JS, CSS, alt text, OG metadata) and fails on any engine or infrastructure tool name.
- **Accessibility:** axe scan with zero serious issues; reduced-motion and reduced-transparency snapshots of the hero; keyboard-only pass through nav, FAQ, and the lead form.
- **Lead form:** valid submit succeeds, invalid email is rejected inline, the honeypot and rate limit block a bot, and no lead value is written to the tenant database (asserted).
- **Performance:** Lighthouse budget check in CI on the built site.
- **No-secret / no-real-data:** the mockups render only synthetic content; a test asserts no real token or customer string appears in the bundle.

## Exit
- The site builds statically and **deploys to Vercel**; `app.` (dashboard on our cluster) and `docs.` links resolve. The site shares no infrastructure with the brain or the tenant database.
- The animated data-flow hero runs, degrades correctly under reduced motion and transparency, and names no engine.
- The HTML dashboard mockups render for the launcher, live view, findings, attack-path graph, and report preview, all masked and token-driven.
- Waitlist and book-a-call both work and keep leads out of the tenant database.
- The denylist, accessibility, and Lighthouse checks pass in CI.
- The branding kit (colors + logo) is applied by swapping tokens and the logo slot, with no layout change required, once the user provides it.

## Risks
- **Over-promising.** Marketing copy can outrun what the product does. Keep claims to what the phases above will actually ship; the coverage story is generated from reality, not hand-waved.
- **Leaking the stack.** A stray screenshot or alt text naming an engine breaks the masking stance. The denylist over the built output is the guard, not reviewer memory.
- **Lead PII.** A marketing form is the easiest place to accidentally collect PII into the wrong store. Keep leads out of the product database by design.
- **Placeholder branding shipping.** Guard the exit so the real kit is applied before launch.
