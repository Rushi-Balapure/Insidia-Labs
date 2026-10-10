# 24 — Site redesign on the ARGUS pattern

Status: approved direction, 10 Oct 2026. Nothing in `site/` has changed yet.
Parent: [21-marketing-website.md](21-marketing-website.md). Gated by [23-productization-plan.md](23-productization-plan.md) F17 (website) and F18 (demo). Videos: [25-video-scripts.md](25-video-scripts.md).

## Goal

Rebuild the homepage so it reads like [arguslabs.in](https://www.arguslabs.in/): one product, one problem, one command, a run you can see, and two videos. The page sells the product, not the license. The words "open source", "open-source", "open core", and "Apache-2.0" do not appear in page copy, meta tags, JSON-LD, the README, or the docs.

## Decisions (Rushi, 10 Oct 2026)

1. **Headline:** "Your AI agent is your newest attack surface."
2. **Install line:** the full GitHub command stays, shown truncated in the hero behind a copy button.
3. **Scope:** the README and docs drop the open-source framing too, not only the site.
4. **Videos:** both are generated animations that we render ourselves, not screen recordings. The long-form video is cut to about 3 minutes. Production is in plan 25.

## What ARGUS does, and what we take

| ARGUS section | What makes it work | Insidia version |
| --- | --- | --- |
| Nav: How it works, Docs, Pricing, Changelog, GitHub star count, Book a call, Get started | Four links, one primary action | How it works, Docs, Pricing, Changelog. GitHub icon with the live star count. Book a call (ghost). Get started (primary). |
| Hero: "Case file 58c376 · Fig. 1 — a silent failure, traced" | A forensic frame. The page reads like evidence, not marketing. | "Finding a1b2c3 · Fig. 1 — an injection, traced". The same exhibit language runs down the page. |
| "New · argus check fails CI on silent failures" pill | Shows the product is moving | "New · `insidia rerun` re-checks a finding with the same config". Taken from the latest changelog entry. |
| Six-word H1, one-sentence sub | Says the outcome, not the category | See "Hero copy" below |
| CTAs: Get started, Watch the film (1 min) | Two actions only | Get started (goes to `#install`) and Watch the film (opens the 60 s how-to video in a modal) |
| `$ pip install argus-agents` under the CTAs | Short enough to read in one glance | `$ uv tool install "git+https://github.com/…/Insidia-Labs#subdirectory=core"` truncated with an ellipsis, plus a copy button that copies the full command. A "pipx" tab beside it. |
| Hero visual: pipeline trace ending in "DEPLOY BLOCKED exit 1" and a root-cause card | Shows a real run, the failing node, and the cause | A scan trace in the real `insidia scan` row format, ending in "RELEASE BLOCKED · exit 1" and a root-cause card. Built from a sanitized real run. |
| Marquee: "Fits the stack you already ship" | Integration names as plain text | Row 1, "Fits the stack you already ship": Claude Code, Cursor, Codex, GitHub Actions, OpenAI, Anthropic, Gemini, Ollama, vLLM. Row 2, "Runs the engines you already trust": garak, promptfoo, PyRIT, DeepTeam, ZAP, Nuclei, Trivy, gitleaks. Only verified engines (F07). |
| The problem: "Your agent didn't crash. It just returned nothing." + Exhibit A code + three numbered beats | Makes the bug concrete with real code | "Your chatbot passed review. It also obeys the PDF." Exhibit A is a retrieval function that pastes uploaded text into the prompt. Three beats below. |
| How it works: "Attach once. Get the root cause on every run." + Exhibit B, three steps | Three commands map to three outcomes | "Point it at your app. Get the finding, the evidence, and the fix." Steps: scope, scan, block and prove the fix. |
| Feature grid: "Built for how agents break", four cards, each with code | Every claim has a snippet | "Built for how AI apps break": four cards, below |
| Design-partner quote | Social proof | Hidden until a real partner agrees to be quoted. No placeholder quote ships. |
| FAQ | Answers objections | Six questions, below |
| Final CTA "Ship agents you can trust." with an `exit 0` visual | Ends on the good state | "Ship AI you'd attack yourself." with the same trace turning green: "RELEASE OK · exit 0" |
| Footer: Product, Developers, Company | Plain | Product (How it works, Pricing, Changelog, FAQ). Developers (Docs, Quickstart, CLI reference, Credits). Company (GitHub, Contact, Security). |

We take the shape, the exhibit motif, and the pacing. We do not copy ARGUS copy, their "16VC" credibility line (we have no equivalent), or their testimonial until we have a real one.

## The "no open source" rule, exactly

Removed from the site:
- Hero kicker "Open source · Apache-2.0", the `<title>`, the meta description, both JSON-LD descriptions, the FAQ answer "You can self-host the Cloud code", and "The code stays Apache-2.0" in the Cloud card.

Kept, because removing it would break something:
- The GitHub link and star count. Developers expect them, and ARGUS shows both.
- Engine names. The engines are credited by name; plan 21 and the repo rules require it. They appear as "Runs the engines you already trust", not as "built on open source".
- `/licenses`, renamed **Credits** and linked only from the footer. It lists each engine and its license, because the license terms require that attribution.

This reverses pillar 1 ("Open and local") in the product brief everywhere we write copy. The `LICENSE` and `NOTICE` files stay; they are legal files, not marketing.

## README and docs

The same rule applies outside the site. Today 44 lines across these files mention open source or the license:

| File | Change |
| --- | --- |
| `README.md` | Drop the Apache-2.0 badge and the "open-source engines" and "open policy" phrasing. Keep a one-line "License" section at the bottom pointing to `LICENSE`, since GitHub shows it anyway. Rename "Credits" content to "Engines" with the same names and links. |
| `brand/readme/hero-dark.png`, `hero-light.png` and their alt text | The image text says "Open-source security testing…". Rerender with `brand/readme/render.sh` using the new headline and sub. |
| `docs/src/content/docs/concepts/engines.md` | Reword "open-source engines" as "the engines Insidia runs". Keep each engine's license column; that is attribution. |
| `site/src/content/changelog.ts` | Reword past entries that say "open source". |
| `site/src/pages/licenses.astro` | Becomes `credits.astro` (see Other pages). |
| GitHub repo description and topics | Change to "Security testing for AI apps, agents, and the APIs around them." Done by Rushi or with `gh repo edit` after he confirms. |

`CONTRIBUTING.md`, `SECURITY.md`, `AGENTS.md` and `plans/` are internal and stay as they are.

## Hero copy

Headline: **Your AI agent is your newest attack surface.**

Sub: "Insidia attacks your AI app and the API behind it, names the check that failed, and blocks the release until it's fixed."

Under the CTAs: the install line · "Runs on your machine" · "No account".

## Hero visual: the traced finding

A panel styled like the ARGUS trace, rendered from a JSON file in `site/src/content/sample-run.json`. That file is generated from a real, sanitized run of the F14 demo app, not typed by hand.

```
FINDING a1b2c3 · Fig. 1 — an injection, traced          RELEASE BLOCKED · exit 1
insidia · scan · policy L1 · coverage standard · 2 targets
support-bot
  ✔ ai.prompt_injection_direct     pass   garak        2.1s
  ✘ ai.prompt_injection_indirect   FAIL   insidia      1.4s
  ✔ ai.data_leakage                pass   promptfoo    3.0s
orders-api
  ✔ api.bola_idor                  pass   insidia      0.6s
  ✔ web.ssrf                       pass   nuclei       0.9s
ROOT CAUSE  retrieval.py puts uploaded text into the system prompt.
            The planted canary came back in reply 3.
```

The rows, families, and engines shown are placeholders until the real run exists. The panel uses the same symbols and column order as `ScanView` in `core/insidia/ui.py`, so the site matches what a user sees in the terminal. Under reduced motion the panel is static. With motion, rows land one at a time, then the root-cause card slides in. Only `transform` and `opacity` animate.

## The problem section

Heading: **Your chatbot passed review. It also obeys the PDF.**

Exhibit A, `support_bot/retrieval.py`:

```python
def build_prompt(question, docs):
    context = "\n".join(d.text for d in docs)   # uploaded files, unfiltered
    return SYSTEM + context + question
```

Annotation: "← a hidden line in an upload becomes an instruction. Nothing raises."

1. **01 / No error.** The bot answers politely. Logs look clean.
2. **02 / Two halves, two tools.** The model call and the API it drives usually get tested by different tools, on different days.
3. **03 / It ships.** The instruction in the document reaches production with everything else.

Claim discipline: describe what happens, never say another tool misses it.

## How it works

Heading: **Point it at your app. Get the finding, the evidence, and the fix.**

1. **Scope in one file.** `insidia init` writes `insidia.yaml`. Only hosts you list get tested. Anything other than localhost needs `authorized: true`.
2. **Scan both layers.** `insidia scan` runs AI and app checks in one pass and names the engine behind every result. A check that couldn't run is marked incomplete, never passed.
3. **Block the release, prove the fix.** The scan exits 1 in CI. Fix the code, then `insidia rerun` checks again with the same config and policy.

Each step has a small exhibit: the YAML scope, three scan rows, and the `rerun` output.

## Feature grid: "Built for how AI apps break"

| Card | Snippet | Line |
| --- | --- | --- |
| Scope guard | `scope:` / `- host: staging.example.com` / `  authorized: true` | It refuses to test a host you didn't list. |
| Evidence, not a score | One finding card: engine, probe, masked secret `[AWS_ACCESS_KEY len=20 fp=3f9a1c07]`, fix | Every finding shows the attack, the reply, and which engine caught it. |
| Hand it to your coding agent | `Test this app with Insidia. Only scan localhost.` | Claude Code, Cursor, or Codex runs it. You confirm the hosts. |
| Local, your keys | `attacker:` / `  provider: ollama` | Scans run on your machine. Bring any model, or none: many checks need no model. |

## FAQ

1. What does Insidia test? (AI and agent checks plus app and API checks, linked to the generated support matrix)
2. Does anything leave my machine? (Traffic to your target and, if you set one, your model. No telemetry.)
3. Which engines does it run? (The verified list, linked to Credits)
4. Can my coding agent run it? (Skill, prompt, `insidia mcp` once F12 passes)
5. Will it test production? (Only hosts in scope; `authorized: true` is yours to set)
6. What does it cost? (The CLI is free. Insidia Cloud, a hosted attacker, opens to design partners first.)

## Videos on the site

- **How-to video (60 s):** the "Watch the film" button in the hero opens it in a modal. It also sits at the top of the Quickstart in the docs.
- **Long-form video (about 3 min):** embedded on a new `/film` page with chapters and the transcript, linked from the footer and docs, and uploaded to YouTube. It is not autoplayed anywhere.
- Both are rendered animations built in `site/video/` (plan 25). Terminal text in them comes from captured output of the real CLI, not typed by hand. The HTML players in `ScriptedDemos.astro` are removed from the homepage when the rendered videos land.
- Video files are self-hosted MP4 + WebM in `site/public/video/` with a poster image, captions (`.vtt`), and a transcript. The YouTube embed on `/film` loads only after a click (no third-party request on page load).

## Other pages

- `/pricing`: two columns. **CLI: free**, with what it includes. **Insidia Cloud: early access**, design partners from December 2026, "Book a call". No prices until they are set.
- `/changelog`: unchanged structure. The newest entry feeds the hero pill.
- `/benchmark`, `/security`, `/launch`: keep, and rewrite any "open-source" lines out of them.
- `/licenses` becomes `/credits` with a redirect from the old path.
- New `/film`: the long-form video, chapters, and the transcript.

## Components

| Action | File |
| --- | --- |
| Replace | `DataFlowHero.tsx` becomes `TraceHero.tsx`, which reads `sample-run.json` |
| New | `Marquee.astro`, `Exhibit.astro` (code + annotation), `StepCard.astro`, `FeatureCard.astro`, `VideoModal.tsx`, `GitHubStars.astro` (star count fetched at build, hidden if the fetch fails) |
| Remove from home | `ScriptedDemos.astro` and `PlayerControls.astro`, once the rendered videos exist |
| Rewrite | `index.astro`, `Header.astro`, `Footer.astro`, `pricing.astro`, `licenses.astro` (as `credits.astro`) |
| Keep | `LeadForm.tsx`, with the F17 fix: show success only after the endpoint confirms |

The brand stays: navy `#101028`, orange `#ED7B39`, magenta `#E33D86`, Sora. Navy text on orange buttons. Dark first, light theme kept.

## What has to be true before this ships

From F17 and F18, restated for this page:
- The hero trace comes from a real sanitized run, and every family and engine in it is verified (F07, F08).
- No AI-to-AppSec chain is shown as a result until a real chain is verified. The CLI has no SQL injection or XSS check today, so the old "prompt injection → SQLi" story stays out of the page and videos.
- Only policy L1 runs. Nothing on the page mentions L2 or L3 as available.
- The install line works on a clean machine (F13). The docs Quickstart link resolves (F16).
- No star count, user count, or quote appears unless it is real.

## Build order

1. Copy pass: remove open-source wording from the site, README, and docs; new nav; new hero text and the copy-button install line. Ship behind the current visuals.
2. Exhibit sections: problem, how it works, feature grid, marquee, FAQ, final CTA.
3. `TraceHero` fed by a hand-made placeholder JSON marked "Representative"; replaced by the generated file after F14.
4. Videos: build the `site/video/` project and render drafts from placeholder data (plan 25). Rerender with captured data after F14, then add the modal and `/film`.
5. Remove `ScriptedDemos` from the homepage, rename licenses to credits, rerender the README hero images, update the sitemap.

Checks: `npm test` and `npm run build` in `site/` and `docs/`, the secrets check, keyboard and reduced-motion pass, 360 px layout.

## Still open

1. Book a call: a Cal.com link, or keep the mailto?
