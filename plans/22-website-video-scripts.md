# 22 - Website video scripts

Scripts for the short videos on the marketing site ([21-marketing-website.md](21-marketing-website.md)). They follow the open-core plan ([00-master-plan.md](00-master-plan.md)): the free CLI and agent skill lead, Insidia Cloud follows.

## Rules for every video
- **Format.** HTML/CSS animated players like the current `DemoReel.astro` (no mp4 on the page), or a screen recording of the real CLI once the CLI ships (Phase 1A). Loop silently, start muted, show captions on screen, have a pause button, and show the final frame when the visitor prefers reduced motion.
- **Length.** 12-30 seconds each. The hero loop is under 15 seconds.
- **Honesty.** Until the CLI exists, label each video "Representative demo". Every command, flag, and file name must match the master plan. Show only targets we own (the sandbox apps, `localhost`, `staging.example.com`). Findings shown must be classes the benchmark covers. No customer names, no invented metrics, no real keys; masked secrets use the `[AWS_ACCESS_KEY len=20 fp=3f9a1c07]` form.
- **Brand.** Navy `#101028` background, Sora, orange `#ED7B39` primary accent, magenta `#E33D86` secondary. Severity colors from `tokens.css`. Navy text on orange buttons. Terminal text in a monospace font on Navy 800 `#181839`.
- **Engine credit.** When a video shows engines, name them (garak, ZAP, and so on). They are credited, not hidden.

Order on the site: 1 in the hero, 2-4 in "How it works", 5-6 in the Cloud section.

---

## 1. Hero loop - "One run, both layers" (14 s)
Purpose: in one glance, show that Insidia tests the AI layer and the app around it, and that it runs from the terminal.

| Time | On screen | Caption |
| --- | --- | --- |
| 0-2 s | A terminal line types `insidia scan`. | Run one command. |
| 2-6 s | Two lanes fill side by side. Left lane "AI layer": prompt injection, jailbreak, tool misuse, RAG leak. Right lane "App layer": SQLi, XSS, SSRF, BOLA. Small engine labels fade in under each lane (garak, promptfoo, PyRIT / ZAP, Nuclei, Dalfox). | It tests the model and the app around it. |
| 6-10 s | A line draws from "prompt injection" in the left lane across to "SQLi" in the right lane, marked "chained". | And finds where they connect. |
| 10-14 s | The lanes collapse into a report card: "L2 Standard - 31/38 controls passed - 3 high". | You get a report you can act on. |

End frame: the report card, holding until the loop restarts.

## 2. "Let your agent run it" (24 s)
Purpose: show the agent skill, the top of the docs, and that the human only confirms scope.

| Time | On screen | Caption |
| --- | --- | --- |
| 0-3 s | A terminal runs `npx skills add Rushi-Balapure/Insidia-Labs --skill insidia`, then shows "Installed skill: insidia". | Add the Insidia skill to your coding agent. |
| 3-7 s | An agent chat panel. The user types: "Test this app with Insidia. Only scan localhost." | Ask in plain words. |
| 7-11 s | The agent replies: "I'll scan `http://localhost:8080/chat` and `http://localhost:3000`. Confirm?" The user clicks "Yes". | You confirm what it may test. |
| 11-18 s | Agent steps tick off: "Installed insidia", "Wrote insidia.yaml", "Running L2 scan", "Read 3 high findings". | The agent does the rest. |
| 18-24 s | The agent writes: "The support bot follows instructions hidden in uploaded PDFs. Here's a fix for `retrieval.py`." A browser tab opens on the HTML report. | It explains the findings, suggests fixes, and opens the report. |

Note: the agent panel is generic. It does not imitate any specific product's UI.

## 3. "The CLI" (20 s)
Purpose: the human path, for people who will run it themselves.

| Time | On screen | Caption |
| --- | --- | --- |
| 0-4 s | `insidia init`; output: "Found: chat endpoint, REST API, repo. Wrote insidia.yaml (scope: localhost)." | Init finds your app and sets a safe scope. |
| 4-8 s | `insidia doctor`; a checklist of engines and the model endpoint, all green. | Doctor checks engines and your model. |
| 8-16 s | `insidia scan --policy L2`; a live list of probes running with engine names, counters for findings by severity. | Scan runs every engine and our gap modules locally. |
| 16-20 s | Final lines: "Policy L2: FAIL (3 high). Report: .insidia/runs/2026-12-01T10-02/report.html", exit code 1. | Exit codes and JSON make it work in CI. |

## 4. "The report" (26 s)
Purpose: show the single-file HTML report and that it needs no server.

| Time | On screen | Caption |
| --- | --- | --- |
| 0-4 s | `insidia report --open`; a browser opens a `file://` URL. | One file. Works offline. |
| 4-10 s | Report summary: the benchmark score with bars for OWASP LLM, Agentic, Web, and API. | Scored against the open Insidia Benchmark. |
| 10-18 s | A finding opens: "Indirect prompt injection via uploaded document", severity high, engine "Insidia gap module: indirect-injection", "Cross-validated with garak". The attack, the response, and a masked secret in evidence. | Every finding shows the attack, the evidence, and who found it. |
| 18-26 s | The fix section and a "Re-run this check" command; a toggle to light theme. | Fix it and re-run just that check. |

## 5. "Custom attacks on Insidia Cloud" (24 s)
Purpose: the paid upgrade. Explain why a hosted uncensored model finds more, without claiming numbers we have not measured.

| Time | On screen | Caption |
| --- | --- | --- |
| 0-5 s | A scan summary with a notice: "Attacker model refused 41 generations. Jailbreak and tool-misuse coverage is thin." | General-purpose models refuse to write attacks. |
| 5-9 s | `insidia login`, then the config line `attacker: { provider: insidia-cloud }`. | Point the attacker at Insidia Cloud. |
| 9-17 s | Generated attacks stream in, specific to the target: a refund-policy bot gets a multi-turn social-engineering attempt; the agent's `lookup_order` tool gets an argument injection. | It writes attacks for your app's domain and tools. |
| 17-24 s | The rescan summary shows new findings marked "custom attack". End card: "The CLI is free. Hosted attacks are metered." | Same CLI, stronger attacker, on our GPUs. |

Placeholder until the Phase 2B benchmark result exists: do not show a "finds N% more" number. Replace the end card with the measured result once it is published.

## 6. "Chained exploit, end to end" (30 s)
Purpose: the differentiator. An AI-layer flaw becomes an app-layer breach. Based on the example chain already on the site.

| Time | On screen | Caption |
| --- | --- | --- |
| 0-6 s | Attack path graph, node 1: "Prompt injection in a support ticket". | It starts in the AI layer. |
| 6-12 s | Node 2: "Agent calls `search_orders` with the attacker's input". | The agent passes it to a tool. |
| 12-18 s | Node 3: "SQL injection in the orders API" with the payload shown. | The tool hits a classic bug. |
| 18-24 s | Node 4: "Other customers' orders returned" with masked rows. | And the data leaks. |
| 24-30 s | The pentest agent's PoC panel: numbered repro steps and "Confirmed by oracle". End card: "Scripted chains: free CLI. Discovered chains: Insidia Cloud pentest agent." | Insidia shows the whole path and proves it. |

## 7. "The dashboard" (22 s)
Purpose: show what a team pays for beyond the model. Build only once Phase 2C has real screens.

| Time | On screen | Caption |
| --- | --- | --- |
| 0-5 s | `insidia connect` uploads a CLI run; it appears in the dashboard history. | Upload CLI runs to see them over time. |
| 5-11 s | The "New scan" button, target picker, schedule "Every night at 02:00". | Launch and schedule scans from the dashboard. |
| 11-17 s | A runner tile: "staging-runner, connected", used for an internal target. | Reach internal apps through a runner. |
| 17-22 s | A diff view, "2 fixed, 1 new since last week", and an export button for an evidence pack. | Track fixes and export evidence for audits. |

## Production checklist
- [ ] Each script reviewed against the shipped CLI before it goes live (commands, flags, output wording).
- [ ] Captions double as the accessible text; each player has an `aria-label` summarizing the video.
- [ ] Reduced-motion final frame shows the end card.
- [ ] Videos 5-7 are hidden or labeled "Coming soon" until Phase 2A/2B/2C exits.
- [ ] Every engine shown on screen is listed on the site's credits page.
