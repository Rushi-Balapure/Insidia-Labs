# Phase 9 — Continuous and developer workflow

Depends on: Phase 2 API keys and scans, Phase 3 SARIF, Phase 1 runner `run`.
Parent: [00-master-plan.md](00-master-plan.md).

## Goal
Scans run without a person at the dashboard: CI on each change, a schedule, and alerts. A pilot customer can block a build on new high-severity findings. Optional Burp and fleet discovery come after the CI path is solid.

## Exit
- `insidia-runner scan --target <id> --profile <id> --wait` exits non-zero when the scan's new findings meet a threshold.
- GitHub Action and a GitLab CI template run that command using an org API key.
- A baseline scan stores a fingerprint set. A later scan fails only on findings not in the baseline (regression), not on accepted or baselined items.
- Scheduled scan fires from Celery beat, notifies Slack or a generic webhook.
- Jira issue create is a documented webhook mapping, not a special case if the generic webhook can carry the fields. If Jira needs auth, add one integration module.
- Burp extension and MDM fleet are specified and prototyped only if the CI exit is already met. They do not block this phase.

## CI runner
The same Go binary. `scan` ensures the daemon is connected (or starts a one-shot session), calls the API to create a scan, streams status, writes SARIF to a path, and exits.
Flags: `--fail-on critical,high`, `--baseline <scan_id>`, `--sarif out.sarif`.
API key from `INSIDIA_API_KEY`. The key cannot read other orgs (Phase 2).

GitHub Action inputs: `api-key`, `target`, `profile`, `fail-on`, `baseline`. Pin the action to a commit in docs. The action does not bundle scanner engines; it only wraps the CLI.

## Baselines
Table `finding_fingerprints (org_id, target_id, probe_id, evidence_hash, state)`.
States: `open`, `accepted`, `fixed`, `false_positive`, `baselined`.
Regression diff is computed in `control.finalize_scan`. The CI exit code uses the diff, not the raw total.
UI: "update baseline" for an owner. Viewers cannot.

## Schedules
`scan_schedules` row: cron, target, profile, fail policy, notification target.
Celery beat enqueues `control.plan_scan` with the org envelope. Missed ticks do not stack more than one pending scan per schedule.

## Notifications
Webhook payload: scan id, counts by severity, link, top new finding titles (our probe ids and taxonomy ids). No transcripts in the webhook by default (they leak into Slack). A flag `include_evidence` defaults off.
Slack and webhook URLs are C3 secrets in `notification_channels.config_enc`: write-only, shown only by fingerprint, and decrypted only by the notifier (see [14-database-schema.md](14-database-schema.md)). Outgoing webhooks are signed (HMAC with a per-channel secret) so customers can verify them.
Email reuses the Phase 2 mail interface.

## SIEM
Optional syslog or HTTPS JSON export on a timer, same redacted finding schema. Document the field list. Do not promise a specific vendor parser in this phase.

## Gap-filling Insidia modules in this phase
From [16-coverage-gaps.md](16-coverage-gaps.md):
- **M-C5 race-condition tester:** single-packet HTTP/2 bursts on endpoints the customer marks as sensitive, opt-in per endpoint because it changes state.
- **M-C7 WebSocket fuzzing:** message-level fuzzing and authorization checks on WebSocket APIs.

## Burp extension (stretch)
A Burp plugin that is a runner: it forwards in-scope proxy history as relay or tunnel traffic for a chosen target. Scope comes from Burp's scope, intersected with the Insidia allowlist. Ship only after CI is done. Language: whatever Burp's current extension API requires; keep it a thin forwarder with no attack logic.

## Fleet discovery (stretch)
A runner config `discover_on_interval` for company-managed machines, using Phase 7 `discover` (no server execution). Results land in the org's inventory view. Enrollment is the same mTLS flow. MDM packaging is a doc (how to push the binary and a token), not a custom MDM product.

## Tests
- CLI against the fixture: clean baseline exits 0; new canary exits 1.
- Schedule fires once in a unit test with a fake clock.
- Webhook body denylist (no upstream names, no transcript unless flagged).
- API key of org A cannot pass `--target` of org B.

## Risks
- CI scans against production. Docs and the default profile should say staging. The product cannot enforce that beyond the allowlist the customer set.
- Baseline freezing hides real bugs. The UI must show accepted and baselined counts next to the green check.
