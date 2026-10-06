# Continuous scanning — CI in Phase 1E, schedules in Phase 2C, the rest in Phase 3

> This file covers continuous scanning. The free path needs no account: `insidia scan` in CI exits 0 when the policy passes, 1 when it fails, and 2 on error, and writes SARIF. The GitHub Action `Rushi-Balapure/Insidia-Labs/actions/scan` (Phase 1E) wraps that CLI and talks to the local engines only. Schedules, webhooks, and Slack notifications are Phase 2C (they run in Cloud). Jira, the GitLab CI template, SIEM export, the Burp extension, and fleet discovery are Phase 3. Race and WebSocket modules run locally in Phase 1B.

Depends on: the CLI (Phase 1E) for CI, and the Cloud API (Phase 2C) for schedules.
Parent: [00-master-plan.md](00-master-plan.md).

## Goal
A repository fails its own build on new high-severity findings with no account. A team that pays can schedule scans and get alerts.

## Exit
- `insidia-runner scan --target <id> --profile <id> --wait` exits non-zero when the scan's new findings meet a threshold.
- The GitHub Action (Phase 1E) and a GitLab CI template (Phase 3) run that command, using an org API key for Cloud scans.
- A baseline scan stores a fingerprint set. A later scan fails only on findings not in the baseline (regression), not on accepted or baselined items.
- Scheduled scan fires from Celery beat, notifies Slack or a generic webhook.
- Jira issue create is a documented webhook mapping (Phase 3) when the generic webhook can carry the fields. If Jira needs auth, add one integration module.
- Burp extension and MDM fleet are specified and prototyped once the CI exit is met. They do not block Phase 1E or Phase 2C.
- Owned matrix cells are green ([17-test-suite.md](17-test-suite.md)).

## CI
The CLI itself. `insidia scan --policy L1 --sarif out.sarif` writes SARIF and exits 1 when the policy fails. `--baseline <run-id>` fails only on findings not in that run. No API key.

The GitHub Action checks out the repo and runs that command, with inputs `policy`, `fail-on`, `baseline`, and an optional `insidia-cloud-key` for teams who want the hosted attacker. Pin the action to a release tag. The action does not bundle engines; the CLI installs them, or the job uses the GHCR image.

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
Email reuses the Phase 2C mail interface.

## SIEM
Optional syslog or HTTPS JSON export on a timer (Phase 3), same redacted finding schema. Document the field list. Specific vendor parsers are out of scope for Phase 3.

## Gap-filling Insidia Labs modules (Phase 1B)
From [16-coverage-gaps.md](16-coverage-gaps.md):
- **M-C5 race-condition tester:** single-packet HTTP/2 bursts on endpoints the customer marks as sensitive, opt-in per endpoint because it changes state.
- **M-C7 WebSocket fuzzing:** message-level fuzzing and authorization checks on WebSocket APIs.

## Burp extension (stretch)
A Burp plugin that is a runner: it forwards in-scope proxy history as relay or tunnel traffic for a chosen target. Scope comes from Burp's scope, intersected with the Insidia Labs allowlist. Ship only after CI is done. Language: whatever Burp's current extension API requires; keep it a thin forwarder with no attack logic.

## Fleet discovery (stretch)
A runner config `discover_on_interval` for company-managed machines, using the agent-security `discover` command from Phase 1C (no server execution). Results land in the org's inventory view. Enrollment is the same mTLS flow. MDM packaging is a doc (how to push the binary and a token), not a custom MDM product.

## Tests
- CLI against the fixture: clean baseline exits 0; new canary exits 1.
- Schedule fires once in a unit test with a fake clock.
- Webhook body contains engine names and contains no transcript unless flagged, and no raw secret.
- API key of org A cannot pass `--target` of org B.

## Risks
- CI scans against production. Docs and the default profile should say staging. The product cannot enforce that beyond the allowlist the customer set.
- Baseline freezing hides real bugs. The UI must show accepted and baselined counts next to the green check.
