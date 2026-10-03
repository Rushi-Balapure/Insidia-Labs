# Phase 10 — Enterprise

Depends on: Phases 0–3 at minimum for a private deployment; Phases 4–9 for a full one. The deployment track can start once compose is production-shaped.
Parent: [00-master-plan.md](00-master-plan.md).

## Goal
A company can use Insidia Labs under their identity provider, with roles, an audit log, and a deployment that matches their data rules: our multi-tenant cloud, a regional instance, a single-tenant cloud, or the whole brain installed in their network.

## Exit
- SSO login via OIDC works for a test IdP. SAML works for one test IdP or is explicitly deferred with OIDC covering the pilot.
- Roles beyond Phase 2: `owner`, `admin`, `member`, `viewer`, plus a custom role that is a set of permissions (`scan:launch`, `finding:read_raw`, `report:export`, `runner:enroll`, `baseline:write`, `audit:read`).
- Audit log is append-only for those actions and is exportable by an admin of that org.
- Helm chart installs API, workers, hub, egress proxy, RabbitMQ, Valkey, and the key service, and configures an external Postgres and the customer's KMS or HSM (Vault Transit or a cloud KMS). A smoke scan runs against the fixture inside the cluster.
- Customers can bring their own master key (BYOK) in the shared cloud, and revoking it crypto-shreds their data (see [14-database-schema.md](14-database-schema.md)).
- Staff access grants are fully self-service for customer admins: approve, revoke, set standing grant policies, and see every staff decryption in their audit log.
- Admin console ([20-admin-console.md](20-admin-console.md)): monthly SOC 2 staff access-review export (the security hardening and full two-person rule already ship in Phase 2), and a reduced operator console in the Helm chart for on-prem and private tenants (health, queues, runners, kill switches, settings; engines shown as Insidia Labs Engine modules).
- On-prem install guide includes `THIRD_PARTY_NOTICES.md` generation for images that are actually shipped. Legal review is a checklist item before the first on-prem customer, not a code task.
- Air-gapped profile: attacker and judge models point at an in-cluster model service (vLLM + AWQ, Stage 1 spec from [19-model-hosting.md](19-model-hosting.md): at least one 48 GB GPU the customer provides, weights shipped with pinned SHA-256); no calls to our SaaS control plane; image pulls from their registry.
- Owned matrix cells are green ([17-test-suite.md](17-test-suite.md)). Phase 10 does not own cells.

## Identity
- OIDC authorization code flow on the dashboard. Map IdP groups to org roles.
- SAML 2.0 if the pilot IdP cannot do OIDC. Do not build both to full depth if one unblocks the contract.
- Break-glass local admin stored hashed, disabled when SSO is required.
- Session and API key behavior from Phase 2 stays. SSO users can still create API keys if their role allows.

## Audit
Table `audit_events` as defined in [14-database-schema.md](14-database-schema.md): hash-chained, metadata and IPs encrypted with the org key, inserted only through the `app_audit` role by the API, not by workers guessing. Workers emit scan lifecycle events the API records. Phase 10 adds admin export (decrypted for the requesting org only), SIEM streaming, and the chain-verification report.
No updates or deletes. Retention is a per-org setting (default 365 days) enforced by a scheduled job that deletes only past the retention window. Export to object storage before delete if the org enables archive.

## Deployment units
- **Shared cloud (default):** one brain, many orgs, fairness from Phase 1. Region is a deployment choice (separate cluster per region), not a column that magically splits data. An org is pinned to one region.
- **Private tenant:** same Helm values, dedicated cluster, dedicated Postgres. Org id still on every row so the code path does not fork.
- **On-prem:** customer runs Helm. We do not receive heartbeats unless they enable a phone-home flag, default off. License key (signed token) gates features if we need a contract check; the key does not contain customer scan data.

Images: api, worker-ai, worker-classic, worker-static, worker-agent, worker-insidia (our gap-filling modules), hub, egress, key-service, dashboard, docs, model (optional). Tags are digests. Cosign signatures verified in the chart notes.

## Air gap
- No telemetry.
- Remote-generation, telemetry, and sharing disables are already in worker images; recheck every image for outbound calls in a CI test that uses a deny-all network except Postgres, RabbitMQ, Valkey, the hub, the key service, and the model.
- On-prem customer docs (install, upgrade, backup, air-gapped models) ship versioned with the release, per [15-customer-docs.md](15-customer-docs.md).
- Taxonomy data is baked into the image so the install does not fetch OWASP or MITRE at runtime.
- Interactsh runs inside their cluster for blind bugs, bound to their scan network, not to our cloud.

## Notices and confidentiality
On-prem **is** distribution. The chart build writes `THIRD_PARTY_NOTICES.md` into each image from the lockfiles. It is not shown in the product UI. Marketing pages still do not name the engines. Counsel reviews the notice file before shipment. Attribution-forced dependencies stay excluded (AI-Infra-Guard).

## SOC 2 readiness (Insidia Labs the company)
Not a feature. A checklist next to this phase: access reviews, audit log, encryption at rest (Postgres and object storage), TLS everywhere, backup restore drill, vulnerability process for our own images. Implementation work that is purely policy stays out of the repo except internal docs in `internal/security/`. The customer-facing security and trust pages live in `docs/`.

## Tests
- OIDC login against a local test IdP (for example Keycloak in compose).
- Viewer role cannot export raw evidence.
- Audit row written on scan launch and finding status change.
- Helm template snapshot renders. Smoke install is nightly, not every PR, if the cluster is expensive.
- Air-gap container test: worker process with no default route except allowed hosts does not fail the fixture scan.

## Risks
- Private tenant and on-prem double the support matrix. One Helm chart, different values, no code forks.
- License enforcement that phones home breaks air gap. Default off, and the product must boot without it when the contract says so.
