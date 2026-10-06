# Threat model

Internal. Phase 0 records the threats and the phase that owns the mitigation. This is not a customer document.

## Stolen runner credential

A stolen runner credential could scan a host outside the customer's allowlist. Mitigation in Phase 2C: the hub allows only hosts enrolled for that runner, and the credential is revocable. Owner: Phase 2C.

## Cross-org data leak

A missing tenant envelope or a shared storage prefix could show one customer's findings to another. Mitigation now: every task requires `org_id`, row-level security is forced, and a missing `app.org_id` matches no rows. Object-storage prefixes arrive with evidence in Phase 2C. Owner: Phase 0 for the database, Phase 2C for objects.

## Tunnel used as a VPN

The WireGuard tunnel could be abused as a route into the customer network. Mitigation in Phase 2C: the tunnel forwards only to the enrolled target, with no general routing. Owner: Phase 2C.

## Scanning a target the customer does not own

Direct mode could be aimed at someone else's host. Mitigation in Phase 2C: ownership verification expires, and the egress proxy refuses unverified hosts. Owner: Phase 2C.

## Untrusted model and target output

Attack output and target responses are hostile data. Workers must not interpret them as code or SQL. Mitigation from Phase 2C: parsers accept structured fields only, and the admin console renders customer text as plain text (Phase 2C). Owner: Phase 2C.

## Secrets in logs, results, or traces

A credential copied into a log, a Celery result, or a trace would leave the encryption boundary. Mitigation now: the redactor exists, task results are status and counts, and the dev master key is refused outside dev mode. Call sites must use the redactor before logging from Phase 2C. Owner: Phase 0 for the result shape, Phase 2C for call sites.

## Database dump or backup theft

A stolen dump must not reveal customer values. Mitigation now: customer values are ciphertext, keys are wrapped, and a copied ciphertext fails associated-data checks. Crypto-shredding of wrapped keys is specified for deletion and is completed with the key service in later phases. Owner: Phase 0.

## Direct mode as SSRF

The egress proxy could be turned toward cloud metadata or our own network. Mitigation in Phase 2C: the proxy blocks private, link-local, and metadata ranges and re-checks redirects. Owner: Phase 2C.

## Engines phoning home

An engine could send telemetry or call its vendor for attack generation and leak attack content. Mitigation in Phase 2C: engine containers have no general internet egress, and remote generation is disabled. The license gate already rejects licenses we cannot ship. Owner: Phase 2C.

## Admin console

The admin console will be able to see every org. Its controls (separate network path, device-bound sessions, just-in-time roles, customer grants) are specified in the admin console plan and ship with Phase 2C, which is when the console exists. Owner: Phase 2C.
