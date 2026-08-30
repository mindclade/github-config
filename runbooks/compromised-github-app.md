# Compromised GitHub App

Use this runbook for suspected exposure or misuse of the Buildkite, artifact-signing, GitOps controller, plan, or apply GitHub App. Protect evidence while preventing new privileged operations. Do not expose a private key to confirm that it is valid.

## Authority and severity

- `security` is incident commander and owns GitHub installation containment.
- `bootstrap` owns private-key material, secret versions, and federation bindings.
- The integration owner listed in `config/integrations/` validates the replacement installation contract.
- A suspected apply or artifact-signing App compromise is severity critical.

Do not delete audit logs, edit state, mint a test token, copy a key, or reinstall an App from an operator workstation.

## Immediate containment

1. Record the App identity, installation, repositories, suspected time window, detection source, and incident reference.
2. Stop protected apply, signing, promotion, or CI dispatches that depend on the App. Preserve completed run logs and redacted evidence.
3. With two-person incident authorization, suspend or revoke the affected installation using GitHub's organization security controls. Record the GitHub audit event identifier. Do not widen another App as a substitute.
4. Ask `bootstrap` operators to disable the affected secret version and federation binding through their protected recovery path. Never rotate key material in this repository.
5. If commits, tags, releases, or checks may be forged, quarantine their evidence and notify each owning repository before resuming automation.

## Investigate

1. Compare observed installation repository selection, permissions, and events with the corresponding integration document.
2. Review GitHub audit logs, workflow runs, check issuers, tag creation, release attestations, and secret access metadata for the incident window.
3. Treat missing audit pages, pagination errors, or ambiguous issuers as incomplete evidence and keep the App disabled.
4. Determine whether the compromise affected only a token, a private-key version, the App registration, a workflow source, or an administrator identity.

## Recover

1. `bootstrap` creates and qualifies replacement credential material; values remain outside catalog, logs, plans, and state.
2. Reconcile the installation to the exact selected repositories, permissions, and events in `config/integrations/`. Bootstrap emits a maximum-seven-day canonical attestation containing its authority, the qualified source SHA, numeric App and installation IDs, `selected` mode, every repository name with its immutable numeric ID, the exact permission/event sets, and UTC creation/expiry. Record the structured attestation plus the SHA-256 digest of its canonical content; never record credentials. Any scope increase requires a separate security review and is not incident recovery.
3. Re-run source validation, observe with the read-only identity, and produce a zero-delete plan.
4. Restore workflows in increasing privilege order: read/observe, plan, CI checks, signing or promotion, then apply. Each stage must produce independently reviewed evidence.

## Exit criteria

- The compromised credential and installation can no longer mint or use tokens.
- Replacement installation permissions, events, and repository selection exactly match the catalog.
- The bootstrap qualification is unexpired, no longer than seven days, self-digesting, and exactly matches the catalog repository names, immutable live repository IDs, permissions, events, installation ID, and App ID. The organization installation API does not independently expose the selected repository names; the canonical bootstrap attestation remains authoritative for that exact list.
- Potentially forged checks, tags, artifacts, and releases have been verified or revoked by their authority owners.
- Drift is clean, protected workflows use exact immutable sources, and independent reviewers approve service restoration.
- The incident record contains audit references and redacted evidence, plus follow-up actions for root cause and key-rotation cadence.
