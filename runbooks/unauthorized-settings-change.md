# Unauthorized GitHub Settings Change

Use this runbook when observed GitHub organization or repository state differs from the compiled catalog and there is no approved change reference explaining the difference. Treat unknown or incomplete observations as an incident; do not interpret them as clean state.

## Preconditions and ownership

- Incident lead: `security` team.
- Configuration authority: this repository's reviewed `config/` catalog.
- Apply authority: the protected `infrastructure-apply` environment only.
- Root identity, state backend, App key, or workload-identity repair belongs to `bootstrap`; this repository must not replace those controls.

Do not repair settings in the GitHub UI, run an ad hoc OpenTofu apply, change state, or weaken a ruleset to restore access.

## Detect and preserve evidence

1. Record the drift workflow run URL, source commit, first detection time in UTC, affected organization/repositories, and the incident/change reference.
2. Download only the redacted evidence artifact from the workflow run. Do not attach tokens, App keys, credential files, plan binaries, or raw API payloads to the incident.
3. Reproduce the observation with a read-only App identity:

   ```sh
   bazelisk run //compiler:github-configctl --lockfile_mode=off -- \
     observe --organization mindclade --output observed.json
   bazelisk run //compiler:github-configctl --lockfile_mode=off -- \
     compile --output catalog.json
   bazelisk run //compiler:github-configctl --lockfile_mode=off -- \
     diff --desired catalog.json --observed observed.json
   ```

4. If observation is partial, rate-limited, or ambiguous, stop. Mark the incident `observation-incomplete` and repeat only after the API and read identity are healthy.

## Contain and classify

1. Suspend governance applies by incident coordination; do not cancel evidence collection or delete workflow history.
2. Classify each difference as approved catalog lag, unauthorized mutation, compromised integration, or observation failure.
3. For a suspected App compromise, follow [Compromised GitHub App](compromised-github-app.md) before attempting reconciliation.
4. Confirm no rule change expanded visibility, bypass actors, direct collaborators, Actions sources, App permissions, OIDC subjects, or environment bypass.

## Recover through the protected path

1. If the catalog is correct, open an incident-linked pull request containing no catalog weakening. If the catalog is wrong, correct it in a separately reviewed pull request.
2. Require CODEOWNERS and two distinct-human approvals. Aliases that map to one `principal_id` count once.
3. Run `protected-apply` against the exact protected `main` commit. The workflow must re-observe state, produce a non-destructive plan, wait at `infrastructure-apply`, recompute the plan, and reject a changed digest.
4. Stop on any delete, replace, visibility expansion, privilege expansion, stale evidence, or changed plan digest. Escalate to `security`; do not add a bypass.

## Verify and close

- A fresh observation matches the catalog with zero unknown or ignored security fields.
- Required checks and both `pull_request` and `merge_group` triggers are healthy.
- The evidence receipt is redacted, bound to the applied commit and plan digest, and retained with the incident.
- The unauthorized actor or process is identified and remediated by its owning repository.
- Any temporary suspension was lifted through its authorized control plane, and a follow-up drift run is clean.
