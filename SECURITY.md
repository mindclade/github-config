# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting or a private Mindclade security
channel available under your controlling agreement. Do not open a public issue
and do not include tokens, private keys, App credentials, state, plans, audit
payloads, member data, or restricted infrastructure identifiers in a report.

Include only the minimum information needed to reproduce the problem:

- affected source commit and path;
- control or authority boundary involved;
- expected and observed behavior;
- whether access, rulesets, OIDC, protected environments, or state integrity
  may have changed; and
- a safe reproduction using synthetic identifiers where possible.

If a credential may be compromised, stop using it and follow
`runbooks/compromised-github-app.md`. Do not rotate or revoke production
credentials from an unprotected workstation or agent session.

## Supported source

Only the current protected `main` branch is supported. Generated plans,
catalogs, observations, evidence, and local state are not release artifacts.
Protected evidence is valid only after its self-digest verifies and the apply
workflow independently recomputes its exact source/workflow SHA, catalog,
complete observed-state digest and immutable organization ID, reviewed plan,
plan/app App and installation identities, WIF qualification, backend and
executor contracts, workflow run and attempt, and expiry bindings. Evidence
also carries a value-free changed-field projection: sensitive fields have no
hash, and nonsensitive states have hashes rather than raw values. A terminal
run diagnostic has `authorization: none`; it records failures and possible
partial mutation but never authorizes an apply or retry.

## Security invariants

- Configuration contains references to secrets, never secret values.
- Organization mutation uses a separately approved apply App; pull-request and
  static-validation jobs receive no privileged identity.
- Readiness variables and self-hashed executor/backend contracts are not
  deployment authority. Activation requires reviewed source-bound values or a
  fresh, independently authenticated bootstrap bundle that the runtime verifies
  against the exact WIF provider, service account, backend, and App installation.
- A plan or observation is not authorization to apply.
- Two GitHub accounts for the same human are one principal for quorum.
- Repository deletion, replacement, visibility expansion, protection
  weakening, OIDC deletion/replacement or non-catalog mutation, and last-admin
  removal are denied. Catalog-exact OIDC create/update remains high risk and
  requires explicit protected-review acknowledgement. Only
  delete-only revocation of an organization membership, team membership,
  team repository grant, or direct repository collaborator is eligible, and
  only after fresh connected preflight proves the desired state preserves
  administrator and reviewer quorum without a simultaneous access grant.
- Unknown or partially observed connected state is a failure, not a clean
  result.
- Live qualification is never inferred from source tests.

## Response boundary

This repository contains procedures for GitHub governance containment and
recovery. Bootstrap owns state/KMS/WIF recovery, `.github` owns reusable
workflow releases, and GitOps owns runtime rollback. Coordinate across those
owners without copying their credentials or state into this repository.
