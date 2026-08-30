# Mindclade GitHub configuration

This repository is the declarative control plane for the `mindclade` GitHub
organization. Human-authored policy lives in `config/`, is validated against
versioned schemas, compiled deterministically, evaluated by Rego, and rendered
as typed input for OpenTofu.

The source is designed to fail closed. Passing local checks proves source
integrity; it does **not** prove that GitHub, the state backend, workload
identity, Apps, or protected reviewers are correctly deployed.

Current qualification status is `PASS_WITH_DEPLOYMENT_PREFLIGHT`: the strict
source tree is implemented, while connected enforcement remains deliberately
blocked by the activation records in `config/` and explicitly unmanaged
provider/external controls. Clearing repository variables is not activation;
approved source-contract changes and fresh connected evidence are both
required before the enforce graph can become reachable.

## Authority boundary

This repository owns organization settings, repositories, teams and access,
rulesets, repository environments, Actions restrictions, OIDC metadata, and
connected drift evidence. It does not own:

- reusable workflow implementations (`mindclade/.github`);
- the GCS state backend, KMS policy, WIF providers, or App-key custody
  (`mindclade/bootstrap`);
- cloud infrastructure (`mindclade/infrastructure-live`);
- Kubernetes desired state (`mindclade/gitops`); or
- product source and build artifacts (`mindclade/mindclade`).

Normal dependency direction is `.github` and bootstrap outputs into this
repository. No workflow here mutates cloud infrastructure or runtime state.

## Repository model

- `config/` contains the only human-authored governance intent.
- `schemas/v1/` defines the accepted document contracts.
- `compiler/` validates, canonicalizes, observes, diffs, and emits evidence.
- `policy/` denies unsafe or incomplete governance.
- `opentofu/` materializes provider-supported GitHub resources.
- `tests/` proves contracts, determinism, plan safety, drift, and recovery.
- `runbooks/` covers the failure modes that must remain operable when GitHub
  governance itself is impaired.

Every configuration document uses `github.mindclade.io/v1`, rejects unknown
fields, and refers to other objects by stable logical ID. Generated catalog,
observation, plan, state, and evidence files are ephemeral and must not be
committed.

## Compiler interface

```text
github-configctl validate
github-configctl compile --output catalog.json
github-configctl observe --organization mindclade --output observed.json
github-configctl diff --desired catalog.json --observed observed.json
github-configctl preflight --desired catalog.json --observed observed.json
github-configctl evidence --catalog catalog.json --plan plan.json \
  --observed observed.json --plan-file tfplan --source-sha "$GITHUB_SHA" \
  --workflow-sha "$GITHUB_WORKFLOW_SHA" \
  --wif-qualification-evidence-digest sha256:... \
  --state-backend-digest sha256:... --executor-contract-digest sha256:... \
  --output receipt.json
github-configctl verify-evidence --input receipt.json
```

`validate` and `compile` are provider-free. `observe` is the only networked
command; it accepts a token only through `GITHUB_TOKEN`, performs bounded GET
requests, and emits a redacted snapshot. `diff` returns `0` for equality, `2`
for drift, and `1` for an operational error. `preflight` is stricter than
source validation and denies connected activation when licensing, identities,
reviewers, integrations, or observations are incomplete. A core observation
is complete only when the unique repository enumeration equals GitHub's
authoritative public-plus-private organization count; missing count fields or
a downscoped partial inventory fail closed.
Plan evidence exposes only resource types, action/risk classes, opaque
deterministic change IDs, and safe changed-field paths. Nonsensitive
before/after states use domain-, path-, side-, resource-, and action-bound
hashes. Terraform-sensitive, credential, identity, and access-topology fields
are marker-only: their values are never hashed or emitted.

## Local validation

The supported entry point is:

```sh
just ci
```

Equivalent focused commands are:

```sh
USE_BAZEL_VERSION=9.2.0 bazelisk build //compiler:github-configctl --lockfile_mode=off
USE_BAZEL_VERSION=9.2.0 bazelisk test //:presubmit \
  --lockfile_mode=off --test_output=errors
(cd compiler && go test -race ./... && go vet ./...)
tofu fmt -check -recursive opentofu
tofu -chdir=opentofu/live/organization init -backend=false -input=false
tofu -chdir=opentofu/live/organization validate
actionlint .github/workflows/*.yml
buildifier -mode=check BUILD.bazel compiler/BUILD.bazel MODULE.bazel
```

The strict blueprint intentionally has no Bazel, OpenTofu, or provider lock
file. The repository pins exact top-level Bazel modules, action commits, and
checksummed workflow tools. OpenTofu pins the exact provider version and
relies on registry-published signed checksums during isolated initialization;
protected evidence records the resolved execution identities.

## Protected operations

There is no supported local apply command. All organization mutation is
manual-dispatch only through `Protected apply`, bound to a full `main` commit
SHA and an approved change reference. The workflow has three controlled
phases:

1. `adopt` permits imports and no create/update/delete action.
   Import targets and IDs must come from a complete live observation; the
   workflow selects only configuration-driven import changes and rejects an
   import that would also update a GitHub object.
2. `foundation` may create missing catalog objects and holds rulesets in
   evaluation mode only after immutable OIDC identities, exact 2FA state,
   capability/quorum checks, every source activation, each integration, and
   the closed-world App inventory are qualified. Unlike `enforce`, it may
   tolerate known missing managed objects, but it cannot bypass an authority
   or activation gate. It rejects replacement, state-forget, protection
   weakening, and every deletion except a delete-only revocation of an
   organization membership, team membership, team repository grant, or
   direct repository collaborator. Those four offboarding operations are
   eligible only after a fresh connected preflight proves the desired state
   retains administrator and reviewer quorum; a simultaneous access grant or
   disguised replacement remains denied. Catalog-authorized privilege
   expansion additionally requires the dispatcher to set
   `acknowledge_privilege_expansion=true`; this attestation is evidence-bound
   and does not override fundamentally prohibited change classes.
3. `enforce` activates qualified protections and also rejects deletion and
   replacement, with the same narrowly constrained offboarding exception.

An unprivileged source job requires `GHCFG_FOUNDATION_READY=true` for adoption
or foundation work and `GHCFG_ACTIVATION_READY=true` for enforcement. The two
flags are intentionally independent so an incomplete organization can be
adopted without falsely declaring its protections active. The plan and apply
jobs use separate GCP WIF identities and separate GitHub Apps. The apply job
re-observes state, recomputes the plan, matches its canonical digest to the
reviewed evidence, applies only the local saved plan, then requires provider
convergence and a fresh live GitHub diff.

Before mutation, apply emits a compiler-verified attempt receipt linked to the
reviewed evidence and recomputed plan. Terminal steps run even after an apply
or verification failure, retain the reviewed classification and redacted
best-effort drift, and explicitly flag possible partial mutation. Terminal
diagnostics are incident evidence only and never authorize retry or apply.
Binary plans, state, raw observations, preflight topology, credential files,
and provider logs are never uploaded. A third-party artifact action is invoked
only after every source, identity, policy (where present), authentication, App,
and executor-contract gate for that job succeeded; an earlier gate failure
remains in GitHub's native run log (and the separate no-OIDC drift reporting
job) rather than bypassing the failed boundary to upload a diagnostic.

Required non-secret variables are:

- `GHCFG_FOUNDATION_READY`, `GHCFG_ACTIVATION_READY`, and
  `GHCFG_ROLLOUT_PHASE` (`foundation` or `enforce` for drift detection);
- `GHCFG_WIF_QUALIFIED_SOURCE_SHA`,
  `GHCFG_WIF_QUALIFICATION_EVIDENCE_DIGEST`, and
  `GHCFG_WIF_QUALIFICATION_EXPIRES_EPOCH` from bootstrap's exact-source,
  maximum-seven-day qualification;
- `GHCFG_STATE_BUCKET`, `GHCFG_STATE_PREFIX`, and the bootstrap-reviewed
  `GHCFG_STATE_BACKEND_EVIDENCE_DIGEST`;
- bootstrap-reviewed `GHCFG_EXECUTOR_CONTRACT_EVIDENCE_DIGEST`;
- `GCP_WIF_PROVIDER_GITHUB_CONFIG_PLAN` and
  `GCP_SERVICE_ACCOUNT_GITHUB_CONFIG_PLAN`;
- `GCP_WIF_PROVIDER_GITHUB_CONFIG_APPLY` and
  `GCP_SERVICE_ACCOUNT_GITHUB_CONFIG_APPLY`;
- `GHCFG_PLAN_APP_ID`, `GHCFG_PLAN_APP_INSTALLATION_ID`, and
  `GHCFG_PLAN_APP_KEY_SECRET`; and
- `GHCFG_APPLY_APP_ID`, `GHCFG_APPLY_APP_INSTALLATION_ID`, and
  `GHCFG_APPLY_APP_KEY_SECRET`.

The backend digest is SHA-256 over repository-canonical JSON
`{version:"gcs-backend/v1",bucket,prefix}`. Canonical bytes are UTF-8 with
lexically sorted keys, two-space indentation, and one terminal LF. The executor
digest uses the same encoding and version `github-config-executor/v1`, binding organization,
the `sts.googleapis.com` audience, the sorted six-repository scope, and both
roles' App ID, installation ID, service account, and WIF provider. Before any
privileged authentication, the plan and apply jobs recompute these contracts
from their effective values and compare them with the source-gate outputs.
After token minting they also verify the installation ID returned by the
pinned action, and every evidence record binds all three reviewed digests.

App private keys remain in Secret Manager and are fetched only after exact
workflow/ref WIF authorization. Jobs that can request an OIDC token have
job-wide `id-token: write`, so their first inline step validates effective
identity, backend, executor, exact-source, and bounded-lifetime contracts
before any third-party action or repository code runs. Before the pinned
cloud-auth exchange, the jobs repeat those checks after policy evaluation.
The corresponding WIF provider condition remains bootstrap-owned and must
bind the same `workflow_sha`.
The referenced bootstrap attestation must also bind the live immutable
organization and repository numeric IDs, the resulting immutable `repo`
subject segment, workflow path/ref, context, audience, and the logical
provider/service-account role. Its digest covers the complete attestation,
including creation and expiry, and its lifetime is at most seven days.
Repository variables and source-gate outputs are only local freshness and
shadowing defenses; they are not cryptographic authority. Successful exchange
under an independently bootstrap-managed WIF condition proves only the claims
accepted by the provider actually selected for that exchange. It does not, by
itself, prove that mutable repository variables still name the bootstrap-
reviewed provider, service account, backend, or App installation. Before either
readiness flag may be enabled, the runtime must therefore enforce those exact
values from reviewed source or fetch and verify an independently authenticated,
fresh bootstrap bundle. That bundle must bind the provider, service account,
audience, source/workflow SHA, backend bucket and prefix, App/key reference and
installation, and an anti-TOCTOU disposition for changes during the run.
The token mint explicitly downscopes repository access to the six catalog
repositories and requests only the named read or write permissions for its
role; it never inherits an installation's full permissions by default.
Private keys are never Terraform variables or saved-plan inputs.
Because that token can enumerate only its selected repositories, the compiler
also requires the organization summary's authoritative repository totals to
match the enumeration. If GitHub omits those totals for the App identity,
connected preflight remains blocked.

Numeric GitHub App, installation, and required-check issuer IDs are not
credentials, but they are still accepted only as reviewed catalog data. An
integration becomes eligible only when its `activation` is ready, its
bootstrap qualification is unexpired and digest-bound to the exact declared
repository list and installation ID, and connected observation matches that
installation ID plus its App ID, permissions, events, selection mode, and
suspension state. GitHub's organization installation listing does not expose
the selected repository names, so the compiler records that scope as
unobserved and never treats selection mode alone as proof of exact scope. The
protected preflight emits the exact non-secret maps consumed by OpenTofu;
workflows do not accept an arbitrary ID overlay.

Closed-world GitHub App inventory is a separate bootstrap qualification. The
organization installation endpoint can inventory App and installation
identity but cannot prove selected-repository scope. Foundation and
enforcement therefore remain blocked until a canonical, time-limited
bootstrap attestation covers every product and governance App, immutable
repository IDs, exact scope, and the explicit disposition of every additional
installation. Embedded per-integration attestations are validated catalog
inputs, not independently authenticated authority: the unconditional
`INSTALLATION_INVENTORY_UNQUALIFIED` blocker must remain until that external
bundle binds the current workflow/source SHA, catalog digest, every embedded
attestation digest, and every installation disposition.

## Activation status

The catalog is source-complete but connected activation is intentionally
blocked until all of the following are true:

- the organization has Enterprise Cloud/GHAS capabilities for private and
  internal rulesets and protected environment reviewers;
- organization 2FA can be enabled without locking out an administrator;
- at least two distinct human principals staff the required owner/reviewer
  teams (two accounts belonging to one person count once);
- the reusable checks in `.github` exist at immutable SHAs and handle both
  pull requests and merge groups;
- required checks are bound to qualified issuer App IDs and an immutable
  required-workflow source repository/ref (a matching context string alone is
  insufficient);
- bootstrap has qualified the GCS backend, KMS policy, WIF identities, and App
  key custody;
- bootstrap has recorded the live organization/repository numeric IDs and
  rejects legacy name-only or transferred/recreated OIDC subjects;
- the governance plan/apply Apps have passed positive and negative permission
  tests;
- a paginated GitHub App inventory and bootstrap attestation account for every
  product, plan, apply, legacy, and broad installation; and
- legacy repositories, teams, and broad App installations have been migrated,
  removed, or explicitly dispositioned.

Several provider gaps are intentionally represented as `managed = false`,
including organization settings that require excluded billing data, runner
policy, independent-human approval composition, environment workflow
provenance, and external OIDC/App authority. Consequently, the current
`enforce` graph is a fail-closed activation stub; connected observations alone
cannot turn those flags into managed controls.

The artifact-signing App is selected-repository only. It needs `contents:write`
to create release refs, but it receives no ruleset-wide bypass: one tag ruleset
allows only its qualified Integration actor to bypass creation restriction,
while a separate no-bypass ruleset forbids tag update and deletion for every
actor, including the signer.

Never weaken policy to work around one of these blockers. Follow the relevant
runbook and use a reviewed forward correction.

## License and security

The contents are proprietary and confidential under [LICENSE](LICENSE).
Report vulnerabilities through the private process in [SECURITY.md](SECURITY.md),
not a public issue.
