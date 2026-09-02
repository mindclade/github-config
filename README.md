# Mindclade GitHub configuration

Owner: @mindclade/developer-platform
Security reviewer: @mindclade/security
Last reviewed: 2026-08-30
Review cadence: 90 days

This repository is the declarative control plane for the `mindclade` GitHub
organization. Human-authored policy lives in `config/`, is validated against
versioned schemas, compiled deterministically, evaluated by Rego, and rendered
as typed input for OpenTofu.

The source is designed to fail closed. Passing local checks proves source
integrity; it does **not** prove that GitHub, the state backend, workload
identity, Apps, or protected reviewers are correctly deployed.

Current qualification status is `SOURCE_READY`: the strict
source tree is implemented, while connected enforcement remains deliberately
blocked by the activation records in `config/` and explicitly unmanaged
provider/external controls. Clearing repository variables is not activation;
approved source-contract changes and fresh connected evidence are both
required before the enforce graph can become reachable.

The declared estate profile is `github-enterprise-cloud-mixed`. It requires
GitHub Enterprise Cloud and GitHub Advanced Security capabilities even though
the current six-repository inventory remains public. Every desired repository
carries `production_authority: none` until independent connected qualification
replaces source bootstrap authority. Normal governance still requires two
independent human principals. The exact, unexpired `FBE-0001` exception may use
the two declared GitHub actor accounts mapped to `founder-primary` only for
foundation bootstrap. It explicitly does not establish independence or
production authority.

The repository-local `flake.nix` and `flake.lock` remain the consumer
system-toolchain lock for supported `aarch64-darwin` and `x86_64-linux` hosts.
They import the four checked-in estate defaults under `generated/`, bound to
the exact `mindclade/.github` authority revision
`b4d28faa5fde98087f60262110a43f25f6da9eb8`; validation rejects any byte drift
and performs no mutable remote policy fetch. The flake exposes the reviewed
toolchain package, identical default/CI shell closures, formatter, and
toolchain/source checks while preserving Go modules, OpenTofu provider locks,
and Bazel as their native dependency authorities:

```bash
nix build --no-accept-flake-config --no-update-lock-file .#toolchain
nix flake check --no-accept-flake-config --no-update-lock-file
nix develop --no-accept-flake-config --no-update-lock-file .#ci --command just ci
```

The root developer-quality interface is `just format`, `just format-check`,
`just lint`, and `just check`. Formatting is limited to handwritten source and
configuration; generated catalogs, observations, plans, state, evidence, and
receipts remain under their owning commands.

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

Every repository declares an Actions access level; `.github` retains the
catalog's `organization` reusable-workflow authority and the other repositories
declare `none`. GitHub's repository access-level control is inapplicable to
public repositories, so the provider resource, import binding, observation,
and drift projection omit it for this public estate rather than pretending a
private-repository sharing boundary exists.
The visible `developer-platform` and `security` teams retain `maintain` and
`push` access respectively so both `.github/CODEOWNERS` entries can resolve
once connected team membership is qualified.

Custom-property enum changes use two source-reviewed phases. `preserve` unions
explicit legacy values with desired definitions before repository assignments
are reconciled. Enforcement stays blocked in that phase. Only after a complete
observation proves the assignments converged may a later change select
`retire`, remove the legacy-value map, and contract the definitions. No
workflow performs an ad-hoc REST write or infers retirement from source alone.

Each branch policy is materialized as three organization rulesets: a no-bypass
integrity layer, a pull-request-governance layer, and a no-bypass required
workflow/status layer. A separate no-bypass repository ruleset owns merge
queue behavior. Only the pull-request-governance layer may contain the
`founder-pr-bypass` team with `bypass_mode=pull_request`; integrity, required
workflow, merge queue, and tag protections have no bypass. The stable branch
contract remains the exact `Pull request / required` check plus the required
`.github/.github/workflows/pull-request.yml@refs/heads/main` workflow.
Protected mutations use the canonical
`infrastructure-apply` environment, which prevents self-review and
administrator bypass.

The structurally durable `founder-pr-bypass.v1` entitlement covers all managed
repositories and paths, permits self-authored pull requests, but grants neither
foundation nor production authority. A bypassed pull request must carry the
exact `founder-bypass` label and an exact three-line comment:
`<!-- founder-pr-bypass:v1 -->`, `head-sha: <current SHA>`, then a nonempty
`reason: <1-500 characters>`.
The comment author must be one of the two accounts mapped to
`founder-primary`; any new commit invalidates the evidence. The nonsecret
consumer artifact is generated with `founder-bypass-policy`.
Generation does not publish or activate that artifact; the `.github` profile
authority must explicitly import it before treating it as enforcement input.

The disaster-recovery workflow's optional connected archive verifier reuses
that canonical `infrastructure-apply` environment. Its checked-in activation
is blocked, so github-config provisions no verifier handoff variables. Only a
reviewed ready transition may materialize the exact non-secret provider,
verifier service-account, and archive-bucket variables; the compiler schema,
OpenTofu module, and plan-evidence catalog binding reject partial or
substituted values. Exact workflow/ref claims and the read-only verifier
service account keep verification authority separate from apply authority.

## Compiler interface

```text
github-configctl validate
github-configctl compile --output catalog.json
github-configctl observe --organization mindclade --output observed.json
github-configctl diff --desired catalog.json --observed observed.json
github-configctl doctor --observed observed.json --output doctor.json \
  --markdown-output doctor.md --authority-root ../
github-configctl workflow-contract --authority-root ../ --output workflow-contract.json
github-configctl founder-bypass-policy --output founder-bypass-policy.json
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
`doctor` composes catalog validation, the live or supplied observation,
workflow-contract validation, secret metadata inventory, ruleset and
required-check drift, and founder evidence audit. It writes deterministic JSON
and Markdown, returns `0` only when healthy, `2` for confirmed drift, and `1`
when any capability or operation is incomplete; incomplete evidence takes
precedence over drift. Secret values, variable values, bypass reasons, and
comment bodies are never emitted. The nightly/manual drift workflow reconciles
one marker-addressed issue: it creates or reopens and updates that issue on a
failure and closes it on recovery.

`workflow-contract` recursively resolves reviewed reusable-workflow calls and
external actions. It rejects mutable action pins, nonexact reusable-workflow
pins, undeclared inputs/secrets/outputs, `secrets: inherit`, cycles, insufficient
caller/callee permissions, and missing semantic permissions such as
`id-token`, `security-events`, `actions`, and `attestations`. The pre-push hook
runs the local contract; CI supplies immutable authority checkouts and enables
`--require-authorities`.
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
nix develop --no-accept-flake-config --no-update-lock-file .#ci --command \
  bazel build --config=ci //compiler:github-configctl
nix develop --no-accept-flake-config --no-update-lock-file .#ci --command \
  bazel test --config=ci //:presubmit
(cd compiler && go test -race ./... && go vet ./...)
tofu fmt -check -recursive opentofu
tofu -chdir=opentofu/live/organization init -backend=false -input=false
tofu -chdir=opentofu/live/organization validate
actionlint .github/workflows/*.yml
buildifier -mode=check BUILD.bazel compiler/BUILD.bazel MODULE.bazel
```

The committed `flake.lock` and `MODULE.bazel.lock` close the system-tool and
Bazel module graphs respectively, and normal commands refuse to update either.
The repository also pins action commits and checksummed workflow tools.
OpenTofu pins the exact provider version and relies on registry-published
signed checksums during isolated initialization; protected evidence records
the resolved execution identities.

Remote Bazel execution and remote caching are intentionally disabled. They may
be enabled only for workers with the exact reviewed Nix store paths or an
immutable, digest-pinned image built from this toolchain closure.

## Protected operations

There is no supported local apply command. All organization mutation is
manual-dispatch only through `Protected apply`, bound to a full `main` commit
SHA and the canonical URL of the merged pull request whose merge commit equals
that SHA. The source gate resolves the pull request and all reviews through the
GitHub API, requires two qualified approving actors including a
CODEOWNER-equivalent actor, rejects a current change request, and requires the
reviewer roster to be disjoint from the protected-environment approver roster
before either plan or apply can exchange cloud identity. The workflow has three
controlled phases:

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
   weakening, and repository deletion. Delete-only revocation of an
   organization membership, team membership, team repository grant, or
   direct repository collaborator remains narrowly governed. The catalog may
   also retire an environment, environment deployment policy, organization or
   repository ruleset, or team only when the exact plan is explicitly acknowledged and
   accompanied by complete plan-bound dependency analysis. Offboarding still
   requires fresh connected quorum proof; a simultaneous access grant,
   disguised replacement, unknown address, or repository removal remains
   denied. Catalog-authorized privilege
   expansion additionally requires the dispatcher to set
   `acknowledge_privilege_expansion=true`; this attestation is evidence-bound
   and does not override fundamentally prohibited change classes.
3. `enforce` activates qualified protections and applies the same exact
   deletion, retirement, acknowledgement, and dependency-analysis rules.

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

Plan evidence is signed with the exact bootstrap-owned asymmetric KMS key
version after its self-digest and eligibility are verified. Apply reconstructs
the qualified public key from canonical base64, checks its SHA-256 digest, and
verifies ECDSA P-256 over the exact evidence bytes offline. Verification binds
the GitHub OIDC issuer, workflow ref and workflow SHA, source revision, merged
pull-request reference, its final reviewed head SHA and exact merge SHA,
API-resolved review-context digest, eligibility, and execution window. It runs
before apply can exchange an OIDC token and repeats
immediately before the evidence is consumed. Missing, malformed, expired, or
mismatched signing material fails closed.

Normal protected review also requires two approved actor IDs from the
bootstrap-qualified independent-principal roster. Only a manual dispatch with
`founder_bootstrap_exception_id=FBE-0001` in `foundation` may instead use the
exact `mindclade-founder` and `robpearc` accounts. That path emits a canonical,
self-digesting authorization bound to the source SHA, saved plan digest,
observed-state digest, review digest, exception expiry, workflow run, and run
attempt. Apply validates every binding and creates an exclusive consumption
marker before mutation; the receipt records no independence and no production
authority. `UNUSED` is the only authorizable projection; consumption records
the exact `UNUSED` to `CONSUMED` transition and its required `sha256` receipt
digest. Legacy `active`, missing receipts, and reused projections fail closed.

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
- `GHCFG_CHANGE_REVIEWER_ACTOR_IDS`, `GHCFG_CODEOWNER_REVIEWER_ACTOR_IDS`,
  `GHCFG_INDEPENDENT_REVIEWER_ACTOR_IDS`,
  `GHCFG_ENVIRONMENT_APPROVER_ACTOR_IDS`, and bootstrap-reviewed
  `GHCFG_REVIEW_ROSTER_QUALIFICATION_DIGEST`; reviewer and environment-approver
  actor sets must be canonical, qualified, and disjoint;
- `GHCFG_PLAN_EVIDENCE_KMS_KEY_VERSION` (an exact
  `bootstrap-signing/github-config-plan-evidence` cryptoKeyVersion),
  `GHCFG_PLAN_EVIDENCE_KMS_ALGORITHM=EC_SIGN_P256_SHA256`,
  `GHCFG_PLAN_EVIDENCE_PUBLIC_KEY_PEM_B64`, and
  `GHCFG_PLAN_EVIDENCE_PUBLIC_KEY_DIGEST` (`sha256:` plus bootstrap's SHA-256
  over the exact UTF-8 public-key PEM bytes);
- `GHCFG_PLAN_EVIDENCE_KEY_QUALIFIED_SOURCE_SHA`,
  `GHCFG_PLAN_EVIDENCE_KEY_QUALIFICATION_EVIDENCE_DIGEST`, and
  `GHCFG_PLAN_EVIDENCE_KEY_QUALIFICATION_EXPIRES_EPOCH` from bootstrap's
  maximum-seven-day signing-key qualification;
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
enforcement therefore require a canonical bootstrap attestation with a maximum
seven-day lifetime. The attestation binds its exact protected-workflow source
SHA, covers the authoritative paginated installation count, and dispositions
every live App/installation ID exactly once as catalogued, approved external,
or pending retirement. Each catalog disposition binds the independently
validated per-integration attestation digest; that attestation in turn binds
immutable repository IDs and exact selected scope. The closed-world document
is self-digested after deterministic installation ordering. Any missing,
duplicate, stale, mismatched, or unobserved entry produces
`INSTALLATION_INVENTORY_UNQUALIFIED`. The checked-in organization state remains
`blocked` until bootstrap issues this short-lived connected evidence.

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
- the `.github` authority inventory independently binds the reviewed catalog
  revision that publishes workflow templates and its earlier immutable
  reusable-workflow implementation revision. Connected validation requires
  the implementation commit to be catalog ancestry, parses every canonical
  template, and independently parses the reusable-workflow tree detached at
  that exact implementation revision;
- the `gitops` authority remains fail-closed until its canonical workflows are
  qualified as the thin, commit-pinned reusable callers required by Blueprint
  A3.8; this is recorded as
  `gitops-thin-reusable-caller-qualification-pending`, with no claimed
  revision;
- required checks are bound to qualified issuer App IDs and an immutable
  required-workflow source repository/ref (a matching context string alone is
  insufficient);
- bootstrap has qualified the GCS backend, KMS policy, WIF identities, and App
  key custody;
- bootstrap has provisioned and qualified the exact plan-evidence asymmetric
  signing key/version, algorithm, offline public key, and source-bound expiry;
- bootstrap has connected-qualified the one active `infrastructure-export`
  `EC_SIGN_P256_SHA256` key version. A ready `infrastructure-apply`
  environment must carry identical development/staging/production/restricted
  key-version, canonical base64 PKIX P-256 public-key PEM, and SPKI-DER SHA-256
  digest tuples; blocked source carries none of these non-secret handoff
  values;
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

The OIDC catalog contains 16 closed identities, and bootstrap source declares
an exact provider/service-account surface for all 16. Eleven are in
bootstrap's active-subject source set: three bootstrap plan/apply/recovery
identities and eight environment/role-specific `infrastructure-live`
identities. The three `github-config` identities,
`infrastructure-drift-plan`, and the CI-evidence verifier remain
activation-disabled and gated pending connected negative/positive exchange
qualification. Each gated identity has an exact checked-in
`not-connected-qualified` blocker. The CI-evidence verifier uses the typed
`canonical-provider-resource` audience because bootstrap intentionally omits
`allowed_audiences`; only the connected bootstrap output can supply the exact
numeric-project provider-resource audience. Policy accepts that marker only
for this disabled verifier and only when the attested token audience exactly
matches the canonical `github-ci-evidence/providers/verifier` resource form.
The contract suite compares provider,
account, workflow/context, environment, audience, and active/gated state with
the sibling bootstrap manifest whenever that canonical repository is present.

### Blueprint interface qualification gap

Connected production qualification is deliberately **nonqualifying** under
Blueprint v3.4.0 as written. The common estate rule says repository-local
workflows are thin callers of organization `.github` reusable workflows, but
the exact A3.9 tree exposes only reusable metadata, documentation, security,
scorecard, Buildkite-dispatch, and required-check interfaces. It exposes no
reusable GitHub-governance plan, drift, or protected-apply interface, while the
exact A3.10 tree requires those three repo-local workflows and forbids adding
another path.

The preferred blueprint amendment adds
`reusable-governance-pull-request.yml`,
`reusable-governance-drift-detection.yml`, and
`reusable-governance-protected-apply.yml` to the A3.9 canonical workflow tree,
plus their interface-policy fixtures/tests, and defines A3.10's three files as
thin pinned callers. Alternatively, A3.10 must explicitly exempt these
privileged control-plane composition roots from the common thin-caller rule
while retaining the existing pin, identity, and evidence requirements. Until
one amendment is ratified and both repositories implement it, no readiness
variable or live observation can make this repository production authority.

Cross-run observation checkpoints are not accepted as authority: GitHub
exposes no organization-wide consistent-read snapshot, so resuming a partially
cached graph could combine incompatible points in time. Reads instead use
bounded exponential backoff with per-client randomized jitter and
`Retry-After`; a failed or partial
observation is recorded non-authoritatively and the next run starts a fresh
full observation before re-planning. OpenTofu's protected remote state and the
attempt/receipt evidence are the mutation checkpoint: after a partial apply,
accepted mutations remain recorded, but continuation always re-observes GitHub
and produces a new exact plan instead of replaying a cached observation or
blindly resuming the failed mutation sequence.

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
