# OIDC Policy Lockout

Use this runbook when a GitHub Actions job cannot exchange its OIDC token for the expected plan or apply identity. Fail closed: an authentication failure is not authorization to use a long-lived credential, broaden a subject, remove an environment, or reuse the plan identity for apply.

## Preconditions and ownership

- `github-config` owns the allowed GitHub OIDC subject contract.
- `bootstrap` owns workload-identity providers, service accounts, IAM bindings, and recovery identities.
- `security` leads the incident; `platform-operations` supports cloud-side read-only diagnosis.

Never print a JWT, credential file, access token, provider resource name, service-account address, or secret payload into logs or tickets.

## Diagnose without mutation

1. Record the failed workflow, job, protected source SHA, environment, audience, UTC time, and redacted provider error.
2. Confirm the workflow is the expected file on protected `main`; do not retry a workflow from an unreviewed ref.
3. Compare the intended claim binding in `config/oidc-policy.yaml` with redacted claim names only. Required subject segments are `repo`, `context`, `workflow_ref`, and `workflow_sha`; the workflow SHA must be immutable. The `repo` segment must use GitHub's immutable `OWNER@OWNER-ID/REPOSITORY@REPOSITORY-ID` form, and both numeric IDs must match a bootstrap-qualified live observation.
4. Verify the intended context:
   - drift plan: `ref:refs/heads/main`;
   - protected plan: `environment:trusted-build`;
   - protected apply: `environment:infrastructure-apply`.
5. Check GitHub and cloud provider status. If either observation is incomplete, retain the lockout and wait for a complete read.

## Recovery decision

1. If repository policy drifted, use the last-known-good procedure and a reviewed catalog correction. Do not broaden a subject to a repository wildcard.
2. If federation or IAM drifted, hand off to the protected `bootstrap` recovery procedure. Do not recreate federation from this repository.
3. If the workflow revision is not qualified, merge the reviewed workflow on protected `main`, then have `bootstrap` bind both WIF providers to that exact `workflow_sha`, immutable organization/repository IDs, subject segment, workflow ref, context, audience, and provider/service-account role. Bootstrap publishes the matching `GHCFG_WIF_QUALIFIED_SOURCE_SHA`, complete-attestation digest, and expiry variables. Never put a self-referential commit SHA or guessed numeric ID in the catalog.
4. If every normal identity is unavailable, only the independently authorized `bootstrap` break-glass procedure may be considered. This runbook does not grant break-glass authority.

## Verify and close

- A read/plan job can authenticate only for the exact repository, workflow, immutable workflow SHA, context, and `sts.googleapis.com` audience.
- The bootstrap evidence digest is SHA-256 over the complete immutable-identity contract; its recorded source equals the running commit, and its attested lifetime is no more than seven days and has not expired.
- A legacy name-only subject, wrong owner/repository ID, repository transfer, namespace recreation, wrong context, or wrong WIF role fails token exchange.
- The apply identity remains unusable outside `infrastructure-apply` and cannot be assumed by the plan job.
- No long-lived credential was introduced and no subject or audience was widened.
- A dry plan and drift observation complete without changes before any protected apply is requested.
- Evidence records the incident, reviewed correction, exact source SHA, and independent approvers without sensitive claims.
