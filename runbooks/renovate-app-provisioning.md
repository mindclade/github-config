# Renovate App provisioning

The estate-wide Renovate pass (`.github/workflows/renovate.yml`) is source-complete
and cannot run until a dedicated GitHub App exists. Its declaration is
`config/integrations/renovate.yaml`, which ships `qualification.state: blocked`
with three blockers. This runbook clears them.

Every step below needs `admin:org` on `mindclade`, or an owner of the GCP
bootstrap projects. Nothing here can be performed by the repository automation,
by design: the App is the credential the automation uses.

## Ordering

The App must exist before the Ring-0 federation change, because the App ID and
installation ID are inputs to it. Do not write the federation change first.

## 1. Create the App

Create a GitHub App owned by the `mindclade` organization.

- Name: `mindclade-renovate`. The bot actor becomes `mindclade-renovate[bot]`,
  which `.github/tests/fixtures/trusted_pull_request.json` and the trusted-context
  actor test already expect.
- Webhook: **disabled**. This is a self-hosted, cron-driven run; it consumes no
  webhook. `config/integrations/renovate.yaml` declares `events: [pull_request]`
  only because the integration schema requires a non-empty list.
- Repository permissions, exactly these and no others:

  | Permission      | Access | Why |
  |---|---|---|
  | Contents        | Write  | create update branches and commits |
  | Issues          | Write  | maintain the dependency dashboard |
  | Metadata        | Read   | mandatory for every App |
  | Pull requests   | Write  | open and update dependency pull requests |
  | Workflows       | Write  | update pinned action SHAs under `.github/workflows` |

  Do **not** grant Administration. The runner uses an explicit repository
  allowlist in `.github/renovate-runner.json`, never autodiscovery, so it has no
  reason to read repository settings.

- Organization permissions: none.

## 2. Install it on exactly seven repositories

Install with **Only select repositories**: `.github`, `bootstrap`, `estate-ci`,
`github-config`, `gitops`, `infrastructure-live`, `mindclade`.

This set must equal `spec.repositories` in `config/integrations/renovate.yaml`
and the `repositories:` list in the workflow's `create-github-app-token` step.
It must also equal `repositories` in `.github/renovate-runner.json`, which is
what actually bounds what Renovate touches.

Record the App ID and the installation ID.

## 3. Store the private key

Generate a private key and store it in GCP Secret Manager in the bootstrap
signing project, following `bootstrap/opentofu/modules/signing-root`:

- `secret_id`: `renovate-app-key`
- Write-only (`secret_data_wo`), so the plaintext never enters OpenTofu state.
- Deletion protection on, `prevent_destroy` on.

Delete the downloaded key file. The workflow reads it at run time through
`google-github-actions/get-secretmanager-secrets`; it is never committed and
never passed as a workflow secret.

## 4. Ring-0 federation (protected apply, two approvers)

`bootstrap/manifests/identity-federation.yaml` closes
`spec.workloadIdentityProviders.github-config.identities` to exactly `plan` and
`apply`, and caps `plan.subjects` at two. Renovate needs a third identity: it is
the only estate identity that writes to repositories, so it must not be folded
into the read-only `plan` identity.

This is a root-trust change. It requires, in one reviewed change:

1. `schemas/v1/federation.schema.json` — admit a `renovate` identity and raise
   the `identities` key set.
2. `manifests/identity-federation.yaml` — add:

   ```yaml
   renovate:
     providerId: github-config-renovate
     serviceAccountId: github-config-renovate
     subjects:
       - id: github-config-renovate
         workflowRef: mindclade/github-config/.github/workflows/renovate.yml@refs/heads/main
         contextType: ref
         contextValue: refs/heads/main
         audience: sts.googleapis.com
   ```

3. `opentofu/modules/github-federation` — the provider attribute condition must
   pin `repository_id`, `repository_owner_id`, `repository_visibility`,
   `runner_environment`, `ref`, `workflow_ref`, and `workflow_sha == sha`,
   exactly as the existing `github-config` identities do.
4. The service account needs `roles/secretmanager.secretAccessor` on
   `renovate-app-key` and nothing else.
5. `tests/plan/test_minimum_privilege.py` and the federation contract tests.

The weekly usage report (`ci-usage-report.yml`) uses the existing read-only
`plan` identity but is a distinct `workflow_ref`, so it needs a third entry in
`plan.subjects` and the `maxItems: 2` cap raised. Land it with the same change.

## 5. Repository variables

Set on `mindclade/github-config`:

| Variable | Shape the workflow asserts before any third-party action runs |
|---|---|
| `GHCFG_RENOVATE_APP_ID` | `^[0-9]+$` |
| `GHCFG_RENOVATE_APP_INSTALLATION_ID` | `^[0-9]+$` |
| `GHCFG_RENOVATE_APP_KEY_SECRET` | `^projects/…/secrets/…/versions/…$` |
| `GCP_SERVICE_ACCOUNT_GITHUB_CONFIG_RENOVATE` | service-account email |
| `GCP_WIF_PROVIDER_GITHUB_CONFIG_RENOVATE` | `^projects/…/locations/global/workloadIdentityPools/…/providers/…$` |

The workflow fails closed on any malformed value before authenticating.

## 6. Clear the blockers and qualify

Remove the three blockers from `config/integrations/renovate.yaml`, set
`qualification.state: qualified` and `activation.state: ready`, and add
`actor_id` — the integration schema requires `actor_id` once activation is
ready. Apply through the protected path.

## 7. Dry run before the first live pass

Run the workflow with `workflow_dispatch`, leaving `dry_run: true` (the default).
That performs a complete read-only pass over all seven repositories and opens
nothing. Confirm in the log that every repository is visited and that the
Renovate version is the pinned digest, then re-run with `dry_run: false`.

Renovate cannot run at all until the organization's Actions allocation is
restored; every workflow in the estate is currently failing at startup.

## Rollback

Uninstall the App. Nothing else needs reverting: Renovate holds no state in the
repositories beyond its branches and pull requests, and the dependency dashboard
issue can be closed. The configuration files are inert without an installation.
