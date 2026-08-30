## Governance change

Describe the intended organization, repository, membership, ruleset, environment, or integration change. Link the approved change record.

## Authority and risk

- [ ] The resource has exactly one authoritative repository.
- [ ] This change does not add a backward dependency across trust rings.
- [ ] New or widened permissions are listed below with owner, purpose, and expiry.
- [ ] No token, private key, secret value, plan payload, or sensitive observed state is included.

Privilege or protection delta:

<!-- State “none” or enumerate every increase, reduction, bypass, reviewer change, OIDC change, visibility change, deletion, or replacement. -->

## Evidence

- Source validation:
- Policy/Bazel tests:
- OpenTofu plan evidence or why connected planning is not applicable:
- Expected create/update/delete/replace counts:

## Failure and recovery

- Rollback or forward-recovery procedure:
- Runbook exercised or updated:
- Connected qualification still outstanding:

## Reviewer checklist

- [ ] Catalog and schemas agree and compilation is deterministic.
- [ ] Actions and reusable workflows use immutable full SHAs.
- [ ] Required checks work for both pull requests and merge queues.
- [ ] The plan is bound to this exact commit and contains no prohibited action.
- [ ] Review and environment approval are performed by distinct human principals.
