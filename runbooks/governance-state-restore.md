# Governance State Restore

Use this runbook when the current catalog, compiled artifact, evidence chain, or GitHub governance state cannot be trusted. The objective is to recompile a verified last-known-good source revision and reconcile through normal protections—not to roll back remote state manually.

## Preconditions and stop conditions

- Incident lead and catalog owner: `security`.
- State backend and recovery identity owner: `bootstrap`.
- A candidate last-known-good revision must be signed, reviewed, reachable from protected history, and accompanied by a previously accepted redacted evidence receipt.

Stop if the candidate revision, signer, schema version, provider/tool digest, backend observation, or target organization is ambiguous. Do not run OpenTofu state commands, force-unlock, import commands, or an apply outside `protected-apply`.

## Select and verify source

1. Record the incident reference and current protected `main` SHA.
2. Identify candidate revisions from retained evidence and audit history. Inspect without changing the working tree:

   ```sh
   git show --show-signature --stat --oneline <candidate-sha>
   git merge-base --is-ancestor <candidate-sha> origin/main
   ```

3. Verify the candidate contains the expected blueprint inventory and schema version, no secret-like values, and an unmodified authority boundary.
4. Recompile the candidate in an isolated checkout or CI job using the repository-pinned toolchain. Require byte-identical canonical output across two runs.

## Observe before recovery

1. Observe GitHub with the read-only App and produce a deterministic diff against the candidate catalog.
2. Obtain state/backend health evidence from `bootstrap`. Do not read backend objects or credentials into this workflow.
3. Classify every proposed action. Reject delete, replace, visibility expansion, bypass creation, permission expansion, membership loss, or unknown action.
4. If remote state itself is unavailable or corrupt, stop this runbook and use the protected `bootstrap` state-backend recovery procedure.

## Restore through review

1. Create a recovery pull request that makes protected `main` reproduce the verified candidate catalog. Include the incident reference and redacted comparison evidence.
2. Require CODEOWNERS and two distinct-human approvals; account aliases mapped to one principal do not satisfy quorum.
3. Dispatch `protected-apply` for the exact merged SHA and the approved recovery phase. Require plan/app identity separation, environment approval, plan digest equality after re-observation, and a zero-delete plan.
4. If apply status is ambiguous, do not retry. Re-observe GitHub and state first, then create a new reviewed plan.

## Verify and close

- Two clean observations agree with the restored catalog and expose no unknown fields.
- The compiler produces the same canonical bytes and digest as the approved recovery artifact.
- Organization settings, team access, repositories, rulesets, environments, Actions, integrations, and OIDC policy are all accounted for.
- Required checks and drift detection succeed from protected `main`.
- The incident retains signed source identity, redacted plan/evidence digests, approver identities, and a documented forward-fix; no credential or sensitive state value is retained.
