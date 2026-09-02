# Contributing

`@mindclade/developer-platform` owns this repository. Security-sensitive
workflow, identity, authorization, and policy changes also require review from
`@mindclade/security`.

Use the repository-root commands from the pinned Nix shell:

```text
just format
just format-check
just lint
just check
just workflow-contract
```

`just format` edits only handwritten source and configuration. Generated
catalogs, observed-state snapshots, plans, state, evidence, and receipts remain
under their owning commands and must not be committed. Lint suppressions must
name the exact rule and explain why the exception is safe.

Pyright is strict by default. Existing dynamic JSON and repository-contract
modules carry an explicit file-level `basic` migration directive with only the
named dynamic checks disabled; newly added Python modules inherit strict
checking.

Passing local checks proves source qualification only. It does not authorize or
prove connected GitHub governance changes.

The pre-push hook runs `github-configctl workflow-contract` against local
sources. Changes to reusable-workflow calls or action pins must also pass CI
with immutable authority checkouts and `--require-authorities`; a locally
unavailable sibling authority is not evidence that the estate contract is
complete.
