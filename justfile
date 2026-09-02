set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

format:
    biome check --write .
    ruff format .
    cd compiler && golangci-lint fmt --config ../.golangci.yml
    opa fmt -w policy
    tofu fmt -recursive opentofu
    git ls-files 'BUILD.bazel' 'MODULE.bazel' '*.bzl' | xargs buildifier -mode=fix
    nixfmt flake.nix
    just --fmt

format-check:
    biome check .
    ruff format --check .
    cd compiler && golangci-lint fmt --config ../.golangci.yml --diff
    opa fmt --fail policy >/dev/null
    tofu fmt -check -recursive opentofu
    git ls-files 'BUILD.bazel' 'MODULE.bazel' '*.bzl' | xargs buildifier -mode=check -lint=warn
    nixfmt --check flake.nix
    just --fmt --check

lint:
    biome lint .
    ruff check .
    pyright
    cd compiler && golangci-lint run --config ../.golangci.yml ./...
    actionlint .github/workflows/*.yml
    zizmor --no-progress --offline .github/workflows/*.yml
    yamllint --config-file .yamllint.yaml .
    markdownlint-cli2

validate:
    cd compiler && go run ./cmd/github-configctl --root .. validate

# Re-attest the reviewed authority revisions against the sibling repository
# mains. Every commit to a reviewed sibling (.github, bootstrap,
# infrastructure-live) makes the recorded revision stale by design; this
# rewrites it so the attestation matches what is actually on main.
sync-authority-revisions:
    python3 tools/sync_authority_revisions.py

# Report authority revision drift without rewriting anything.
authority-drift:
    python3 tools/sync_authority_revisions.py --check

compile output="build/catalog.json" tofu_vars="":
    cd compiler && go run ./cmd/github-configctl --root .. compile --output "../{{ output }}" {{ if tofu_vars != "" { "--tofu-var-file ../" + tofu_vars } else { "" } }}

go-test:
    cd compiler && go test -race ./... && go vet ./...

python-test:
    temporary="$(mktemp -d)"; trap 'rm -rf "$temporary"' EXIT; cd compiler; go build -o "$temporary/github-configctl" ./cmd/github-configctl; cd ..; for test_file in tests/contract/test_*.py tests/plan/test_*.py tests/drift/test_*.py tests/recovery/test_*.py; do GITHUB_CONFIGCTL="$temporary/github-configctl" python3 "$test_file"; done

bazel-test:
    @bazel_args=(); if test -n "${MACOSX_DEPLOYMENT_TARGET:-}"; then bazel_args+=("--repo_env=MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET}" "--action_env=MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET}" "--copt=-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET}" "--linkopt=-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET}"); fi; bazel test --config=ci ${bazel_args[@]+"${bazel_args[@]}"} //:presubmit

policy-test:
    temporary="$(mktemp -d)"; trap 'rm -rf "$temporary"' EXIT; cd compiler; go run ./cmd/github-configctl --root .. policy-input --output "$temporary/policy-input.json"; cd ..; opa test policy; for package in least_privilege protected_rulesets workflow_sources oidc_subjects environment_approvals; do opa eval --fail --data policy --input "$temporary/policy-input.json" "count(data.github_config.$package.deny) == 0" >/dev/null; done

tofu-check:
    tofu fmt -check -recursive opentofu
    temporary="$(mktemp -d)"; trap 'rm -rf "$temporary"' EXIT; cp -R opentofu "$temporary/opentofu"; tofu -chdir="$temporary/opentofu/live/organization" init -backend=false -input=false; tofu -chdir="$temporary/opentofu/live/organization" validate

workflow-lint:
    actionlint .github/workflows/*.yml
    zizmor --no-progress --offline .github/workflows/*.yml

workflow-contract:
    temporary="$(mktemp -d)"; trap 'rm -rf "$temporary"' EXIT; cd compiler; go run ./cmd/github-configctl --root .. workflow-contract --output "$temporary/workflow-contract.json"

bazel-format:
    git ls-files 'BUILD.bazel' 'MODULE.bazel' '*.bzl' | xargs buildifier -mode=check -lint=warn

whitespace-check:
    if rg --hidden -n '[[:blank:]]+$' --glob '!.git/**' --glob '!bazel-*' .; then echo 'trailing whitespace is prohibited' >&2; exit 1; fi

flake-check:
    nix flake check --no-accept-flake-config --no-build --no-update-lock-file

# Vulnerability scan of declared dependencies. Requires network access to the
# OSV database, so it is deliberately separate from the hermetic lint recipe.
security:
    osv-scanner scan source --recursive .

check: format-check lint validate workflow-contract go-test python-test bazel-test policy-test tofu-check whitespace-check security flake-check

ci: check
