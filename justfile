set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

validate:
    cd compiler && go run ./cmd/github-configctl --root .. validate

compile output="build/catalog.json" tofu_vars="":
    cd compiler && go run ./cmd/github-configctl --root .. compile --output "../{{output}}" {{ if tofu_vars != "" { "--tofu-var-file ../" + tofu_vars } else { "" } }}

go-test:
    cd compiler && test -z "$(gofmt -l .)" && go test -race ./... && go vet ./...

python-test:
    temporary="$(mktemp -d)"; trap 'rm -rf "$temporary"' EXIT; cd compiler; go build -o "$temporary/github-configctl" ./cmd/github-configctl; cd ..; for test_file in tests/contract/test_*.py tests/plan/test_*.py tests/drift/test_*.py tests/recovery/test_*.py; do GITHUB_CONFIGCTL="$temporary/github-configctl" python3 "$test_file"; done

bazel-test:
    USE_BAZEL_VERSION=9.2.0 bazelisk test //:presubmit --lockfile_mode=off --test_output=errors

policy-test:
    temporary="$(mktemp -d)"; trap 'rm -rf "$temporary"' EXIT; cd compiler; go run ./cmd/github-configctl --root .. policy-input --output "$temporary/policy-input.json"; cd ..; opa test policy; for package in least_privilege protected_rulesets workflow_sources oidc_subjects environment_approvals; do opa eval --fail --data policy --input "$temporary/policy-input.json" "count(data.github_config.$package.deny) == 0" >/dev/null; done

tofu-check:
    tofu fmt -check -recursive opentofu
    temporary="$(mktemp -d)"; trap 'rm -rf "$temporary"' EXIT; cp -R opentofu "$temporary/opentofu"; tofu -chdir="$temporary/opentofu/live/organization" init -backend=false -input=false; tofu -chdir="$temporary/opentofu/live/organization" validate

workflow-lint:
    actionlint .github/workflows/*.yml

bazel-format:
    buildifier -mode=check BUILD.bazel compiler/BUILD.bazel MODULE.bazel

whitespace-check:
    if rg --hidden -n '[[:blank:]]+$' --glob '!.git/**' --glob '!bazel-*' .; then echo 'trailing whitespace is prohibited' >&2; exit 1; fi

ci: go-test python-test bazel-test policy-test tofu-check workflow-lint bazel-format whitespace-check
