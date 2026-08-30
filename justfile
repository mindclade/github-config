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
    temporary="$(mktemp -d)"; trap 'rm -rf "$temporary"' EXIT; case "$(uname -s)/$(uname -m)" in Darwin/x86_64) opa_asset=opa_darwin_amd64; opa_sha=2e0ba7a7a45940ac4c7df878af269ebd86b221d4776f746a7fa0b6d85ba209d4 ;; Darwin/arm64) opa_asset=opa_darwin_arm64; opa_sha=2b805d476099f81828e0a72466f23b7c5f7035e8e51823f5e1ef3cbf4f2321ce ;; Linux/x86_64) opa_asset=opa_linux_amd64; opa_sha=4814caaf89062b9929e7373c745eb1b73be8aa347be61da06491f68fe910245b ;; Linux/aarch64|Linux/arm64) opa_asset=opa_linux_arm64; opa_sha=07a36a8376fba1a7a44f703d4eb314c36d2f9aeb6df5d8bdb257063fdfcd5b5e ;; *) printf 'unsupported OPA qualification platform: %s/%s\n' "$(uname -s)" "$(uname -m)" >&2; exit 1 ;; esac; opa="$temporary/opa"; curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 10 --max-time 120 --retry 3 --retry-all-errors "https://github.com/open-policy-agent/opa/releases/download/v1.20.1/$opa_asset" --output "$opa"; if command -v sha256sum >/dev/null 2>&1; then actual_sha="$(sha256sum "$opa" | awk '{print $1}')"; else actual_sha="$(shasum -a 256 "$opa" | awk '{print $1}')"; fi; test "$actual_sha" = "$opa_sha"; chmod 0755 "$opa"; cd compiler; go run ./cmd/github-configctl --root .. policy-input --output "$temporary/policy-input.json"; cd ..; "$opa" test policy; for package in least_privilege protected_rulesets workflow_sources oidc_subjects environment_approvals; do "$opa" eval --fail --data policy --input "$temporary/policy-input.json" "count(data.github_config.$package.deny) == 0" >/dev/null; done

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
