import json
import hashlib
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CLI = os.environ.get("GITHUB_CONFIGCTL") or (sys.argv[1] if len(sys.argv) > 1 else "")


def invoke(*arguments, root=ROOT):
    if CLI:
        command = [str(Path(CLI).resolve())]
        cwd = ROOT
    else:
        command = ["go", "run", "./cmd/github-configctl"]
        cwd = ROOT / "compiler"
    return subprocess.run(
        command + ["--root", str(root), *arguments],
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class CatalogSchemaTest(unittest.TestCase):
    def temporary_catalog(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        shutil.copytree(ROOT / "config", root / "config")
        shutil.copytree(ROOT / "schemas", root / "schemas")
        self.addCleanup(temporary.cleanup)
        return root

    def test_authoritative_catalog_validates_and_has_contract_shape(self):
        result = invoke("validate")
        self.assertEqual(result.returncode, 0, result.stderr)
        validation = json.loads(result.stdout)
        self.assertEqual(validation["status"], "valid")
        self.assertRegex(validation["source_digest"], r"^sha256:[0-9a-f]{64}$")

    def test_repository_tree_matches_blueprint_inventory_exactly(self):
        expected = {
            ".editorconfig", ".gitignore", "BLUEPRINT.md", "BUILD.bazel", "LICENSE",
            "MODULE.bazel", "README.md", "SECURITY.md", "component.yaml", "justfile",
            ".github/CODEOWNERS", ".github/dependabot.yml", ".github/pull_request_template.md",
            ".github/workflows/pull-request.yml", ".github/workflows/drift-detection.yml",
            ".github/workflows/protected-apply.yml",
            "config/organization.yaml", "config/actions-policy.yaml", "config/security-policy.yaml",
            "config/oidc-policy.yaml", "config/members.yaml", "config/outside-collaborators.yaml",
            *{f"config/teams/{name}.yaml" for name in (
                "architecture", "biological-safety", "computational-biology", "data-platform",
                "developer-platform", "ml-systems", "platform-operations", "product-engineering",
                "release-engineering", "security",
            )},
            *{f"config/repositories/{name}.yaml" for name in (
                "dot-github", "github-config", "bootstrap", "infrastructure-live", "gitops", "mindclade",
            )},
            *{f"config/rulesets/{name}.yaml" for name in (
                "application-source", "governance-source", "infrastructure-source", "deployment-source", "release-tags",
            )},
            "config/repository-gates/infrastructure-live-authorities.yaml",
            *{f"config/environments/{name}.yaml" for name in (
                "trusted-build", "release-signing", "infrastructure-apply", "production-promotion",
                "infrastructure-source-review", "security-source-review",
            )},
            *{f"config/integrations/{name}.yaml" for name in ("buildkite", "artifact-signing", "gitops-controller")},
            *{f"schemas/v1/{name}.schema.json" for name in (
                "organization", "actions_policy", "security_policy", "oidc_policy", "membership",
                "team", "repository", "ruleset", "repository_gate", "environment", "integration",
            )},
            "compiler/cmd/github-configctl/main.go", "compiler/internal/catalog/catalog.go",
            "compiler/internal/validation/validation.go", "compiler/internal/rendering/rendering.go",
            "compiler/internal/diff/github_diff.go", "compiler/internal/evidence/plan_evidence.go",
            "compiler/go.mod", "compiler/go.sum", "compiler/BUILD.bazel",
            *{f"opentofu/modules/{module}/{name}.tf" for module in (
                "organization-settings", "repository-governance", "team-access", "ruleset", "repository-environment",
            ) for name in ("main", "variables", "outputs")},
            *{f"opentofu/live/organization/{name}.tf" for name in (
                "backend", "versions", "providers", "main", "imports", "outputs",
            )},
            *{f"policy/{name}.rego" for name in (
                "least_privilege", "protected_rulesets", "workflow_sources", "oidc_subjects", "environment_approvals",
            )},
            *{f"policy/tests/{name}_test.rego" for name in (
                "least_privilege", "protected_rulesets", "workflow_sources", "oidc_subjects", "environment_approvals",
            )},
            "tests/contract/test_catalog_schema.py", "tests/contract/test_compiler_determinism.py",
            "tests/plan/test_ruleset_plan.py", "tests/plan/test_permission_reduction.py",
            "tests/drift/test_observed_state_diff.py", "tests/recovery/test_last_known_good_restore.py",
            *{f"runbooks/{name}.md" for name in (
                "unauthorized-settings-change", "oidc-policy-lockout", "compromised-github-app", "governance-state-restore",
            )},
        }
        ignored_directories = {".git", "__pycache__", ".pytest_cache", ".terraform"}
        actual = set()
        source_symlinks = []
        for directory, children, files in os.walk(ROOT, followlinks=False):
            relative_directory = Path(directory).relative_to(ROOT)
            for child in children:
                child_path = Path(directory) / child
                if child_path.is_symlink() and child not in ignored_directories and not child.startswith("bazel-"):
                    source_symlinks.append((relative_directory / child).as_posix())
            children[:] = [
                child for child in children
                if child not in ignored_directories and not child.startswith("bazel-")
            ]
            for name in files:
                path = Path(directory) / name
                relative = path.relative_to(ROOT).as_posix()
                if relative == "MODULE.bazel.lock" or name == ".DS_Store" or name.endswith((".pyc", ".pyo")):
                    continue
                if path.is_symlink():
                    source_symlinks.append(relative)
                actual.add(relative)
        self.assertEqual(source_symlinks, [], "blueprint source paths must be regular, non-symlink files")
        self.assertEqual(actual, expected)

    def test_policy_input_contains_raw_envelopes_and_real_workflow_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "policy-input.json"
            result = invoke("policy-input", "--output", str(output))
            self.assertEqual(result.returncode, 0, result.stderr)
            policy_input = json.loads(output.read_text())
        self.assertEqual(policy_input["organization"]["kind"], "Organization")
        self.assertEqual(len(policy_input["memberships"]), 2)
        self.assertEqual(len(policy_input["repositories"]), 6)
        self.assertEqual(len(policy_input["rulesets"]), 5)
        self.assertEqual(len(policy_input["repository_gates"]), 1)
        self.assertEqual(len(policy_input["environments"]), 6)
        self.assertEqual(len(policy_input["workflows"]), 3)
        self.assertTrue(all(workflow["uses"] for workflow in policy_input["workflows"]))
        self.assertNotIn(
            "pull_request_target",
            {event for workflow in policy_input["workflows"] for event in workflow["events"]},
        )

    def test_oidc_jobs_do_not_run_always_third_party_steps_after_failed_gates(self):
        drift = (ROOT / ".github" / "workflows" / "drift-detection.yml").read_text()
        protected = (ROOT / ".github" / "workflows" / "protected-apply.yml").read_text()
        for source in (drift, protected):
            self.assertNotIn("if: ${{ always() }}\n        uses:", source)

        drift_upload = next(
            line.strip() for line in drift.splitlines()
            if "steps.pre-auth-contract-gate.outcome" in line and "steps.policy-gate.outcome" in line
        )
        for gate in (
            "pre-auth-contract-gate", "identity-gate", "policy-gate", "static-contract-gate",
            "google-auth", "app-key", "app-token", "contract-gate",
        ):
            self.assertIn(f"steps.{gate}.outcome == 'success'", drift_upload)

        apply_upload = next(
            line.strip() for line in protected.splitlines()
            if "steps.pre-auth-contract-gate.outcome" in line and "steps.source-revalidation.outcome" in line
        )
        for gate in (
            "pre-auth-contract-gate", "source-revalidation", "identity-gate", "static-contract-gate",
            "google-auth", "app-key", "app-token", "contract-gate",
        ):
            self.assertIn(f"steps.{gate}.outcome == 'success'", apply_upload)

        report_job = drift.split("\n  report:\n", 1)[1]
        self.assertNotIn("id-token: write", report_job)
        self.assertIn("issues: write", report_job)
        self.assertNotIn("permission-security-events: write", protected)
        self.assertGreaterEqual(protected.count("permission-security-events: read"), 2)

    def test_duplicate_alias_unknown_and_secret_inputs_fail_closed(self):
        cases = {
            "duplicate": "\nkind: Organization\n",
            "alias": "\nforbidden_anchor: &shared value\nforbidden_alias: *shared\n",
            "unknown": "\nunexpected_test_field: true\n",
            "secret": "\naccess_token: ghp_abcdefghijklmnopqrstuvwxyz123456\n",
        }
        for label, addition in cases.items():
            with self.subTest(label=label):
                root = self.temporary_catalog()
                organization = root / "config" / "organization.yaml"
                organization.write_text(organization.read_text() + addition)
                result = invoke("validate", root=root)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("ghp_", result.stderr)

    def test_unknown_file_and_symlink_are_rejected(self):
        root = self.temporary_catalog()
        (root / "config" / "unmanaged.yaml").write_text("{}\n")
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected file", result.stderr)

        root = self.temporary_catalog()
        link = root / "config" / "teams" / "linked.yaml"
        try:
            link.symlink_to(root / "config" / "teams" / "security.yaml")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable")
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr.lower())

    def test_repository_access_and_environment_reviewer_invariants(self):
        root = self.temporary_catalog()
        repository = root / "config" / "repositories" / "github-config.yaml"
        repository.write_text(repository.read_text().replace("permission: maintain", "permission: admin", 1))
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)

        root = self.temporary_catalog()
        environment = root / "config" / "environments" / "trusted-build.yaml"
        environment.write_text(environment.read_text().replace("      team: security", "      team: biological-safety", 1))
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not have repository access", result.stderr)

        root = self.temporary_catalog()
        environment = root / "config" / "environments" / "release-signing.yaml"
        environment.write_text(environment.read_text().replace("state: blocked", "state: ready", 1))
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no exact immutable OIDC subject authority", result.stderr)

        root = self.temporary_catalog()
        environment = root / "config" / "environments" / "security-source-review.yaml"
        environment.write_text(environment.read_text().replace("      team: security", "      team: platform-operations", 1))
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("distinct reviewer authority teams", result.stderr)

    def test_semantic_identity_and_security_policy_invariants(self):
        root = self.temporary_catalog()
        actions = root / "config" / "actions-policy.yaml"
        actions.write_text(actions.read_text().replace("source: bazel-contrib/setup-bazel", "source: actions/checkout"))
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate allowed action source", result.stderr)

        root = self.temporary_catalog()
        integration = root / "config" / "integrations" / "artifact-signing.yaml"
        integration.write_text(integration.read_text().replace("name: attestations", "name: actions"))
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate integration permission", result.stderr)

        root = self.temporary_catalog()
        repository = root / "config" / "repositories" / "github-config.yaml"
        repository.write_text(repository.read_text().replace("secret_scanning: true", "secret_scanning: false", 1))
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be enabled by security policy", result.stderr)

    def test_outside_collaborators_require_managed_sponsors_and_max_permission(self):
        collaborator = """outside_collaborators:
    - login: external-reviewer
      principal_id: external-reviewer
      sponsor_login: unknown-sponsor
      expires_on: 2027-12-31
      justification: Time-bounded external review engagement.
      approval_reference: GOV-1234
      repository_permissions:
        - repository: github-config
          permission: maintain"""
        root = self.temporary_catalog()
        outside = root / "config" / "outside-collaborators.yaml"
        outside.write_text(outside.read_text().replace("outside_collaborators: []", collaborator))
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not an active managed organization member", result.stderr)

        root = self.temporary_catalog()
        outside = root / "config" / "outside-collaborators.yaml"
        outside.write_text(outside.read_text().replace(
            "outside_collaborators: []",
            collaborator.replace("unknown-sponsor", "external-reviewer"),
        ))
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot sponsor itself", result.stderr)

        root = self.temporary_catalog()
        outside = root / "config" / "outside-collaborators.yaml"
        outside_sponsor = collaborator.replace(
            "login: external-reviewer", "login: external-sponsor",
        ).replace("unknown-sponsor", "robpearc")
        sponsored_collaborator = collaborator.replace(
            "unknown-sponsor", "external-sponsor",
        ).replace("outside_collaborators:\n", "", 1)
        outside.write_text(outside.read_text().replace(
            "outside_collaborators: []",
            outside_sponsor + "\n" + sponsored_collaborator,
        ))
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not an active managed organization member", result.stderr)

        root = self.temporary_catalog()
        outside = root / "config" / "outside-collaborators.yaml"
        outside.write_text(outside.read_text().replace(
            "outside_collaborators: []",
            collaborator
            .replace("unknown-sponsor", "robpearc")
            .replace("principal_id: external-reviewer", "principal_id: founder-primary"),
        ))
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must have distinct principal_id values", result.stderr)

        root = self.temporary_catalog()
        outside = root / "config" / "outside-collaborators.yaml"
        outside.write_text(outside.read_text().replace(
            "outside_collaborators: []",
            collaborator.replace("unknown-sponsor", "robpearc"),
        ))
        result = invoke("validate", root=root)
        self.assertEqual(result.returncode, 0, result.stderr)

        root = self.temporary_catalog()
        outside = root / "config" / "outside-collaborators.yaml"
        outside.write_text(outside.read_text().replace(
            "outside_collaborators: []",
            collaborator
            .replace("unknown-sponsor", "robpearc")
            .replace("2027-12-31", "2027-02-30"),
        ))
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not satisfy membership.schema.json", result.stderr)

        root = self.temporary_catalog()
        outside = root / "config" / "outside-collaborators.yaml"
        outside.write_text(
            outside.read_text()
            .replace("max_permission: maintain", "max_permission: pull")
            .replace("outside_collaborators: []", collaborator.replace("unknown-sponsor", "robpearc"))
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exceeds max_permission", result.stderr)

    def test_qualified_integration_attestation_is_self_digesting_and_time_bounded(self):
        root = self.temporary_catalog()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        attestation = {
            "authority": "bootstrap",
            "source_sha": "a" * 40,
            "app_id": 123,
            "installation_id": 456,
            "repository_selection": "selected",
            "repositories": [{"name": "mindclade", "id": 789}],
            "permissions": [
                {"name": "checks", "access": "write"},
                {"name": "contents", "access": "read"},
                {"name": "metadata", "access": "read"},
                {"name": "pull_requests", "access": "read"},
                {"name": "statuses", "access": "write"},
            ],
            "events": ["check_run", "check_suite", "pull_request", "push"],
            "created_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        }
        digest = "sha256:" + hashlib.sha256(
            (json.dumps(attestation, sort_keys=True, indent=2) + "\n").encode()
        ).hexdigest()
        integration = root / "config" / "integrations" / "buildkite.yaml"
        source = integration.read_text().replace(
            "  type: github_app\n", "  type: github_app\n  actor_id: 123\n", 1,
        )
        source = source.replace(
            "  qualification:\n    state: blocked\n    authority: bootstrap",
            f"""  qualification:
    state: qualified
    authority: bootstrap
    evidence_digest: {digest}
    attestation:
      authority: bootstrap
      source_sha: {'a' * 40}
      app_id: 123
      installation_id: 456
      repository_selection: selected
      repositories:
        - name: mindclade
          id: 789
      permissions:
        - name: checks
          access: write
        - name: contents
          access: read
        - name: metadata
          access: read
        - name: pull_requests
          access: read
        - name: statuses
          access: write
      events: [check_run, check_suite, pull_request, push]
      created_at: {attestation['created_at']}
      expires_at: {attestation['expires_at']}""",
            1,
        )
        integration.write_text(source)
        result = invoke("validate", root=root)
        self.assertEqual(result.returncode, 0, result.stderr)

        integration.write_text(source.replace(digest, "sha256:" + "0" * 64, 1))
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("evidence_digest does not match", result.stderr)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
