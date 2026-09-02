# pyright: basic, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI = os.environ.get("GITHUB_CONFIGCTL") or (sys.argv[1] if len(sys.argv) > 1 else "")
EXPORT_PUBLIC_KEY_PEM_B64 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFWGxweHIzcUJIenBXUTl4N2JuZFJmTDlBdTZCRApGb0syQnJ2RDZvd0JrSHo1dEtmM3RtSTZrZjRuRDdnODhFZUMzV2JhVzhNN1dmaDFhUjR4RUJyTWhnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
EXPORT_PUBLIC_KEY_DIGEST = "sha256:93009eb9d670bf27e3df2c42773636588f0c351b5a4b3ce3f82db827302d83fb"
EXPORT_KEY_VERSION = "projects/signing-root/locations/us-central1/keyRings/bootstrap-signing/cryptoKeys/infrastructure-export/cryptoKeyVersions/1"


def qualified_infrastructure_apply_variables():
    values = {
        "CI_EVIDENCE_ARCHIVE_BUCKET": "production-ci-evidence",
        "CI_EVIDENCE_VERIFIER_SERVICE_ACCOUNT": "ci-evidence-verifier@identity-root.iam.gserviceaccount.com",
        "CI_EVIDENCE_VERIFIER_WIF_PROVIDER": "projects/123/locations/global/workloadIdentityPools/github-ci-evidence/providers/verifier",
    }
    for environment in ("DEVELOPMENT", "STAGING", "PRODUCTION", "RESTRICTED"):
        values[f"INFRASTRUCTURE_EXPORT_KMS_KEY_VERSION_{environment}"] = EXPORT_KEY_VERSION
        values[f"INFRASTRUCTURE_EXPORT_PUBLIC_KEY_PEM_B64_{environment}"] = (
            EXPORT_PUBLIC_KEY_PEM_B64
        )
        values[f"INFRASTRUCTURE_EXPORT_PUBLIC_KEY_DIGEST_{environment}"] = EXPORT_PUBLIC_KEY_DIGEST
    return "  variables:\n" + "".join(f"    {name}: {value}\n" for name, value in values.items())


def invoke(*arguments, root=ROOT, environment=None):
    if CLI:
        command = [str(Path(CLI).resolve())]
        cwd = ROOT
    else:
        command = ["go", "run", "./cmd/github-configctl"]
        cwd = ROOT / "compiler"
    env = os.environ.copy()
    env.update(environment or {})
    return subprocess.run(
        [*command, "--root", str(root), *arguments],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


class CatalogSchemaTest(unittest.TestCase):
    def temporary_catalog(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        shutil.copytree(ROOT / "config", root / "config")
        shutil.copytree(ROOT / "schemas", root / "schemas")
        shutil.copy2(ROOT / "component.yaml", root / "component.yaml")
        self.addCleanup(temporary.cleanup)
        return root

    def test_authoritative_catalog_validates_and_has_contract_shape(self):
        result = invoke("validate")
        self.assertEqual(result.returncode, 0, result.stderr)
        validation = json.loads(result.stdout)
        self.assertEqual(validation["status"], "valid")
        self.assertRegex(validation["source_digest"], r"^sha256:[0-9a-f]{64}$")

    def test_public_free_estate_and_founder_exception_are_exact(self):
        result = invoke("compile", "--output", "-")
        self.assertEqual(result.returncode, 0, result.stderr)
        catalog = json.loads(result.stdout)
        organization = catalog["organization"]
        exception = organization["founder_bootstrap_exception"]
        self.assertEqual(organization["estate_profile"], "github-free-public")
        self.assertEqual(
            exception,
            {
                "id": "FBE-0001",
                "state": "UNUSED",
                "scope": "founder-bootstrap-only",
                "workflow_ref": "mindclade/github-config/.github/workflows/protected-apply.yml@refs/heads/main",
                "allowed_operations": [
                    "foundation-plan",
                    "foundation-apply",
                    "foundation-verification",
                ],
                "denied_operations": [
                    "adoption",
                    "enforcement",
                    "production-authority",
                    "exception-replay",
                ],
                "single_use_initial_state": "UNUSED",
                "single_use_terminal_state": "CONSUMED",
                "receipt_required": True,
                "receipt_digest_algorithm": "sha256",
                "principal_id": "founder-primary",
                "github_actor_accounts": ["mindclade-founder", "robpearc"],
                "minimum_distinct_actor_accounts": 2,
                "independent_principals": False,
                "production_authority": False,
                "expires_at": "2026-09-30T23:59:59Z",
            },
        )
        self.assertEqual(
            set(catalog["repositories"]),
            {
                "bootstrap",
                "dot-github",
                "github-config",
                "gitops",
                "infrastructure-live",
                "mindclade",
            },
        )
        for repository in catalog["repositories"].values():
            self.assertEqual(repository["visibility"], "public")
            expected_access = "organization" if repository["name"] == ".github" else "none"
            self.assertEqual(repository["actions_access_level"], expected_access)
            self.assertEqual(repository["custom_properties"]["data_classification"], "public")
            self.assertEqual(repository["custom_properties"]["production_authority"], "none")

        component = (ROOT / "component.yaml").read_text()
        self.assertIn("data_classification: public", component)
        self.assertIn("production_authority: false", component)
        workflow = (ROOT / ".github" / "workflows" / "protected-apply.yml").read_text()
        for source_contract in (
            "FBE-0001",
            "founder-bootstrap-only",
            "independent-principals",
            "independent_principals: false",
            "production_authority: false",
            "GHCFG_INDEPENDENT_REVIEWER_ACTOR_IDS",
            'state: "UNUSED"',
            'state: "CONSUMED"',
            "foundation-verification",
            "exception-replay",
            "receipt_digest_algorithm",
        ):
            self.assertIn(source_contract, workflow)

    def test_founder_projection_rejects_weak_or_replayable_shapes(self):
        replacements = (
            ("state: UNUSED", "state: active"),
            (
                "workflow_ref: mindclade/github-config/.github/workflows/protected-apply.yml@refs/heads/main",
                "workflow_ref: mindclade/github-config/.github/workflows/drift-detection.yml@refs/heads/main",
            ),
            ("- foundation-apply", "- enforcement"),
            ("receipt_required: true", "receipt_required: false"),
            ("state: UNUSED", "state: CONSUMED"),
        )
        for old, new in replacements:
            with self.subTest(replacement=new):
                root = self.temporary_catalog()
                organization = root / "config" / "organization.yaml"
                organization.write_text(organization.read_text().replace(old, new, 1))
                result = invoke("validate", root=root)
                self.assertNotEqual(result.returncode, 0)

        root = self.temporary_catalog()
        organization = root / "config" / "organization.yaml"
        organization.write_text(
            organization.read_text().replace(
                "    receipt_digest_algorithm: sha256\n",
                "    receipt_digest_algorithm: sha256\n"
                f"    consumption_receipt_digest: sha256:{'0' * 64}\n",
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)

        root = self.temporary_catalog()
        organization = root / "config" / "organization.yaml"
        consumed = organization.read_text().replace("state: UNUSED", "state: CONSUMED", 1)
        consumed = consumed.replace(
            "    receipt_digest_algorithm: sha256\n",
            "    receipt_digest_algorithm: sha256\n"
            f"    consumption_receipt_digest: sha256:{'1' * 64}\n",
            1,
        )
        organization.write_text(consumed)
        result = invoke("validate", root=root)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_oidc_lifecycle_accepts_exact_blocked_and_connected_profiles(self):
        result = invoke("compile", "--output", "-")
        self.assertEqual(result.returncode, 0, result.stderr)
        activation = json.loads(result.stdout)["oidc_policy"]["activation"]
        self.assertEqual(activation["state"], "FOUNDER_BOOTSTRAPPED")
        self.assertEqual(activation["exception_ref"], "FBE-0001")
        self.assertEqual(activation["gated_subject_ids"], [])
        self.assertEqual(
            activation["blockers"],
            [
                "independent-review-not-connected-qualified",
                "production-authority-disabled",
            ],
        )

        root = self.temporary_catalog()
        oidc = root / "config" / "oidc-policy.yaml"
        prefix = oidc.read_text().split("  activation:\n", 1)[0]
        now = datetime.now(UTC).replace(microsecond=0)
        source_sha = "a" * 40
        qualification = {
            "authority": "bootstrap",
            "source_sha": source_sha,
            "workflow_ref": (
                "mindclade/bootstrap/.github/workflows/protected-apply.yml@" + source_sha
            ),
            "independent_principal_ids": ["founder-primary", "security-independent"],
            "created_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        }
        qualification_digest = (
            "sha256:"
            + hashlib.sha256(
                (json.dumps(qualification, sort_keys=True, indent=2) + "\n").encode()
            ).hexdigest()
        )
        active_yaml = "".join(
            f"      - {subject_id}\n" for subject_id in activation["active_subject_ids"]
        )
        connected = f"""  activation:
    state: CONNECTED_QUALIFIED
    active_subject_ids:
{active_yaml}    gated_subject_ids: []
    blockers: []
    connected_qualification:
      authority: bootstrap
      source_sha: {source_sha}
      workflow_ref: {qualification["workflow_ref"]}
      independent_principal_ids:
        - founder-primary
        - security-independent
      created_at: {qualification["created_at"]}
      expires_at: {qualification["expires_at"]}
      evidence_digest: {qualification_digest}
"""
        oidc.write_text(prefix + connected)
        connected_result = invoke("validate", root=root)
        self.assertEqual(connected_result.returncode, 0, connected_result.stderr)

        oidc.write_text(
            (prefix + connected).replace(
                "    state: CONNECTED_QUALIFIED\n",
                "    state: CONNECTED_QUALIFIED\n    exception_ref: FBE-0001\n",
                1,
            )
        )
        leaked = invoke("validate", root=root)
        self.assertNotEqual(leaked.returncode, 0)

        oidc.write_text((prefix + connected).replace(qualification_digest, "sha256:" + "0" * 64))
        tampered = invoke("validate", root=root)
        self.assertNotEqual(tampered.returncode, 0)
        self.assertIn("evidence_digest does not match", tampered.stderr)

        blocked_active = activation["active_subject_ids"][:11]
        blocked_gated = activation["active_subject_ids"][11:]
        blocked = """  activation:
    state: BLOCKED
    active_subject_ids:
{}    gated_subject_ids:
{}    blockers:
      - github-config-control-plane-federation-not-connected-qualified
      - infrastructure-drift-federation-not-connected-qualified
      - ci-evidence-federation-not-connected-qualified
""".format(
            "".join(f"      - {item}\n" for item in blocked_active),
            "".join(f"      - {item}\n" for item in blocked_gated),
        )
        oidc.write_text(prefix + blocked)
        blocked_result = invoke("validate", root=root)
        self.assertEqual(blocked_result.returncode, 0, blocked_result.stderr)

    def test_oidc_catalog_matches_sibling_bootstrap_federation_or_is_explicitly_blocked(self):
        bootstrap = ROOT.parent / "bootstrap"
        manifest_path = bootstrap / "manifests" / "identity-federation.yaml"
        signing_path = bootstrap / "manifests" / "signing-roots.yaml"
        compiler_path = bootstrap / "tooling" / "internal" / "manifest" / "manifest.go"
        if not manifest_path.is_file() or not signing_path.is_file() or not compiler_path.is_file():
            self.skipTest("sibling bootstrap canonical source is not present")

        result = invoke("compile", "--output", "-")
        self.assertEqual(result.returncode, 0, result.stderr)
        policy = json.loads(result.stdout)["oidc_policy"]
        subjects = {subject["id"]: subject for subject in policy["subjects"]}
        infrastructure_ids = {
            f"infrastructure-live-{environment}-{role}"
            for environment in ("development", "staging", "production", "restricted")
            for role in ("plan", "apply")
        }
        bootstrap_ids = {
            "bootstrap-protected-plan",
            "bootstrap-protected-apply",
            "bootstrap-recovery-verification",
        }
        gated_ids = {
            "github-config-drift-plan",
            "github-config-protected-plan",
            "github-config-protected-apply",
            "infrastructure-drift-plan",
            "infrastructure-ci-evidence-verifier",
        }
        self.assertEqual(
            set(subjects),
            infrastructure_ids | bootstrap_ids | gated_ids,
        )
        self.assertEqual(len(subjects), 16)

        manifest = manifest_path.read_text()
        active_block = re.search(
            r"^    activeSubjectIds:\n((?:      - [a-z0-9-]+\n)+)",
            manifest,
            re.MULTILINE,
        )
        gated_block = re.search(
            r"^    gatedSubjectIds:(?: \[\])?\n((?:      - [a-z0-9-]+\n)*)",
            manifest,
            re.MULTILINE,
        )
        blockers_block = re.search(
            r"^    blockers:(?: \[\])?\n((?:      - [a-z0-9-]+\n)*)",
            manifest,
            re.MULTILINE,
        )
        activation_state = re.search(
            r"^    state: ([A-Z_]+)$",
            manifest,
            re.MULTILINE,
        )
        activation_exception = re.search(
            r"^    exceptionRef: ([A-Z]+-[0-9]+)$",
            manifest,
            re.MULTILINE,
        )
        self.assertIsNotNone(active_block)
        self.assertIsNotNone(gated_block)
        self.assertIsNotNone(blockers_block)
        self.assertIsNotNone(activation_state)
        bootstrap_active_ids = set(re.findall(r"- ([a-z0-9-]+)", active_block.group(1)))
        bootstrap_gated_ids = set(re.findall(r"- ([a-z0-9-]+)", gated_block.group(1)))
        bootstrap_blockers = re.findall(r"- ([a-z0-9-]+)", blockers_block.group(1))
        if activation_state.group(1) == "FOUNDER_BOOTSTRAPPED":
            self.assertIsNotNone(activation_exception)
            self.assertEqual(activation_exception.group(1), "FBE-0001")
            self.assertEqual(
                bootstrap_active_ids,
                infrastructure_ids
                | bootstrap_ids
                | {
                    "github-config-protected-plan",
                    "github-config-protected-apply",
                },
            )
            self.assertEqual(
                bootstrap_gated_ids,
                {
                    "github-config-drift-plan",
                    "infrastructure-drift-plan",
                    "infrastructure-ci-evidence-verifier",
                },
            )
            self.assertEqual(
                bootstrap_blockers,
                [
                    "independent-review-not-connected-qualified",
                    "production-authority-disabled",
                ],
            )
            self.assertEqual(len(bootstrap_active_ids), 13)
            self.assertEqual(len(bootstrap_gated_ids), 3)
            expected_github_config_activation = "true"
            expected_infrastructure_drift_activation = "false"
            expected_ci_evidence_activation = "false"
        elif activation_state.group(1) == "CONNECTED_QUALIFIED":
            self.assertIsNone(activation_exception)
            self.assertEqual(
                bootstrap_active_ids,
                infrastructure_ids | bootstrap_ids | gated_ids,
            )
            self.assertEqual(bootstrap_gated_ids, set())
            self.assertEqual(bootstrap_blockers, [])
            self.assertEqual(len(bootstrap_active_ids), 16)
            expected_github_config_activation = "true"
            expected_infrastructure_drift_activation = "true"
            expected_ci_evidence_activation = "true"
        else:
            self.assertEqual(activation_state.group(1), "BLOCKED")
            self.assertIsNone(activation_exception)
            self.assertEqual(bootstrap_active_ids, infrastructure_ids | bootstrap_ids)
            self.assertEqual(bootstrap_gated_ids, gated_ids)
            self.assertEqual(
                bootstrap_blockers,
                [
                    "github-config-control-plane-federation-not-connected-qualified",
                    "infrastructure-drift-federation-not-connected-qualified",
                    "ci-evidence-federation-not-connected-qualified",
                ],
            )
            self.assertEqual(len(bootstrap_active_ids), 11)
            self.assertEqual(len(bootstrap_gated_ids), 5)
            expected_github_config_activation = "false"
            expected_infrastructure_drift_activation = "false"
            expected_ci_evidence_activation = "false"
        for subject_id in sorted(infrastructure_ids):
            identity = subject_id.removeprefix("infrastructure-live-")
            subject = subjects[subject_id]
            expected_environment = (
                "trusted-build" if identity.endswith("-plan") else "infrastructure-apply"
            )
            self.assertEqual(subject["workload_identity_provider_ref"], identity)
            self.assertEqual(subject["service_account_ref"], identity)
            self.assertEqual(subject["context"]["value"], expected_environment)
            block = re.compile(
                rf"^        {re.escape(identity)}:\n"
                rf"          providerId: {re.escape(identity)}\n"
                rf"          environment: {re.escape(expected_environment)}\n"
                rf"          allowedAudience:\n"
                rf"            literal: {re.escape(subject['audience'])}\n"
                rf"          serviceAccount:\n"
                rf"            projectRef: [a-z0-9-]+\n"
                rf"            accountId: {re.escape(identity)}\n",
                re.MULTILINE,
            )
            self.assertRegex(manifest, block)

        compiler = compiler_path.read_text()
        self.assertIn("githubAudiences[role] = githubAudienceBase", compiler)
        self.assertIn('githubAudienceBase != "sts.googleapis.com"', compiler)
        for role, subject_id in (
            ("plan", "bootstrap-protected-plan"),
            ("apply", "bootstrap-protected-apply"),
            ("recovery", "bootstrap-recovery-verification"),
        ):
            subject = subjects[subject_id]
            self.assertEqual(subject["workload_identity_provider_ref"], f"github-actions-{role}")
            self.assertEqual(subject["service_account_ref"], f"bootstrap-{role}")
            self.assertEqual(subject["audience"], "sts.googleapis.com")
            self.assertIn(f"accountId: bootstrap-{role}", manifest)

        github_config_section = manifest.split("    github-config:\n", 1)[1].split(
            "    github-infrastructure:\n",
            1,
        )[0]
        self.assertIn(
            f"      activationEnabled: {expected_github_config_activation}",
            github_config_section,
        )
        for identity, subject_ids in (
            ("plan", ("github-config-drift-plan", "github-config-protected-plan")),
            ("apply", ("github-config-protected-apply",)),
        ):
            self.assertRegex(
                github_config_section,
                rf"(?m)^        {identity}:\n"
                rf"          providerId: github-config-{identity}\n"
                rf"          serviceAccountId: github-config-{identity}\n",
            )
            for subject_id in subject_ids:
                subject = subjects[subject_id]
                workflow_ref = (
                    f"mindclade/{subject['repository']}/{subject['workflow']}@refs/heads/main"
                )
                self.assertRegex(
                    github_config_section,
                    rf"(?m)^            - id: {re.escape(subject_id)}\n"
                    rf"              workflowRef: {re.escape(workflow_ref)}\n"
                    rf"              contextType: {re.escape(subject['context']['type'])}\n"
                    rf"              contextValue: {re.escape(subject['context']['value'])}\n"
                    rf"              audience: {re.escape(subject['audience'])}$",
                )

        infrastructure_section = manifest.split("    github-infrastructure:\n", 1)[1].split(
            "    github-ci-evidence:\n",
            1,
        )[0]
        drift = subjects["infrastructure-drift-plan"]
        self.assertRegex(
            infrastructure_section,
            r"(?m)^      drift:\n"
            rf"        activationEnabled: {expected_infrastructure_drift_activation}\n"
            r"        subjectId: infrastructure-drift-plan\n"
            r"        providerId: infrastructure-plan\n"
            r"        serviceAccountId: infrastructure-plan\n"
            r"        workflowRef: mindclade/infrastructure-live/\.github/workflows/drift-detection\.yml@refs/heads/main\n"
            r"        environment: trusted-build\n"
            r"        allowedAudience: sts\.googleapis\.com$",
        )
        self.assertEqual(drift["audience"], "sts.googleapis.com")

        ci_evidence_section = manifest.split("    github-ci-evidence:\n", 1)[1].split(
            "    buildkite:\n",
            1,
        )[0]
        self.assertIn(
            f"      activationEnabled: {expected_ci_evidence_activation}",
            ci_evidence_section,
        )
        verifier = subjects["infrastructure-ci-evidence-verifier"]
        self.assertEqual(verifier["workload_identity_provider_ref"], "verifier")
        self.assertEqual(verifier["service_account_ref"], "ci-evidence-verifier")
        self.assertEqual(verifier["audience"], "canonical-provider-resource")
        verifier_section = ci_evidence_section.split("      verifier:\n", 1)[1]
        self.assertIn("        providerId: verifier", verifier_section)
        self.assertIn(
            "        workflowRef:\n"
            "          literal: mindclade/infrastructure-live/.github/workflows/disaster-recovery.yml@refs/heads/main",
            verifier_section,
        )
        self.assertIn("        environment: infrastructure-apply", verifier_section)
        self.assertIn("          accountId: ci-evidence-verifier", verifier_section)
        self.assertNotIn("allowedAudience", verifier_section)

        signing = signing_path.read_text()
        signing_section = signing.split("    github-config-plan-evidence:\n", 1)[1].split(
            "    infrastructure-export:\n",
            1,
        )[0]
        self.assertIn("      purpose: ASYMMETRIC_SIGN", signing_section)
        self.assertIn("      algorithm: EC_SIGN_P256_SHA256", signing_section)
        self.assertIn("      protectionLevel: HSM", signing_section)
        self.assertIn("          env: GITHUB_CONFIG_PLAN_EVIDENCE_SIGNER", signing_section)

        local_activation = policy["activation"]
        self.assertEqual(local_activation["state"], "FOUNDER_BOOTSTRAPPED")
        self.assertEqual(local_activation["exception_ref"], "FBE-0001")
        self.assertEqual(set(local_activation["active_subject_ids"]), set(subjects))
        self.assertEqual(local_activation["gated_subject_ids"], [])
        self.assertEqual(
            local_activation["blockers"],
            [
                "independent-review-not-connected-qualified",
                "production-authority-disabled",
            ],
        )

    def test_dot_github_catalog_and_implementation_revisions_have_template_closure(self):
        policy = (ROOT / "config" / "actions-policy.yaml").read_text()
        authority = re.search(
            r"- repository: \.github\n"
            r"\s+revision: ([0-9a-f]{40})\n"
            r"\s+implementation_revision: ([0-9a-f]{40})\n",
            policy,
        )
        self.assertIsNotNone(authority)
        catalog_revision, implementation_revision = authority.groups()
        self.assertNotEqual(catalog_revision, implementation_revision)

        repository = ROOT.parent / ".github"
        if not (repository / ".git").exists():
            self.skipTest("sibling .github canonical source is not present")
        for revision in (catalog_revision, implementation_revision):
            result = subprocess.run(
                ["git", "-C", str(repository), "cat-file", "-e", f"{revision}^{{commit}}"],
                check=False,
            )
            self.assertEqual(result.returncode, 0, f"missing .github authority revision {revision}")
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "merge-base",
                "--is-ancestor",
                implementation_revision,
                catalog_revision,
            ],
            check=False,
        )
        self.assertEqual(result.returncode, 0, "implementation revision is not catalog ancestry")

        expected_templates = {
            "workflow-templates/buildkite-bridge.yml",
            "workflow-templates/repository-metadata.yml",
        }
        referenced_workflows = set()
        reference_pattern = re.compile(
            r"mindclade/\.github/\.github/workflows/([A-Za-z0-9_.-]+\.ya?ml)@([0-9a-f]{40})"
        )
        for template in expected_templates:
            content = subprocess.run(
                ["git", "-C", str(repository), "show", f"{catalog_revision}:{template}"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout
            references = reference_pattern.findall(content)
            self.assertTrue(references, f"{template} has no reusable-workflow reference")
            for workflow, revision in references:
                self.assertEqual(revision, implementation_revision)
                referenced_workflows.add(workflow)
        for workflow in referenced_workflows:
            result = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "cat-file",
                    "-e",
                    f"{implementation_revision}:.github/workflows/{workflow}",
                ],
                check=False,
            )
            self.assertEqual(result.returncode, 0, f"missing reusable workflow {workflow}")

    def test_reviewed_authority_revisions_have_sibling_source_closure(self):
        result = invoke("compile", "--output", "-")
        self.assertEqual(result.returncode, 0, result.stderr)
        authorities = json.loads(result.stdout)["actions_policy"]["authority_inventories"]
        reviewed = [item for item in authorities if item["activation"]["state"] == "reviewed"]
        self.assertEqual(
            {item["repository"] for item in reviewed},
            {".github", "bootstrap", "infrastructure-live"},
        )
        present = 0
        for authority in reviewed:
            repository = ROOT.parent / authority["repository"]
            if not (repository / ".git").exists():
                continue
            present += 1
            revision = authority["revision"]
            with self.subTest(repository=authority["repository"], revision=revision):
                result = subprocess.run(
                    ["git", "-C", str(repository), "cat-file", "-e", f"{revision}^{{commit}}"],
                    check=False,
                )
                self.assertEqual(result.returncode, 0, "reviewed revision is unavailable")
                result = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(repository),
                        "merge-base",
                        "--is-ancestor",
                        revision,
                        "refs/heads/main",
                    ],
                    check=False,
                )
                self.assertEqual(result.returncode, 0, "reviewed revision is not on canonical main")
                main_revision = subprocess.run(
                    ["git", "-C", str(repository), "rev-parse", "refs/heads/main"],
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                ).stdout.strip()
                self.assertEqual(
                    revision, main_revision, "reviewed revision is stale relative to sibling main"
                )
                for workflow in authority["workflows"]:
                    result = subprocess.run(
                        [
                            "git",
                            "-C",
                            str(repository),
                            "cat-file",
                            "-e",
                            f"{revision}:.github/workflows/{workflow}",
                        ],
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, f"missing workflow {workflow}")
        if present == 0:
            self.skipTest("no sibling canonical authority repositories are present")

    def test_infrastructure_handoff_and_drift_audience_match_reviewed_authority(self):
        repository = ROOT.parent / "infrastructure-live"
        if not (repository / ".git").exists():
            self.skipTest("sibling infrastructure-live canonical source is not present")
        result = invoke("compile", "--output", "-")
        self.assertEqual(result.returncode, 0, result.stderr)
        catalog = json.loads(result.stdout)
        authority = next(
            item
            for item in catalog["actions_policy"]["authority_inventories"]
            if item["repository"] == "infrastructure-live"
        )
        self.assertEqual(authority["activation"]["state"], "reviewed")
        revision = authority["revision"]
        protected = subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "show",
                f"{revision}:.github/workflows/protected-apply.yml",
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        disaster_recovery = subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "show",
                f"{revision}:.github/workflows/disaster-recovery.yml",
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        drift_detection = subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "show",
                f"{revision}:.github/workflows/drift-detection.yml",
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        for environment in ("DEVELOPMENT", "STAGING", "PRODUCTION", "RESTRICTED"):
            for prefix in (
                "INFRASTRUCTURE_EXPORT_KMS_KEY_VERSION_",
                "INFRASTRUCTURE_EXPORT_PUBLIC_KEY_PEM_B64_",
                "INFRASTRUCTURE_EXPORT_PUBLIC_KEY_DIGEST_",
            ):
                self.assertIn(prefix + environment, protected)
        for variable in (
            "CI_EVIDENCE_VERIFIER_WIF_PROVIDER",
            "CI_EVIDENCE_VERIFIER_SERVICE_ACCOUNT",
            "CI_EVIDENCE_ARCHIVE_BUCKET",
        ):
            self.assertIn(variable, disaster_recovery)
        drift_subject = next(
            subject
            for subject in catalog["oidc_policy"]["subjects"]
            if subject["id"] == "infrastructure-drift-plan"
        )
        self.assertEqual(drift_subject["audience"], "sts.googleapis.com")
        self.assertEqual(
            re.findall(r"(?m)^\s+audience:\s+([^\s#]+)", drift_detection),
            [drift_subject["audience"]],
        )

    def test_component_metadata_is_truthful_and_complete(self):
        root = self.temporary_catalog()
        component = root / "component.yaml"
        source = component.read_text()
        for old, new, expected in (
            ("owner: developer-platform", "owner: security", "spec.owner"),
            ("trust_tier: privileged-governance", "trust_tier: ''", "spec.trust_tier"),
            ("production_authority: false", "production_authority: true", "production_authority"),
            ("  activation:\n", "  disconnected_activation:\n", "spec.activation"),
        ):
            with self.subTest(field=expected):
                component.write_text(source.replace(old, new, 1))
                result = invoke("validate", root=root)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)
                component.write_text(source)

    def test_repository_tree_matches_blueprint_inventory_exactly(self):
        expected = {
            ".bazelignore",
            ".bazelrc",
            ".bazelversion",
            ".editorconfig",
            ".gitignore",
            ".golangci.yml",
            ".markdownlint-cli2.yaml",
            ".pre-commit-config.yaml",
            ".vscode/extensions.json",
            ".vscode/settings.json",
            ".yamllint.yaml",
            "BUILD.bazel",
            "CONTRIBUTING.md",
            "LICENSE",
            "MODULE.bazel",
            "MODULE.bazel.lock",
            "README.md",
            "SECURITY.md",
            "component.yaml",
            "flake.lock",
            "flake.nix",
            "justfile",
            "biome.json",
            "pyproject.toml",
            ".github/CODEOWNERS",
            ".github/actionlint.yaml",
            ".github/dependabot.yml",
            ".github/pull_request_template.md",
            ".github/workflows/pull-request.yml",
            ".github/workflows/drift-detection.yml",
            ".github/workflows/protected-apply.yml",
            "config/organization.yaml",
            "config/actions-policy.yaml",
            "config/security-policy.yaml",
            "config/oidc-policy.yaml",
            "config/members.yaml",
            "config/outside-collaborators.yaml",
            *{
                f"config/teams/{name}.yaml"
                for name in (
                    "architecture",
                    "biological-safety",
                    "computational-biology",
                    "data-platform",
                    "developer-platform",
                    "ml-systems",
                    "platform-operations",
                    "product-engineering",
                    "release-engineering",
                    "security",
                )
            },
            *{
                f"config/repositories/{name}.yaml"
                for name in (
                    "dot-github",
                    "github-config",
                    "bootstrap",
                    "infrastructure-live",
                    "gitops",
                    "mindclade",
                )
            },
            *{
                f"config/rulesets/{name}.yaml"
                for name in (
                    "application-source",
                    "governance-source",
                    "infrastructure-source",
                    "deployment-source",
                    "release-tags",
                )
            },
            *{
                f"config/environments/{name}.yaml"
                for name in (
                    "trusted-build",
                    "release-signing",
                    "infrastructure-apply",
                    "production-promotion",
                )
            },
            *{
                f"config/integrations/{name}.yaml"
                for name in ("buildkite", "artifact-signing", "gitops-controller")
            },
            *{
                f"schemas/v1/{name}.schema.json"
                for name in (
                    "organization",
                    "actions_policy",
                    "security_policy",
                    "oidc_policy",
                    "membership",
                    "team",
                    "repository",
                    "ruleset",
                    "environment",
                    "integration",
                )
            },
            "compiler/cmd/github-configctl/main.go",
            "compiler/internal/catalog/catalog.go",
            "compiler/internal/validation/validation.go",
            "compiler/internal/rendering/rendering.go",
            "compiler/internal/diff/github_diff.go",
            "compiler/internal/evidence/plan_evidence.go",
            "compiler/go.mod",
            "compiler/go.sum",
            "compiler/BUILD.bazel",
            *{
                f"opentofu/modules/{module}/{name}.tf"
                for module in (
                    "organization-settings",
                    "repository-governance",
                    "team-access",
                    "ruleset",
                    "repository-environment",
                )
                for name in ("main", "variables", "outputs")
            },
            *{
                f"opentofu/live/organization/{name}.tf"
                for name in (
                    "backend",
                    "versions",
                    "providers",
                    "main",
                    "imports",
                    "outputs",
                )
            },
            *{
                f"policy/{name}.rego"
                for name in (
                    "least_privilege",
                    "protected_rulesets",
                    "workflow_sources",
                    "oidc_subjects",
                    "environment_approvals",
                )
            },
            *{
                f"policy/tests/{name}_test.rego"
                for name in (
                    "least_privilege",
                    "protected_rulesets",
                    "workflow_sources",
                    "oidc_subjects",
                    "environment_approvals",
                )
            },
            "tests/contract/test_catalog_schema.py",
            "tests/contract/test_compiler_determinism.py",
            "tests/plan/test_ruleset_plan.py",
            "tests/plan/test_permission_reduction.py",
            "tests/drift/test_observed_state_diff.py",
            "tests/recovery/test_last_known_good_restore.py",
            *{
                f"runbooks/{name}.md"
                for name in (
                    "unauthorized-settings-change",
                    "oidc-policy-lockout",
                    "compromised-github-app",
                    "governance-state-restore",
                )
            },
        }
        ignored_directories = {
            ".git",
            ".ruff_cache",
            "__pycache__",
            ".pytest_cache",
            ".terraform",
        }
        actual = set()
        source_symlinks = []
        for directory, children, files in os.walk(ROOT, followlinks=False):
            relative_directory = Path(directory).relative_to(ROOT)
            for child in children:
                child_path = Path(directory) / child
                if (
                    child_path.is_symlink()
                    and child not in ignored_directories
                    and not child.startswith("bazel-")
                ):
                    source_symlinks.append((relative_directory / child).as_posix())
            children[:] = [
                child
                for child in children
                if child not in ignored_directories and not child.startswith("bazel-")
            ]
            for name in files:
                path = Path(directory) / name
                relative = path.relative_to(ROOT).as_posix()
                if name == ".DS_Store" or name.endswith((".pyc", ".pyo")):
                    continue
                if relative_directory == Path() and name.startswith("bazel-") and path.is_symlink():
                    continue
                if path.is_symlink():
                    source_symlinks.append(relative)
                actual.add(relative)
        self.assertEqual(
            source_symlinks, [], "blueprint source paths must be regular, non-symlink files"
        )
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
        self.assertNotIn("repository_gates", policy_input)
        self.assertEqual(len(policy_input["environments"]), 4)
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
            line.strip()
            for line in drift.splitlines()
            if "steps.pre-auth-contract-gate.outcome" in line
            and "steps.policy-gate.outcome" in line
        )
        for gate in (
            "pre-auth-contract-gate",
            "identity-gate",
            "policy-gate",
            "static-contract-gate",
            "google-auth",
            "app-key",
            "app-token",
            "contract-gate",
        ):
            self.assertIn(f"steps.{gate}.outcome == 'success'", drift_upload)

        apply_upload = next(
            line.strip()
            for line in protected.splitlines()
            if "steps.pre-auth-contract-gate.outcome" in line
            and "steps.source-revalidation.outcome" in line
        )
        for gate in (
            "pre-auth-contract-gate",
            "source-revalidation",
            "identity-gate",
            "static-contract-gate",
            "google-auth",
            "app-key",
            "app-token",
            "contract-gate",
        ):
            self.assertIn(f"steps.{gate}.outcome == 'success'", apply_upload)

        report_job = drift.split("\n  report:\n", 1)[1]
        self.assertNotIn("id-token: write", report_job)
        self.assertIn("issues: write", report_job)
        self.assertNotIn("permission-security-events: write", protected)
        self.assertGreaterEqual(protected.count("permission-security-events: read"), 2)
        self.assertIn('gh api "repos/$GITHUB_REPOSITORY/pulls/$pull_number"', protected)
        self.assertIn(".html_url == $change_reference", protected)
        self.assertIn(".merge_commit_sha == $expected_sha", protected)
        self.assertIn(".commit_id == $pull_head_sha", protected)
        self.assertIn("reviewed_pull_head_sha: $pull_head_sha", protected)
        self.assertIn(
            "The merged change requires at least two distinct approving actors", protected
        )
        self.assertIn("reviewer_environment_approver_separation: true", protected)
        self.assertIn("review_context_digest=$review_context_digest", protected)
        apply_job = protected.split("\n  apply:\n", 1)[1]
        self.assertLess(
            apply_job.index("Authenticate reviewed evidence before apply identity exchange"),
            apply_job.index("Authenticate the apply cloud identity"),
        )
        self.assertGreaterEqual(
            apply_job.count('--signature "$RUNNER_TEMP/reviewed/plan-evidence.sig"'), 2
        )
        self.assertIn("gcloud kms asymmetric-sign", protected)
        self.assertIn(
            "keyRings/bootstrap-signing/cryptoKeys/github-config-plan-evidence/cryptoKeyVersions/",
            protected,
        )
        self.assertIn('--signature-algorithm "$PLAN_EVIDENCE_KMS_ALGORITHM"', protected)
        self.assertEqual(
            drift.count('implementation_destination="$authority_root/.github-implementation"'), 1
        )
        self.assertEqual(
            protected.count('implementation_destination="$authority_root/.github-implementation"'),
            2,
        )

    def test_governed_retirements_align_evidence_and_opentofu_lifecycle(self):
        environment_module = (
            ROOT / "opentofu" / "modules" / "repository-environment" / "main.tf"
        ).read_text()
        ruleset_module = (ROOT / "opentofu" / "modules" / "ruleset" / "main.tf").read_text()
        team_module = (ROOT / "opentofu" / "modules" / "team-access" / "main.tf").read_text()
        repository_module = (
            ROOT / "opentofu" / "modules" / "repository-governance" / "main.tf"
        ).read_text()

        environment_resource = environment_module.split(
            'resource "github_repository_environment" "this" {',
            1,
        )[1].split('resource "github_repository_environment_deployment_policy"', 1)[0]
        deployment_policy_resource = environment_module.split(
            'resource "github_repository_environment_deployment_policy" "this" {',
            1,
        )[1].split('resource "github_actions_environment_variable"', 1)[0]
        team_resource = team_module.split('resource "github_team" "this" {', 1)[1].split(
            'resource "github_organization_role_team"',
            1,
        )[0]
        repository_resource = repository_module.split(
            'resource "github_repository" "this" {',
            1,
        )[1].split('resource "github_repository_dependabot_security_updates"', 1)[0]

        self.assertNotIn("prevent_destroy", environment_resource)
        self.assertNotIn("prevent_destroy", deployment_policy_resource)
        self.assertNotIn("prevent_destroy", ruleset_module)
        self.assertNotIn("prevent_destroy", team_resource)
        self.assertIn("prevent_destroy = true", repository_resource)

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
        except OSError:
            self.skipTest("symlinks are unavailable")
        except NotImplementedError:
            self.skipTest("symlinks are unavailable")
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr.lower())

    def test_repository_access_and_environment_reviewer_invariants(self):
        root = self.temporary_catalog()
        repository = root / "config" / "repositories" / "github-config.yaml"
        repository.write_text(
            repository.read_text().replace("permission: maintain", "permission: admin", 1)
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)

        root = self.temporary_catalog()
        environment = root / "config" / "environments" / "trusted-build.yaml"
        environment.write_text(
            environment.read_text().replace(
                "      team: security", "      team: biological-safety", 1
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not have repository access", result.stderr)

        root = self.temporary_catalog()
        environment = root / "config" / "environments" / "release-signing.yaml"
        environment.write_text(environment.read_text().replace("state: blocked", "state: ready", 1))
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no exact immutable OIDC subject authority", result.stderr)

    def test_gitops_connected_governance_contract_fails_closed(self):
        cases = {
            "repository-owner": (
                "config/repositories/gitops.yaml",
                "owner_team: platform-operations",
                "owner_team: release-engineering",
                "owned by platform-operations",
            ),
            "codeowner-access": (
                "config/repositories/gitops.yaml",
                "    - team: security\n      permission: push\n",
                "    - team: security\n      permission: pull\n",
                'CODEOWNERS team "security"',
            ),
            "ruleset-owner": (
                "config/rulesets/deployment-source.yaml",
                "owner_team: platform-operations",
                "owner_team: release-engineering",
                "ruleset must be owned by platform-operations",
            ),
            "required-context": (
                "config/rulesets/deployment-source.yaml",
                "context: Pull request / required",
                "context: Pull request validation / required",
                "canonical Pull request / required",
            ),
            "rollback-authority": (
                "config/environments/production-promotion.yaml",
                "    - .github/workflows/rollback-verification.yml\n",
                "",
                "authorize exactly promotion and rollback verification",
            ),
            "workflow-activation": (
                "config/actions-policy.yaml",
                "gitops-thin-reusable-caller-qualification-pending",
                "gitops-authority-action-pin-parity-pending",
                "blocked on thin reusable caller qualification",
            ),
        }
        for label, (relative, old, new, expected) in cases.items():
            with self.subTest(label=label):
                root = self.temporary_catalog()
                path = root / relative
                source = path.read_text()
                self.assertIn(old, source)
                path.write_text(source.replace(old, new, 1))
                result = invoke("validate", root=root)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    def test_sibling_gitops_codeowners_have_explicit_write_access(self):
        gitops = ROOT.parent / "gitops"
        codeowners = gitops / ".github" / "CODEOWNERS"
        if not codeowners.is_file():
            self.skipTest("sibling GitOps CODEOWNERS source is not present")

        result = invoke("compile", "--output", "-")
        self.assertEqual(result.returncode, 0, result.stderr)
        repository = json.loads(result.stdout)["repositories"]["gitops"]
        ranks = {"pull": 1, "triage": 2, "push": 3, "maintain": 4}
        grants = {grant["team"]: ranks[grant["permission"]] for grant in repository["team_grants"]}
        owner_teams = set(re.findall(r"@mindclade/([a-z0-9-]+)", codeowners.read_text()))
        self.assertEqual(
            owner_teams,
            {"platform-operations", "release-engineering", "security"},
        )
        for team in owner_teams:
            self.assertGreaterEqual(grants.get(team, 0), ranks["push"], team)

    def test_every_local_codeowners_team_has_visible_write_access(self):
        root = self.temporary_catalog()
        (root / ".github").mkdir()
        shutil.copy2(ROOT / ".github" / "CODEOWNERS", root / ".github" / "CODEOWNERS")
        repository = root / "config" / "repositories" / "github-config.yaml"
        repository.write_text(
            repository.read_text().replace(
                "    - team: architecture\n      permission: push\n",
                "    - team: architecture\n      permission: pull\n",
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            'CODEOWNERS team "architecture" requires explicit push-or-higher', result.stderr
        )

        root = self.temporary_catalog()
        (root / ".github").mkdir()
        (root / ".github" / "CODEOWNERS").write_text("* @mindclade/undeclared-team\n")
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('CODEOWNERS team "undeclared-team" is not declared', result.stderr)

    def test_infrastructure_apply_environment_variables_are_activation_gated(self):
        root = self.temporary_catalog()
        environment = root / "config" / "environments" / "infrastructure-apply.yaml"
        environment.write_text(
            environment.read_text().replace(
                "  activation:\n",
                "  variables:\n"
                "    CI_EVIDENCE_VERIFIER_WIF_PROVIDER: projects/123/locations/global/workloadIdentityPools/github-ci-evidence/providers/verifier\n"
                "    CI_EVIDENCE_VERIFIER_SERVICE_ACCOUNT: ci-evidence-verifier@identity-root.iam.gserviceaccount.com\n"
                "    CI_EVIDENCE_ARCHIVE_BUCKET: production-ci-evidence\n"
                "  activation:\n",
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("variables", result.stderr)

        root = self.temporary_catalog()
        environment = root / "config" / "environments" / "infrastructure-apply.yaml"
        environment.write_text(
            environment.read_text().replace(
                "  activation:\n"
                "    state: blocked\n"
                "    blockers:\n"
                "      - independent-reviewer-required\n"
                "      - protected-environment-not-qualified\n"
                "      - ci-evidence-verifier-handoff-not-connected-qualified\n"
                "      - infrastructure-export-verifier-handoff-not-connected-qualified\n",
                qualified_infrastructure_apply_variables()
                + "  activation:\n    state: ready\n    blockers: []\n",
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertEqual(result.returncode, 0, result.stderr)

        environment.write_text(
            environment.read_text().replace(
                EXPORT_PUBLIC_KEY_PEM_B64,
                "bm90IGEgcGVt",
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one PKIX PUBLIC KEY PEM block", result.stderr)

        environment.write_text(
            environment.read_text().replace(
                "bm90IGEgcGVt",
                EXPORT_PUBLIC_KEY_PEM_B64,
                1,
            )
        )
        environment.write_text(
            environment.read_text().replace(
                EXPORT_PUBLIC_KEY_DIGEST,
                "sha256:" + "0" * 64,
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the decoded SPKI DER", result.stderr)

        environment.write_text(
            environment.read_text()
            .replace(
                "sha256:" + "0" * 64,
                EXPORT_PUBLIC_KEY_DIGEST,
                1,
            )
            .replace(
                f"INFRASTRUCTURE_EXPORT_KMS_KEY_VERSION_RESTRICTED: {EXPORT_KEY_VERSION}",
                "INFRASTRUCTURE_EXPORT_KMS_KEY_VERSION_RESTRICTED: "
                + EXPORT_KEY_VERSION.removesuffix("/1")
                + "/2",
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("all environment export-verifier tuples", result.stderr)

        root = self.temporary_catalog()
        environment = root / "config" / "environments" / "infrastructure-apply.yaml"
        environment.write_text(environment.read_text().replace("state: blocked", "state: ready", 1))
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("variables", result.stderr)

    def test_workflow_sharing_codeowners_and_custom_property_migration_are_fail_closed(self):
        root = self.temporary_catalog()
        dot_github = root / "config" / "repositories" / "dot-github.yaml"
        dot_github.write_text(
            dot_github.read_text().replace(
                "actions_access_level: organization",
                "actions_access_level: none",
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must share reusable workflows", result.stderr)

        root = self.temporary_catalog()
        dot_github = root / "config" / "repositories" / "dot-github.yaml"
        dot_github.write_text(
            dot_github.read_text().replace(
                "    - team: security\n      permission: push",
                "    - team: security\n      permission: pull",
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("security push-or-higher", result.stderr)

        root = self.temporary_catalog()
        security_team = root / "config" / "teams" / "security.yaml"
        security_team.write_text(
            security_team.read_text().replace("privacy: closed", "privacy: secret", 1)
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be organization-visible", result.stderr)

        root = self.temporary_catalog()
        product = root / "config" / "repositories" / "mindclade.yaml"
        product.write_text(
            product.read_text().replace(
                "actions_access_level: none",
                "actions_access_level: organization",
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only the organization .github repository", result.stderr)

        root = self.temporary_catalog()
        organization = root / "config" / "organization.yaml"
        organization.write_text(
            organization.read_text().replace(
                "owner_team: [platform]",
                "owner_team: [platform, security]",
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is already desired", result.stderr)

        root = self.temporary_catalog()
        organization = root / "config" / "organization.yaml"
        organization.write_text(
            organization.read_text().replace("phase: preserve", "phase: retire", 1)
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("retirement requires an empty", result.stderr)

    def test_semantic_identity_and_security_policy_invariants(self):
        root = self.temporary_catalog()
        oidc = root / "config" / "oidc-policy.yaml"
        oidc.write_text(
            oidc.read_text().replace(
                """    - id: infrastructure-live-staging-plan
      repository: infrastructure-live
      workflow: .github/workflows/protected-apply.yml
      context:
        type: environment
        value: trusted-build
      audience: https://github.mindclade.io/oidc/infrastructure-live/staging/plan
""",
                """    - id: infrastructure-live-staging-plan
      repository: infrastructure-live
      workflow: .github/workflows/protected-apply.yml
      context:
        type: environment
        value: trusted-build
      audience: https://github.mindclade.io/oidc/infrastructure-live/development/plan
""",
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate effective OIDC subject authority", result.stderr)

        root = self.temporary_catalog()
        oidc = root / "config" / "oidc-policy.yaml"
        oidc.write_text(
            oidc.read_text().replace(
                "workload_identity_provider_ref: github-config-plan",
                "workload_identity_provider_ref: github-config-apply",
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match its exact", result.stderr)

        root = self.temporary_catalog()
        oidc = root / "config" / "oidc-policy.yaml"
        oidc.write_text(
            oidc.read_text().replace(
                "    - id: github-config-drift-plan\n"
                "      repository: github-config\n"
                "      workflow: .github/workflows/drift-detection.yml\n"
                "      context:\n"
                "        type: ref\n"
                "        value: refs/heads/main\n"
                "      audience: sts.googleapis.com\n",
                "    - id: github-config-drift-plan\n"
                "      repository: github-config\n"
                "      workflow: .github/workflows/drift-detection.yml\n"
                "      context:\n"
                "        type: ref\n"
                "        value: refs/heads/main\n"
                "      audience: canonical-provider-resource\n",
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match its exact", result.stderr)

        root = self.temporary_catalog()
        oidc = root / "config" / "oidc-policy.yaml"
        oidc.write_text(
            oidc.read_text().replace(
                "    - id: infrastructure-ci-evidence-verifier\n"
                "      repository: infrastructure-live\n"
                "      workflow: .github/workflows/disaster-recovery.yml\n"
                "      context:\n"
                "        type: environment\n"
                "        value: infrastructure-apply\n"
                "      audience: canonical-provider-resource\n",
                "    - id: infrastructure-ci-evidence-verifier\n"
                "      repository: infrastructure-live\n"
                "      workflow: .github/workflows/disaster-recovery.yml\n"
                "      context:\n"
                "        type: environment\n"
                "        value: infrastructure-apply\n"
                "      audience: sts.googleapis.com\n",
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match its exact", result.stderr)

        root = self.temporary_catalog()
        actions = root / "config" / "actions-policy.yaml"
        actions.write_text(
            actions.read_text().replace(
                "source: opentofu/setup-opentofu", "source: actions/checkout"
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate allowed action source", result.stderr)

        result = invoke(
            "validate",
            environment={"MINDCLADE_REQUIRE_AUTHORITY_INVENTORIES": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires MINDCLADE_AUTHORITY_ROOT", result.stderr)

        root = self.temporary_catalog()
        shutil.copytree(ROOT / ".github" / "workflows", root / ".github" / "workflows")
        workflow = root / ".github" / "workflows" / "pull-request.yml"
        workflow.write_text(
            workflow.read_text().replace(
                "mindclade/.github/.github/workflows/reusable-nix-validation.yml@"
                "c097ef86c25991a400050c13e78574e8d3d8c071",
                "mindclade/.github/.github/workflows/reusable-required-check.yml@" + "a" * 40,
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("canonical .github implementation authority requires", result.stderr)

        root = self.temporary_catalog()
        shutil.copytree(ROOT / ".github" / "workflows", root / ".github" / "workflows")
        workflow = root / ".github" / "workflows" / "pull-request.yml"
        implementation_revision = re.search(
            r"- repository: \.github\n\s+revision: [0-9a-f]{40}\n"
            r"\s+implementation_revision: ([0-9a-f]{40})",
            (root / "config" / "actions-policy.yaml").read_text(),
        ).group(1)
        workflow.write_text(
            workflow.read_text().replace(
                "mindclade/.github/.github/workflows/reusable-nix-validation.yml@"
                "c097ef86c25991a400050c13e78574e8d3d8c071",
                "mindclade/.github/.github/workflows/not-declared.yml@" + implementation_revision,
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("absent from the canonical .github authority inventory", result.stderr)

        root = self.temporary_catalog()
        actions = root / "config" / "actions-policy.yaml"
        actions.write_text(
            actions.read_text().replace(
                "    - repository: mindclade\n",
                "    - repository: bootstrap\n",
                1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate canonical workflow authority", result.stderr)

        root = self.temporary_catalog()
        actions = root / "config" / "actions-policy.yaml"
        source = actions.read_text()
        catalog_revision = re.search(
            r"- repository: \.github\n\s+revision: ([0-9a-f]{40})",
            source,
        ).group(1)
        actions.write_text(
            re.sub(
                r"(\s+implementation_revision: )[0-9a-f]{40}",
                rf"\g<1>{catalog_revision}",
                source,
                count=1,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("distinct immutable catalog and implementation revisions", result.stderr)

        root = self.temporary_catalog()
        integration = root / "config" / "integrations" / "artifact-signing.yaml"
        integration.write_text(
            integration.read_text().replace("name: attestations", "name: actions")
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate integration permission", result.stderr)

        root = self.temporary_catalog()
        repository = root / "config" / "repositories" / "github-config.yaml"
        repository.write_text(
            repository.read_text().replace("secret_scanning: true", "secret_scanning: false", 1)
        )
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
        outside.write_text(
            outside.read_text().replace(
                "outside_collaborators: []",
                collaborator.replace("unknown-sponsor", "external-reviewer"),
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot sponsor itself", result.stderr)

        root = self.temporary_catalog()
        outside = root / "config" / "outside-collaborators.yaml"
        outside_sponsor = collaborator.replace(
            "login: external-reviewer",
            "login: external-sponsor",
        ).replace("unknown-sponsor", "robpearc")
        sponsored_collaborator = collaborator.replace(
            "unknown-sponsor",
            "external-sponsor",
        ).replace("outside_collaborators:\n", "", 1)
        outside.write_text(
            outside.read_text().replace(
                "outside_collaborators: []",
                outside_sponsor + "\n" + sponsored_collaborator,
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not an active managed organization member", result.stderr)

        root = self.temporary_catalog()
        outside = root / "config" / "outside-collaborators.yaml"
        outside.write_text(
            outside.read_text().replace(
                "outside_collaborators: []",
                collaborator.replace("unknown-sponsor", "robpearc").replace(
                    "principal_id: external-reviewer", "principal_id: founder-primary"
                ),
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must have distinct principal_id values", result.stderr)

        root = self.temporary_catalog()
        outside = root / "config" / "outside-collaborators.yaml"
        outside.write_text(
            outside.read_text().replace(
                "outside_collaborators: []",
                collaborator.replace("unknown-sponsor", "robpearc"),
            )
        )
        result = invoke("validate", root=root)
        self.assertEqual(result.returncode, 0, result.stderr)

        root = self.temporary_catalog()
        outside = root / "config" / "outside-collaborators.yaml"
        outside.write_text(
            outside.read_text().replace(
                "outside_collaborators: []",
                collaborator.replace("unknown-sponsor", "robpearc").replace(
                    "2027-12-31", "2027-02-30"
                ),
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not satisfy membership.schema.json", result.stderr)

        root = self.temporary_catalog()
        outside = root / "config" / "outside-collaborators.yaml"
        outside.write_text(
            outside.read_text()
            .replace("max_permission: maintain", "max_permission: pull")
            .replace(
                "outside_collaborators: []", collaborator.replace("unknown-sponsor", "robpearc")
            )
        )
        result = invoke("validate", root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exceeds max_permission", result.stderr)

    def test_ci_revalidates_exact_main_before_privileged_jobs(self):
        pull_request = (ROOT / ".github/workflows/pull-request.yml").read_text()
        protected_apply = (ROOT / ".github/workflows/protected-apply.yml").read_text()

        self.assertIn("push:\n    branches: [main]", pull_request)
        self.assertIn("accept-flake-config = false", protected_apply)
        validation = (
            "nix develop --no-accept-flake-config --no-update-lock-file .#ci --command just ci"
        )
        self.assertIn(validation, protected_apply)
        self.assertLess(protected_apply.index(validation), protected_apply.index("\n  plan:\n"))

    def test_qualified_integration_attestation_is_self_digesting_and_time_bounded(self):
        root = self.temporary_catalog()
        now = datetime.now(UTC).replace(microsecond=0)
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
        digest = (
            "sha256:"
            + hashlib.sha256(
                (json.dumps(attestation, sort_keys=True, indent=2) + "\n").encode()
            ).hexdigest()
        )
        integration = root / "config" / "integrations" / "buildkite.yaml"
        source = integration.read_text().replace(
            "  type: github_app\n",
            "  type: github_app\n  actor_id: 123\n",
            1,
        )
        source = source.replace(
            "  qualification:\n    state: blocked\n    authority: bootstrap",
            f"""  qualification:
    state: qualified
    authority: bootstrap
    evidence_digest: {digest}
    attestation:
      authority: bootstrap
      source_sha: {"a" * 40}
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
      created_at: {attestation["created_at"]}
      expires_at: {attestation["expires_at"]}""",
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
