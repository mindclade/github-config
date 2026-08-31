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


def invoke(*arguments, root=ROOT):
    if CLI:
        command, cwd = [str(Path(CLI).resolve())], ROOT
    else:
        command, cwd = ["go", "run", "./cmd/github-configctl"], ROOT / "compiler"
    return subprocess.run(
        [*command, "--root", str(root), *arguments],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def plan_json_digest(plan):
    projection = {
        key: plan[key]
        for key in ("format_version", "terraform_version", "resource_changes", "output_changes")
        if key in plan
    }
    canonical = (
        json.dumps(
            projection,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def write_dependency_analysis(path, plan, change_ids, change_reference="GOV-TEST"):
    path.write_text(
        json.dumps(
            {
                "api_version": "github.mindclade.io/v1",
                "kind": "DependencyAnalysis",
                "plan_json_digest": plan_json_digest(plan),
                "change_reference": change_reference,
                "destructive_changes": [
                    {
                        "change_id": change_id,
                        "dependencies": [],
                        "impact": "Reviewed removal has no undeclared dependent authority.",
                        "rollback": "Restore the reviewed catalog declaration and re-plan.",
                    }
                    for change_id in change_ids
                ],
            },
            sort_keys=True,
        )
    )


class LastKnownGoodRestoreTest(unittest.TestCase):
    def test_restore_reproduces_identical_catalog_and_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root = directory / "repository"
            shutil.copytree(ROOT / "config", root / "config")
            shutil.copytree(ROOT / "schemas", root / "schemas")
            shutil.copytree(ROOT / ".github", root / ".github")
            shutil.copy2(ROOT / "component.yaml", root / "component.yaml")
            first = directory / "first.json"
            restored = directory / "restored.json"
            result = invoke("compile", "--output", str(first), root=root)
            self.assertEqual(result.returncode, 0, result.stderr)

            target = root / "config" / "security-policy.yaml"
            last_known_good = target.read_bytes()
            target.write_text(target.read_text() + "\nunknown_recovery_field: true\n")
            invalid = invoke("validate", root=root)
            self.assertNotEqual(invalid.returncode, 0)
            target.write_bytes(last_known_good)

            result = invoke("compile", "--output", str(restored), root=root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(first.read_bytes(), restored.read_bytes())

    def test_evidence_detects_plan_tampering_without_exposing_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            catalog_path = directory / "catalog.json"
            self.assertEqual(invoke("compile", "--output", str(catalog_path)).returncode, 0)
            plan_path = directory / "plan.json"
            plan_file = directory / "tfplan"
            receipt_one = directory / "receipt-one.json"
            receipt_two = directory / "receipt-two.json"
            receipt_reformatted = directory / "receipt-reformatted.json"
            plan = {
                "format_version": "1.2",
                "terraform_version": "1.12.6",
                "resource_changes": [
                    {
                        "address": 'github_repository.governed["github-config"]',
                        "change": {
                            "actions": ["update"],
                            "before": {
                                "description": "shared-low-entropy-a",
                                "homepage": "shared-low-entropy-b",
                                "private_key": "must-not-appear",
                            },
                            "after": {
                                "description": "shared-low-entropy-b",
                                "homepage": "shared-low-entropy-a",
                                "private_key": "also-must-not-appear",
                            },
                            "before_sensitive": {"private_key": True},
                            "after_sensitive": {"private_key": True},
                        },
                    }
                ],
            }
            plan_path.write_text(json.dumps(plan, sort_keys=True))
            plan_file.write_bytes(b"opaque-plan-v1")
            result = invoke(
                "evidence",
                "--plan",
                str(plan_path),
                "--plan-file",
                str(plan_file),
                "--catalog",
                str(catalog_path),
                "--output",
                str(receipt_one),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt_text = receipt_one.read_text()
            self.assertNotIn("must-not-appear", receipt_text)
            self.assertNotIn("shared-low-entropy-a", receipt_text)
            self.assertNotIn("shared-low-entropy-b", receipt_text)
            self.assertNotIn("github_repository.governed", receipt_text)
            receipt = json.loads(receipt_text)
            write = receipt["plan"]["writes"][0]
            self.assertEqual(write["change_id"], "change-000001")
            self.assertNotIn("address_digest", write)
            changed_fields = {field["path"]: field for field in write["changed_fields"]}
            self.assertEqual(
                changed_fields["/private_key"],
                {"path": "/private_key", "sensitive": True},
            )
            description = changed_fields["/description"]
            self.assertFalse(description["sensitive"])
            self.assertRegex(description["before_hash"], r"^sha256:[0-9a-f]{64}$")
            self.assertRegex(description["after_hash"], r"^sha256:[0-9a-f]{64}$")
            self.assertNotEqual(description["before_hash"], description["after_hash"])
            homepage = changed_fields["/homepage"]
            self.assertEqual(
                len(
                    {
                        description["before_hash"],
                        description["after_hash"],
                        homepage["before_hash"],
                        homepage["after_hash"],
                    }
                ),
                4,
            )

            address = 'github_repository.governed["github-config"]'
            dictionary_candidates = {
                "sha256:" + hashlib.sha256(address.encode()).hexdigest(),
                "sha256:"
                + hashlib.sha256(
                    ("github-config/plan-address/v1\n" + address).encode(),
                ).hexdigest(),
            }
            for value in ("shared-low-entropy-a", "shared-low-entropy-b"):
                legacy = json.dumps(
                    {"present": True, "value": value},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                dictionary_candidates.add("sha256:" + hashlib.sha256(legacy).hexdigest())
            self.assertTrue(
                dictionary_candidates.isdisjoint(
                    set(
                        re.findall(
                            r"sha256:[0-9a-f]{64}",
                            receipt_text,
                        )
                    )
                )
            )

            plan["timestamp"] = "volatile-plan-render-metadata"
            plan_path.write_text(json.dumps(plan, indent=4))
            result = invoke(
                "evidence",
                "--plan",
                str(plan_path),
                "--plan-file",
                str(plan_file),
                "--catalog",
                str(catalog_path),
                "--output",
                str(receipt_reformatted),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(receipt_one.read_bytes(), receipt_reformatted.read_bytes())

            plan_file.write_bytes(b"opaque-plan-v2")
            result = invoke(
                "evidence",
                "--plan",
                str(plan_path),
                "--plan-file",
                str(plan_file),
                "--catalog",
                str(catalog_path),
                "--output",
                str(receipt_two),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            first = json.loads(receipt_one.read_text())
            second = json.loads(receipt_two.read_text())
            self.assertNotEqual(first["digests"]["plan_file"], second["digests"]["plan_file"])
            self.assertNotEqual(first["evidence_digest"], second["evidence_digest"])

    def test_destructive_dependency_analysis_must_bind_the_exact_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            plan_path = directory / "plan.json"
            analysis_path = directory / "dependency-analysis.json"
            output_path = directory / "evidence.json"
            plan = {
                "format_version": "1.2",
                "terraform_version": "1.12.6",
                "resource_changes": [
                    {
                        "address": 'github_repository_collaborator.direct["former-user"]',
                        "type": "github_repository_collaborator",
                        "change": {
                            "actions": ["delete"],
                            "before": {"permission": "push"},
                            "after": None,
                        },
                    }
                ],
            }
            plan_path.write_text(json.dumps(plan))
            write_dependency_analysis(analysis_path, plan, ["change-000001"])
            analysis = json.loads(analysis_path.read_text())
            analysis["plan_json_digest"] = "sha256:" + "0" * 64
            analysis_path.write_text(json.dumps(analysis))
            rejected = invoke(
                "evidence",
                "--plan",
                str(plan_path),
                "--phase",
                "foundation",
                "--change-reference",
                "GOV-TEST",
                "--destructive-change-acknowledged",
                "--dependency-analysis",
                str(analysis_path),
                "--output",
                str(output_path),
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("not bound to the exact plan JSON digest", rejected.stderr)

    def test_evidence_identity_and_access_topology_is_marker_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            plan_path = directory / "plan.json"
            output = directory / "evidence.json"
            addresses = [
                'github_membership.this["sensitive-member"]',
                'github_repository.governed["restricted-repository"]',
                'github_repository_collaborator.direct["sensitive-member:restricted-repository"]',
            ]
            plan_path.write_text(
                json.dumps(
                    {
                        "format_version": "1.2",
                        "terraform_version": "1.12.6",
                        "resource_changes": [
                            {
                                "address": addresses[2],
                                "type": "github_repository_collaborator",
                                "change": {
                                    "actions": ["update"],
                                    "before": {
                                        "username": "sensitive-member",
                                        "repository": "restricted-repository",
                                        "permission": "pull",
                                    },
                                    "after": {
                                        "username": "sensitive-member",
                                        "repository": "restricted-repository",
                                        "permission": "push",
                                    },
                                },
                            },
                            {
                                "address": addresses[0],
                                "type": "github_membership",
                                "change": {
                                    "actions": ["update"],
                                    "before": {"username": "sensitive-member", "role": "member"},
                                    "after": {"username": "sensitive-member", "role": "admin"},
                                },
                            },
                            {
                                "address": addresses[1],
                                "type": "github_repository",
                                "change": {
                                    "actions": ["update"],
                                    "before": {
                                        "custom_properties": {"restricted-trial-code": "alpha"}
                                    },
                                    "after": {
                                        "custom_properties": {"restricted-trial-code": "beta"}
                                    },
                                },
                            },
                        ],
                    },
                    sort_keys=True,
                )
            )
            result = invoke("evidence", "--plan", str(plan_path), "--output", str(output))
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt_text = output.read_text()
            for forbidden in [
                *addresses,
                "sensitive-member",
                "restricted-repository",
                "restricted-trial-code",
                "alpha",
                "beta",
            ]:
                self.assertNotIn(forbidden, receipt_text)

            receipt = json.loads(receipt_text)
            writes = receipt["plan"]["writes"]
            self.assertEqual(
                [write["change_id"] for write in writes],
                ["change-000001", "change-000002", "change-000003"],
            )
            for write in writes:
                self.assertNotIn("address_digest", write)
                self.assertTrue(write["changed_fields"])
                self.assertTrue(all(field["sensitive"] for field in write["changed_fields"]))
                self.assertTrue(
                    all("before_hash" not in field for field in write["changed_fields"])
                )
                self.assertTrue(all("after_hash" not in field for field in write["changed_fields"]))
            repository_write = next(
                write for write in writes if write["resource_type"] == "github_repository"
            )
            self.assertEqual(
                repository_write["changed_fields"],
                [{"path": "/custom_properties", "sensitive": True}],
            )
            high_risk_ids = {change["change_id"] for change in receipt["plan"]["high_risk_changes"]}
            self.assertTrue(
                high_risk_ids.issubset(
                    {
                        "change-000001",
                        "change-000002",
                        "change-000003",
                    }
                )
            )

            digest_candidates = set()
            for address in addresses:
                digest_candidates.add("sha256:" + hashlib.sha256(address.encode()).hexdigest())
                digest_candidates.add(
                    "sha256:"
                    + hashlib.sha256(
                        ("github-config/plan-address/v1\n" + address).encode(),
                    ).hexdigest()
                )
            self.assertTrue(
                digest_candidates.isdisjoint(
                    set(
                        re.findall(
                            r"sha256:[0-9a-f]{64}",
                            receipt_text,
                        )
                    )
                )
            )

    def test_evidence_classifies_semantic_risk_and_narrow_permission_reductions(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            output = directory / "evidence.json"

            def evidence(changes, *extra, evidence_root=ROOT, destructive_review=False):
                plan = directory / "plan.json"
                plan_document = {
                    "format_version": "1.2",
                    "terraform_version": "1.12.6",
                    "resource_changes": changes,
                }
                plan.write_text(json.dumps(plan_document))
                arguments = list(extra)
                if destructive_review:
                    analysis = directory / "dependency-analysis.json"
                    ordered_changes = sorted(
                        changes,
                        key=lambda change: (
                            change.get("address", ""),
                            json.dumps(change, sort_keys=True, separators=(",", ":")),
                        ),
                    )
                    destructive_ids = [
                        f"change-{index:06d}"
                        for index, change in enumerate(ordered_changes, start=1)
                        if any(
                            action in {"delete", "forget"}
                            for action in change.get("change", {}).get("actions", [])
                        )
                    ]
                    write_dependency_analysis(
                        analysis,
                        plan_document,
                        destructive_ids,
                    )
                    arguments.extend(
                        [
                            "--change-reference",
                            "GOV-TEST",
                            "--destructive-change-acknowledged",
                            "--dependency-analysis",
                            str(analysis),
                        ]
                    )
                result = invoke(
                    "evidence",
                    "--plan",
                    str(plan),
                    "--phase",
                    "foundation",
                    "--output",
                    str(output),
                    *arguments,
                    root=evidence_root,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(output.read_text())

            safe_create = evidence(
                [
                    {
                        "address": 'github_repository.governed["new-private"]',
                        "type": "github_repository",
                        "change": {
                            "actions": ["create"],
                            "before": None,
                            "after": {"visibility": "private", "id": None},
                            "after_unknown": {"id": True},
                        },
                    }
                ],
                "--risk-acknowledged",
            )
            self.assertTrue(safe_create["decision"]["eligible_for_protected_apply"])
            self.assertEqual(
                safe_create["plan"]["writes"][0]["change_class"], "privilege_expansion"
            )

            unknown_permission = evidence(
                [
                    {
                        "address": 'github_team_repository.access["security:repo"]',
                        "type": "github_team_repository",
                        "change": {
                            "actions": ["update"],
                            "before": {"permission": "pull"},
                            "after": {"permission": "push"},
                            "after_unknown": {"permission": True},
                        },
                    }
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(unknown_permission["decision"]["eligible_for_protected_apply"])
            self.assertIn("unknown_change", unknown_permission["plan"]["writes"][0]["classes"])

            permission_reduction = evidence(
                [
                    {
                        "address": 'github_repository_collaborator.direct["former-user"]',
                        "type": "github_repository_collaborator",
                        "change": {
                            "actions": ["delete"],
                            "before": {"permission": "push"},
                            "after": None,
                        },
                    }
                ]
            )
            self.assertFalse(permission_reduction["decision"]["eligible_for_protected_apply"])
            self.assertIn(
                "permission_reduction", permission_reduction["plan"]["writes"][0]["classes"]
            )
            self.assertEqual(
                permission_reduction["plan"]["destructive_change_ids"], ["change-000001"]
            )
            self.assertTrue(
                permission_reduction["decision"]["requires_destructive_change_acknowledgement"]
            )

            reviewed_permission_reduction = evidence(
                [
                    {
                        "address": 'github_repository_collaborator.direct["former-user"]',
                        "type": "github_repository_collaborator",
                        "change": {
                            "actions": ["delete"],
                            "before": {"permission": "push"},
                            "after": None,
                        },
                    }
                ],
                destructive_review=True,
            )
            self.assertTrue(
                reviewed_permission_reduction["decision"]["eligible_for_protected_apply"]
            )
            self.assertTrue(
                reviewed_permission_reduction["decision"]["dependency_analysis_verified"]
            )

            disguised_replacement = evidence(
                [
                    {
                        "address": 'github_team_membership.access["old-key"]',
                        "type": "github_team_membership",
                        "change": {
                            "actions": ["delete"],
                            "before": {"role": "member"},
                            "after": None,
                        },
                    },
                    {
                        "address": 'github_team_membership.access["new-key"]',
                        "type": "github_team_membership",
                        "change": {
                            "actions": ["create"],
                            "before": None,
                            "after": {"role": "member"},
                        },
                    },
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(disguised_replacement["decision"]["eligible_for_protected_apply"])
            self.assertTrue(
                all(
                    "authority_replacement" in write["classes"]
                    for write in disguised_replacement["plan"]["writes"]
                )
            )

            delete_plus_grant = evidence(
                [
                    {
                        "address": 'github_team_repository.access["retired:repo"]',
                        "type": "github_team_repository",
                        "change": {
                            "actions": ["delete"],
                            "before": {"permission": "push"},
                            "after": None,
                        },
                    },
                    {
                        "address": 'github_team_repository.access["replacement:repo"]',
                        "type": "github_team_repository",
                        "change": {
                            "actions": ["update"],
                            "before": {"permission": "pull"},
                            "after": {"permission": "push"},
                        },
                    },
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(delete_plus_grant["decision"]["eligible_for_protected_apply"])
            self.assertTrue(
                all(
                    "authority_replacement" in write["classes"]
                    for write in delete_plus_grant["plan"]["writes"]
                )
            )

            delete_plus_routine_write = evidence(
                [
                    {
                        "address": 'github_membership.this["former-user"]',
                        "type": "github_membership",
                        "change": {
                            "actions": ["delete"],
                            "before": {"role": "member"},
                            "after": None,
                        },
                    },
                    {
                        "address": 'github_repository.governed["github-config"]',
                        "type": "github_repository",
                        "change": {
                            "actions": ["update"],
                            "before": {"description": "old"},
                            "after": {"description": "new"},
                        },
                    },
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(delete_plus_routine_write["decision"]["eligible_for_protected_apply"])
            self.assertTrue(
                all(
                    "authority_replacement" in write["classes"]
                    for write in delete_plus_routine_write["plan"]["writes"]
                )
            )

            unknown_delete = evidence(
                [
                    {
                        "address": "unknown_resource.example",
                        "type": "unknown_resource",
                        "change": {"actions": ["delete"], "before": {}, "after": None},
                    }
                ]
            )
            self.assertFalse(unknown_delete["decision"]["eligible_for_protected_apply"])
            self.assertIn("destructive", unknown_delete["plan"]["writes"][0]["classes"])

            reviewed_ruleset_retirement = evidence(
                [
                    {
                        "address": 'module.rulesets.github_organization_ruleset.this["retired-policy"]',
                        "type": "github_organization_ruleset",
                        "change": {
                            "actions": ["delete"],
                            "before": {"name": "retired-policy", "enforcement": "evaluate"},
                            "after": None,
                        },
                    }
                ],
                destructive_review=True,
            )
            self.assertTrue(
                reviewed_ruleset_retirement["decision"]["eligible_for_protected_apply"],
            )
            self.assertIn(
                "governed_retirement",
                reviewed_ruleset_retirement["plan"]["writes"][0]["classes"],
            )

            disguised_ruleset_replacement = evidence(
                [
                    {
                        "address": 'module.rulesets.github_organization_ruleset.this["old"]',
                        "type": "github_organization_ruleset",
                        "change": {
                            "actions": ["delete"],
                            "before": {"name": "old", "enforcement": "evaluate"},
                            "after": None,
                        },
                    },
                    {
                        "address": 'module.rulesets.github_organization_ruleset.this["new"]',
                        "type": "github_organization_ruleset",
                        "change": {
                            "actions": ["create"],
                            "before": None,
                            "after": {"name": "new", "enforcement": "active"},
                        },
                    },
                ],
                "--risk-acknowledged",
                destructive_review=True,
            )
            self.assertFalse(
                disguised_ruleset_replacement["decision"]["eligible_for_protected_apply"],
            )
            self.assertTrue(
                all(
                    "authority_replacement" in write["classes"]
                    for write in disguised_ruleset_replacement["plan"]["writes"]
                )
            )

            for resource_type, address in (
                (
                    "github_actions_environment_variable",
                    "module.repository_environments."
                    'github_actions_environment_variable.this["retired:repo:HANDOFF"]',
                ),
                (
                    "github_repository_environment",
                    'module.repository_environments.github_repository_environment.this["github-config:retired"]',
                ),
                (
                    "github_repository_environment_deployment_policy",
                    'module.repository_environments.github_repository_environment_deployment_policy.this["github-config:retired:branch:main"]',
                ),
                (
                    "github_team",
                    'module.team_access.github_team.this["retired-team"]',
                ),
            ):
                with self.subTest(governed_retirement=resource_type):
                    reviewed_retirement = evidence(
                        [
                            {
                                "address": address,
                                "type": resource_type,
                                "change": {
                                    "actions": ["delete"],
                                    "before": {"id": 1},
                                    "after": None,
                                },
                            }
                        ],
                        destructive_review=True,
                    )
                    self.assertTrue(reviewed_retirement["decision"]["eligible_for_protected_apply"])
                    self.assertIn(
                        "governed_retirement",
                        reviewed_retirement["plan"]["writes"][0]["classes"],
                    )

            reviewed_team_retirement = evidence(
                [
                    {
                        "address": 'module.team_access.github_team_membership.this["retired-team:user"]',
                        "type": "github_team_membership",
                        "change": {
                            "actions": ["delete"],
                            "before": {"role": "member"},
                            "after": None,
                        },
                    },
                    {
                        "address": 'module.team_access.github_team_repository.this["repo:retired-team"]',
                        "type": "github_team_repository",
                        "change": {
                            "actions": ["delete"],
                            "before": {"permission": "push"},
                            "after": None,
                        },
                    },
                    {
                        "address": 'module.team_access.github_team.this["retired-team"]',
                        "type": "github_team",
                        "change": {
                            "actions": ["delete"],
                            "before": {"name": "retired-team"},
                            "after": None,
                        },
                    },
                ],
                destructive_review=True,
            )
            self.assertTrue(reviewed_team_retirement["decision"]["eligible_for_protected_apply"])
            self.assertEqual(
                reviewed_team_retirement["plan"]["destructive_change_ids"],
                ["change-000001", "change-000002", "change-000003"],
            )

            reviewed_repository_deletion = evidence(
                [
                    {
                        "address": 'module.repository_governance.github_repository.this["github-config"]',
                        "type": "github_repository",
                        "change": {
                            "actions": ["delete"],
                            "before": {"name": "github-config", "visibility": "private"},
                            "after": None,
                        },
                    }
                ],
                destructive_review=True,
            )
            self.assertFalse(
                reviewed_repository_deletion["decision"]["eligible_for_protected_apply"],
            )
            self.assertIn(
                "destructive",
                reviewed_repository_deletion["plan"]["writes"][0]["classes"],
            )

            weakening = evidence(
                [
                    {
                        "address": 'github_organization_ruleset.protected["main"]',
                        "type": "github_organization_ruleset",
                        "change": {
                            "actions": ["update"],
                            "before": {
                                "bypass_actors": [],
                                "required_status_checks": [{"context": "required"}],
                            },
                            "after": {
                                "bypass_actors": [{"actor_id": 1}],
                                "required_status_checks": [],
                            },
                        },
                    }
                ],
                "--risk-acknowledged",
            )
            classes = weakening["plan"]["writes"][0]["classes"]
            self.assertFalse(weakening["decision"]["eligible_for_protected_apply"])
            self.assertIn("protection_weakening", classes)

            provider_shaped_weakening = evidence(
                [
                    {
                        "address": 'github_organization_ruleset.protected["main"]',
                        "type": "github_organization_ruleset",
                        "change": {
                            "actions": ["update"],
                            "before": {
                                "rules": [
                                    {
                                        "type": "required_status_checks",
                                        "parameters": {
                                            "required_status_checks": [{"context": "required"}]
                                        },
                                    }
                                ]
                            },
                            "after": {
                                "rules": [
                                    {
                                        "type": "required_status_checks",
                                        "parameters": {"required_status_checks": []},
                                    }
                                ]
                            },
                        },
                    },
                    {
                        "address": 'github_repository_ruleset.gate["authority"]',
                        "type": "github_repository_ruleset",
                        "change": {
                            "actions": ["update"],
                            "before": {
                                "rules": [
                                    {
                                        "required_deployments": [
                                            {
                                                "required_deployment_environments": [
                                                    "platform-review",
                                                    "security-review",
                                                ],
                                            }
                                        ],
                                        "required_status_checks": [
                                            {
                                                "strict_required_status_checks_policy": True,
                                                "do_not_enforce_on_create": False,
                                                "required_check": [
                                                    {
                                                        "context": "Authority / platform",
                                                        "integration_id": 0,
                                                    },
                                                    {
                                                        "context": "Authority / security",
                                                        "integration_id": 0,
                                                    },
                                                ],
                                            }
                                        ],
                                    }
                                ]
                            },
                            "after": {
                                "rules": [
                                    {
                                        "required_deployments": [
                                            {
                                                "required_deployment_environments": [
                                                    "platform-review"
                                                ],
                                            }
                                        ],
                                        "required_status_checks": [
                                            {
                                                "strict_required_status_checks_policy": True,
                                                "do_not_enforce_on_create": False,
                                                "required_check": [
                                                    {
                                                        "context": "Authority / platform",
                                                        "integration_id": 0,
                                                    },
                                                ],
                                            }
                                        ],
                                    }
                                ]
                            },
                        },
                    },
                    {
                        "address": 'github_repository.governed["github-config"]',
                        "type": "github_repository",
                        "change": {
                            "actions": ["update"],
                            "before": {
                                "security_and_analysis": [
                                    {"secret_scanning": [{"status": "enabled"}]}
                                ]
                            },
                            "after": {
                                "security_and_analysis": [
                                    {"secret_scanning": [{"status": "disabled"}]}
                                ]
                            },
                        },
                    },
                    {
                        "address": 'github_repository_dependabot_security_updates.this["github-config"]',
                        "type": "github_repository_dependabot_security_updates",
                        "change": {
                            "actions": ["update"],
                            "before": {"enabled": True},
                            "after": {"enabled": False},
                        },
                    },
                    {
                        "address": 'github_repository_environment.this["github-config:trusted-build"]',
                        "type": "github_repository_environment",
                        "change": {
                            "actions": ["update"],
                            "before": {"reviewers": [{"teams": [101, 202], "users": []}]},
                            "after": {"reviewers": [{"teams": [101], "users": []}]},
                        },
                    },
                ],
                "--risk-acknowledged",
            )
            shaped_classes = [
                set(write["classes"]) for write in provider_shaped_weakening["plan"]["writes"]
            ]
            self.assertFalse(provider_shaped_weakening["decision"]["eligible_for_protected_apply"])
            self.assertTrue(any("protection_weakening" in classes for classes in shaped_classes))
            environment_write = next(
                write
                for write in provider_shaped_weakening["plan"]["writes"]
                if write["resource_type"] == "github_repository_environment"
            )
            self.assertNotIn("protection_weakening", environment_write["classes"])
            self.assertIn("permission_reduction", environment_write["classes"])
            self.assertEqual(sum("security_weakening" in classes for classes in shaped_classes), 2)
            repository_ruleset_write = next(
                write
                for write in provider_shaped_weakening["plan"]["writes"]
                if write["resource_type"] == "github_repository_ruleset"
            )
            self.assertIn("protection_weakening", repository_ruleset_write["classes"])

            deployment_policy_changes = evidence(
                [
                    {
                        "address": (
                            "module.repository_environments."
                            'github_repository_environment_deployment_policy.this["changed"]'
                        ),
                        "type": "github_repository_environment_deployment_policy",
                        "change": {
                            "actions": ["update"],
                            "before": {
                                "repository": "infrastructure-live",
                                "environment": "infrastructure-apply",
                                "branch_pattern": "refs/pull/*/merge",
                                "tag_pattern": None,
                            },
                            "after": {
                                "repository": "infrastructure-live",
                                "environment": "infrastructure-apply",
                                "branch_pattern": "refs/heads/release/*",
                                "tag_pattern": None,
                            },
                        },
                    },
                    {
                        "address": (
                            "module.repository_environments."
                            'github_repository_environment_deployment_policy.this["deleted"]'
                        ),
                        "type": "github_repository_environment_deployment_policy",
                        "change": {
                            "actions": ["delete"],
                            "before": {
                                "repository": "infrastructure-live",
                                "environment": "infrastructure-apply",
                                "branch_pattern": "refs/pull/*/merge",
                                "tag_pattern": None,
                            },
                            "after": None,
                        },
                    },
                    {
                        "address": (
                            "module.repository_environments."
                            'github_repository_environment_deployment_policy.this["replaced"]'
                        ),
                        "type": "github_repository_environment_deployment_policy",
                        "change": {
                            "actions": ["delete", "create"],
                            "before": {
                                "repository": "infrastructure-live",
                                "environment": "infrastructure-apply",
                                "branch_pattern": "refs/pull/*/merge",
                                "tag_pattern": None,
                            },
                            "after": {
                                "repository": "infrastructure-live",
                                "environment": "infrastructure-apply",
                                "branch_pattern": None,
                                "tag_pattern": "v*",
                            },
                        },
                    },
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(deployment_policy_changes["decision"]["eligible_for_protected_apply"])
            policy_writes = deployment_policy_changes["plan"]["writes"]
            self.assertIn("protection_weakening", policy_writes[0]["classes"])
            self.assertIn("governed_retirement", policy_writes[1]["classes"])
            self.assertIn("replacement", policy_writes[2]["classes"])

            reviewer_addition = evidence(
                [
                    {
                        "address": 'github_repository_environment.this["github-config:trusted-build"]',
                        "type": "github_repository_environment",
                        "change": {
                            "actions": ["update"],
                            "before": {"reviewers": [{"teams": [101], "users": []}]},
                            "after": {"reviewers": [{"teams": [101, 202], "users": []}]},
                        },
                    }
                ],
                "--risk-acknowledged",
            )
            reviewer_addition_write = reviewer_addition["plan"]["writes"][0]
            self.assertFalse(reviewer_addition["decision"]["eligible_for_protected_apply"])
            self.assertIn("environment_bypass", reviewer_addition_write["classes"])

            reviewer_reduction = evidence(
                [
                    {
                        "address": 'github_repository_environment.this["github-config:trusted-build"]',
                        "type": "github_repository_environment",
                        "change": {
                            "actions": ["update"],
                            "before": {
                                "reviewers": [{"teams": [101, 202], "users": []}],
                                "can_admins_bypass": False,
                                "prevent_self_review": True,
                            },
                            "after": {
                                "reviewers": [{"teams": [101], "users": []}],
                                "can_admins_bypass": False,
                                "prevent_self_review": True,
                            },
                        },
                    }
                ]
            )
            reviewer_reduction_write = reviewer_reduction["plan"]["writes"][0]
            self.assertTrue(reviewer_reduction["decision"]["eligible_for_protected_apply"])
            self.assertIn("permission_reduction", reviewer_reduction_write["classes"])
            self.assertNotIn("environment_bypass", reviewer_reduction_write["classes"])
            self.assertNotIn("protection_weakening", reviewer_reduction_write["classes"])

            final_reviewer_removal = evidence(
                [
                    {
                        "address": 'github_repository_environment.this["github-config:trusted-build"]',
                        "type": "github_repository_environment",
                        "change": {
                            "actions": ["update"],
                            "before": {"reviewers": [{"teams": [101], "users": []}]},
                            "after": {"reviewers": []},
                        },
                    }
                ],
                "--risk-acknowledged",
            )
            final_reviewer_write = final_reviewer_removal["plan"]["writes"][0]
            self.assertFalse(final_reviewer_removal["decision"]["eligible_for_protected_apply"])
            self.assertIn("environment_bypass", final_reviewer_write["classes"])

            malformed_reviewers = evidence(
                [
                    {
                        "address": 'github_repository_environment.this["github-config:trusted-build"]',
                        "type": "github_repository_environment",
                        "change": {
                            "actions": ["update"],
                            "before": {"reviewers": [{"teams": [101], "users": []}]},
                            "after": {"reviewers": [{"teams": ["unknown"], "users": []}]},
                        },
                    }
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(malformed_reviewers["decision"]["eligible_for_protected_apply"])
            self.assertIn("unknown_change", malformed_reviewers["plan"]["writes"][0]["classes"])

            branch_policy = [
                {
                    "protected_branches": True,
                    "custom_branch_policies": False,
                }
            ]
            branch_policy_removals = evidence(
                [
                    {
                        "address": 'github_repository_environment.this["repo:missing"]',
                        "type": "github_repository_environment",
                        "change": {
                            "actions": ["update"],
                            "before": {"deployment_branch_policy": branch_policy},
                            "after": {},
                        },
                    },
                    {
                        "address": 'github_repository_environment.this["repo:null"]',
                        "type": "github_repository_environment",
                        "change": {
                            "actions": ["update"],
                            "before": {"deployment_branch_policy": branch_policy},
                            "after": {"deployment_branch_policy": None},
                        },
                    },
                    {
                        "address": 'github_repository_environment.this["repo:empty"]',
                        "type": "github_repository_environment",
                        "change": {
                            "actions": ["update"],
                            "before": {"deployment_branch_policy": branch_policy},
                            "after": {"deployment_branch_policy": []},
                        },
                    },
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(branch_policy_removals["decision"]["eligible_for_protected_apply"])
            self.assertTrue(
                all(
                    "environment_bypass" in write["classes"]
                    for write in branch_policy_removals["plan"]["writes"]
                )
            )

            branch_policy_narrowing = evidence(
                [
                    {
                        "address": 'github_repository_environment.this["repo:strengthened"]',
                        "type": "github_repository_environment",
                        "change": {
                            "actions": ["update"],
                            "before": {
                                "can_admins_bypass": False,
                                "prevent_self_review": True,
                            },
                            "after": {
                                "deployment_branch_policy": branch_policy,
                                "can_admins_bypass": False,
                                "prevent_self_review": True,
                            },
                        },
                    }
                ]
            )
            self.assertTrue(branch_policy_narrowing["decision"]["eligible_for_protected_apply"])
            self.assertEqual(
                branch_policy_narrowing["plan"]["writes"][0]["change_class"],
                "routine_write",
            )

            malformed_branch_policy = evidence(
                [
                    {
                        "address": 'github_repository_environment.this["repo:malformed"]',
                        "type": "github_repository_environment",
                        "change": {
                            "actions": ["update"],
                            "before": {"deployment_branch_policy": branch_policy},
                            "after": {"deployment_branch_policy": [{"protected_branches": True}]},
                        },
                    }
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(malformed_branch_policy["decision"]["eligible_for_protected_apply"])
            self.assertIn(
                "unknown_change",
                malformed_branch_policy["plan"]["writes"][0]["classes"],
            )

            ruleset_creation_weakening = evidence(
                [
                    {
                        "address": 'github_organization_ruleset.tags["release-tags-creator-gate"]',
                        "type": "github_organization_ruleset",
                        "change": {
                            "actions": ["update"],
                            "before": {"rules": [{"creation": True}]},
                            "after": {"rules": [{"creation": False}]},
                        },
                    }
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(
                ruleset_creation_weakening["decision"]["eligible_for_protected_apply"],
            )
            self.assertIn(
                "protection_weakening",
                ruleset_creation_weakening["plan"]["writes"][0]["classes"],
            )

            repository_archival = evidence(
                [
                    {
                        "address": 'github_repository.governed["github-config"]',
                        "type": "github_repository",
                        "change": {
                            "actions": ["update"],
                            "before": {"archived": False},
                            "after": {"archived": True},
                        },
                    }
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(repository_archival["decision"]["eligible_for_protected_apply"])
            self.assertIn("destructive", repository_archival["plan"]["writes"][0]["classes"])

            ambiguous_archival = evidence(
                [
                    {
                        "address": 'github_repository.governed["github-config"]',
                        "type": "github_repository",
                        "change": {
                            "actions": ["update"],
                            "before": {"archived": False},
                            "after": {"archived": None},
                        },
                    }
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(ambiguous_archival["decision"]["eligible_for_protected_apply"])
            self.assertIn("unknown_change", ambiguous_archival["plan"]["writes"][0]["classes"])

            internal_visibility = evidence(
                [
                    {
                        "address": 'github_repository.governed["internalized"]',
                        "type": "github_repository",
                        "change": {
                            "actions": ["update"],
                            "before": {"visibility": "private"},
                            "after": {"visibility": "internal"},
                        },
                    }
                ],
                "--risk-acknowledged",
            )
            visibility_classes = internal_visibility["plan"]["writes"][0]["classes"]
            self.assertTrue(internal_visibility["decision"]["eligible_for_protected_apply"])
            self.assertIn("privilege_expansion", visibility_classes)
            self.assertNotIn("public_visibility", visibility_classes)

            actions_expansion = evidence(
                [
                    {
                        "address": "github_actions_organization_permissions.this",
                        "type": "github_actions_organization_permissions",
                        "change": {
                            "actions": ["update"],
                            "before": {"github_owned_allowed": False},
                            "after": {"github_owned_allowed": True},
                        },
                    }
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(actions_expansion["decision"]["eligible_for_protected_apply"])
            self.assertIn(
                "actions_policy_expansion", actions_expansion["plan"]["writes"][0]["classes"]
            )

            local_actions_expansion = evidence(
                [
                    {
                        "address": "github_actions_organization_permissions.this",
                        "type": "github_actions_organization_permissions",
                        "change": {
                            "actions": ["update"],
                            "before": {"allowed_actions": "selected"},
                            "after": {"allowed_actions": "local_only"},
                        },
                    }
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(local_actions_expansion["decision"]["eligible_for_protected_apply"])
            self.assertIn(
                "actions_policy_expansion",
                local_actions_expansion["plan"]["writes"][0]["classes"],
            )

            actions_lockout = evidence(
                [
                    {
                        "address": "github_actions_organization_permissions.all",
                        "type": "github_actions_organization_permissions",
                        "change": {
                            "actions": ["update"],
                            "before": {"enabled_repositories": "all"},
                            "after": {"enabled_repositories": "none"},
                        },
                    },
                    {
                        "address": "github_actions_organization_permissions.selected",
                        "type": "github_actions_organization_permissions",
                        "change": {
                            "actions": ["update"],
                            "before": {"enabled_repositories": "selected"},
                            "after": {"enabled_repositories": "none"},
                        },
                    },
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(actions_lockout["decision"]["eligible_for_protected_apply"])
            self.assertTrue(
                all(
                    "destructive" in write["classes"] for write in actions_lockout["plan"]["writes"]
                )
            )

            malformed_actions_scope = evidence(
                [
                    {
                        "address": "github_actions_organization_permissions.this",
                        "type": "github_actions_organization_permissions",
                        "change": {
                            "actions": ["update"],
                            "before": {"enabled_repositories": "all"},
                            "after": {"enabled_repositories": 17},
                        },
                    }
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(malformed_actions_scope["decision"]["eligible_for_protected_apply"])
            self.assertIn(
                "unknown_change",
                malformed_actions_scope["plan"]["writes"][0]["classes"],
            )

            lifecycle_expansions = [
                {
                    "address": 'github_team.governed["security"]',
                    "type": "github_team",
                    "change": {
                        "actions": ["update"],
                        "before": {"privacy": "secret"},
                        "after": {"privacy": "closed"},
                    },
                },
                {
                    "address": 'github_repository.governed["reactivated"]',
                    "type": "github_repository",
                    "change": {
                        "actions": ["update"],
                        "before": {"archived": True},
                        "after": {"archived": False},
                    },
                },
            ]
            unacknowledged_lifecycle = evidence(lifecycle_expansions)
            self.assertFalse(
                unacknowledged_lifecycle["decision"]["eligible_for_protected_apply"],
            )
            self.assertTrue(
                all(
                    "privilege_expansion" in write["classes"]
                    for write in unacknowledged_lifecycle["plan"]["writes"]
                )
            )
            acknowledged_lifecycle = evidence(lifecycle_expansions, "--risk-acknowledged")
            self.assertTrue(
                acknowledged_lifecycle["decision"]["eligible_for_protected_apply"],
            )

            create_check_bypass = evidence(
                [
                    {
                        "address": 'github_organization_ruleset.governed["application-source"]',
                        "type": "github_organization_ruleset",
                        "change": {
                            "actions": ["update"],
                            "before": {
                                "rules": [
                                    {
                                        "type": "required_status_checks",
                                        "parameters": [{"do_not_enforce_on_create": False}],
                                    }
                                ],
                            },
                            "after": {
                                "rules": [
                                    {
                                        "type": "required_status_checks",
                                        "parameters": [{"do_not_enforce_on_create": True}],
                                    }
                                ],
                            },
                        },
                    }
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(create_check_bypass["decision"]["eligible_for_protected_apply"])
            self.assertIn(
                "protection_weakening",
                create_check_bypass["plan"]["writes"][0]["classes"],
            )

            editable_custom_properties = evidence(
                [
                    {
                        "address": "github_organization_custom_properties.governed",
                        "type": "github_organization_custom_properties",
                        "change": {
                            "actions": ["update"],
                            "before": {
                                "property": [
                                    {
                                        "property_name": "data_classification",
                                        "values_editable_by": "org_actors",
                                    }
                                ]
                            },
                            "after": {
                                "property": [
                                    {
                                        "property_name": "data_classification",
                                        "values_editable_by": "org_and_repo_actors",
                                    }
                                ]
                            },
                        },
                    }
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(editable_custom_properties["decision"]["eligible_for_protected_apply"])
            self.assertIn(
                "protection_weakening",
                editable_custom_properties["plan"]["writes"][0]["classes"],
            )

            parent_team_change = [
                {
                    "address": 'github_team.governed["platform-operations"]',
                    "type": "github_team",
                    "change": {
                        "actions": ["update"],
                        "before": {"parent_team_id": 101},
                        "after": {"parent_team_id": 202},
                    },
                }
            ]
            unacknowledged_parent = evidence(parent_team_change)
            self.assertFalse(
                unacknowledged_parent["decision"]["eligible_for_protected_apply"],
            )
            self.assertIn(
                "privilege_expansion",
                unacknowledged_parent["plan"]["writes"][0]["classes"],
            )
            acknowledged_parent = evidence(parent_team_change, "--risk-acknowledged")
            self.assertFalse(acknowledged_parent["decision"]["eligible_for_protected_apply"])
            self.assertIn(
                "unknown_change",
                acknowledged_parent["plan"]["writes"][0]["classes"],
            )

            catalog_path = directory / "catalog.json"
            compiled = invoke("compile", "--output", str(catalog_path))
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            compiled_catalog = json.loads(catalog_path.read_text())
            current_patterns = [
                f"{action['source']}@{action['commit']}"
                for action in compiled_catalog["actions_policy"]["allowed_actions"]
            ]
            old_patterns = list(current_patterns)
            checkout_index = next(
                index
                for index, pattern in enumerate(old_patterns)
                if pattern.startswith("actions/checkout@")
            )
            old_patterns[checkout_index] = "actions/checkout@" + "1" * 40

            def actions_state(patterns):
                return {
                    "allowed_actions": "selected",
                    "enabled_repositories": "all",
                    "sha_pinning_required": True,
                    "allowed_actions_config": [
                        {
                            "github_owned_allowed": False,
                            "patterns_allowed": patterns,
                            "verified_allowed": False,
                        }
                    ],
                }

            pin_rotation = evidence(
                [
                    {
                        "address": "module.organization_settings.github_actions_organization_permissions.this",
                        "type": "github_actions_organization_permissions",
                        "change": {
                            "actions": ["update"],
                            "before": actions_state(old_patterns),
                            "after": actions_state(current_patterns),
                        },
                    }
                ],
                "--catalog",
                str(catalog_path),
                "--risk-acknowledged",
            )
            self.assertTrue(pin_rotation["decision"]["eligible_for_protected_apply"])
            self.assertNotIn(
                "actions_policy_expansion", pin_rotation["plan"]["writes"][0]["classes"]
            )

            unreviewed_patterns = list(current_patterns)
            unreviewed_patterns[checkout_index] = "actions/checkout@" + "2" * 40
            unreviewed_pin = evidence(
                [
                    {
                        "address": "module.organization_settings.github_actions_organization_permissions.this",
                        "type": "github_actions_organization_permissions",
                        "change": {
                            "actions": ["update"],
                            "before": actions_state(old_patterns),
                            "after": actions_state(unreviewed_patterns),
                        },
                    }
                ],
                "--catalog",
                str(catalog_path),
                "--risk-acknowledged",
            )
            self.assertFalse(unreviewed_pin["decision"]["eligible_for_protected_apply"])
            self.assertIn(
                "actions_policy_expansion", unreviewed_pin["plan"]["writes"][0]["classes"]
            )

            claims = ["workflow_sha", "context", "repo", "workflow_ref"]
            oidc_create = evidence(
                [
                    {
                        "address": "module.organization_settings.github_actions_organization_oidc_subject_claim_customization_template.this[0]",
                        "type": "github_actions_organization_oidc_subject_claim_customization_template",
                        "change": {
                            "actions": ["create"],
                            "before": None,
                            "after": {"include_claim_keys": claims},
                        },
                    }
                ],
                "--catalog",
                str(catalog_path),
                "--risk-acknowledged",
            )
            self.assertTrue(oidc_create["decision"]["eligible_for_protected_apply"])
            self.assertNotIn("oidc_mutation", oidc_create["plan"]["writes"][0]["classes"])

            repository_oidc_create = evidence(
                [
                    {
                        "address": 'module.repository_governance.github_actions_repository_oidc_subject_claim_customization_template.this["github-config"]',
                        "type": "github_actions_repository_oidc_subject_claim_customization_template",
                        "change": {
                            "actions": ["create"],
                            "before": None,
                            "after": {
                                "repository": "github-config",
                                "use_default": False,
                                "include_claim_keys": claims,
                            },
                        },
                    }
                ],
                "--catalog",
                str(catalog_path),
                "--risk-acknowledged",
            )
            self.assertTrue(repository_oidc_create["decision"]["eligible_for_protected_apply"])

            weak_oidc_create = evidence(
                [
                    {
                        "address": 'module.repository_governance.github_actions_repository_oidc_subject_claim_customization_template.this["github-config"]',
                        "type": "github_actions_repository_oidc_subject_claim_customization_template",
                        "change": {
                            "actions": ["create"],
                            "before": None,
                            "after": {
                                "repository": "github-config",
                                "use_default": True,
                                "include_claim_keys": ["repo", "context", "workflow_ref"],
                            },
                        },
                    }
                ],
                "--catalog",
                str(catalog_path),
                "--risk-acknowledged",
            )
            self.assertFalse(weak_oidc_create["decision"]["eligible_for_protected_apply"])
            self.assertIn("oidc_mutation", weak_oidc_create["plan"]["writes"][0]["classes"])

            authorization_root = directory / "authorization-root"
            shutil.copytree(ROOT / "config", authorization_root / "config")
            shutil.copytree(ROOT / "schemas", authorization_root / "schemas")
            shutil.copytree(ROOT / ".github", authorization_root / ".github")
            shutil.copy2(ROOT / "component.yaml", authorization_root / "component.yaml")
            outside_source = authorization_root / "config" / "outside-collaborators.yaml"
            outside_source.write_text(
                outside_source.read_text().replace(
                    "outside_collaborators: []",
                    """outside_collaborators:
    - login: external-reviewer
      principal_id: external-reviewer
      sponsor_login: robpearc
      expires_on: 2027-12-31
      justification: Time-bounded external review engagement.
      approval_reference: GOV-1234
      repository_permissions:
        - repository: github-config
          permission: pull""",
                )
            )
            authorization_catalog_path = directory / "authorization-catalog.json"
            compiled_authorization = invoke(
                "compile",
                "--output",
                str(authorization_catalog_path),
                root=authorization_root,
            )
            self.assertEqual(compiled_authorization.returncode, 0, compiled_authorization.stderr)
            outside_grant = evidence(
                [
                    {
                        "address": 'module.team_access.github_repository_collaborator.outside["external-reviewer:github-config"]',
                        "type": "github_repository_collaborator",
                        "change": {
                            "actions": ["create"],
                            "before": None,
                            "after": {
                                "repository": "github-config",
                                "username": "external-reviewer",
                                "permission": "pull",
                                "permission_diff_suppression": False,
                            },
                        },
                    }
                ],
                "--catalog",
                str(authorization_catalog_path),
                "--risk-acknowledged",
                evidence_root=authorization_root,
            )
            self.assertTrue(outside_grant["decision"]["eligible_for_protected_apply"])
            self.assertNotIn("direct_collaborator", outside_grant["plan"]["writes"][0]["classes"])

            unmatched_collaborator = evidence(
                [
                    {
                        "address": 'module.team_access.github_repository_collaborator.outside["undeclared:github-config"]',
                        "type": "github_repository_collaborator",
                        "change": {
                            "actions": ["create"],
                            "before": None,
                            "after": {
                                "repository": "github-config",
                                "username": "undeclared",
                                "permission": "pull",
                                "permission_diff_suppression": False,
                            },
                        },
                    }
                ],
                "--catalog",
                str(authorization_catalog_path),
                "--risk-acknowledged",
                evidence_root=authorization_root,
            )
            self.assertFalse(unmatched_collaborator["decision"]["eligible_for_protected_apply"])
            self.assertIn(
                "direct_collaborator", unmatched_collaborator["plan"]["writes"][0]["classes"]
            )

            role_observed_path = directory / "role-observed.json"
            role_observed_path.write_text(
                json.dumps(
                    {
                        "core_observation_complete": True,
                        "organization": {"id": 42, "login": "mindclade"},
                        "organization_roles": {"roles": [{"id": 99, "name": "security_manager"}]},
                    }
                )
            )
            security_manager_assignment = evidence(
                [
                    {
                        "address": "module.team_access.github_organization_role_team.security_manager",
                        "type": "github_organization_role_team",
                        "change": {
                            "actions": ["create"],
                            "before": None,
                            "after": {"role_id": 99, "team_slug": "security"},
                        },
                    }
                ],
                "--catalog",
                str(catalog_path),
                "--observed",
                str(role_observed_path),
                "--risk-acknowledged",
            )
            self.assertTrue(security_manager_assignment["decision"]["eligible_for_protected_apply"])
            self.assertNotIn(
                "administrative_grant",
                security_manager_assignment["plan"]["writes"][0]["classes"],
            )

            unrelated_role_assignment = evidence(
                [
                    {
                        "address": "github_organization_role_team.unreviewed",
                        "type": "github_organization_role_team",
                        "change": {
                            "actions": ["create"],
                            "before": None,
                            "after": {"role_id": 100, "team_slug": "architecture"},
                        },
                    }
                ],
                "--catalog",
                str(catalog_path),
                "--observed",
                str(role_observed_path),
                "--risk-acknowledged",
            )
            self.assertFalse(unrelated_role_assignment["decision"]["eligible_for_protected_apply"])
            self.assertIn(
                "administrative_grant", unrelated_role_assignment["plan"]["writes"][0]["classes"]
            )

            membership_promotion = evidence(
                [
                    {
                        "address": 'github_membership.this["operator"]',
                        "type": "github_membership",
                        "change": {
                            "actions": ["update"],
                            "before": {"role": "member"},
                            "after": {"role": "admin"},
                        },
                    }
                ],
                "--risk-acknowledged",
            )
            self.assertFalse(membership_promotion["decision"]["eligible_for_protected_apply"])
            self.assertIn(
                "administrative_grant", membership_promotion["plan"]["writes"][0]["classes"]
            )

    def test_catalog_binding_rejects_unmanaged_fields_and_proves_access_revocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            catalog = directory / "catalog.json"
            plan = directory / "plan.json"
            output = directory / "evidence.json"
            observed = directory / "observed.json"
            self.assertEqual(invoke("compile", "--output", str(catalog)).returncode, 0)

            def evidence(
                changes, catalog_path=catalog, evidence_root=ROOT, destructive_review=False
            ):
                plan_document = {
                    "format_version": "1.2",
                    "terraform_version": "1.12.6",
                    "resource_changes": changes,
                }
                plan.write_text(json.dumps(plan_document))
                destructive_arguments = []
                if destructive_review:
                    analysis = directory / "revocation-dependency-analysis.json"
                    write_dependency_analysis(analysis, plan_document, ["change-000001"])
                    destructive_arguments = [
                        "--change-reference",
                        "GOV-TEST",
                        "--destructive-change-acknowledged",
                        "--dependency-analysis",
                        str(analysis),
                    ]
                result = invoke(
                    "evidence",
                    "--plan",
                    str(plan),
                    "--catalog",
                    str(catalog_path),
                    "--observed",
                    str(observed),
                    "--phase",
                    "foundation",
                    "--risk-acknowledged",
                    "--output",
                    str(output),
                    *destructive_arguments,
                    root=evidence_root,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(output.read_text())

            observed.write_text(
                json.dumps(
                    {
                        "core_observation_complete": True,
                        "organization": {"id": 42, "login": "mindclade"},
                        "teams": {"architecture": {"id": 101}},
                        "team_members": {
                            "architecture": [
                                {
                                    "login": "mindclade-founder",
                                    "role": "maintainer",
                                }
                            ],
                        },
                    }
                )
            )

            denied_cases = [
                {
                    "address": 'module.repository_governance.github_repository.this["github-config"]',
                    "type": "github_repository",
                    "change": {
                        "actions": ["update"],
                        "before": {"default_branch": "main"},
                        "after": {"default_branch": "unreviewed"},
                    },
                },
                {
                    "address": 'module.repository_environments.github_repository_environment.this["github-config:trusted-build"]',
                    "type": "github_repository_environment",
                    "change": {
                        "actions": ["update"],
                        "before": {"wait_timer": 0},
                        "after": {"wait_timer": 1},
                    },
                },
                {
                    "address": 'module.repository_governance.github_repository.this["github-config"]',
                    "type": "github_repository",
                    "change": {
                        "actions": ["create"],
                        "before": None,
                        "after": {"fork": None},
                        "after_unknown": {"fork": True},
                    },
                },
            ]
            for change in denied_cases:
                receipt = evidence([change])
                self.assertFalse(receipt["decision"]["eligible_for_protected_apply"])
                self.assertIn("unknown_change", receipt["plan"]["writes"][0]["classes"])

            deletion = {
                "address": 'module.team_access.github_team_membership.this["architecture:mindclade-founder"]',
                "type": "github_team_membership",
                "change": {
                    "actions": ["delete"],
                    "before": {
                        "team_id": "101",
                        "username": "mindclade-founder",
                        "role": "maintainer",
                    },
                    "after": None,
                },
            }
            still_declared = evidence([deletion])
            self.assertFalse(still_declared["decision"]["eligible_for_protected_apply"])
            self.assertIn(
                "authority_replacement",
                still_declared["plan"]["writes"][0]["classes"],
            )

            revocation_root = directory / "revocation-root"
            shutil.copytree(ROOT / "config", revocation_root / "config")
            shutil.copytree(ROOT / "schemas", revocation_root / "schemas")
            shutil.copytree(ROOT / ".github", revocation_root / ".github")
            shutil.copy2(ROOT / "component.yaml", revocation_root / "component.yaml")
            architecture = revocation_root / "config" / "teams" / "architecture.yaml"
            architecture.write_text(
                architecture.read_text().replace(
                    "    - login: mindclade-founder\n      role: maintainer\n",
                    "",
                )
            )
            revocation_catalog = directory / "revocation-catalog.json"
            compiled = invoke(
                "compile",
                "--output",
                str(revocation_catalog),
                root=revocation_root,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            proved_revocation = evidence(
                [deletion],
                catalog_path=revocation_catalog,
                evidence_root=revocation_root,
                destructive_review=True,
            )
            self.assertTrue(proved_revocation["decision"]["eligible_for_protected_apply"])
            self.assertIn(
                "permission_reduction",
                proved_revocation["plan"]["writes"][0]["classes"],
            )

            observed.write_text(
                json.dumps(
                    {
                        "core_observation_complete": True,
                        "organization": {"id": 42, "login": "mindclade"},
                        "teams": {"architecture": {"id": 101}},
                        "team_members": {"architecture": []},
                    }
                )
            )
            unobserved_revocation = evidence(
                [deletion],
                catalog_path=revocation_catalog,
                evidence_root=revocation_root,
            )
            self.assertFalse(unobserved_revocation["decision"]["eligible_for_protected_apply"])
            self.assertIn(
                "authority_replacement",
                unobserved_revocation["plan"]["writes"][0]["classes"],
            )

    def test_catalog_binding_accepts_exact_actions_access_and_custom_properties(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            catalog = directory / "catalog.json"
            plan = directory / "plan.json"
            output = directory / "evidence.json"
            compiled = invoke("compile", "--output", str(catalog))
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            compiled_catalog = json.loads(catalog.read_text())

            def evidence(change):
                plan.write_text(
                    json.dumps(
                        {
                            "format_version": "1.2",
                            "terraform_version": "1.12.6",
                            "resource_changes": [change],
                        }
                    )
                )
                result = invoke(
                    "evidence",
                    "--plan",
                    str(plan),
                    "--catalog",
                    str(catalog),
                    "--phase",
                    "foundation",
                    "--risk-acknowledged",
                    "--output",
                    str(output),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(output.read_text())

            actions_access = {
                "address": (
                    "module.repository_governance."
                    'github_actions_repository_access_level.this["dot-github"]'
                ),
                "type": "github_actions_repository_access_level",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {
                        "repository": ".github",
                        "access_level": "organization",
                        "id": None,
                    },
                    "after_unknown": {"id": True},
                },
            }
            exact_access = evidence(actions_access)
            self.assertTrue(exact_access["decision"]["eligible_for_protected_apply"])
            self.assertNotIn("unknown_change", exact_access["plan"]["writes"][0]["classes"])

            overbroad_access = json.loads(json.dumps(actions_access))
            overbroad_access["change"]["after"]["access_level"] = "enterprise"
            denied_access = evidence(overbroad_access)
            self.assertFalse(denied_access["decision"]["eligible_for_protected_apply"])
            self.assertIn("unknown_change", denied_access["plan"]["writes"][0]["classes"])

            owner_property = next(
                property_definition
                for property_definition in compiled_catalog["organization"]["custom_properties"]
                if property_definition["name"] == "owner_team"
            )
            effective_owner_values = sorted(
                set(
                    owner_property["allowed_values"]
                    + compiled_catalog["organization"]["custom_property_migration"][
                        "legacy_allowed_values"
                    ]["owner_team"]
                )
            )
            organization_property = {
                "address": (
                    "module.organization_settings."
                    'github_organization_custom_properties.this["owner_team"]'
                ),
                "type": "github_organization_custom_properties",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {
                        "property_name": "owner_team",
                        "value_type": owner_property["value_type"],
                        "required": owner_property["required"],
                        "allowed_values": effective_owner_values,
                        "values_editable_by": owner_property["values_editable_by"],
                        "id": None,
                    },
                    "after_unknown": {"id": True},
                },
            }
            preserved_property = evidence(organization_property)
            self.assertTrue(preserved_property["decision"]["eligible_for_protected_apply"])
            self.assertNotIn("unknown_change", preserved_property["plan"]["writes"][0]["classes"])

            premature_retirement = json.loads(json.dumps(organization_property))
            premature_retirement["change"]["after"]["allowed_values"].remove("platform")
            denied_retirement = evidence(premature_retirement)
            self.assertFalse(denied_retirement["decision"]["eligible_for_protected_apply"])
            self.assertIn("unknown_change", denied_retirement["plan"]["writes"][0]["classes"])

            retirement_root = directory / "retirement-root"
            shutil.copytree(ROOT / "config", retirement_root / "config")
            shutil.copytree(ROOT / "schemas", retirement_root / "schemas")
            shutil.copytree(ROOT / ".github", retirement_root / ".github")
            shutil.copy2(ROOT / "component.yaml", retirement_root / "component.yaml")
            organization_source = retirement_root / "config" / "organization.yaml"
            organization_source.write_text(
                organization_source.read_text().replace(
                    "  custom_property_migration:\n"
                    "    phase: preserve\n"
                    "    legacy_allowed_values:\n"
                    "      owner_team: [platform]\n"
                    "      ci_profile: [none]\n"
                    "      production_authority: [enterprise-control]\n",
                    "  custom_property_migration:\n"
                    "    phase: retire\n"
                    "    legacy_allowed_values: {}\n",
                )
            )
            retirement_catalog = directory / "retirement-catalog.json"
            retirement_compile = invoke(
                "compile",
                "--output",
                str(retirement_catalog),
                root=retirement_root,
            )
            self.assertEqual(retirement_compile.returncode, 0, retirement_compile.stderr)
            retirement_desired = json.loads(retirement_catalog.read_text())
            observed_assignments = {
                "core_observation_complete": True,
                "organization": {"id": 42, "login": "mindclade"},
                "repositories": {
                    repository["name"]: {"name": repository["name"]}
                    for repository in retirement_desired["repositories"].values()
                },
                "repository_custom_properties": {
                    repository["name"]: [
                        {"property_name": name, "value": value}
                        for name, value in repository["custom_properties"].items()
                    ]
                    for repository in retirement_desired["repositories"].values()
                },
            }
            dot_github_properties = observed_assignments["repository_custom_properties"][".github"]
            owner_assignment = next(
                assignment
                for assignment in dot_github_properties
                if assignment["property_name"] == "owner_team"
            )
            owner_assignment["value"] = "platform"
            observed_path = directory / "retirement-observed.json"
            retirement_change = json.loads(json.dumps(organization_property))
            retirement_change["change"]["after"]["allowed_values"] = owner_property[
                "allowed_values"
            ]

            def retirement_evidence():
                plan.write_text(
                    json.dumps(
                        {
                            "format_version": "1.2",
                            "terraform_version": "1.12.6",
                            "resource_changes": [retirement_change],
                        }
                    )
                )
                observed_path.write_text(json.dumps(observed_assignments))
                result = invoke(
                    "evidence",
                    "--plan",
                    str(plan),
                    "--catalog",
                    str(retirement_catalog),
                    "--observed",
                    str(observed_path),
                    "--phase",
                    "foundation",
                    "--risk-acknowledged",
                    "--output",
                    str(output),
                    root=retirement_root,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(output.read_text())

            unqualified_retirement = retirement_evidence()
            self.assertFalse(unqualified_retirement["decision"]["eligible_for_protected_apply"])
            self.assertIn(
                "unknown_change",
                unqualified_retirement["plan"]["writes"][0]["classes"],
            )

            owner_assignment["value"] = retirement_desired["repositories"]["dot-github"][
                "custom_properties"
            ]["owner_team"]
            qualified_retirement = retirement_evidence()
            self.assertTrue(qualified_retirement["decision"]["eligible_for_protected_apply"])
            self.assertNotIn(
                "unknown_change",
                qualified_retirement["plan"]["writes"][0]["classes"],
            )

    def test_ci_evidence_environment_variables_bind_exact_qualified_catalog_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            catalog_path = directory / "catalog.json"
            plan_path = directory / "plan.json"
            output_path = directory / "evidence.json"
            qualified_root = directory / "qualified-root"
            shutil.copytree(ROOT / "config", qualified_root / "config")
            shutil.copytree(ROOT / "schemas", qualified_root / "schemas")
            shutil.copytree(ROOT / ".github", qualified_root / ".github")
            shutil.copy2(ROOT / "component.yaml", qualified_root / "component.yaml")
            environment_path = (
                qualified_root / "config" / "environments" / "infrastructure-apply.yaml"
            )
            environment_path.write_text(
                environment_path.read_text().replace(
                    "  activation:\n"
                    "    state: blocked\n"
                    "    blockers:\n"
                    "      - independent-reviewer-required\n"
                    "      - protected-environment-not-qualified\n"
                    "      - ci-evidence-verifier-handoff-not-connected-qualified\n"
                    "      - infrastructure-export-verifier-handoff-not-connected-qualified\n",
                    qualified_infrastructure_apply_variables() + "  activation:\n"
                    "    state: ready\n"
                    "    blockers: []\n",
                    1,
                )
            )
            compiled = invoke(
                "compile",
                "--output",
                str(catalog_path),
                root=qualified_root,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)

            change = {
                "address": (
                    "module.repository_environments."
                    "github_actions_environment_variable.this"
                    '["infrastructure-apply:infrastructure-live:'
                    'CI_EVIDENCE_ARCHIVE_BUCKET"]'
                ),
                "type": "github_actions_environment_variable",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {
                        "repository": "infrastructure-live",
                        "environment": "infrastructure-apply",
                        "variable_name": "CI_EVIDENCE_ARCHIVE_BUCKET",
                        "value": "production-ci-evidence",
                        "id": None,
                        "created_at": None,
                        "updated_at": None,
                    },
                    "after_unknown": {
                        "id": True,
                        "created_at": True,
                        "updated_at": True,
                    },
                },
            }

            def evidence(resource_change):
                plan_path.write_text(
                    json.dumps(
                        {
                            "format_version": "1.2",
                            "terraform_version": "1.12.6",
                            "resource_changes": [resource_change],
                        }
                    )
                )
                result = invoke(
                    "evidence",
                    "--plan",
                    str(plan_path),
                    "--catalog",
                    str(catalog_path),
                    "--phase",
                    "foundation",
                    "--risk-acknowledged",
                    "--output",
                    str(output_path),
                    root=qualified_root,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(output_path.read_text())

            exact = evidence(change)
            self.assertTrue(exact["decision"]["eligible_for_protected_apply"])
            self.assertIn("privilege_expansion", exact["plan"]["writes"][0]["classes"])
            self.assertNotIn("unknown_change", exact["plan"]["writes"][0]["classes"])
            self.assertNotIn("production-ci-evidence", output_path.read_text())

            substituted = json.loads(json.dumps(change))
            substituted["change"]["after"]["value"] = "unreviewed-bucket"
            denied = evidence(substituted)
            self.assertFalse(denied["decision"]["eligible_for_protected_apply"])
            self.assertIn("unknown_change", denied["plan"]["writes"][0]["classes"])

    def test_protected_evidence_verification_requires_complete_authority_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            catalog = directory / "catalog.json"
            plan = directory / "plan.json"
            plan_file = directory / "tfplan"
            observed = directory / "observed.json"
            output = directory / "evidence.json"
            self.assertEqual(invoke("compile", "--output", str(catalog)).returncode, 0)
            plan.write_text(json.dumps({"format_version": "1.2", "resource_changes": []}))
            plan_file.write_bytes(b"reviewed-binary-plan")
            observed.write_text(
                json.dumps(
                    {
                        "core_observation_complete": True,
                        "organization": {"id": 4242, "login": "mindclade"},
                    }
                )
            )
            result = invoke(
                "evidence",
                "--plan",
                str(plan),
                "--plan-file",
                str(plan_file),
                "--catalog",
                str(catalog),
                "--observed",
                str(observed),
                "--change-reference",
                "https://github.com/mindclade/github-config/pull/1",
                "--workflow-ref",
                "mindclade/github-config/.github/workflows/protected-apply.yml@refs/heads/main",
                "--oidc-issuer",
                "https://token.actions.githubusercontent.com",
                "--source-sha",
                "a" * 40,
                "--workflow-sha",
                "b" * 40,
                "--actor-id",
                "1",
                "--plan-app-id",
                "10",
                "--apply-app-id",
                "11",
                "--run-id",
                "100",
                "--run-attempt",
                "1",
                "--created-epoch",
                "1800000000",
                "--expires-epoch",
                "1800003600",
                "--wif-qualification-evidence-digest",
                "sha256:" + "c" * 64,
                "--state-backend-digest",
                "sha256:" + "d" * 64,
                "--executor-contract-digest",
                "sha256:" + "e" * 64,
                "--review-context-digest",
                "sha256:" + "f" * 64,
                "--output",
                str(output),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            verified = invoke("verify-evidence", "--input", str(output))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            evidence_link = directory / "evidence-link.json"
            try:
                evidence_link.symlink_to(output)
            except OSError:
                evidence_link = None
            if evidence_link is not None:
                rejected_link = invoke("verify-evidence", "--input", str(evidence_link))
                self.assertNotEqual(rejected_link.returncode, 0)
                self.assertIn("non-symlink", rejected_link.stderr)

            private_key = directory / "evidence-private.pem"
            public_key = directory / "evidence-public.pem"
            signature = directory / "evidence.sig"
            subprocess.run(
                [
                    "openssl",
                    "ecparam",
                    "-name",
                    "prime256v1",
                    "-genkey",
                    "-noout",
                    "-out",
                    str(private_key),
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "openssl",
                    "dgst",
                    "-sha256",
                    "-sign",
                    str(private_key),
                    "-out",
                    str(signature),
                    str(output),
                ],
                check=True,
                capture_output=True,
            )
            public_key_digest = "sha256:" + hashlib.sha256(public_key.read_bytes()).hexdigest()
            authenticated = invoke(
                "verify-evidence",
                "--input",
                str(output),
                "--signature",
                str(signature),
                "--public-key",
                str(public_key),
                "--public-key-digest",
                public_key_digest,
                "--kms-key-version",
                "projects/mindclade-bootstrap/locations/us-central1/keyRings/bootstrap-signing/cryptoKeys/github-config-plan-evidence/cryptoKeyVersions/1",
                "--signature-algorithm",
                "EC_SIGN_P256_SHA256",
                "--at-epoch",
                "1800000100",
                "--require-eligible",
                "--expected-change-reference",
                "https://github.com/mindclade/github-config/pull/1",
                "--expected-review-context-digest",
                "sha256:" + "f" * 64,
                "--expected-source-sha",
                "a" * 40,
                "--expected-workflow-ref",
                "mindclade/github-config/.github/workflows/protected-apply.yml@refs/heads/main",
                "--expected-workflow-sha",
                "b" * 40,
            )
            self.assertEqual(authenticated.returncode, 0, authenticated.stderr)
            wrong_key_authority = invoke(
                "verify-evidence",
                "--input",
                str(output),
                "--signature",
                str(signature),
                "--public-key",
                str(public_key),
                "--public-key-digest",
                public_key_digest,
                "--kms-key-version",
                "projects/mindclade-bootstrap/locations/us-central1/keyRings/bootstrap-signing/cryptoKeys/recovery-evidence/cryptoKeyVersions/1",
                "--signature-algorithm",
                "EC_SIGN_P256_SHA256",
                "--at-epoch",
                "1800000100",
                "--require-eligible",
                "--expected-change-reference",
                "https://github.com/mindclade/github-config/pull/1",
                "--expected-review-context-digest",
                "sha256:" + "f" * 64,
                "--expected-source-sha",
                "a" * 40,
                "--expected-workflow-ref",
                "mindclade/github-config/.github/workflows/protected-apply.yml@refs/heads/main",
                "--expected-workflow-sha",
                "b" * 40,
            )
            self.assertNotEqual(wrong_key_authority.returncode, 0)
            self.assertIn(
                "bootstrap-signing/github-config-plan-evidence", wrong_key_authority.stderr
            )
            signature.write_bytes(
                signature.read_bytes()[:-1] + bytes([signature.read_bytes()[-1] ^ 1])
            )
            rejected_signature = invoke(
                "verify-evidence",
                "--input",
                str(output),
                "--signature",
                str(signature),
                "--public-key",
                str(public_key),
                "--public-key-digest",
                public_key_digest,
                "--kms-key-version",
                "projects/mindclade-bootstrap/locations/us-central1/keyRings/bootstrap-signing/cryptoKeys/github-config-plan-evidence/cryptoKeyVersions/1",
                "--signature-algorithm",
                "EC_SIGN_P256_SHA256",
                "--at-epoch",
                "1800000100",
                "--require-eligible",
                "--expected-change-reference",
                "https://github.com/mindclade/github-config/pull/1",
                "--expected-review-context-digest",
                "sha256:" + "f" * 64,
                "--expected-source-sha",
                "a" * 40,
                "--expected-workflow-ref",
                "mindclade/github-config/.github/workflows/protected-apply.yml@refs/heads/main",
                "--expected-workflow-sha",
                "b" * 40,
            )
            self.assertNotEqual(rejected_signature.returncode, 0)
            self.assertIn("signature verification failed", rejected_signature.stderr)

            forged = json.loads(output.read_text())
            forged.pop("evidence_digest")
            forged["digests"].pop("plan_file")
            forged["bindings"].pop("plan_file")
            canonical = (
                json.dumps(
                    forged,
                    sort_keys=True,
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            )
            forged["evidence_digest"] = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
            output.write_text(json.dumps(forged))
            rejected = invoke("verify-evidence", "--input", str(output))
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("plan_file", rejected.stderr)

    def test_evidence_execution_window_is_bound_before_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            plan = directory / "plan.json"
            observed = directory / "observed.json"
            output = directory / "evidence.json"
            plan.write_text(json.dumps({"format_version": "1.2", "resource_changes": []}))
            observed.write_text(
                json.dumps(
                    {
                        "core_observation_complete": True,
                        "organization": {"id": 4242, "login": "mindclade"},
                    }
                )
            )
            result = invoke(
                "evidence",
                "--plan",
                str(plan),
                "--output",
                str(output),
                "--observed",
                str(observed),
                "--run-id",
                "123",
                "--run-attempt",
                "2",
                "--created-epoch",
                "1800000000",
                "--expires-epoch",
                "1800021600",
                "--reviewed-evidence-digest",
                "sha256:" + "a" * 64,
                "--reviewed-plan-digest",
                "b" * 64,
                "--post-apply-drift-digest",
                "c" * 64,
                "--post-apply-drift-exit-code",
                "0",
                "--attempt-status",
                "failed",
                "--apply-started",
                "true",
                "--failure-stage",
                "apply",
                "--apply-exit-code",
                "1",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads(output.read_text())
            self.assertEqual(receipt["bindings"]["run_id"], 123)
            self.assertEqual(receipt["bindings"]["organization"], "mindclade")
            self.assertEqual(receipt["bindings"]["organization_id"], 4242)
            self.assertRegex(receipt["digests"]["observed_state"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(
                receipt["bindings"]["expires_epoch"] - receipt["bindings"]["created_epoch"], 21600
            )
            self.assertRegex(receipt["evidence_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(receipt["bindings"]["reviewed_plan_digest"], "b" * 64)
            self.assertEqual(receipt["bindings"]["attempt_status"], "failed")
            self.assertTrue(receipt["bindings"]["apply_started"])
            self.assertEqual(receipt["bindings"]["failure_stage"], "apply")
            self.assertEqual(receipt["bindings"]["apply_exit_code"], 1)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            verified = invoke("verify-evidence", "--input", str(output))
            self.assertEqual(verified.returncode, 0, verified.stderr)

            receipt["bindings"]["run_attempt"] = 3
            output.write_text(json.dumps(receipt))
            tampered = invoke("verify-evidence", "--input", str(output))
            self.assertNotEqual(tampered.returncode, 0)

            invalid = invoke(
                "evidence",
                "--plan",
                str(plan),
                "--output",
                str(output),
                "--created-epoch",
                "1800000000",
                "--expires-epoch",
                "1800021601",
            )
            self.assertNotEqual(invalid.returncode, 0)

    def test_evidence_allowlist_covers_every_declared_github_resource_type(self):
        resource_types = set()
        for path in (ROOT / "opentofu").rglob("*.tf"):
            resource_types.update(
                re.findall(r'^resource\s+"(github_[^"]+)"', path.read_text(), re.MULTILINE)
            )
        self.assertTrue(resource_types)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            plan = directory / "plan.json"
            output = directory / "evidence.json"
            plan.write_text(
                json.dumps(
                    {
                        "format_version": "1.2",
                        "resource_changes": [
                            {
                                "address": f"{resource_type}.contract",
                                "type": resource_type,
                                "change": {"actions": ["update"], "before": {}, "after": {}},
                            }
                            for resource_type in sorted(resource_types)
                        ],
                    }
                )
            )
            result = invoke(
                "evidence",
                "--plan",
                str(plan),
                "--phase",
                "foundation",
                "--risk-acknowledged",
                "--output",
                str(output),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            writes = {
                write["resource_type"]: write
                for write in json.loads(output.read_text())["plan"]["writes"]
            }
            self.assertEqual(set(writes), resource_types)
            for resource_type, write in writes.items():
                self.assertNotIn("unknown_change", write["classes"], resource_type)

    def test_evidence_rejects_catalog_identity_mismatch_and_incomplete_protected_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            catalog = directory / "catalog.json"
            plan = directory / "plan.json"
            output = directory / "evidence.json"
            self.assertEqual(invoke("compile", "--output", str(catalog)).returncode, 0)
            plan.write_text(json.dumps({"format_version": "1.2", "resource_changes": []}))
            mismatch = invoke(
                "evidence",
                "--plan",
                str(plan),
                "--catalog",
                str(catalog),
                "--organization",
                "different-org",
                "--output",
                str(output),
            )
            self.assertNotEqual(mismatch.returncode, 0)
            incomplete = invoke(
                "evidence",
                "--plan",
                str(plan),
                "--plan-app-id",
                "10",
                "--apply-app-id",
                "10",
                "--output",
                str(output),
            )
            self.assertNotEqual(incomplete.returncode, 0)
            missing_observed = invoke(
                "evidence",
                "--plan",
                str(plan),
                "--catalog",
                str(catalog),
                "--organization",
                "mindclade",
                "--change-reference",
                "https://github.com/mindclade/github-config/pull/1",
                "--workflow-ref",
                "mindclade/github-config/.github/workflows/protected-apply.yml@refs/heads/main",
                "--oidc-issuer",
                "https://token.actions.githubusercontent.com",
                "--source-sha",
                "a" * 40,
                "--workflow-sha",
                "b" * 40,
                "--actor-id",
                "1",
                "--plan-app-id",
                "10",
                "--apply-app-id",
                "11",
                "--output",
                str(output),
                "--wif-qualification-evidence-digest",
                "sha256:" + "c" * 64,
                "--state-backend-digest",
                "sha256:" + "d" * 64,
                "--executor-contract-digest",
                "sha256:" + "e" * 64,
                "--review-context-digest",
                "sha256:" + "f" * 64,
            )
            self.assertNotEqual(missing_observed.returncode, 0)
            self.assertIn("requires --observed", missing_observed.stderr)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
