import json
import hashlib
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CLI = os.environ.get("GITHUB_CONFIGCTL") or (sys.argv[1] if len(sys.argv) > 1 else "")


def invoke(*arguments):
    if CLI:
        command, cwd = [str(Path(CLI).resolve())], ROOT
    else:
        command, cwd = ["go", "run", "./cmd/github-configctl"], ROOT / "compiler"
    return subprocess.run(command + ["--root", str(ROOT), *arguments], cwd=cwd, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


class PermissionReductionTest(unittest.TestCase):
    def compile_catalog(self, directory):
        output = directory / "catalog.json"
        result = invoke("compile", "--output", str(output))
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(output.read_text()), output

    def test_catalog_grants_no_admin_or_direct_repository_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            catalog, _ = self.compile_catalog(Path(temporary))
        self.assertEqual(catalog["organization"]["default_repository_permission"], "none")
        rank = {"pull": 0, "triage": 1, "push": 2, "maintain": 3}
        for name, repository in catalog["repositories"].items():
            self.assertEqual(repository["direct_collaborators"], [], name)
            for grant in repository["team_grants"]:
                self.assertIn(grant["permission"], rank, name)
                self.assertLessEqual(rank[grant["permission"]], rank["maintain"], name)

    def test_aliases_do_not_satisfy_distinct_human_preflight(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            catalog, catalog_path = self.compile_catalog(directory)
            observed = {
                "core_observation_complete": True,
                "observation_complete": True,
                "repository_inventory_complete": True,
                "errors": [],
                "organization": {"login": "mindclade", "two_factor_requirement_enabled": True},
                "members": [{"login": member["login"]} for member in catalog["members"]],
                "organization_admins": [{"login": member["login"]} for member in catalog["members"]],
                "managed_projection": {},
                "capabilities": {
                    "enterprise_cloud": True,
                    "advanced_security": True,
                    "advanced_security_available": True,
                    "protected_environments": True,
                    "protected_environments_available": True,
                },
                "integrations": {
                    name: {"qualified": True} for name in catalog["integrations"]
                },
            }
            observed_path = directory / "observed.json"
            report_path = directory / "preflight.json"
            observed_path.write_text(json.dumps(observed))
            result = invoke(
                "preflight", "--desired", str(catalog_path),
                "--observed", str(observed_path), "--output", str(report_path),
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(report_path.read_text())
            codes = {blocker["code"] for blocker in report["blockers"]}
            self.assertIn("INSUFFICIENT_DISTINCT_HUMANS", codes)
            self.assertIn("DESIRED_ACTIVATION_BLOCKED", codes)
            self.assertIn("REVIEWER_QUORUM_UNSATISFIED", codes)
            self.assertFalse(report["eligible"])

            adopt = invoke(
                "preflight", "--desired", str(catalog_path), "--observed", str(observed_path),
                "--phase", "adopt", "--output", str(report_path),
            )
            self.assertEqual(adopt.returncode, 0, adopt.stderr)
            self.assertEqual(json.loads(report_path.read_text())["blockers"], [])

            foundation = invoke(
                "preflight", "--desired", str(catalog_path), "--observed", str(observed_path),
                "--phase", "foundation", "--output", str(report_path),
            )
            self.assertEqual(foundation.returncode, 2, foundation.stderr)
            foundation_report = json.loads(report_path.read_text())
            foundation_codes = {item["code"] for item in foundation_report["blockers"]}
            self.assertIn("DESIRED_ACTIVATION_BLOCKED", foundation_codes)
            self.assertIn("INSTALLATION_INVENTORY_UNQUALIFIED", foundation_codes)

            blocked_ids = {
                key for key, activation in catalog["activation"].items()
                if activation["state"] != "ready" or activation["blockers"]
            }
            activation_messages = [
                item["message"] for item in foundation_report["blockers"]
                if item["code"] == "DESIRED_ACTIVATION_BLOCKED"
            ]
            for blocked_id in blocked_ids:
                self.assertTrue(
                    any(f"/activation/{blocked_id}:" in message for message in activation_messages),
                    blocked_id,
                )

    def test_adopt_accepts_capability_unknowns_while_foundation_blocks_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            catalog, catalog_path = self.compile_catalog(directory)
            observed = {
                "core_observation_complete": True,
                "observation_complete": False,
                "errors": [{"section": "organization_rulesets", "error": "404 Not Found"}],
                "organization": {"login": catalog["organization"]["organization_login"]},
                "managed_projection": {"rulesets": {"status": "unknown"}},
            }
            observed_path = directory / "observed.json"
            report_path = directory / "preflight.json"
            observed_path.write_text(json.dumps(observed))
            adopt = invoke(
                "preflight", "--desired", str(catalog_path), "--observed", str(observed_path),
                "--phase", "adopt", "--output", str(report_path),
            )
            self.assertEqual(adopt.returncode, 0, adopt.stderr)
            foundation = invoke(
                "preflight", "--desired", str(catalog_path), "--observed", str(observed_path),
                "--phase", "foundation", "--output", str(report_path),
            )
            self.assertEqual(foundation.returncode, 2, foundation.stderr)
            self.assertIn(
                "CAPABILITY_OBSERVATION_INCOMPLETE",
                {item["code"] for item in json.loads(report_path.read_text())["blockers"]},
            )

    def test_greenfield_foundation_blocks_until_mutation_authority_is_ready(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            catalog, catalog_path = self.compile_catalog(directory)
            catalog["members"][1]["principal_id"] = "independent-administrator"
            catalog["teams"]["release-engineering"]["members"].append({
                "login": catalog["members"][0]["login"], "role": "maintainer",
            })
            catalog_path.write_text(json.dumps(catalog))
            observed = {
                "core_observation_complete": True,
                "observation_complete": True,
                "repository_inventory_complete": True,
                "errors": [],
                "organization": {
                    "login": catalog["organization"]["organization_login"],
                    "two_factor_requirement_enabled": False,
                },
                "members": [{"login": member["login"]} for member in catalog["members"]],
                "organization_admins": [{"login": member["login"]} for member in catalog["members"]],
                "teams": {}, "repositories": {}, "rulesets": {}, "environments": {},
                "managed_projection": {},
                "managed_state_matches_desired": False,
                "capabilities": {
                    "enterprise_cloud": True,
                    "advanced_security": False,
                    "advanced_security_available": True,
                    "protected_environments": False,
                    "protected_environments_available": True,
                },
            }
            observed_path = directory / "observed.json"
            report_path = directory / "preflight.json"
            observed_path.write_text(json.dumps(observed))
            foundation = invoke(
                "preflight", "--desired", str(catalog_path), "--observed", str(observed_path),
                "--phase", "foundation", "--output", str(report_path),
            )
            self.assertEqual(foundation.returncode, 2, foundation.stderr)
            foundation_codes = {item["code"] for item in json.loads(report_path.read_text())["blockers"]}
            self.assertIn("DESIRED_ACTIVATION_BLOCKED", foundation_codes)
            self.assertIn("INSTALLATION_INVENTORY_UNQUALIFIED", foundation_codes)
            self.assertIn("TWO_FACTOR_REQUIREMENT_MISMATCH", foundation_codes)
            self.assertIn("OIDC_IDENTITY_INCOMPLETE", foundation_codes)
            enforce = invoke(
                "preflight", "--desired", str(catalog_path), "--observed", str(observed_path),
                "--phase", "enforce", "--output", str(report_path),
            )
            self.assertEqual(enforce.returncode, 2, enforce.stderr)
            codes = {item["code"] for item in json.loads(report_path.read_text())["blockers"]}
            self.assertIn("MANAGED_STATE_NOT_CONVERGED", codes)
            self.assertIn("OIDC_IDENTITY_INCOMPLETE", codes)

    def test_adoption_maps_are_derived_only_from_authoritative_live_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            catalog, catalog_path = self.compile_catalog(directory)
            claims = catalog["oidc_policy"]["include_claim_keys"]
            members = catalog["members"]
            managed_property = catalog["organization"]["custom_properties"][0]
            observed = {
                "core_observation_complete": True,
                "observation_complete": True,
                "errors": [],
                "organization": {"id": 1, "login": catalog["organization"]["organization_login"]},
                "oidc_policy": {"include_claim_keys": claims, "use_immutable_subject": True},
                "repository_oidc_policies": {
                    "github-config": {
                        "use_default": False, "include_claim_keys": claims,
                        "use_immutable_subject": True,
                    },
                },
                "members": [{"login": member["login"]} for member in members],
                "organization_admins": [{"login": member["login"]} for member in members],
                "teams": {"security": {"id": 10, "name": "security", "slug": "security"}},
                "team_members": {"security": [
                    {"login": member["login"], "role": "maintainer"} for member in members
                ]},
                "repositories": {
                    repository["name"]: {"id": 20 + index, "name": repository["name"]}
                    for index, repository in enumerate(catalog["repositories"].values())
                },
                "repository_team_grants": {
                    "github-config": [{"slug": "security", "permission": "maintain"}],
                },
                "repository_dependabot_security_updates": {"github-config": True},
                "repository_custom_properties": {"github-config": []},
                "repository_direct_collaborators": {"github-config": []},
                "organization_custom_properties": [{
                    "property_name": managed_property["name"],
                    "value_type": managed_property["value_type"],
                    "required": managed_property["required"],
                    "allowed_values": managed_property["allowed_values"],
                    "values_editable_by": managed_property["values_editable_by"],
                }],
                "security_manager_teams": [],
                "organization_roles": {"roles": []},
            }
            observed_path = directory / "observed.json"
            report_path = directory / "preflight.json"
            observed_path.write_text(json.dumps(observed))
            result = invoke(
                "preflight", "--desired", str(catalog_path), "--observed", str(observed_path),
                "--phase", "adopt", "--output", str(report_path),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(report_path.read_text())
            self.assertEqual(report["adopted_team_ids"]["security"], 10)
            self.assertEqual(report["adopted_repository_names"]["github-config"], "github-config")
            self.assertEqual(report["adopted_organization_oidc_templates"], {"organization": "mindclade"})
            self.assertEqual(report["adopted_repository_oidc_templates"], {"github-config": "github-config"})
            self.assertEqual(report["adopted_memberships"][members[0]["login"]], f"mindclade:{members[0]['login']}")
            self.assertEqual(
                report["adopted_team_memberships"][f"security:{members[0]['login']}"],
                f"10:{members[0]['login']}",
            )
            self.assertEqual(
                report["adopted_team_repository_grants"]["github-config:security"],
                "10:github-config",
            )
            self.assertEqual(report["adopted_dependabot_security_updates"], {"github-config": "github-config"})
            self.assertEqual(
                report["adopted_organization_custom_properties"],
                {managed_property["name"]: managed_property["name"]},
            )
            self.assertEqual(report["observed_oidc_identity"]["organization_id"], 1)
            self.assertEqual(
                set(report["observed_oidc_identity"]["repository_ids"]),
                set(catalog["repositories"]),
            )

            observed["organization_custom_properties"][0]["values_editable_by"] = "repository_actors"
            observed_path.write_text(json.dumps(observed))
            result = invoke(
                "preflight", "--desired", str(catalog_path), "--observed", str(observed_path),
                "--phase", "adopt", "--output", str(report_path),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(
                managed_property["name"],
                json.loads(report_path.read_text())["adopted_organization_custom_properties"],
            )

    def test_integration_qualification_requires_self_digest_and_observed_repository_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            now = datetime.now(timezone.utc).replace(microsecond=0)
            attestation = {
                "authority": "bootstrap",
                "source_sha": "a" * 40,
                "app_id": 123,
                "installation_id": 456,
                "repository_selection": "selected",
                "repositories": [{"name": "repo", "id": 2}],
                "permissions": [{"name": "contents", "access": "read"}],
                "events": ["push"],
                "created_at": now.isoformat().replace("+00:00", "Z"),
                "expires_at": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            }
            canonical_attestation = json.dumps(attestation, sort_keys=True, indent=2) + "\n"
            digest = "sha256:" + hashlib.sha256(canonical_attestation.encode()).hexdigest()
            desired = {
                "organization": {"organization_login": "mindclade", "two_factor_requirement": False},
                "security_policy": {"required_capabilities": []},
                "members": [
                    {"login": "admin-one", "role": "admin", "principal_id": "one", "active": True},
                    {"login": "admin-two", "role": "admin", "principal_id": "two", "active": True},
                ],
                "teams": {"owner": {"name": "owner", "members": []}},
                "repositories": {"repo": {
                    "name": "repo",
                    "custom_properties": {"owner_team": "owner"},
                    "team_grants": [{"team": "owner", "permission": "maintain"}],
                }},
                "rulesets": {},
                "environments": {},
                "integrations": {"app": {
                    "actor_id": 123,
                    "repository_selection": "selected",
                    "repositories": ["repo"],
                    "permissions": [{"name": "contents", "access": "read"}],
                    "events": ["push"],
                    "qualification": {
                        "state": "qualified", "authority": "bootstrap",
                        "evidence_digest": digest, "attestation": attestation,
                    },
                    "activation": {"state": "ready", "blockers": []},
                }},
                "activation": {"app": {"state": "ready", "blockers": []}},
            }
            observed = {
                "core_observation_complete": True,
                "observation_complete": True,
                "repository_inventory_complete": True,
                "errors": [],
                "organization": {
                    "id": 1, "login": "mindclade", "two_factor_requirement_enabled": False,
                },
                "members": [{"login": "admin-one"}, {"login": "admin-two"}],
                "organization_admins": [{"login": "admin-one"}, {"login": "admin-two"}],
                "repositories": {"repo": {"id": 2, "name": "repo"}},
                "managed_projection": {},
                "managed_state_matches_desired": True,
                "capabilities": {},
                "integrations": {"app": {
                    "installed": True,
                    "qualified": False,
                    "actor_id": 123,
                    "installation_id": 456,
                    "app_slug": "app",
                    "events": ["push"],
                    "suspended_at": None,
                    "repository_selection": "selected",
                    "permissions": {"contents": "read"},
                    "repository_scope_observed": False,
                }},
            }
            desired_path = directory / "desired.json"
            observed_path = directory / "observed.json"
            report_path = directory / "preflight.json"
            desired_path.write_text(json.dumps(desired))
            observed_path.write_text(json.dumps(observed))
            result = invoke(
                "preflight", "--desired", str(desired_path), "--observed", str(observed_path),
                "--phase", "enforce", "--output", str(report_path),
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            qualified_report = json.loads(report_path.read_text())
            self.assertEqual(qualified_report["qualified_integration_actor_ids"], {"app": 123})
            self.assertIn(
                "INSTALLATION_INVENTORY_UNQUALIFIED",
                {item["code"] for item in qualified_report["blockers"]},
            )

            observed["repositories"]["repo"]["id"] = 3
            observed_path.write_text(json.dumps(observed))
            result = invoke(
                "preflight", "--desired", str(desired_path), "--observed", str(observed_path),
                "--phase", "enforce", "--output", str(report_path),
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn(
                "INTEGRATION_UNQUALIFIED",
                {item["code"] for item in json.loads(report_path.read_text())["blockers"]},
            )

            observed["repositories"]["repo"]["id"] = 2
            observed_path.write_text(json.dumps(observed))
            desired["integrations"]["app"]["qualification"]["evidence_digest"] = "sha256:" + "0" * 64
            desired_path.write_text(json.dumps(desired))
            result = invoke(
                "preflight", "--desired", str(desired_path), "--observed", str(observed_path),
                "--phase", "enforce", "--output", str(report_path),
            )
            self.assertEqual(result.returncode, 2, result.stderr)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
