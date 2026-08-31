# pyright: basic, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI = os.environ.get("GITHUB_CONFIGCTL") or (sys.argv[1] if len(sys.argv) > 1 else "")


def invoke(*arguments):
    if CLI:
        command, cwd = [str(Path(CLI).resolve())], ROOT
    else:
        command, cwd = ["go", "run", "./cmd/github-configctl"], ROOT / "compiler"
    return subprocess.run(
        [*command, "--root", str(ROOT), *arguments],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


class RulesetPlanTest(unittest.TestCase):
    def test_compiled_rulesets_are_active_immutable_and_merge_queue_compatible(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "catalog.json"
            result = invoke("compile", "--output", str(output))
            self.assertEqual(result.returncode, 0, result.stderr)
            catalog = json.loads(output.read_text())

        self.assertEqual(
            set(catalog["rulesets"]),
            {
                "application-source",
                "governance-source",
                "infrastructure-source",
                "deployment-source",
                "release-tags",
            },
        )
        for name, ruleset in catalog["rulesets"].items():
            self.assertEqual(ruleset["enforcement"], "active", name)
            self.assertEqual(ruleset["bypass_actors"], [], name)
            rules = ruleset["rules"]
            self.assertTrue(rules["deletion"], name)
            self.assertTrue(rules["non_fast_forward"], name)
            if ruleset["target"] == "branch":
                self.assertTrue(rules["required_signatures"], name)
                self.assertTrue(rules["required_linear_history"], name)
                self.assertTrue(rules["merge_queue"], name)
                pull_request = rules["pull_request"]
                self.assertGreaterEqual(pull_request["required_approving_review_count"], 2)
                self.assertTrue(pull_request["require_code_owner_review"])
                self.assertTrue(pull_request["require_distinct_principals"])
                checks = rules["required_status_checks"]["checks"]
                self.assertTrue(checks)
                for check in checks:
                    self.assertEqual(set(check["triggers"]), {"pull_request", "merge_group"})
            else:
                self.assertTrue(rules["update"], name)

        application = catalog["rulesets"]["application-source"]
        self.assertEqual(application["bypass_actors"], [])
        self.assertEqual(
            application["rules"]["pull_request"]["required_approving_review_count"],
            2,
        )
        self.assertEqual(
            application["rules"]["required_status_checks"]["checks"],
            [
                {
                    "context": "Pull request / required",
                    "issuer_type": "github_actions",
                    "workflow_path": ".github/workflows/required-check.yml",
                    "triggers": ["pull_request", "merge_group"],
                }
            ],
        )

        deployment = catalog["rulesets"]["deployment-source"]
        self.assertEqual(deployment["repositories"], ["gitops"])
        self.assertEqual(
            deployment["rules"]["required_status_checks"]["checks"],
            [
                {
                    "context": "Pull request / required",
                    "issuer_type": "github_actions",
                    "workflow_path": ".github/workflows/pull-request.yml",
                    "triggers": ["pull_request", "merge_group"],
                }
            ],
        )

    def test_repository_ruleset_references_resolve(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "catalog.json"
            result = invoke("compile", "--output", str(output))
            self.assertEqual(result.returncode, 0, result.stderr)
            catalog = json.loads(output.read_text())
        repositories = {value["name"] for value in catalog["repositories"].values()}
        for ruleset in catalog["rulesets"].values():
            self.assertLessEqual(set(ruleset["repositories"]), repositories)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
