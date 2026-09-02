# pyright: basic, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI = os.environ.get("GITHUB_CONFIGCTL") or (sys.argv[1] if len(sys.argv) > 1 else "")


def invoke(*arguments, root=ROOT, environment=None):
    if CLI:
        command, cwd = [str(Path(CLI).resolve())], ROOT
    else:
        command, cwd = ["go", "run", "./cmd/github-configctl"], ROOT / "compiler"
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


class CompilerDeterminismTest(unittest.TestCase):
    def compile(self, root, destination, environment=None):
        result = invoke("compile", "--output", str(destination), root=root, environment=environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        return destination.read_bytes()

    def test_output_is_stable_across_runs_paths_timezone_locale_and_yaml_order(self):
        with (
            tempfile.TemporaryDirectory() as first_temp,
            tempfile.TemporaryDirectory() as second_temp,
        ):
            first = Path(first_temp)
            second = Path(second_temp)
            shutil.copytree(ROOT / "config", second / "config")
            shutil.copytree(ROOT / "schemas", second / "schemas")
            shutil.copytree(ROOT / "generated", second / "generated")
            shutil.copy2(ROOT / "component.yaml", second / "component.yaml")

            organization = second / "config" / "organization.yaml"
            lines = organization.read_text().splitlines(keepends=True)
            organization.write_text("".join(lines[1:] + lines[:1]))

            baseline = self.compile(ROOT, first / "catalog-a.json", {"TZ": "UTC", "LC_ALL": "C"})
            repeated = self.compile(
                ROOT, first / "catalog-b.json", {"TZ": "America/Detroit", "LC_ALL": "C"}
            )
            relocated = self.compile(
                second, first / "catalog-c.json", {"TZ": "Pacific/Honolulu", "LC_ALL": "C"}
            )
            self.assertEqual(baseline, repeated)
            self.assertEqual(baseline, relocated)
            catalog = json.loads(baseline)
            self.assertEqual(
                set(catalog),
                {
                    "api_version",
                    "activation",
                    "organization",
                    "actions_policy",
                    "security_policy",
                    "oidc_policy",
                    "members",
                    "outside_collaborators",
                    "teams",
                    "repositories",
                    "rulesets",
                    "environments",
                    "integrations",
                    "source_digest",
                },
            )

    def test_tofu_variable_file_wraps_the_identical_catalog(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            catalog_path = directory / "catalog.json"
            variables_path = directory / "catalog.auto.tfvars.json"
            result = invoke(
                "compile",
                "--output",
                str(catalog_path),
                "--tofu-var-file",
                str(variables_path),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads(variables_path.read_text())["catalog"],
                json.loads(catalog_path.read_text()),
            )


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
