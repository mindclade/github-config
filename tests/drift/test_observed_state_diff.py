import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[2]
CLI = os.environ.get("GITHUB_CONFIGCTL") or (sys.argv[1] if len(sys.argv) > 1 else "")


def invoke(*arguments, environment=None):
    if CLI:
        command, cwd = [str(Path(CLI).resolve())], ROOT
    else:
        command, cwd = ["go", "run", "./cmd/github-configctl"], ROOT / "compiler"
    env = os.environ.copy()
    env.update(environment or {})
    if env.get("GITHUB_API_URL", "").startswith(("http://127.0.0.1:", "http://localhost:")):
        env.setdefault("MINDCLADE_GITHUB_RETRY_TEST_CLOCK", "advancing")
    return subprocess.run(command + ["--root", str(ROOT), *arguments], cwd=cwd, env=env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


class ObservedStateDiffTest(unittest.TestCase):
    @staticmethod
    def managed_projection(catalog):
        def pick(value, keys):
            return {key: value[key] for key in keys if key in value}

        def ruleset(value):
            rules = value["rules"]
            projected = pick(value, [
                "target", "enforcement", "repositories", "include_refs", "exclude_refs", "bypass_actors",
            ])
            projected["conditions"] = {
                "repository_name": {"exclude": [], "protected": True},
            }
            rule_types = [
                rule_type for rule_type in [
                    "update", "deletion", "non_fast_forward", "required_linear_history",
                    "required_signatures", "merge_queue",
                ]
                if rules.get(rule_type, False)
            ]
            if rules.get("creation_restricted", False):
                rule_types.append("creation")
            if "pull_request" in rules:
                rule_types.append("pull_request")
            if "required_status_checks" in rules:
                rule_types.append("required_status_checks")
            projected["rule_types"] = sorted(rule_types)
            projected_rules = pick(rules, [
                "update", "deletion", "non_fast_forward", "required_linear_history",
                "required_signatures", "merge_queue", "creation_restricted",
                "authorized_creator_integrations",
            ])
            if "pull_request" in rules:
                projected_rules["pull_request"] = pick(rules["pull_request"], [
                    "required_approving_review_count", "require_code_owner_review",
                    "dismiss_stale_reviews", "require_last_push_approval",
                    "required_review_thread_resolution",
                ])
            if "required_status_checks" in rules:
                required = rules["required_status_checks"]
                projected_rules["required_status_checks"] = {
                    "strict": required["strict"],
                    "do_not_enforce_on_create": False,
                    "checks": [pick(check, ["context", "integration_id"]) for check in required["checks"]],
                }
            projected["rules"] = projected_rules
            return projected

        def environment(value):
            settings = pick(value, [
                "prevent_self_review", "can_admins_bypass", "deployment_branch_policy",
            ])
            settings["deployment_branch_policy"] = {
                **settings["deployment_branch_policy"],
                "branch_patterns": settings["deployment_branch_policy"].get("branch_patterns", []),
                "tag_patterns": settings["deployment_branch_policy"].get("tag_patterns", []),
            }
            settings["required_reviewers"] = [
                pick(reviewer, ["type", "team"]) for reviewer in value["required_reviewers"]
            ]
            return {
                "name": value["name"], "repositories": value["repositories"],
                "repository_settings": {repository: settings for repository in value["repositories"]},
            }

        def repository(value):
            projected = {
                **pick(value, [
                    "name", "description", "visibility", "archived", "features",
                    "merge_policy", "custom_properties",
                ]),
                "web_commit_signoff_required": catalog["organization"]["web_commit_signoff_required"],
                "security": pick(value["security"], [
                    "vulnerability_alerts", "dependabot_security_updates", "advanced_security",
                    "secret_scanning", "secret_scanning_push_protection",
                ]),
                "team_grants": [pick(grant, ["team", "permission"]) for grant in value["team_grants"]],
                "direct_collaborators": [
                    pick(collaborator, ["login", "permission"])
                    for collaborator in value["direct_collaborators"]
                ],
            }
            if value["visibility"].lower() == "public":
                projected["actions_access_level"] = {
                    "applicability": "not_applicable",
                    "visibility": "public",
                }
            else:
                projected["actions_access_level"] = value["actions_access_level"]
            return projected

        organization = pick(catalog["organization"], [
            "organization_login", "default_repository_permission",
            "members_can_create_repositories", "members_can_create_public_repositories",
            "members_can_create_private_repositories", "members_can_create_internal_repositories",
            "members_can_create_pages", "members_can_fork_private_repositories",
            "web_commit_signoff_required", "two_factor_requirement",
        ])
        migration = catalog["organization"]["custom_property_migration"]
        organization["custom_properties"] = []
        for property_definition in catalog["organization"]["custom_properties"]:
            effective = dict(property_definition)
            if migration["phase"] == "preserve":
                effective["allowed_values"] = sorted(set(
                    property_definition["allowed_values"]
                    + migration["legacy_allowed_values"].get(property_definition["name"], [])
                ))
            organization["custom_properties"].append(effective)

        return {
            "projection_version": "github-rest/v1",
            "organization": organization,
            "actions_policy": {
                **pick(catalog["actions_policy"], [
                "mode", "github_owned_allowed", "verified_creator_allowed",
                "default_workflow_permissions", "can_approve_pull_request_reviews", "required_pin", "runner_policy",
                ]),
                "enabled_repositories": catalog["actions_policy"].get("enabled_repositories", "all"),
                "allowed_patterns": [
                    f'{action["source"]}@{action["commit"]}'
                    for action in catalog["actions_policy"]["allowed_actions"]
                ],
            },
            "security_policy": pick(catalog["security_policy"], [
                "security_manager_team", "dependency_graph_required", "dependabot_alerts_required",
                "dependabot_security_updates_required", "advanced_security_required",
                "code_scanning_default_setup_required", "secret_scanning_required",
                "secret_scanning_push_protection_required", "private_vulnerability_reporting_required",
            ]),
            "oidc_policy": {
                **pick(catalog["oidc_policy"], [
                    "use_default_subject", "use_immutable_subject", "include_claim_keys",
                ]),
                "repository_subject_templates": {
                    key: {
                        "use_default": False,
                        "include_claim_keys": catalog["oidc_policy"]["include_claim_keys"],
                        "use_immutable_subject": catalog["oidc_policy"]["use_immutable_subject"],
                    }
                    for key in catalog["repositories"]
                },
            },
            "members": [pick(member, ["login", "role"]) for member in catalog["members"]],
            "outside_collaborators": [pick(member, ["login"]) for member in catalog["outside_collaborators"]],
            "teams": {
                key: {
                    **pick(value, ["name", "description", "privacy", "parent_team"]),
                    "members": [pick(member, ["login", "role"]) for member in value["members"]],
                }
                for key, value in catalog["teams"].items()
            },
            "repositories": {
                key: repository(value)
                for key, value in catalog["repositories"].items()
            },
            "rulesets": {
                key: ruleset(value)
                for key, value in catalog["rulesets"].items()
            },
            "environments": {
                key: environment(value)
                for key, value in catalog["environments"].items()
            },
        }

    def test_repository_signoff_and_custom_property_editability_are_managed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            desired = directory / "desired.json"
            observed = directory / "observed.json"
            report = directory / "report.json"
            result = invoke("compile", "--output", str(desired))
            self.assertEqual(result.returncode, 0, result.stderr)
            projection = self.managed_projection(json.loads(desired.read_text()))
            projection["repositories"]["github-config"]["web_commit_signoff_required"] = False
            projection["repositories"]["github-config"]["actions_access_level"] = "organization"
            projection["organization"]["custom_properties"][0]["values_editable_by"] = "repository_actors"
            observed.write_text(json.dumps({"managed_projection": projection}))
            result = invoke("diff", "--desired", str(desired), "--observed", str(observed), "--output", str(report))
            self.assertEqual(result.returncode, 2, result.stderr)
            paths = {change["path"] for change in json.loads(report.read_text())["changes"]}
            self.assertIn(
                "/repositories/github-config/web_commit_signoff_required", paths,
            )
            self.assertIn("/repositories/github-config/actions_access_level", paths)
            self.assertIn("/organization/custom_properties", paths)

    def test_public_repository_actions_access_projection_is_explicit_and_closed_world(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            desired = directory / "desired.json"
            observed = directory / "observed.json"
            report = directory / "report.json"
            result = invoke("compile", "--output", str(desired))
            self.assertEqual(result.returncode, 0, result.stderr)
            projection = self.managed_projection(json.loads(desired.read_text()))
            repository_ids = {
                "bootstrap", "dot-github", "github-config", "gitops",
                "infrastructure-live", "mindclade",
            }
            self.assertEqual(set(projection["repositories"]), repository_ids)
            public_semantics = {
                "applicability": "not_applicable",
                "visibility": "public",
            }
            self.assertEqual(
                {
                    repository_id: projection["repositories"][repository_id]["actions_access_level"]
                    for repository_id in repository_ids
                },
                {repository_id: public_semantics for repository_id in repository_ids},
            )

            missing_projection = json.loads(json.dumps(projection))
            for repository_id in repository_ids:
                del missing_projection["repositories"][repository_id]["actions_access_level"]
            observed.write_text(json.dumps({"managed_projection": missing_projection}))
            missing = invoke(
                "diff", "--desired", str(desired), "--observed", str(observed),
                "--output", str(report),
            )
            self.assertEqual(missing.returncode, 2, missing.stderr)
            missing_report = json.loads(report.read_text())
            expected_paths = {
                f"/repositories/{repository_id}/actions_access_level"
                for repository_id in repository_ids
            }
            self.assertEqual(missing_report["summary"]["missing"], 6)
            self.assertEqual(
                {(change["kind"], change["path"]) for change in missing_report["changes"]},
                {("missing", path) for path in expected_paths},
            )

            extra_projection = json.loads(json.dumps(projection))
            extra_projection["repositories"]["github-config"]["actions_access_level"][
                "undeclared_actions_control"
            ] = True
            observed.write_text(json.dumps({"managed_projection": extra_projection}))
            extra = invoke(
                "diff", "--desired", str(desired), "--observed", str(observed),
                "--output", str(report),
            )
            self.assertEqual(extra.returncode, 2, extra.stderr)
            extra_report = json.loads(report.read_text())
            self.assertEqual(extra_report["summary"]["extra"], 1)
            self.assertEqual(
                {(change["kind"], change["path"]) for change in extra_report["changes"]},
                {(
                    "extra",
                    "/repositories/github-config/actions_access_level/undeclared_actions_control",
                )},
            )

    def test_provider_required_repository_defaults_are_managed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            desired = directory / "desired.json"
            observed = directory / "observed.json"
            report = directory / "report.json"
            result = invoke("compile", "--output", str(desired))
            self.assertEqual(result.returncode, 0, result.stderr)
            projection = self.managed_projection(json.loads(desired.read_text()))
            repository = projection["repositories"]["github-config"]
            repository["features"]["downloads"] = True
            repository["merge_policy"]["squash_merge_commit_title"] = "COMMIT_OR_PR_TITLE"
            repository["merge_policy"]["squash_merge_commit_message"] = "BLANK"
            observed.write_text(json.dumps({"managed_projection": projection}))
            result = invoke("diff", "--desired", str(desired), "--observed", str(observed), "--output", str(report))
            self.assertEqual(result.returncode, 2, result.stderr)
            paths = {change["path"] for change in json.loads(report.read_text())["changes"]}
            self.assertEqual(paths, {
                "/repositories/github-config/features/downloads",
                "/repositories/github-config/merge_policy/squash_merge_commit_message",
                "/repositories/github-config/merge_policy/squash_merge_commit_title",
            })

    def test_provider_fixed_ruleset_controls_are_managed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            desired = directory / "desired.json"
            observed = directory / "observed.json"
            report = directory / "report.json"
            result = invoke("compile", "--output", str(desired))
            self.assertEqual(result.returncode, 0, result.stderr)
            projection = self.managed_projection(json.loads(desired.read_text()))
            ruleset = projection["rulesets"]["application-source"]
            ruleset["conditions"]["repository_name"]["exclude"] = ["legacy-repository"]
            ruleset["conditions"]["repository_name"]["protected"] = False
            ruleset["rules"]["required_status_checks"]["do_not_enforce_on_create"] = True
            ruleset["rule_types"].append("unexpected_rule")
            observed.write_text(json.dumps({"managed_projection": projection}))
            result = invoke("diff", "--desired", str(desired), "--observed", str(observed), "--output", str(report))
            self.assertEqual(result.returncode, 2, result.stderr)
            paths = {change["path"] for change in json.loads(report.read_text())["changes"]}
            self.assertEqual(paths, {
                "/rulesets/application-source/conditions/repository_name/exclude",
                "/rulesets/application-source/conditions/repository_name/protected",
                "/rulesets/application-source/rule_types",
                "/rulesets/application-source/rules/required_status_checks/do_not_enforce_on_create",
            })

    def test_explicit_managed_projection_converges_and_unknown_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            desired = directory / "desired.json"
            observed = directory / "observed.json"
            report = directory / "report.json"
            result = invoke("compile", "--output", str(desired))
            self.assertEqual(result.returncode, 0, result.stderr)
            catalog = json.loads(desired.read_text())
            projection = self.managed_projection(catalog)
            observed.write_text(json.dumps({"kind": "GitHubObservedState", "managed_projection": projection}))
            clean = invoke("diff", "--desired", str(desired), "--observed", str(observed), "--output", str(report))
            self.assertEqual(clean.returncode, 0, clean.stderr)
            self.assertEqual(json.loads(report.read_text())["status"], "clean")

            projection["repositories"]["github-config"] = {"status": "unknown"}
            observed.write_text(json.dumps({"kind": "GitHubObservedState", "managed_projection": projection}))
            unknown = invoke("diff", "--desired", str(desired), "--observed", str(observed), "--output", str(report))
            self.assertEqual(unknown.returncode, 2, unknown.stderr)
            self.assertEqual(json.loads(report.read_text())["summary"]["unknown"], 1)

    def test_repository_oidc_opt_in_and_immutable_posture_are_managed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            desired = directory / "desired.json"
            observed = directory / "observed.json"
            report = directory / "report.json"
            result = invoke("compile", "--output", str(desired))
            self.assertEqual(result.returncode, 0, result.stderr)
            projection = self.managed_projection(json.loads(desired.read_text()))
            repository_id = sorted(projection["oidc_policy"]["repository_subject_templates"])[0]
            projection["oidc_policy"]["repository_subject_templates"][repository_id]["use_default"] = True
            projection["oidc_policy"]["repository_subject_templates"][repository_id]["use_immutable_subject"] = False
            observed.write_text(json.dumps({"managed_projection": projection}))
            result = invoke("diff", "--desired", str(desired), "--observed", str(observed), "--output", str(report))
            self.assertEqual(result.returncode, 2, result.stderr)
            paths = {change["path"] for change in json.loads(report.read_text())["changes"]}
            self.assertIn(
                f"/oidc_policy/repository_subject_templates/{repository_id}/use_default", paths,
            )
            self.assertIn(
                f"/oidc_policy/repository_subject_templates/{repository_id}/use_immutable_subject", paths,
            )

    def test_closed_world_collections_report_undeclared_live_objects(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            desired = directory / "desired.json"
            observed = directory / "observed.json"
            report = directory / "report.json"
            result = invoke("compile", "--output", str(desired))
            self.assertEqual(result.returncode, 0, result.stderr)
            projection = self.managed_projection(json.loads(desired.read_text()))
            projection["teams"]["rogue-team"] = {"name": "rogue-team"}
            projection["repositories"]["rogue-repository"] = {"name": "rogue-repository"}
            projection["rulesets"]["rogue-ruleset"] = {"target": "branch"}
            projection["environments"]["rogue-environment"] = {"name": "rogue-environment"}
            observed.write_text(json.dumps({"managed_projection": projection}))
            result = invoke("diff", "--desired", str(desired), "--observed", str(observed), "--output", str(report))
            self.assertEqual(result.returncode, 2, result.stderr)
            payload = json.loads(report.read_text())
            self.assertEqual(payload["summary"]["extra"], 4)

    def test_clean_changed_and_unknown_states_have_stable_exit_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            desired = directory / "desired.json"
            observed = directory / "observed.json"
            report = directory / "report.json"
            result = invoke("compile", "--output", str(desired))
            self.assertEqual(result.returncode, 0, result.stderr)
            observed.write_bytes(desired.read_bytes())

            clean = invoke("diff", "--desired", str(desired), "--observed", str(observed), "--output", str(report))
            self.assertEqual(clean.returncode, 0, clean.stderr)
            self.assertEqual(json.loads(report.read_text())["status"], "clean")

            state = json.loads(observed.read_text())
            state["organization"]["default_repository_permission"] = "read"
            state["observed_at"] = "volatile-and-ignored"
            observed.write_text(json.dumps(state))
            drift = invoke("diff", "--desired", str(desired), "--observed", str(observed), "--output", str(report))
            self.assertEqual(drift.returncode, 2, drift.stderr)
            payload = json.loads(report.read_text())
            self.assertEqual(payload["summary"]["changed"], 1)
            self.assertEqual(payload["changes"][0]["path"], "/organization/default_repository_permission")
            self.assertFalse(payload["changes"][0]["sensitive"])
            self.assertRegex(payload["changes"][0]["desired_hash"], r"^sha256:[0-9a-f]{64}$")
            self.assertRegex(payload["changes"][0]["observed_hash"], r"^sha256:[0-9a-f]{64}$")
            self.assertNotIn("desired", payload["changes"][0])
            self.assertNotIn("observed", payload["changes"][0])

            state = json.loads(desired.read_text())
            state["repositories"]["github-config"] = {"status": "unknown"}
            observed.write_text(json.dumps(state))
            unknown = invoke("diff", "--desired", str(desired), "--observed", str(observed), "--output", str(report))
            self.assertEqual(unknown.returncode, 2, unknown.stderr)
            self.assertEqual(json.loads(report.read_text())["summary"]["unknown"], 1)

    def test_diff_redacts_inline_secret_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            desired = directory / "desired.json"
            observed = directory / "observed.json"
            desired.write_text(json.dumps({"credential": {"access_token": "ghp_abcdefghijklmnopqrstuvwxyz123456"}}))
            observed.write_text(json.dumps({"credential": {"access_token": "changed"}}))
            result = invoke("diff", "--desired", str(desired), "--observed", str(observed))
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn("ghp_", result.stdout)
            change = json.loads(result.stdout)["changes"][0]
            self.assertEqual(change, {
                "kind": "changed", "path": "/credential/access_token", "sensitive": True,
            })

    def test_drift_report_never_serializes_identity_or_restricted_property_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            desired = directory / "desired.json"
            observed = directory / "observed.json"
            first = directory / "first.json"
            second = directory / "second.json"
            desired_value = {
                "members": [{"login": "member-login-must-not-appear", "role": "admin"}],
                "repositories": {
                    "restricted-repository-must-not-appear": {
                        "custom_properties": {
                            "data_classification": "restricted-value-must-not-appear",
                        },
                    },
                },
            }
            observed_value = {
                "members": [{"login": "other-login-must-not-appear", "role": "member"}],
                "repositories": {
                    "restricted-repository-must-not-appear": {
                        "custom_properties": {
                            "data_classification": "confidential-value-must-not-appear",
                        },
                    },
                },
            }
            desired.write_text(json.dumps(desired_value, sort_keys=True))
            observed.write_text(json.dumps(observed_value, sort_keys=True))
            result = invoke(
                "diff", "--desired", str(desired), "--observed", str(observed),
                "--output", str(first),
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            report_text = first.read_text()
            for forbidden in [
                "member-login-must-not-appear", "other-login-must-not-appear",
                "restricted-repository-must-not-appear", "restricted-value-must-not-appear",
                "confidential-value-must-not-appear",
            ]:
                self.assertNotIn(forbidden, report_text)
            report = json.loads(report_text)
            self.assertTrue(report["changes"])
            for change in report["changes"]:
                self.assertTrue(change["sensitive"])
                self.assertNotIn("desired_hash", change)
                self.assertNotIn("observed_hash", change)
                self.assertNotIn("desired", change)
                self.assertNotIn("observed", change)

            desired.write_text(json.dumps(desired_value, indent=4))
            observed.write_text(json.dumps(observed_value, separators=(",", ":")))
            result = invoke(
                "diff", "--desired", str(desired), "--observed", str(observed),
                "--output", str(second),
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_observer_restricts_token_origin_and_rejects_redirects(self):
        rejected = invoke(
            "observe", "--organization", "mindclade", "--output", "-",
            environment={
                "GITHUB_TOKEN": "must-not-leak",
                "GITHUB_API_URL": "https://example.invalid",
            },
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("exactly https://api.github.com", rejected.stderr)
        self.assertNotIn("must-not-leak", rejected.stderr)

        requests = []

        class RedirectHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_GET(self):
                requests.append(self.path)
                if self.path == "/token-sink":
                    self.send_response(200)
                    payload = b'{}'
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                self.send_response(302)
                self.send_header(
                    "Location", f"http://127.0.0.1:{self.server.server_port}/token-sink",
                )
                self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            redirected = invoke(
                "observe", "--organization", "mindclade", "--output", "-",
                environment={
                    "GITHUB_TOKEN": "must-not-leak",
                    "GITHUB_API_URL": f"http://127.0.0.1:{server.server_port}",
                },
            )
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
        self.assertNotEqual(redirected.returncode, 0)
        self.assertEqual(requests, ["/orgs/mindclade"])
        self.assertNotIn("must-not-leak", redirected.stderr)

    def test_observer_uses_explicit_oidc_and_security_control_api_fields(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_GET(self):
                requests.append((self.path, self.headers.get("X-GitHub-Api-Version")))
                parsed_url = urlparse(self.path)
                path = parsed_url.path
                query = parse_qs(parsed_url.query)
                attempt = self.server.retry_counts.get(path, 0) + 1
                self.server.retry_counts[path] = attempt
                if (
                    (path in self.server.retry_once and attempt == 1)
                    or path in self.server.retry_always
                    or attempt <= self.server.retry_until.get(path, 0)
                ):
                    self.send_response(429)
                    self.send_header(
                        "Retry-After", str(self.server.retry_after_seconds.get(path, 0)),
                    )
                    self.send_header("X-GitHub-Request-Id", f"retry-{attempt}")
                    self.end_headers()
                    return
                status, value = 200, {}
                list_paths = {
                    "/orgs/mindclade/properties/schema",
                    "/orgs/mindclade/organization-roles/77/teams",
                    "/orgs/mindclade/teams", "/orgs/mindclade/members",
                    "/orgs/mindclade/outside_collaborators", "/orgs/mindclade/rulesets",
                    "/repos/mindclade/github-config/teams",
                    "/repos/mindclade/github-config/collaborators",
                    "/repos/mindclade/github-config/properties/values",
                }
                if path == "/orgs/mindclade":
                    value = {
                        "id": 1, "login": "mindclade", "plan": {"name": "enterprise"},
                        "public_repos": 0, "total_private_repos": 2,
                    }
                elif path == "/orgs/mindclade/properties/schema":
                    value = [{
                        "property_name": "repository_class", "value_type": "single_select",
                        "required": True, "allowed_values": ["governance-source"],
                        "values_editable_by": "org_actors",
                    }]
                elif path == "/orgs/mindclade/rulesets":
                    value = [{"id": 99, "name": "application-source"}]
                    if self.server.organization_rulesets_duplicate:
                        value.append({"id": 100, "name": "application-source"})
                elif path in ("/orgs/mindclade/rulesets/99", "/orgs/mindclade/rulesets/100"):
                    value = {
                        "id": int(path.rsplit("/", 1)[1]),
                        "name": "application-source", "target": "branch",
                        "enforcement": "active", "bypass_actors": [],
                        "conditions": {
                            "repository_name": {
                                "include": ["mindclade"], "exclude": [], "protected": True,
                            },
                            "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []},
                        },
                        "rules": [{
                            "type": "required_status_checks",
                            "parameters": {
                                "strict_required_status_checks_policy": True,
                                "do_not_enforce_on_create": False,
                                "required_status_checks": [{"context": "Pull request / required"}],
                            },
                        }],
                    }
                elif path in list_paths:
                    value = []
                elif path == "/orgs/mindclade/organization-roles":
                    value = {"roles": [{"id": 77, "name": "security_manager"}]}
                elif path == "/orgs/mindclade/actions/permissions":
                    value = {"enabled_repositories": "all", "allowed_actions": "selected", "sha_pinning_required": False}
                elif path == "/orgs/mindclade/actions/permissions/selected-actions":
                    value = {"github_owned_allowed": False, "verified_allowed": False, "patterns_allowed": []}
                elif path == "/orgs/mindclade/actions/permissions/workflow":
                    value = {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False}
                elif path == "/orgs/mindclade/actions/runners":
                    value = {"total_count": 0, "runners": []}
                elif path == "/orgs/mindclade/actions/permissions/self-hosted-runners":
                    value = {"enabled_repositories": "none"}
                elif path == "/orgs/mindclade/actions/permissions/fork-pr-contributor-approval":
                    value = {"approval_policy": "first_time_contributors_new_to_github"}
                elif path == "/orgs/mindclade/actions/oidc/customization/sub":
                    value = {
                        "include_claim_keys": ["repo", "context", "workflow_ref", "workflow_sha"],
                        "use_immutable_subject": True,
                    }
                elif path == "/orgs/mindclade/repos":
                    value = [
                        {
                            "id": 2, "name": "github-config", "visibility": self.server.github_config_visibility,
                            "web_commit_signoff_required": True,
                            "has_downloads": False,
                            "squash_merge_commit_title": "PR_TITLE",
                            "squash_merge_commit_message": "PR_BODY",
                            "security_and_analysis": {
                                "advanced_security": {"status": "enabled"},
                                "secret_scanning": {"status": "enabled"},
                                "secret_scanning_push_protection": {"status": "enabled"},
                            },
                        },
                        {"id": 3, "name": "infrastructure-live", "visibility": "private"},
                    ]
                elif path == "/orgs/mindclade/installations":
                    value = {"total_count": 0, "installations": []}
                elif path.startswith("/repos/mindclade/") and path.endswith("/actions/oidc/customization/sub"):
                    value = {
                        "use_default": False,
                        "include_claim_keys": ["repo", "context", "workflow_ref", "workflow_sha"],
                        "use_immutable_subject": True,
                    }
                elif path.startswith("/repos/mindclade/") and path.endswith("/actions/permissions/access"):
                    value = {"access_level": "none"}
                elif path == "/repos/mindclade/github-config/environments":
                    value = {"total_count": 0, "environments": []}
                elif path == "/repos/mindclade/infrastructure-live/environments":
                    primary_environment = {
                        "name": "infrastructure-apply",
                        "can_admins_bypass": False,
                        "deployment_branch_policy": {
                            "protected_branches": False, "custom_branch_policies": True,
                        },
                        "protection_rules": [{
                            "type": "required_reviewers", "prevent_self_review": True,
                            "reviewers": [{
                                "type": "Team", "reviewer": {"slug": "security"},
                            }],
                        }],
                    }
                    if self.server.environment_inventory_case == "paginated":
                        page = int(query.get("page", ["1"])[0])
                        if page == 1:
                            environments_page = [primary_environment] + [
                                {
                                    "name": f"extra-{index:03d}",
                                    "deployment_branch_policy": {
                                        "protected_branches": True, "custom_branch_policies": False,
                                    },
                                }
                                for index in range(99)
                            ]
                        else:
                            environments_page = [{
                                "name": "extra-100",
                                "deployment_branch_policy": {
                                    "protected_branches": True, "custom_branch_policies": False,
                                },
                            }]
                        value = {"total_count": 101, "environments": environments_page}
                    elif self.server.environment_inventory_case == "count_mismatch":
                        value = {"total_count": 2, "environments": [primary_environment]}
                    else:
                        value = {"total_count": 1, "environments": [primary_environment]}
                elif path == "/repos/mindclade/infrastructure-live/environments/infrastructure-apply/deployment-branch-policies":
                    if self.server.environment_policy_readable:
                        value = {
                            "total_count": self.server.environment_policy_total_count,
                            "branch_policies": [
                                {"type": "branch", "name": "refs/pull/*/merge"},
                                {"type": "branch", "name": "refs/heads/gh-readonly-queue/main/*"},
                                {"type": "tag", "name": "refs/tags/review-*"},
                            ],
                        }
                    else:
                        status, value = 500, {"message": "deployment policies unavailable"}
                elif path.startswith("/repos/mindclade/") and path.endswith((
                    "/teams", "/collaborators", "/properties/values",
                )):
                    value = []
                elif path.endswith(("/vulnerability-alerts", "/dependency-graph/sbom", "/automated-security-fixes", "/private-vulnerability-reporting")):
                    status, value = 204, None
                elif path.endswith("/code-scanning/default-setup"):
                    value = {"state": "configured"}
                else:
                    status, value = 404, {"message": "not found"}
                self.send_response(status)
                if value is not None:
                    payload = json.dumps(value).encode()
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if value is not None:
                    self.wfile.write(payload)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.environment_policy_readable = True
        server.environment_policy_total_count = 3
        server.environment_inventory_case = "complete"
        server.github_config_visibility = "private"
        server.organization_rulesets_duplicate = False
        server.retry_counts = {}
        server.retry_once = {
            "/orgs/mindclade",
            "/repos/mindclade/github-config/vulnerability-alerts",
            "/repos/mindclade/github-config/code-scanning/default-setup",
        }
        server.retry_always = set()
        server.retry_until = {}
        server.retry_after_seconds = {}
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "observed.json"
                result = invoke(
                    "observe", "--organization", "mindclade", "--output", str(output),
                    environment={
                        "GITHUB_TOKEN": "fixture-token",
                        "GITHUB_API_URL": f"http://127.0.0.1:{server.server_port}",
                    },
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                observed = json.loads(output.read_text())
                self.assertEqual(
                    {path: server.retry_counts[path] for path in server.retry_once},
                    {path: 2 for path in server.retry_once},
                )
                server.retry_once = set()
                persistent_path = "/repos/mindclade/github-config/dependency-graph/sbom"
                attempts_before = server.retry_counts[persistent_path]
                server.retry_always = {persistent_path}
                bounded_output = Path(temporary) / "observed-bounded-retry.json"
                bounded_result = invoke(
                    "observe", "--organization", "mindclade", "--output", str(bounded_output),
                    environment={
                        "GITHUB_TOKEN": "fixture-token",
                        "GITHUB_API_URL": f"http://127.0.0.1:{server.server_port}",
                    },
                )
                self.assertEqual(bounded_result.returncode, 0, bounded_result.stderr)
                bounded_observed = json.loads(bounded_output.read_text())
                self.assertFalse(bounded_observed["observation_complete"])
                self.assertEqual(server.retry_counts[persistent_path] - attempts_before, 6)
                self.assertIn(
                    "dependency_graph:github-config",
                    {error["section"] for error in bounded_observed["errors"]},
                )
                server.retry_always = set()
                attempts_before = server.retry_counts[persistent_path]
                server.retry_until[persistent_path] = attempts_before + 3
                server.retry_after_seconds[persistent_path] = 20
                recovered_output = Path(temporary) / "observed-rate-limit-recovered.json"
                recovered_result = invoke(
                    "observe", "--organization", "mindclade", "--output", str(recovered_output),
                    environment={
                        "GITHUB_TOKEN": "fixture-token",
                        "GITHUB_API_URL": f"http://127.0.0.1:{server.server_port}",
                    },
                )
                self.assertEqual(recovered_result.returncode, 0, recovered_result.stderr)
                self.assertEqual(server.retry_counts[persistent_path] - attempts_before, 4)
                recovered = json.loads(recovered_output.read_text())
                self.assertNotIn(
                    "dependency_graph:github-config",
                    {error["section"] for error in recovered["errors"]},
                )
                server.retry_until = {}
                attempts_before = server.retry_counts[persistent_path]
                server.retry_after_seconds[persistent_path] = 120
                server.retry_always = {persistent_path}
                instructed_output = Path(temporary) / "observed-retry-after.json"
                instructed_result = invoke(
                    "observe", "--organization", "mindclade", "--output", str(instructed_output),
                    environment={
                        "GITHUB_TOKEN": "fixture-token",
                        "GITHUB_API_URL": f"http://127.0.0.1:{server.server_port}",
                    },
                )
                self.assertEqual(instructed_result.returncode, 0, instructed_result.stderr)
                self.assertEqual(server.retry_counts[persistent_path] - attempts_before, 1)
                server.retry_after_seconds = {}
                server.retry_always = set()
                server.environment_policy_readable = False
                unreadable_output = Path(temporary) / "observed-unreadable-policy.json"
                unreadable_result = invoke(
                    "observe", "--organization", "mindclade", "--output", str(unreadable_output),
                    environment={
                        "GITHUB_TOKEN": "fixture-token",
                        "GITHUB_API_URL": f"http://127.0.0.1:{server.server_port}",
                    },
                )
                self.assertEqual(unreadable_result.returncode, 0, unreadable_result.stderr)
                unreadable_observed = json.loads(unreadable_output.read_text())
                server.environment_policy_readable = True
                server.environment_policy_total_count = 4
                incomplete_output = Path(temporary) / "observed-incomplete-policy.json"
                incomplete_result = invoke(
                    "observe", "--organization", "mindclade", "--output", str(incomplete_output),
                    environment={
                        "GITHUB_TOKEN": "fixture-token",
                        "GITHUB_API_URL": f"http://127.0.0.1:{server.server_port}",
                    },
                )
                self.assertEqual(incomplete_result.returncode, 0, incomplete_result.stderr)
                incomplete_observed = json.loads(incomplete_output.read_text())
                server.environment_policy_total_count = 3
                server.environment_inventory_case = "paginated"
                paginated_output = Path(temporary) / "observed-paginated-environments.json"
                paginated_result = invoke(
                    "observe", "--organization", "mindclade", "--output", str(paginated_output),
                    environment={
                        "GITHUB_TOKEN": "fixture-token",
                        "GITHUB_API_URL": f"http://127.0.0.1:{server.server_port}",
                    },
                )
                self.assertEqual(paginated_result.returncode, 0, paginated_result.stderr)
                paginated_observed = json.loads(paginated_output.read_text())
                server.environment_inventory_case = "count_mismatch"
                mismatched_output = Path(temporary) / "observed-mismatched-environments.json"
                mismatched_result = invoke(
                    "observe", "--organization", "mindclade", "--output", str(mismatched_output),
                    environment={
                        "GITHUB_TOKEN": "fixture-token",
                        "GITHUB_API_URL": f"http://127.0.0.1:{server.server_port}",
                    },
                )
                self.assertEqual(mismatched_result.returncode, 0, mismatched_result.stderr)
                mismatched_observed = json.loads(mismatched_output.read_text())
                server.environment_inventory_case = "complete"
                request_offset = len(requests)
                server.github_config_visibility = "public"
                public_output = Path(temporary) / "observed-public-migration.json"
                public_result = invoke(
                    "observe", "--organization", "mindclade", "--output", str(public_output),
                    environment={
                        "GITHUB_TOKEN": "fixture-token",
                        "GITHUB_API_URL": f"http://127.0.0.1:{server.server_port}",
                    },
                )
                self.assertEqual(public_result.returncode, 0, public_result.stderr)
                public_observed = json.loads(public_output.read_text())
                public_requests = {urlparse(path).path for path, _ in requests[request_offset:]}
                server.github_config_visibility = "private"
                server.organization_rulesets_duplicate = True
                duplicate_organization_result = invoke(
                    "observe", "--organization", "mindclade",
                    "--output", str(Path(temporary) / "duplicate-organization-ruleset.json"),
                    environment={
                        "GITHUB_TOKEN": "fixture-token",
                        "GITHUB_API_URL": f"http://127.0.0.1:{server.server_port}",
                    },
                )
                self.assertNotEqual(duplicate_organization_result.returncode, 0)
                self.assertIn('duplicate "name" values', duplicate_organization_result.stderr)
                self.assertNotIn("application-source", duplicate_organization_result.stderr)
                desired_output = Path(temporary) / "desired.json"
                drift_output = Path(temporary) / "unreadable-policy-drift.json"
                compiled = invoke("compile", "--output", str(desired_output))
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                drift = invoke(
                    "diff", "--desired", str(desired_output), "--observed", str(unreadable_output),
                    "--output", str(drift_output),
                )
                self.assertEqual(drift.returncode, 2, drift.stderr)
                unreadable_drift = json.loads(drift_output.read_text())
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
        repository_oidc = observed["managed_projection"]["oidc_policy"]["repository_subject_templates"]["github-config"]
        self.assertFalse(repository_oidc["use_default"])
        self.assertTrue(repository_oidc["use_immutable_subject"])
        repository_security = observed["managed_projection"]["repositories"]["github-config"]["security"]
        self.assertTrue(repository_security["secret_scanning"])
        self.assertTrue(repository_security["secret_scanning_push_protection"])
        self.assertTrue(
            observed["managed_projection"]["repositories"]["github-config"]["web_commit_signoff_required"],
        )
        self.assertEqual(
            observed["managed_projection"]["repositories"]["github-config"]["actions_access_level"],
            "none",
        )
        self.assertFalse(
            observed["managed_projection"]["repositories"]["github-config"]["features"]["downloads"],
        )
        self.assertEqual(
            observed["managed_projection"]["repositories"]["github-config"]["merge_policy"]["squash_merge_commit_title"],
            "PR_TITLE",
        )
        self.assertEqual(
            observed["managed_projection"]["repositories"]["github-config"]["merge_policy"]["squash_merge_commit_message"],
            "PR_BODY",
        )
        self.assertEqual(
            observed["managed_projection"]["organization"]["custom_properties"][0]["values_editable_by"],
            "org_actors",
        )
        observed_ruleset = observed["managed_projection"]["rulesets"]["application-source"]
        self.assertEqual(
            observed_ruleset["conditions"]["repository_name"],
            {"exclude": [], "protected": True},
        )
        self.assertFalse(
            observed_ruleset["rules"]["required_status_checks"]["do_not_enforce_on_create"],
        )
        self.assertEqual(observed_ruleset["rule_types"], ["required_status_checks"])
        observed_policy = observed["managed_projection"]["environments"]["infrastructure-apply"][
            "repository_settings"
        ]["infrastructure-live"]["deployment_branch_policy"]
        self.assertEqual(
            observed_policy["branch_patterns"],
            ["refs/heads/gh-readonly-queue/main/*", "refs/pull/*/merge"],
        )
        self.assertEqual(observed_policy["tag_patterns"], ["refs/tags/review-*"])
        unreadable_policy = unreadable_observed["managed_projection"]["environments"][
            "infrastructure-apply"
        ]["repository_settings"]["infrastructure-live"]["deployment_branch_policy"]
        self.assertEqual(unreadable_policy, {"status": "unknown"})
        self.assertFalse(unreadable_observed["observation_complete"])
        incomplete_policy = incomplete_observed["managed_projection"]["environments"][
            "infrastructure-apply"
        ]["repository_settings"]["infrastructure-live"]["deployment_branch_policy"]
        self.assertEqual(incomplete_policy, {"status": "unknown"})
        self.assertFalse(incomplete_observed["observation_complete"])
        self.assertTrue(paginated_observed["observation_complete"])
        self.assertIn(
            "/repos/mindclade/infrastructure-live/environments?per_page=100&page=2",
            {path for path, _ in requests},
        )
        self.assertFalse(mismatched_observed["observation_complete"])
        self.assertIn(
            "repository_environments:infrastructure-live",
            {error["section"] for error in mismatched_observed["errors"]},
        )
        self.assertNotIn("/repos/mindclade/github-config/actions/permissions/access", public_requests)
        self.assertIn("/repos/mindclade/github-config/private-vulnerability-reporting", public_requests)
        self.assertNotIn(
            "repository_actions_access:github-config",
            {error["section"] for error in public_observed["errors"]},
        )
        self.assertEqual(
            public_observed["managed_projection"]["repositories"]["github-config"][
                "actions_access_level"
            ],
            {"applicability": "not_applicable", "visibility": "public"},
        )
        self.assertIn(
            "environment_deployment_policies:infrastructure-live:infrastructure-apply",
            {error["section"] for error in incomplete_observed["errors"]},
        )
        self.assertIn(
            {
                "kind": "unknown",
                "path": "/environments/infrastructure-apply/repository_settings/infrastructure-live/deployment_branch_policy",
            },
            [
                {"kind": change["kind"], "path": change["path"]}
                for change in unreadable_drift["changes"]
            ],
        )
        self.assertEqual(observed["managed_projection"]["actions_policy"]["mode"], "selected")
        self.assertEqual(observed["managed_projection"]["actions_policy"]["enabled_repositories"], "all")
        self.assertEqual(observed["managed_projection"]["actions_policy"]["required_pin"], "unrestricted")
        self.assertTrue(observed["repository_inventory_complete"])
        self.assertTrue(observed["core_observation_complete"])
        self.assertTrue(observed["installation_inventory"]["api_inventory_complete"])
        self.assertFalse(observed["installation_inventory"]["bootstrap_qualified"])
        self.assertTrue(requests)
        self.assertEqual({version for _, version in requests}, {"2026-03-10"})
        requested_paths = {urlparse(path).path for path, _ in requests}
        self.assertIn("/orgs/mindclade/organization-roles/77/teams", requested_paths)
        self.assertNotIn("/orgs/mindclade/security-managers", requested_paths)
        self.assertIn(
            "/repos/mindclade/github-config/actions/permissions/access",
            requested_paths,
        )

    def test_repository_inventory_requires_authoritative_organization_totals(self):
        repository_names = [
            ".github", "github-config", "bootstrap", "infrastructure-live", "gitops", "mindclade",
        ]

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_GET(self):
                parsed_url = urlparse(self.path)
                path = parsed_url.path
                query = parse_qs(parsed_url.query)
                status, value = 200, {}
                if path == "/orgs/mindclade":
                    value = {"id": 1, "login": "mindclade", "plan": {"name": "enterprise"}}
                    totals = self.server.repository_totals
                    if totals is not None:
                        value["public_repos"], value["total_private_repos"] = totals
                elif path == "/orgs/mindclade/repos":
                    value = [
                        {"id": index + 10, "name": name, "visibility": "private"}
                        for index, name in enumerate(repository_names)
                    ]
                elif path == "/orgs/mindclade/organization-roles":
                    value = {"roles": [{"id": 77, "name": "security_manager"}]}
                elif path == "/orgs/mindclade/actions/permissions":
                    value = {
                        "enabled_repositories": "all", "allowed_actions": "selected",
                        "sha_pinning_required": True,
                    }
                elif path == "/orgs/mindclade/actions/permissions/selected-actions":
                    value = {"github_owned_allowed": False, "verified_allowed": False, "patterns_allowed": []}
                elif path == "/orgs/mindclade/actions/permissions/workflow":
                    value = {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False}
                elif path == "/orgs/mindclade/actions/runners":
                    value = {"total_count": 0, "runners": []}
                elif path == "/orgs/mindclade/actions/permissions/self-hosted-runners":
                    value = {"enabled_repositories": "none"}
                elif path == "/orgs/mindclade/actions/permissions/fork-pr-contributor-approval":
                    value = {"approval_policy": "first_time_contributors_new_to_github"}
                elif path == "/orgs/mindclade/actions/oidc/customization/sub":
                    value = {
                        "include_claim_keys": ["repo", "context", "workflow_ref", "workflow_sha"],
                        "use_immutable_subject": True,
                    }
                elif path == "/orgs/mindclade/installations":
                    installation_case = self.server.installation_case
                    if installation_case == "extra":
                        value = {"total_count": 1, "installations": [{
                            "id": 900, "app_id": 901, "app_slug": "rogue-app",
                            "repository_selection": "selected", "permissions": {}, "events": [],
                            "suspended_at": None,
                        }]}
                    elif installation_case == "count_mismatch":
                        value = {"total_count": 2, "installations": [{
                            "id": 900, "app_id": 901, "app_slug": "rogue-app",
                            "repository_selection": "selected", "permissions": {}, "events": [],
                            "suspended_at": None,
                        }]}
                    elif installation_case == "missing_page":
                        if query.get("page") == ["2"]:
                            status, value = 500, {"message": "missing page"}
                        else:
                            value = {"total_count": 101, "installations": [{
                                "id": 1000 + index, "app_id": 2000 + index,
                                "app_slug": f"app-{index}", "repository_selection": "selected",
                                "permissions": {}, "events": [], "suspended_at": None,
                            } for index in range(100)]}
                    else:
                        value = {"total_count": 0, "installations": []}
                elif path.startswith("/repos/mindclade/") and path.endswith("/actions/permissions/access"):
                    repository = path.split("/")[4]
                    value = {"access_level": "organization" if repository == ".github" else "none"}
                elif path.endswith("/actions/oidc/customization/sub"):
                    value = {
                        "use_default": False,
                        "include_claim_keys": ["repo", "context", "workflow_ref", "workflow_sha"],
                        "use_immutable_subject": True,
                    }
                elif path.endswith("/environments"):
                    value = {"total_count": 0, "environments": []}
                elif path.endswith((
                    "/vulnerability-alerts", "/dependency-graph/sbom", "/automated-security-fixes",
                    "/private-vulnerability-reporting",
                )):
                    status, value = 204, None
                elif path.endswith("/code-scanning/default-setup"):
                    value = {"state": "configured"}
                elif path in {
                    "/orgs/mindclade/properties/schema", "/orgs/mindclade/organization-roles/77/teams",
                    "/orgs/mindclade/teams", "/orgs/mindclade/members",
                    "/orgs/mindclade/outside_collaborators", "/orgs/mindclade/rulesets",
                } or path.endswith(("/teams", "/collaborators", "/properties/values")):
                    value = []
                else:
                    status, value = 404, {"message": "not found"}
                self.send_response(status)
                if value is not None:
                    payload = json.dumps(value).encode()
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if value is not None:
                    self.wfile.write(payload)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.installation_case = "empty"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)

                def observe(label, totals, installation_case="empty"):
                    server.repository_totals = totals
                    server.installation_case = installation_case
                    output = directory / f"{label}.json"
                    result = invoke(
                        "observe", "--organization", "mindclade", "--output", str(output),
                        environment={
                            "GITHUB_TOKEN": "fixture-token",
                            "GITHUB_API_URL": f"http://127.0.0.1:{server.server_port}",
                        },
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    return json.loads(output.read_text())

                restricted = observe("restricted", (0, 7))
                self.assertFalse(restricted["repository_inventory_complete"])
                self.assertFalse(restricted["core_observation_complete"])
                self.assertEqual(restricted["repository_inventory"]["enumerated_unique_count"], 6)
                self.assertEqual(restricted["repository_inventory"]["authoritative_total_count"], 7)

                complete = observe("complete", (0, 6))
                self.assertTrue(complete["repository_inventory_complete"])
                self.assertTrue(complete["core_observation_complete"])

                missing_totals = observe("missing-totals", None)
                self.assertFalse(missing_totals["repository_inventory_complete"])
                self.assertFalse(missing_totals["core_observation_complete"])
                self.assertFalse(missing_totals["repository_inventory"]["totals_known"])

                extra_installation = observe("extra-installation", (0, 6), "extra")
                self.assertTrue(extra_installation["installation_inventory"]["api_inventory_complete"])
                self.assertFalse(extra_installation["installation_inventory"]["catalog_disposition_complete"])
                self.assertFalse(extra_installation["installation_inventory"]["bootstrap_qualified"])

                count_mismatch = observe("installation-count-mismatch", (0, 6), "count_mismatch")
                self.assertFalse(count_mismatch["installation_inventory"]["api_inventory_complete"])
                self.assertFalse(count_mismatch["observation_complete"])

                missing_page = observe("installation-missing-page", (0, 6), "missing_page")
                self.assertFalse(missing_page["installation_inventory"]["api_inventory_complete"])
                self.assertFalse(missing_page["observation_complete"])

        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
