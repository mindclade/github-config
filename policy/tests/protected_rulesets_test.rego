package github_config.protected_rulesets_test

import data.github_config.protected_rulesets
import rego.v1

strong_branch_ruleset := {
	"metadata": {"id": "governance-source"},
	"spec": {
		"target": "branch",
		"enforcement": "active",
		"bypass_actors": [{"actor_type": "team", "actor": "founder-pr-bypass", "mode": "pull_request"}],
		"rules": {
			"deletion": true,
			"non_fast_forward": true,
			"required_linear_history": true,
			"required_signatures": true,
			"merge_queue": true,
			"required_workflow": {
				"repository": "dot-github",
				"path": ".github/workflows/pull-request.yml",
				"ref": "refs/heads/main",
			},
			"pull_request": {
				"required_approving_review_count": 2,
				"require_code_owner_review": true,
				"dismiss_stale_reviews": true,
				"require_last_push_approval": true,
				"required_review_thread_resolution": true,
				"require_distinct_principals": true,
			},
			"required_status_checks": {
				"strict": true,
				"checks": [{"context": "Pull request / required", "triggers": ["pull_request", "merge_group"]}],
			},
		},
	},
}

test_strong_branch_ruleset_allowed if {
	denials := protected_rulesets.deny with input as {"rulesets": [strong_branch_ruleset]}
	count(denials) == 0
}

test_single_approval_denied if {
	weak := object.union_n([
		strong_branch_ruleset,
		{"spec": object.union(strong_branch_ruleset.spec, {"rules": object.union(strong_branch_ruleset.spec.rules, {"pull_request": object.union(strong_branch_ruleset.spec.rules.pull_request, {"required_approving_review_count": 1})})})},
	])
	denials := protected_rulesets.deny with input as {"rulesets": [weak]}
	some message in denials
	contains(message, "fewer than two approvals")
}

test_merge_group_omission_denied if {
	status_checks := {"strict": true, "checks": [{"context": "Pull request / required", "triggers": ["pull_request"]}]}
	weak := object.union_n([
		strong_branch_ruleset,
		{"spec": object.union(strong_branch_ruleset.spec, {"rules": object.union(strong_branch_ruleset.spec.rules, {"required_status_checks": status_checks})})},
	])
	denials := protected_rulesets.deny with input as {"rulesets": [weak]}
	some message in denials
	contains(message, "omits merge_group")
}

test_immutable_release_tags_allowed if {
	denials := protected_rulesets.deny with input as {"rulesets": [{
		"metadata": {"id": "release-tags"},
		"spec": {
			"target": "tag",
			"enforcement": "active",
			"bypass_actors": [],
			"rules": {
				"deletion": true,
				"update": true,
				"non_fast_forward": true,
				"creation_restricted": true,
				"authorized_creator_integrations": ["artifact-signing"],
			},
		},
	}]}
	count(denials) == 0
}

test_ready_security_requires_qualified_check_issuer if {
	denials := protected_rulesets.deny with input as {
		"security_policy": {"spec": {"activation": {"state": "ready", "blockers": []}}},
		"rulesets": [strong_branch_ruleset],
	}
	some message in denials
	contains(message, "no qualified issuer ID")
}
