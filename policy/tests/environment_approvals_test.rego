package github_config.environment_approvals_test

import rego.v1
import data.github_config.environment_approvals

alias_membership := {
    "spec": {
        "scope": "organization_members",
        "organization_members": [
            {"login": "robpearc", "role": "admin", "principal_id": "founder-primary"},
            {"login": "mindclade-founder", "role": "admin", "principal_id": "founder-primary"},
        ],
    },
}

security_alias_team := {
    "metadata": {"id": "security"},
    "spec": {
        "members": [
            {"login": "robpearc", "role": "maintainer"},
            {"login": "mindclade-founder", "role": "maintainer"},
        ],
    },
}

platform_alias_team := {
    "metadata": {"id": "platform-operations"},
    "spec": {
        "members": [
            {"login": "robpearc", "role": "maintainer"},
            {"login": "mindclade-founder", "role": "maintainer"},
        ],
    },
}

authority_environment(id, team) := {
    "metadata": {"id": id},
    "spec": {
        "name": id,
        "prevent_self_review": true,
        "can_admins_bypass": false,
        "required_reviewers": [{"type": "team", "team": team}],
        "approval_policy": {
            "minimum_required_reviewers": 1,
            "minimum_distinct_principals": 2,
            "require_pr_approval": true,
            "require_code_owner_review": true,
            "require_reviewer_different_from_pr_approver": true,
        },
        "deployment_branch_policy": {
            "protected_branches": false,
            "custom_branch_policies": true,
            "branch_patterns": ["refs/pull/*/merge", "refs/heads/gh-readonly-queue/main/*"],
            "tag_patterns": [],
        },
        "allowed_workflows": [".github/workflows/authority-review.yml"],
        "activation": {"state": "blocked", "blockers": ["independent-reviewer-required"]},
    },
}

authority_gate(state, blockers) := {
    "metadata": {"id": "infrastructure-live-authorities"},
    "spec": {
        "enforcement": "active",
        "bypass_actors": [],
        "required_deployments": ["infrastructure-source-review", "security-source-review"],
        "required_status_checks": {"checks": [
            {
                "context": "Authority review / platform-operations",
                "issuer_type": "github_actions",
                "workflow_path": ".github/workflows/authority-review.yml",
                "triggers": ["pull_request", "merge_group"],
            },
            {
                "context": "Authority review / security",
                "issuer_type": "github_actions",
                "workflow_path": ".github/workflows/authority-review.yml",
                "triggers": ["pull_request", "merge_group"],
            },
        ]},
        "activation": {"state": state, "blockers": blockers},
    },
}

environment(state, blockers) := {
    "spec": {
        "name": "infrastructure-apply",
        "prevent_self_review": true,
        "can_admins_bypass": false,
        "required_reviewers": [{"type": "team", "team": "security"}],
        "approval_policy": {
            "minimum_required_reviewers": 1,
            "minimum_distinct_principals": 2,
            "require_pr_approval": true,
            "require_code_owner_review": true,
            "require_reviewer_different_from_pr_approver": true,
        },
        "activation": {"state": state, "blockers": blockers},
    },
}

test_aliases_count_as_one_and_ready_activation_is_denied if {
    denials := environment_approvals.deny with input as {
        "memberships": [alias_membership],
        "teams": [security_alias_team],
        "environments": [environment("ready", [])],
    }
    some message in denials
    contains(message, "must remain blocked")
}

test_aliases_count_as_one_and_blocked_activation_is_allowed if {
    denials := environment_approvals.deny with input as {
        "memberships": [alias_membership],
        "teams": [security_alias_team],
        "environments": [environment("blocked", ["independent-reviewer-required"])],
    }
    count(denials) == 0
}

test_two_independent_principals_allow_activation if {
    membership := {"spec": {
        "scope": "organization_members",
        "organization_members": [
            {"login": "reviewer-one", "role": "member", "principal_id": "reviewer-one"},
            {"login": "reviewer-two", "role": "member", "principal_id": "reviewer-two"},
        ],
    }}
    team := {"metadata": {"id": "security"}, "spec": {"members": [
        {"login": "reviewer-one", "role": "maintainer"},
        {"login": "reviewer-two", "role": "maintainer"},
    ]}}
    denials := environment_approvals.deny with input as {
        "memberships": [membership],
        "teams": [team],
        "environments": [environment("ready", [])],
    }
    count(denials) == 0
}

test_admin_bypass_denied if {
    unsafe_environment := object.union_n([
        environment("blocked", ["independent-reviewer-required"]),
        {"spec": object.union(environment("blocked", ["independent-reviewer-required"]).spec, {"can_admins_bypass": true})},
    ])
    denials := environment_approvals.deny with input as {
        "memberships": [alias_membership],
        "teams": [security_alias_team],
        "environments": [unsafe_environment],
    }
    some message in denials
    contains(message, "administrator bypass")
}

test_overlapping_authorities_cannot_activate_repository_gate if {
    denials := environment_approvals.deny with input as {
        "memberships": [alias_membership],
        "teams": [platform_alias_team, security_alias_team],
        "environments": [
            authority_environment("infrastructure-source-review", "platform-operations"),
            authority_environment("security-source-review", "security"),
        ],
        "repository_gates": [authority_gate("ready", [])],
    }
    some message in denials
    contains(message, "must remain blocked until its reviewer authorities are independent")
}

test_overlapping_authorities_are_explicitly_blocked if {
    denials := environment_approvals.deny with input as {
        "memberships": [alias_membership],
        "teams": [platform_alias_team, security_alias_team],
        "environments": [
            authority_environment("infrastructure-source-review", "platform-operations"),
            authority_environment("security-source-review", "security"),
        ],
        "repository_gates": [authority_gate("blocked", ["independent-reviewer-required"])],
    }
    count({message | some message in denials; contains(message, "repository gate")}) == 0
    count({message | some message in denials; contains(message, "authority check")}) == 0
    count({message | some message in denials; contains(message, "authority environment")}) == 0
}

test_authority_context_substitution_is_denied if {
    unsafe := object.union_n([
        authority_gate("blocked", ["independent-reviewer-required"]),
        {"spec": object.union(authority_gate("blocked", ["independent-reviewer-required"]).spec, {
            "required_status_checks": {"checks": [{
                "context": "untrusted",
                "issuer_type": "github_actions",
                "workflow_path": ".github/workflows/authority-review.yml",
                "triggers": ["pull_request", "merge_group"],
            }]},
        })},
    ])
    denials := environment_approvals.deny with input as {
        "memberships": [alias_membership],
        "teams": [platform_alias_team, security_alias_team],
        "environments": [
            authority_environment("infrastructure-source-review", "platform-operations"),
            authority_environment("security-source-review", "security"),
        ],
        "repository_gates": [unsafe],
    }
    some message in denials
    contains(message, "does not require both authority checks")
}
