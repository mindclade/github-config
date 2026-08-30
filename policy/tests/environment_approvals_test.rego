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
