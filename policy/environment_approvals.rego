package github_config.environment_approvals

import rego.v1

reviewer_principals(environment) := principals if {
    principals := {principal |
        some reviewer in environment.spec.required_reviewers
        some team in input.teams
        team.metadata.id == reviewer.team
        some team_member in team.spec.members
        some membership in input.memberships
        membership.spec.scope == "organization_members"
        some member in membership.spec.organization_members
        member.login == team_member.login
        principal := member.principal_id
    }
}

authority_environment(environment_id) := environment if {
    some environment in input.environments
    environment.metadata.id == environment_id
}

expected_authority_team("infrastructure-source-review") := "platform-operations"
expected_authority_team("security-source-review") := "security"

has_string(values, expected) if {
    some value in values
    value == expected
}

authorities_overlap(gate) if {
    some left_index, right_index
    left_index < right_index
    left_id := gate.spec.required_deployments[left_index]
    right_id := gate.spec.required_deployments[right_index]
    left := authority_environment(left_id)
    right := authority_environment(right_id)
    some principal in reviewer_principals(left)
    principal in reviewer_principals(right)
}

invalid_authority_check(check) if {
    check.issuer_type != "github_actions"
}

invalid_authority_check(check) if {
    check.workflow_path != ".github/workflows/authority-review.yml"
}

invalid_authority_check(check) if {
    triggers := {trigger | some trigger in check.triggers}
    triggers != {"pull_request", "merge_group"}
}

invalid_authority_deployment_policy(policy) if {
    actual := {pattern | some pattern in object.get(policy, "branch_patterns", [])}
    actual != {"refs/pull/*/merge", "refs/heads/gh-readonly-queue/main/*"}
}

invalid_authority_deployment_policy(policy) if {
    count(object.get(policy, "tag_patterns", [])) != 0
}

authority_gate_safely_blocked(gate) if {
    gate.spec.activation.state == "blocked"
    has_string(gate.spec.activation.blockers, "independent-reviewer-required")
}

deny contains sprintf("environment %q permits self-review", [environment.spec.name]) if {
    some environment in input.environments
    not environment.spec.prevent_self_review
}

deny contains sprintf("environment %q permits administrator bypass", [environment.spec.name]) if {
    some environment in input.environments
    environment.spec.can_admins_bypass
}

deny contains sprintf("environment %q does not require PR approval", [environment.spec.name]) if {
    some environment in input.environments
    not environment.spec.approval_policy.require_pr_approval
}

deny contains sprintf("environment %q does not require CODEOWNERS review", [environment.spec.name]) if {
    some environment in input.environments
    not environment.spec.approval_policy.require_code_owner_review
}

deny contains sprintf("environment %q permits the PR approver to approve the environment", [environment.spec.name]) if {
    some environment in input.environments
    not environment.spec.approval_policy.require_reviewer_different_from_pr_approver
}

deny contains sprintf("environment %q requires fewer than two distinct principals", [environment.spec.name]) if {
    some environment in input.environments
    environment.spec.approval_policy.minimum_distinct_principals < 2
}

deny contains sprintf("environment %q must remain blocked until independent reviewers exist", [environment.spec.name]) if {
    some environment in input.environments
    principals := reviewer_principals(environment)
    count(principals) < environment.spec.approval_policy.minimum_distinct_principals
    environment.spec.activation.state != "blocked"
}

deny contains sprintf("blocked environment %q has no activation blocker", [environment.spec.name]) if {
    some environment in input.environments
    environment.spec.activation.state == "blocked"
    count(environment.spec.activation.blockers) == 0
}

deny contains sprintf("repository gate %q is not active", [gate.metadata.id]) if {
    some gate in object.get(input, "repository_gates", [])
    gate.spec.enforcement != "active"
}

deny contains sprintf("repository gate %q defines bypass actors", [gate.metadata.id]) if {
    some gate in object.get(input, "repository_gates", [])
    count(gate.spec.bypass_actors) > 0
}

deny contains sprintf("repository gate %q does not require both authority deployments", [gate.metadata.id]) if {
    some gate in object.get(input, "repository_gates", [])
    actual := {deployment | some deployment in gate.spec.required_deployments}
    actual != {"infrastructure-source-review", "security-source-review"}
}

deny contains sprintf("repository gate %q does not require both authority checks", [gate.metadata.id]) if {
    some gate in object.get(input, "repository_gates", [])
    actual := {check.context | some check in gate.spec.required_status_checks.checks}
    actual != {"Authority review / platform-operations", "Authority review / security"}
}

deny contains sprintf("authority check %q in repository gate %q has invalid provenance", [check.context, gate.metadata.id]) if {
    some gate in object.get(input, "repository_gates", [])
    some check in gate.spec.required_status_checks.checks
    invalid_authority_check(check)
}

deny contains sprintf("authority environment %q has the wrong reviewer team", [deployment]) if {
    some gate in object.get(input, "repository_gates", [])
    some deployment in gate.spec.required_deployments
    environment := authority_environment(deployment)
    actual := {reviewer.team | some reviewer in environment.spec.required_reviewers}
    actual != {expected_authority_team(deployment)}
}

deny contains sprintf("authority environment %q allows an unapproved workflow", [deployment]) if {
    some gate in object.get(input, "repository_gates", [])
    some deployment in gate.spec.required_deployments
    environment := authority_environment(deployment)
    actual := {workflow | some workflow in environment.spec.allowed_workflows}
    actual != {".github/workflows/authority-review.yml"}
}

deny contains sprintf("authority environment %q has invalid pull-request deployment patterns", [deployment]) if {
    some gate in object.get(input, "repository_gates", [])
    some deployment in gate.spec.required_deployments
    environment := authority_environment(deployment)
    policy := environment.spec.deployment_branch_policy
    invalid_authority_deployment_policy(policy)
}

deny contains sprintf("repository gate %q must remain blocked until its reviewer authorities are independent", [gate.metadata.id]) if {
    some gate in object.get(input, "repository_gates", [])
    authorities_overlap(gate)
    not authority_gate_safely_blocked(gate)
}

allow if count(deny) == 0
