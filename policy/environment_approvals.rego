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

allow if count(deny) == 0
