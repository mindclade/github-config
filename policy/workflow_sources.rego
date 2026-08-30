package github_config.workflow_sources

import rego.v1

sha_pattern := "^[0-9a-f]{40}$"
pinned_reusable_workflow_pattern := "^mindclade/\\.github/\\.github/workflows/[A-Za-z0-9_.-]+\\.ya?ml@[0-9a-f]{40}$"

approved_action(reference) if {
    some action in input.actions_policy.spec.allowed_actions
    reference == sprintf("%s@%s", [action.source, action.commit])
}

approved_reusable_workflow(reference) if {
    regex.match(pinned_reusable_workflow_pattern, reference)
}

approved_local_source(reference) if {
    startswith(reference, "./")
}

approved_source(reference) if approved_action(reference)
approved_source(reference) if approved_reusable_workflow(reference)
approved_source(reference) if approved_local_source(reference)

deny contains "GitHub-owned Actions wildcard allowance must be disabled" if {
    input.actions_policy.spec.github_owned_allowed
}

deny contains "verified-creator Actions wildcard allowance must be disabled" if {
    input.actions_policy.spec.verified_creator_allowed
}

deny contains sprintf("allowed action %q is not pinned to a commit", [action.source]) if {
    some action in input.actions_policy.spec.allowed_actions
    not regex.match(sha_pattern, action.commit)
}

deny contains sprintf("workflow %q uses unapproved source %q", [workflow.name, reference]) if {
    some workflow in input.workflows
    some reference in workflow.uses
    not approved_source(reference)
}

deny contains sprintf("workflow %q uses pull_request_target", [workflow.name]) if {
    some workflow in input.workflows
    workflow.events[_] == "pull_request_target"
}

allow if count(deny) == 0
