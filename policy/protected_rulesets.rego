package github_config.protected_rulesets

import rego.v1

has_trigger(check, trigger) if {
	check.triggers[_] == trigger
}

has_authorized_creator(ruleset, integration) if {
	ruleset.spec.rules.authorized_creator_integrations[_] == integration
}

deny contains sprintf("ruleset %q is not active", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.enforcement != "active"
}

founder_pr_bypass(actor) if {
	actor.actor_type == "team"
	actor.actor == "founder-pr-bypass"
	actor.mode == "pull_request"
}

deny contains sprintf("branch ruleset %q omits the evidence-gated founder PR entitlement", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	count(ruleset.spec.bypass_actors) != 1
}

deny contains sprintf("branch ruleset %q defines a noncanonical bypass actor", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	some actor in ruleset.spec.bypass_actors
	not founder_pr_bypass(actor)
}

deny contains sprintf("non-branch ruleset %q defines bypass actors", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target != "branch"
	count(ruleset.spec.bypass_actors) > 0
}

deny contains sprintf("branch ruleset %q permits deletion", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	not ruleset.spec.rules.deletion
}

deny contains sprintf("branch ruleset %q permits non-fast-forward updates", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	not ruleset.spec.rules.non_fast_forward
}

deny contains sprintf("branch ruleset %q lacks signed commits", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	not ruleset.spec.rules.required_signatures
}

deny contains sprintf("branch ruleset %q lacks linear history", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	not ruleset.spec.rules.required_linear_history
}

deny contains sprintf("branch ruleset %q lacks merge queue protection", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	not ruleset.spec.rules.merge_queue
}

deny contains sprintf("branch ruleset %q lacks the protected organization workflow", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	ruleset.spec.rules.required_workflow.repository != "dot-github"
}

deny contains sprintf("branch ruleset %q uses a noncanonical required workflow", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	workflow := ruleset.spec.rules.required_workflow
	workflow.path != ".github/workflows/pull-request.yml"
}

deny contains sprintf("branch ruleset %q does not bind the protected main workflow", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	ruleset.spec.rules.required_workflow.ref != "refs/heads/main"
}

deny contains sprintf("branch ruleset %q requires fewer than two approvals", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	ruleset.spec.rules.pull_request.required_approving_review_count < 2
}

deny contains sprintf("branch ruleset %q lacks CODEOWNERS review", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	not ruleset.spec.rules.pull_request.require_code_owner_review
}

deny contains sprintf("branch ruleset %q keeps stale reviews", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	not ruleset.spec.rules.pull_request.dismiss_stale_reviews
}

deny contains sprintf("branch ruleset %q permits last-pusher approval", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	not ruleset.spec.rules.pull_request.require_last_push_approval
}

deny contains sprintf("branch ruleset %q permits unresolved conversations", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	not ruleset.spec.rules.pull_request.required_review_thread_resolution
}

deny contains sprintf("branch ruleset %q does not require distinct principals", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	not ruleset.spec.rules.pull_request.require_distinct_principals
}

deny contains sprintf("branch ruleset %q does not require strict status checks", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	not ruleset.spec.rules.required_status_checks.strict
}

deny contains sprintf("check %q in ruleset %q omits pull_request", [check.context, ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	some check in ruleset.spec.rules.required_status_checks.checks
	not has_trigger(check, "pull_request")
}

deny contains sprintf("check %q in ruleset %q omits merge_group", [check.context, ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	some check in ruleset.spec.rules.required_status_checks.checks
	not has_trigger(check, "merge_group")
}

deny contains sprintf("check %q in ruleset %q has no qualified issuer ID", [check.context, ruleset.metadata.id]) if {
	input.security_policy.spec.activation.state == "ready"
	some ruleset in input.rulesets
	ruleset.spec.target == "branch"
	some check in ruleset.spec.rules.required_status_checks.checks
	not check.integration_id
}

deny contains sprintf("tag ruleset %q permits deletion", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "tag"
	not ruleset.spec.rules.deletion
}

deny contains sprintf("tag ruleset %q permits tag updates", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "tag"
	not ruleset.spec.rules.update
}

deny contains sprintf("tag ruleset %q permits tag movement", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "tag"
	not ruleset.spec.rules.non_fast_forward
}

deny contains sprintf("tag ruleset %q does not restrict creation", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "tag"
	not ruleset.spec.rules.creation_restricted
}

deny contains sprintf("tag ruleset %q lacks the qualified signing identity", [ruleset.metadata.id]) if {
	some ruleset in input.rulesets
	ruleset.spec.target == "tag"
	not has_authorized_creator(ruleset, "artifact-signing")
}

allow if count(deny) == 0
