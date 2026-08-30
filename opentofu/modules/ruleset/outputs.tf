output "ruleset_ids" {
  description = "Numeric GitHub ruleset IDs keyed by stable catalog identifier."
  value       = { for key, ruleset in github_organization_ruleset.this : key => ruleset.ruleset_id }
}

output "repository_gate_ids" {
  description = "Numeric repository-ruleset IDs keyed by authority-gate catalog identifier."
  value       = { for key, ruleset in github_repository_ruleset.gate : key => ruleset.ruleset_id }
}

output "effective_enforcement" {
  description = "Effective ruleset mode after applying the protected rollout phase."
  value       = { for key, ruleset in local.rulesets : key => ruleset.effective_enforcement }
}

output "physical_rulesets" {
  description = "Stable mapping from physical rulesets to logical catalog policy and security role."
  value = {
    for key, ruleset in local.rulesets : key => {
      logical_key = ruleset.logical_key
      name        = ruleset.effective_name
      role        = ruleset.physical_role
      enforcement = ruleset.effective_enforcement
      rules = {
        creation         = var.rollout_phase == "enforce" && ruleset.rules.creation_restricted
        update           = ruleset.rules.update
        deletion         = ruleset.rules.deletion
        non_fast_forward = ruleset.rules.non_fast_forward
      }
      bypass_actors = ruleset.resolved_bypass_actors
    }
  }
}

output "deployment_preflight" {
  description = "Ruleset intentions that require external qualification or are unavailable in provider 6.13.0."
  value = {
    for key, ruleset in local.rulesets : key => {
      merge_queue = {
        managed             = false
        desired             = ruleset.rules.merge_queue
        enforcement_blocked = ruleset.rules.merge_queue
        reason              = "provider 6.13.0 does not expose an organization-ruleset merge_queue block; active enforce is blocked while desired"
      }
      distinct_principals = {
        managed = false
        desired = try(ruleset.rules.pull_request.require_distinct_principals, false)
        reason  = "GitHub approval counts are account-based; principal alias independence is enforced by catalog policy and preflight"
      }
      status_check_issuers = {
        managed = ruleset.rules.required_status_checks == null ? true : alltrue([
          for check in ruleset.rules.required_status_checks.checks :
          check.integration_id != null || contains(keys(var.qualified_status_check_integration_ids), check.issuer_type)
        ])
        desired = try(ruleset.rules.required_status_checks.checks, [])
        actor_ids = ruleset.rules.required_status_checks == null ? {} : {
          for check in ruleset.rules.required_status_checks.checks :
          check.issuer_type => try(coalesce(check.integration_id, lookup(var.qualified_status_check_integration_ids, check.issuer_type, null)), null)
        }
        reason = "numeric issuer App IDs are enforced when qualified; immutable workflow path and trigger provenance remain workflow-policy preflight evidence"
      }
      workflow_provenance = {
        managed             = ruleset.rules.required_status_checks == null
        enforcement_blocked = ruleset.rules.required_status_checks != null
        desired = try([
          for check in ruleset.rules.required_status_checks.checks : {
            context       = check.context
            workflow_path = check.workflow_path
            triggers      = check.triggers
          }
        ], [])
        reason = "provider required_workflows needs a source repository ID and immutable ref; catalog workflow_path and trigger declarations are retained but enforcement stays blocked until a digest-bound binding exists"
      }
      authorized_creator_integrations = {
        managed    = ruleset.physical_role != "creator_gate" || (length(ruleset.unresolved_integration_actors) == 0 && length(ruleset.original_bypass_actors) == 0)
        desired    = ruleset.rules.authorized_creator_integrations
        actor_ids  = { for integration in ruleset.rules.authorized_creator_integrations : integration => lookup(var.qualified_integration_actor_ids, integration, null) }
        unresolved = ruleset.unresolved_integration_actors
        reason     = "integration records remain audit-only; ruleset bypass uses only observed numeric App IDs admitted by connected preflight"
      }
      bypass_actors = {
        managed_teams           = [for actor in ruleset.bypass_actors : actor if actor.actor_type == "team"]
        unresolved_integrations = [for actor in ruleset.bypass_actors : actor if actor.actor_type == "integration" && !contains(keys(var.qualified_integration_actor_ids), actor.actor)]
        reason                  = "team actor IDs resolve from managed teams; App actor IDs require connected observation and qualification"
      }
      tag_rule_separation = {
        logical_key = ruleset.logical_key
        role        = ruleset.physical_role
        reason      = "creation authorization is isolated from deletion and non-fast-forward protection so creator Apps cannot move or delete immutable tags"
      }
    }
  }
}

output "repository_gate_preflight" {
  description = "Repository authority-gate controls and their connected qualification state."
  value = {
    for key, gate in local.repository_gates : key => {
      required_deployments = {
        managed = true
        desired = gate.environment_names
      }
      status_check_issuers = {
        managed = alltrue([
          for check in gate.required_status_checks.checks :
          check.integration_id != null || contains(keys(var.qualified_status_check_integration_ids), check.issuer_type)
        ])
        desired = gate.required_status_checks.checks
      }
      bypass_actors = {
        managed = length(gate.bypass_actors) == 0
        desired = gate.bypass_actors
      }
      effective_enforcement = gate.effective_enforcement
    }
  }
}

output "managed_resource_ids" {
  description = "Non-sensitive ruleset resource identifiers for evidence."
  value = {
    organization     = { for key, ruleset in github_organization_ruleset.this : key => ruleset.id }
    repository_gates = { for key, ruleset in github_repository_ruleset.gate : key => ruleset.id }
  }
}
