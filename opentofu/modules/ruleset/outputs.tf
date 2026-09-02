output "ruleset_ids" {
  description = "Numeric GitHub ruleset IDs keyed by stable catalog identifier."
  value       = { for key, ruleset in github_organization_ruleset.this : key => ruleset.ruleset_id }
}

output "repository_ruleset_ids" {
  description = "Numeric repository merge-queue ruleset IDs keyed by physical identifier."
  value       = { for key, ruleset in github_repository_ruleset.merge_queue : key => ruleset.ruleset_id }
}

output "effective_enforcement" {
  description = "Effective organization and repository ruleset mode after the protected rollout phase."
  value = merge(
    { for key, ruleset in local.rulesets : key => ruleset.effective_enforcement },
    { for key, ruleset in local.repository_merge_queue_rulesets : key => ruleset.enforcement },
  )
}

output "physical_rulesets" {
  description = "Stable mapping from physical rulesets to logical catalog policy and security role."
  value = merge({
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
    }, {
    for key, ruleset in local.repository_merge_queue_rulesets : key => {
      logical_key = ruleset.logical_key
      name        = ruleset.name
      role        = ruleset.physical_role
      enforcement = ruleset.enforcement
      repository  = ruleset.repository
      rules = {
        merge_queue = true
      }
      bypass_actors = {}
    }
  })
}

output "deployment_preflight" {
  description = "Ruleset intentions that require external qualification or are unavailable in provider 6.13.0."
  value = merge({
    for key, ruleset in local.rulesets : key => {
      merge_queue = {
        managed             = true
        desired             = false
        enforcement_blocked = false
        reason              = "merge queue is isolated in a no-bypass repository ruleset"
      }
      distinct_principals = {
        managed = true
        desired = try(ruleset.rules.pull_request.require_distinct_principals, false)
        reason  = "the no-bypass organization required workflow validates review identities against the principal mapping"
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
        managed             = ruleset.rules.required_status_checks == null || ruleset.rules.required_workflow != null
        enforcement_blocked = ruleset.rules.required_status_checks != null && ruleset.rules.required_workflow == null
        desired = try([
          for check in ruleset.rules.required_status_checks.checks : {
            context       = check.context
            workflow_path = check.workflow_path
            triggers      = check.triggers
          }
        ], [])
        reason = "provider 6.13.0 binds the protected organization workflow to the managed .github repository and main ref"
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
    }, {
    for key, ruleset in local.repository_merge_queue_rulesets : key => {
      merge_queue = {
        managed             = true
        desired             = true
        enforcement_blocked = false
        reason              = "provider 6.13.0 materializes merge_queue on a repository ruleset"
      }
      distinct_principals = {
        managed = true
        desired = false
        reason  = "not applicable to the isolated merge-queue resource"
      }
      status_check_issuers = {
        managed   = true
        desired   = []
        actor_ids = {}
        reason    = "the separate no-bypass required-workflow organization ruleset owns checks"
      }
      workflow_provenance = {
        managed             = true
        enforcement_blocked = false
        desired             = []
        reason              = "the separate no-bypass required-workflow organization ruleset owns provenance"
      }
      authorized_creator_integrations = {
        managed    = true
        desired    = []
        actor_ids  = {}
        unresolved = []
        reason     = "not applicable to branch merge queues"
      }
      bypass_actors = {
        managed_teams           = []
        unresolved_integrations = []
        reason                  = "repository merge-queue rulesets never carry bypass actors"
      }
      tag_rule_separation = {
        logical_key = ruleset.logical_key
        role        = ruleset.physical_role
        reason      = "merge queue is isolated from the pull-request bypass entitlement"
      }
    }
  })
}

output "managed_resource_ids" {
  description = "Non-sensitive ruleset resource identifiers for evidence."
  value = {
    organization = { for key, ruleset in github_organization_ruleset.this : key => ruleset.id }
    repository   = { for key, ruleset in github_repository_ruleset.merge_queue : key => ruleset.id }
  }
}
