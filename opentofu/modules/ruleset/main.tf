terraform {
  required_providers {
    github = {
      source = "integrations/github"
    }
  }
}

locals {
  repository_reference_to_name = merge(
    var.repository_names,
    { for name in values(var.repository_names) : name => name },
  )

  logical_rulesets = {
    for key, ruleset in var.rulesets : key => merge(ruleset, {
      logical_key    = key
      effective_name = coalesce(ruleset.name, key)
      repository_names = [
        for reference in ruleset.repositories :
        lookup(local.repository_reference_to_name, reference, reference)
      ]
      is_creation_restricted_tag = ruleset.target == "tag" && ruleset.rules.creation_restricted
    })
  }

  tag_immutability_rulesets = {
    for key, ruleset in local.logical_rulesets : key => merge(ruleset, {
      physical_role          = "immutability"
      original_bypass_actors = ruleset.bypass_actors
      bypass_actors          = []
      rules = merge(ruleset.rules, {
        creation_restricted             = false
        required_linear_history         = false
        required_signatures             = false
        merge_queue                     = false
        required_workflow               = null
        authorized_creator_integrations = []
        pull_request                    = null
        required_status_checks          = null
      })
    }) if ruleset.target == "tag"
  }

  creator_gate_rulesets = {
    for key, ruleset in local.logical_rulesets : "${key}--creator-gate" => merge(ruleset, {
      physical_role          = "creator_gate"
      effective_name         = "${ruleset.effective_name}-creator-gate"
      original_bypass_actors = ruleset.bypass_actors
      bypass_actors          = []
      rules = merge(ruleset.rules, {
        update                  = false
        deletion                = false
        non_fast_forward        = false
        required_linear_history = false
        required_signatures     = false
        creation_restricted     = true
        merge_queue             = false
        required_workflow       = null
        pull_request            = null
        required_status_checks  = null
      })
    }) if ruleset.is_creation_restricted_tag
  }

  branch_integrity_rulesets = {
    for key, ruleset in local.logical_rulesets : "${key}--integrity" => merge(ruleset, {
      physical_role          = "integrity"
      effective_name         = "${ruleset.effective_name}-integrity"
      original_bypass_actors = ruleset.bypass_actors
      bypass_actors          = []
      rules = merge(ruleset.rules, {
        update                          = false
        creation_restricted             = false
        merge_queue                     = false
        required_workflow               = null
        authorized_creator_integrations = []
        pull_request                    = null
        required_status_checks          = null
      })
    }) if ruleset.target == "branch"
  }

  branch_pr_governance_rulesets = {
    for key, ruleset in local.logical_rulesets : "${key}--pr-governance" => merge(ruleset, {
      physical_role          = "pr_governance"
      effective_name         = "${ruleset.effective_name}-pr-governance"
      original_bypass_actors = ruleset.bypass_actors
      bypass_actors          = ruleset.bypass_actors
      rules = merge(ruleset.rules, {
        update                          = false
        deletion                        = false
        non_fast_forward                = false
        required_linear_history         = false
        required_signatures             = false
        creation_restricted             = false
        merge_queue                     = false
        required_workflow               = null
        authorized_creator_integrations = []
        required_status_checks          = null
      })
    }) if ruleset.target == "branch"
  }

  branch_required_workflow_rulesets = {
    for key, ruleset in local.logical_rulesets : "${key}--required-workflow" => merge(ruleset, {
      physical_role          = "required_workflow"
      effective_name         = "${ruleset.effective_name}-required-workflow"
      original_bypass_actors = ruleset.bypass_actors
      bypass_actors          = []
      rules = merge(ruleset.rules, {
        update                          = false
        deletion                        = false
        non_fast_forward                = false
        required_linear_history         = false
        required_signatures             = false
        creation_restricted             = false
        merge_queue                     = false
        authorized_creator_integrations = []
        pull_request                    = null
      })
    }) if ruleset.target == "branch"
  }

  physical_rulesets = merge(
    local.tag_immutability_rulesets,
    local.creator_gate_rulesets,
    local.branch_integrity_rulesets,
    local.branch_pr_governance_rulesets,
    local.branch_required_workflow_rulesets,
  )

  rulesets = {
    for key, ruleset in local.physical_rulesets : key => merge(ruleset, {
      effective_enforcement = (
        var.rollout_phase == "adopt" && contains(keys(var.adopted_ruleset_enforcements), key) ? var.adopted_ruleset_enforcements[key] :
        var.rollout_phase == "enforce" ? ruleset.enforcement :
        var.rollout_phase == "foundation" ? "evaluate" : "disabled"
      )
      resolved_bypass_actors = merge(
        {
          for actor in ruleset.bypass_actors :
          "Team:${actor.actor}:${actor.mode}" => {
            actor_type  = "Team"
            actor_id    = var.team_ids[actor.actor]
            bypass_mode = actor.mode
          } if actor.actor_type == "team" && contains(keys(var.team_ids), actor.actor)
        },
        {
          for actor in ruleset.bypass_actors :
          "Integration:${actor.actor}:${actor.mode}" => {
            actor_type  = "Integration"
            actor_id    = var.qualified_integration_actor_ids[actor.actor]
            bypass_mode = actor.mode
          } if actor.actor_type == "integration" && contains(keys(var.qualified_integration_actor_ids), actor.actor)
        },
        {
          for integration in ruleset.rules.authorized_creator_integrations :
          "Integration:${integration}:always" => {
            actor_type  = "Integration"
            actor_id    = var.qualified_integration_actor_ids[integration]
            bypass_mode = "always"
          } if ruleset.physical_role == "creator_gate" && var.rollout_phase == "enforce" && contains(keys(var.qualified_integration_actor_ids), integration)
        },
      )
      unresolved_integration_actors = distinct(concat(
        [for actor in ruleset.bypass_actors : actor.actor if actor.actor_type == "integration" && !contains(keys(var.qualified_integration_actor_ids), actor.actor)],
        [for integration in ruleset.rules.authorized_creator_integrations : integration if ruleset.physical_role == "creator_gate" && !contains(keys(var.qualified_integration_actor_ids), integration)],
      ))
    })
  }

  repository_merge_queue_rulesets = merge([
    for key, ruleset in local.logical_rulesets : {
      for reference in ruleset.repositories : "${key}--merge-queue--${reference}" => {
        logical_key    = key
        physical_role  = "merge_queue"
        name           = "${ruleset.effective_name}-merge-queue"
        repository_ref = reference
        repository     = lookup(local.repository_reference_to_name, reference, reference)
        target         = "branch"
        include_refs   = ruleset.include_refs
        exclude_refs   = ruleset.exclude_refs
        enforcement = (
          var.rollout_phase == "adopt" && contains(keys(var.adopted_repository_ruleset_enforcements), "${key}--merge-queue--${reference}") ?
          var.adopted_repository_ruleset_enforcements["${key}--merge-queue--${reference}"] :
          var.rollout_phase == "enforce" ? ruleset.enforcement : "disabled"
        )
      }
    } if ruleset.target == "branch" && ruleset.rules.merge_queue
  ]...)
}

resource "github_organization_ruleset" "this" {
  for_each = local.rulesets

  name        = each.value.effective_name
  target      = each.value.target
  enforcement = each.value.effective_enforcement

  dynamic "bypass_actors" {
    for_each = each.value.resolved_bypass_actors

    content {
      actor_type  = bypass_actors.value.actor_type
      actor_id    = bypass_actors.value.actor_id
      bypass_mode = bypass_actors.value.bypass_mode
    }
  }

  conditions {
    repository_name {
      include   = each.value.repository_names
      exclude   = []
      protected = true
    }

    ref_name {
      include = each.value.include_refs
      exclude = each.value.exclude_refs
    }
  }

  rules {
    creation                = var.rollout_phase == "enforce" && each.value.rules.creation_restricted
    update                  = each.value.rules.update
    deletion                = each.value.rules.deletion
    non_fast_forward        = each.value.rules.non_fast_forward
    required_linear_history = each.value.rules.required_linear_history
    required_signatures     = each.value.rules.required_signatures

    dynamic "pull_request" {
      for_each = each.value.rules.pull_request == null ? [] : [each.value.rules.pull_request]

      content {
        dismiss_stale_reviews_on_push     = pull_request.value.dismiss_stale_reviews
        require_code_owner_review         = pull_request.value.require_code_owner_review
        require_last_push_approval        = pull_request.value.require_last_push_approval
        required_approving_review_count   = pull_request.value.required_approving_review_count
        required_review_thread_resolution = pull_request.value.required_review_thread_resolution
      }
    }

    dynamic "required_status_checks" {
      for_each = each.value.rules.required_status_checks == null ? [] : [each.value.rules.required_status_checks]

      content {
        strict_required_status_checks_policy = required_status_checks.value.strict
        do_not_enforce_on_create             = false

        dynamic "required_check" {
          for_each = required_status_checks.value.checks

          content {
            context = required_check.value.context
            integration_id = try(coalesce(
              required_check.value.integration_id,
              lookup(var.qualified_status_check_integration_ids, required_check.value.issuer_type, null),
            ), null)
          }
        }
      }
    }

    dynamic "required_workflows" {
      for_each = each.value.rules.required_workflow == null ? [] : [each.value.rules.required_workflow]

      content {
        do_not_enforce_on_create = false

        required_workflow {
          repository_id = var.repository_ids[required_workflows.value.repository]
          path          = required_workflows.value.path
          ref           = required_workflows.value.ref
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition = alltrue([
        for reference in each.value.repositories :
        contains(keys(local.repository_reference_to_name), reference)
      ])
      error_message = "Ruleset references an unknown repository."
    }

    precondition {
      condition = alltrue([
        for actor in each.value.bypass_actors :
        actor.actor_type != "team" || contains(keys(var.team_ids), actor.actor)
      ])
      error_message = "Ruleset team bypass references an unknown team."
    }

    precondition {
      condition = (
        var.rollout_phase != "enforce" ||
        each.value.effective_enforcement != "active" ||
        length(each.value.unresolved_integration_actors) == 0
      )
      error_message = "Integration bypass actors require observed, preflight-qualified numeric GitHub App IDs before enforcement."
    }

    precondition {
      condition = (
        var.rollout_phase != "enforce" ||
        each.value.effective_enforcement != "active" ||
        each.value.physical_role != "creator_gate" || (
          length(each.value.rules.authorized_creator_integrations) > 0 &&
          alltrue([
            for integration in each.value.rules.authorized_creator_integrations :
            contains(keys(var.qualified_integration_actor_ids), integration)
          ])
        )
      )
      error_message = "Creation-restricted refs require a qualified Integration actor ID before enforcement can be applied."
    }

    precondition {
      condition = (
        var.rollout_phase != "enforce" ||
        each.value.effective_enforcement != "active" ||
        each.value.physical_role != "creator_gate" ||
        length(each.value.original_bypass_actors) == 0
      )
      error_message = "Creation-restricted tag policies must express creators only through authorized_creator_integrations; broad logical bypass actors cannot be mapped without weakening immutability."
    }

    precondition {
      condition = (
        var.rollout_phase != "enforce" ||
        each.value.effective_enforcement != "active" ||
        each.value.physical_role != "immutability" || (
          each.value.rules.update &&
          each.value.rules.deletion &&
          each.value.rules.non_fast_forward
        )
      )
      error_message = "Immutable tag enforcement requires update, deletion, and non-fast-forward rules together."
    }

    precondition {
      condition = (
        var.rollout_phase != "enforce" ||
        each.value.effective_enforcement != "active" ||
        (each.value.rules.required_status_checks == null ? true : alltrue([
          for check in each.value.rules.required_status_checks.checks :
          check.integration_id != null || contains(keys(var.qualified_status_check_integration_ids), check.issuer_type)
        ]))
      )
      error_message = "Active required checks need preflight-qualified numeric issuer App IDs to prevent same-context spoofing."
    }


    precondition {
      condition = (
        var.rollout_phase != "enforce" ||
        each.value.effective_enforcement != "active" ||
        each.value.rules.required_workflow == null ||
        contains(keys(var.repository_ids), each.value.rules.required_workflow.repository)
      )
      error_message = "Active organization required workflows need a managed numeric source repository ID."
    }

    precondition {
      condition = (
        each.value.physical_role == "pr_governance" || length(each.value.bypass_actors) == 0
      )
      error_message = "Only the split pull-request-governance ruleset may carry bypass actors."
    }
  }
}

resource "github_repository_ruleset" "merge_queue" {
  for_each = local.repository_merge_queue_rulesets

  name        = each.value.name
  repository  = each.value.repository
  target      = each.value.target
  enforcement = each.value.enforcement

  conditions {
    ref_name {
      include = each.value.include_refs
      exclude = each.value.exclude_refs
    }
  }

  rules {
    merge_queue {
      check_response_timeout_minutes    = 30
      grouping_strategy                 = "ALLGREEN"
      max_entries_to_build              = 2
      max_entries_to_merge              = 1
      merge_method                      = "SQUASH"
      min_entries_to_merge              = 1
      min_entries_to_merge_wait_minutes = 0
    }
  }

  lifecycle {
    precondition {
      condition     = contains(keys(local.repository_reference_to_name), each.value.repository_ref)
      error_message = "Repository merge-queue ruleset references an unknown repository."
    }

    precondition {
      condition     = var.rollout_phase == "enforce" || each.value.enforcement == "disabled"
      error_message = "Repository rulesets stay disabled until the protected enforce phase because evaluate mode is organization-only."
    }
  }
}
