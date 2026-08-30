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

  repository_reference_to_key = merge(
    { for key in keys(var.repository_names) : key => key },
    { for key, name in var.repository_names : name => key },
  )

  assignments = merge(
    {},
    [
      for environment_key, environment in var.environments : {
        for repository_reference in environment.repositories :
        "${environment_key}:${repository_reference}" => {
          environment_key      = environment_key
          environment_name     = environment.name
          repository_reference = repository_reference
          repository_key       = lookup(local.repository_reference_to_key, repository_reference, repository_reference)
          repository_name      = lookup(local.repository_reference_to_name, repository_reference, repository_reference)
          prevent_self_review  = environment.prevent_self_review
          can_admins_bypass    = environment.can_admins_bypass
          reviewer_team_keys = [
            for reviewer in environment.required_reviewers : reviewer.team
            if reviewer.type == "team"
          ]
          branch_policy     = environment.deployment_branch_policy
          approval_policy   = environment.approval_policy
          allowed_workflows = environment.allowed_workflows
        }
      }
    ]...
  )

  deployment_policies = merge(
    {},
    [
      for assignment_key, assignment in local.assignments : merge(
        {
          for pattern in assignment.branch_policy.branch_patterns :
          "${assignment_key}:branch:${pattern}" => merge(assignment, {
            policy_type = "branch"
            pattern     = pattern
          })
        },
        {
          for pattern in assignment.branch_policy.tag_patterns :
          "${assignment_key}:tag:${pattern}" => merge(assignment, {
            policy_type = "tag"
            pattern     = pattern
          })
        },
      )
    ]...
  )
}

resource "github_repository_environment" "this" {
  for_each = local.assignments

  environment         = each.value.environment_name
  repository          = each.value.repository_name
  can_admins_bypass   = each.value.can_admins_bypass
  prevent_self_review = each.value.prevent_self_review

  reviewers {
    teams = [for team_key in each.value.reviewer_team_keys : var.team_ids[team_key]]
    users = []
  }

  deployment_branch_policy {
    protected_branches     = each.value.branch_policy.protected_branches
    custom_branch_policies = each.value.branch_policy.custom_branch_policies
  }

  lifecycle {
    prevent_destroy = true

    # wait_timer is not part of the catalog or compiler managed projection.
    # Preserve any live timer until the source contract explicitly models it.
    ignore_changes = [wait_timer]

    precondition {
      condition     = contains(keys(local.repository_reference_to_name), each.value.repository_reference)
      error_message = "Environment assignment references an unknown repository."
    }

    precondition {
      condition = alltrue([
        for team_key in each.value.reviewer_team_keys : contains(keys(var.team_ids), team_key)
      ])
      error_message = "Environment reviewer references an unknown team."
    }

    precondition {
      condition = alltrue([
        for team_key in each.value.reviewer_team_keys :
        contains(keys(lookup(var.repository_team_grants, each.value.repository_key, {})), team_key)
      ])
      error_message = "Environment reviewer teams must have an explicit repository grant."
    }
  }
}

resource "github_repository_environment_deployment_policy" "this" {
  for_each = local.deployment_policies

  repository     = each.value.repository_name
  environment    = each.value.environment_name
  branch_pattern = each.value.policy_type == "branch" ? each.value.pattern : null
  tag_pattern    = each.value.policy_type == "tag" ? each.value.pattern : null

  depends_on = [github_repository_environment.this]

  lifecycle {
    prevent_destroy = true
  }
}
