variable "environments" {
  description = "Repository environments keyed by stable catalog identifier."
  type = map(object({
    name                = string
    repositories        = list(string)
    prevent_self_review = bool
    can_admins_bypass   = bool
    required_reviewers = list(object({
      type = string
      team = optional(string)
      user = optional(string)
    }))
    approval_policy = object({
      minimum_required_reviewers                  = number
      minimum_distinct_principals                 = number
      require_pr_approval                         = bool
      require_code_owner_review                   = bool
      require_reviewer_different_from_pr_approver = bool
    })
    deployment_branch_policy = object({
      protected_branches     = bool
      custom_branch_policies = bool
    })
    allowed_workflows = list(string)
    activation        = optional(any)
  }))

  validation {
    condition = alltrue([
      for environment in values(var.environments) :
      length(environment.repositories) > 0 &&
      environment.prevent_self_review &&
      !environment.can_admins_bypass &&
      environment.approval_policy.minimum_required_reviewers >= 1 &&
      length(environment.required_reviewers) >= 1 &&
      length(environment.required_reviewers) <= 6 &&
      alltrue([for reviewer in environment.required_reviewers : reviewer.type == "team" && reviewer.team != null])
    ])
    error_message = "Protected environments require repositories, team reviewers, self-review prevention, and no admin bypass."
  }

  validation {
    condition = alltrue([
      for environment in values(var.environments) :
      environment.deployment_branch_policy.protected_branches &&
      !environment.deployment_branch_policy.custom_branch_policies
    ])
    error_message = "Catalog v1 environments must use protected branches; custom branch/tag policies are not source-expressible and are rejected fail closed."
  }
}

variable "repository_names" {
  description = "Repository names keyed by stable catalog identifier."
  type        = map(string)
}

variable "team_ids" {
  description = "Numeric GitHub team IDs keyed by stable catalog identifier."
  type        = map(number)
}

variable "repository_team_grants" {
  description = "Explicit repository permissions keyed by repository and team catalog identifiers."
  type        = map(map(string))
}
