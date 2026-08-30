variable "organization" {
  description = "Validated organization settings from the compiled catalog."
  type = object({
    organization_login                       = string
    default_repository_permission            = string
    members_can_create_repositories          = bool
    members_can_create_public_repositories   = bool
    members_can_create_private_repositories  = bool
    members_can_create_internal_repositories = bool
    members_can_create_pages                 = bool
    members_can_fork_private_repositories    = bool
    web_commit_signoff_required              = bool
    two_factor_requirement                   = bool
    custom_properties = list(object({
      name               = string
      value_type         = string
      required           = bool
      allowed_values     = list(string)
      values_editable_by = string
    }))
  })

  validation {
    condition     = var.organization.organization_login != ""
    error_message = "organization_login must be set."
  }

  validation {
    condition = contains(
      ["none", "read", "write", "admin"],
      var.organization.default_repository_permission,
    )
    error_message = "default_repository_permission must be none, read, write, or admin."
  }

  validation {
    condition = alltrue([
      for property in var.organization.custom_properties :
      property.name != "" &&
      contains(["string", "single_select", "multi_select", "true_false"], property.value_type) &&
      property.values_editable_by == "org_actors"
    ])
    error_message = "Each custom property must have a name, a supported type, and organization-only edit authority."
  }
}

variable "actions_policy" {
  description = "Organization-wide GitHub Actions policy."
  type = object({
    mode                             = string
    github_owned_allowed             = bool
    verified_creator_allowed         = bool
    default_workflow_permissions     = string
    can_approve_pull_request_reviews = bool
    required_pin                     = string
    runner_policy = object({
      github_hosted             = bool
      self_hosted               = bool
      public_fork_pull_requests = bool
    })
    allowed_actions = list(object({
      source = string
      commit = string
    }))
    enabled_repositories = optional(string, "all")
  })

  validation {
    condition = (
      contains(["all", "local_only", "selected"], var.actions_policy.mode) &&
      contains(["all", "none"], var.actions_policy.enabled_repositories) &&
      contains(["read", "write"], var.actions_policy.default_workflow_permissions) &&
      var.actions_policy.required_pin == "commit_sha" &&
      alltrue([
        for action in var.actions_policy.allowed_actions :
        can(regex("^[0-9a-f]{40}$", action.commit))
      ])
    )
    error_message = "Actions mode, enabled repositories, or default workflow permissions are invalid. Selected repositories are intentionally unsupported in this module."
  }
}

variable "security_policy" {
  description = "Validated security policy. Provider-unsupported controls are exposed for preflight."
  type = object({
    security_manager_team                    = string
    dependency_graph_required                = bool
    dependabot_alerts_required               = bool
    dependabot_security_updates_required     = bool
    advanced_security_required               = bool
    code_scanning_default_setup_required     = bool
    secret_scanning_required                 = bool
    secret_scanning_push_protection_required = bool
    private_vulnerability_reporting_required = bool
    required_capabilities                    = list(string)
    activation = object({
      state    = string
      blockers = list(string)
    })
  })
}

variable "oidc_policy" {
  description = "Organization Actions OIDC claim policy."
  type = object({
    issuer                = string
    use_default_subject   = bool
    use_immutable_subject = optional(bool, false)
    include_claim_keys    = list(string)
    audiences             = optional(list(string), [])
    subjects              = optional(any, [])
    activation = optional(object({
      state    = string
      blockers = list(string)
    }))
  })

  validation {
    condition = (
      var.oidc_policy.use_default_subject ||
      length(var.oidc_policy.include_claim_keys) > 0
    )
    error_message = "A custom OIDC subject template must include at least one claim key."
  }

  validation {
    condition     = var.oidc_policy.issuer == "https://token.actions.githubusercontent.com"
    error_message = "The GitHub Actions OIDC issuer is immutable and must use the public GitHub issuer URL."
  }
}
