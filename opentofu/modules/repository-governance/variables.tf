variable "repositories" {
  description = "Repositories keyed by stable catalog identifier."
  type = map(object({
    name                 = string
    description          = string
    visibility           = string
    actions_access_level = string
    archived             = bool
    archive_on_destroy   = bool
    features = object({
      issues      = bool
      projects    = bool
      wiki        = bool
      discussions = bool
      downloads   = bool
    })
    merge_policy = object({
      allow_squash_merge          = bool
      allow_merge_commit          = bool
      allow_rebase_merge          = bool
      allow_auto_merge            = bool
      allow_update_branch         = bool
      delete_branch_on_merge      = bool
      squash_merge_commit_title   = string
      squash_merge_commit_message = string
    })
    security = object({
      vulnerability_alerts            = bool
      dependabot_security_updates     = bool
      advanced_security               = bool
      secret_scanning                 = bool
      secret_scanning_push_protection = bool
    })
    custom_properties = map(any)
    team_grants = list(object({
      team       = string
      permission = string
    }))
    direct_collaborators = list(object({
      login      = string
      permission = string
    }))
  }))

  validation {
    condition = alltrue([
      for repository in values(var.repositories) :
      contains(["private", "internal", "public"], repository.visibility) &&
      contains(["none", "organization"], repository.actions_access_level) &&
      contains(["PR_TITLE", "COMMIT_OR_PR_TITLE"], repository.merge_policy.squash_merge_commit_title) &&
      contains(["PR_BODY", "COMMIT_MESSAGES", "BLANK"], repository.merge_policy.squash_merge_commit_message) &&
      length(repository.direct_collaborators) == 0
    ])
    error_message = "Repositories require valid visibility, Actions access, and squash-commit policy and may not declare direct collaborators."
  }

  validation {
    condition = alltrue(flatten([
      for repository in values(var.repositories) : [
        for permission in [for grant in repository.team_grants : grant.permission] :
        contains(["pull", "triage", "push", "maintain"], permission)
      ]
    ]))
    error_message = "Team repository grants may not exceed maintain permission."
  }
}

variable "web_commit_signoff_required" {
  description = "Organization repository web-commit signoff policy projected onto every catalog repository."
  type        = bool
}

variable "custom_property_types" {
  description = "Organization property types keyed by property name."
  type        = map(string)
}

variable "oidc_policy" {
  description = "Organization OIDC subject-template contract applied explicitly to every catalog repository."
  type = object({
    use_default_subject   = bool
    use_immutable_subject = bool
    include_claim_keys    = list(string)
  })

  validation {
    condition = (
      !var.oidc_policy.use_default_subject &&
      length(var.oidc_policy.include_claim_keys) > 0 &&
      contains(var.oidc_policy.include_claim_keys, "workflow_ref") &&
      contains(var.oidc_policy.include_claim_keys, "workflow_sha")
    )
    error_message = "Every repository must opt out of GitHub's default subject and include immutable workflow_ref/workflow_sha claims."
  }
}

variable "rollout_phase" {
  description = "Protected rollout phase used to fail closed on provider OIDC capability gaps."
  type        = string

  validation {
    condition     = contains(["adopt", "foundation", "enforce"], var.rollout_phase)
    error_message = "rollout_phase must be adopt, foundation, or enforce."
  }
}
