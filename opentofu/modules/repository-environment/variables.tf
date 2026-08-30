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
      branch_patterns        = optional(list(string), [])
      tag_patterns           = optional(list(string), [])
    })
    allowed_workflows = list(string)
    variables         = optional(map(string), {})
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
      environment.deployment_branch_policy.protected_branches != environment.deployment_branch_policy.custom_branch_policies &&
      (
        environment.deployment_branch_policy.custom_branch_policies ?
        length(environment.deployment_branch_policy.branch_patterns) + length(environment.deployment_branch_policy.tag_patterns) > 0 :
        length(environment.deployment_branch_policy.branch_patterns) + length(environment.deployment_branch_policy.tag_patterns) == 0
      )
    ])
    error_message = "Environment branch policy modes are mutually exclusive; custom policies require at least one exact branch or tag pattern and protected-branch policies may not declare patterns."
  }

  validation {
    condition = alltrue([
      for environment in values(var.environments) :
      environment.name == "infrastructure-apply" && try(environment.activation.state, "blocked") == "ready" ? (
        toset(keys(environment.variables)) == toset([
          "CI_EVIDENCE_ARCHIVE_BUCKET",
          "CI_EVIDENCE_VERIFIER_SERVICE_ACCOUNT",
          "CI_EVIDENCE_VERIFIER_WIF_PROVIDER",
          "INFRASTRUCTURE_EXPORT_KMS_KEY_VERSION_DEVELOPMENT",
          "INFRASTRUCTURE_EXPORT_KMS_KEY_VERSION_STAGING",
          "INFRASTRUCTURE_EXPORT_KMS_KEY_VERSION_PRODUCTION",
          "INFRASTRUCTURE_EXPORT_KMS_KEY_VERSION_RESTRICTED",
          "INFRASTRUCTURE_EXPORT_PUBLIC_KEY_PEM_B64_DEVELOPMENT",
          "INFRASTRUCTURE_EXPORT_PUBLIC_KEY_PEM_B64_STAGING",
          "INFRASTRUCTURE_EXPORT_PUBLIC_KEY_PEM_B64_PRODUCTION",
          "INFRASTRUCTURE_EXPORT_PUBLIC_KEY_PEM_B64_RESTRICTED",
          "INFRASTRUCTURE_EXPORT_PUBLIC_KEY_DIGEST_DEVELOPMENT",
          "INFRASTRUCTURE_EXPORT_PUBLIC_KEY_DIGEST_STAGING",
          "INFRASTRUCTURE_EXPORT_PUBLIC_KEY_DIGEST_PRODUCTION",
          "INFRASTRUCTURE_EXPORT_PUBLIC_KEY_DIGEST_RESTRICTED",
        ]) &&
        can(regex("^projects/[1-9][0-9]*/locations/global/workloadIdentityPools/github-ci-evidence/providers/verifier$", environment.variables.CI_EVIDENCE_VERIFIER_WIF_PROVIDER)) &&
        can(regex("^ci-evidence-verifier@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", environment.variables.CI_EVIDENCE_VERIFIER_SERVICE_ACCOUNT)) &&
        can(regex("^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$", environment.variables.CI_EVIDENCE_ARCHIVE_BUCKET)) &&
        alltrue([
          for environment_name in ["DEVELOPMENT", "STAGING", "PRODUCTION", "RESTRICTED"] :
          can(regex("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/us-central1/keyRings/bootstrap-signing/cryptoKeys/infrastructure-export/cryptoKeyVersions/[1-9][0-9]*$", environment.variables["INFRASTRUCTURE_EXPORT_KMS_KEY_VERSION_${environment_name}"])) &&
          can(regex("^[A-Za-z0-9+/]+={0,2}$", environment.variables["INFRASTRUCTURE_EXPORT_PUBLIC_KEY_PEM_B64_${environment_name}"])) &&
          can(base64decode(environment.variables["INFRASTRUCTURE_EXPORT_PUBLIC_KEY_PEM_B64_${environment_name}"])) &&
          can(regex("^sha256:[0-9a-f]{64}$", environment.variables["INFRASTRUCTURE_EXPORT_PUBLIC_KEY_DIGEST_${environment_name}"]))
        ]) &&
        length(toset([
          for environment_name in ["DEVELOPMENT", "STAGING", "PRODUCTION", "RESTRICTED"] :
          environment.variables["INFRASTRUCTURE_EXPORT_KMS_KEY_VERSION_${environment_name}"]
        ])) == 1 &&
        length(toset([
          for environment_name in ["DEVELOPMENT", "STAGING", "PRODUCTION", "RESTRICTED"] :
          environment.variables["INFRASTRUCTURE_EXPORT_PUBLIC_KEY_PEM_B64_${environment_name}"]
        ])) == 1 &&
        length(toset([
          for environment_name in ["DEVELOPMENT", "STAGING", "PRODUCTION", "RESTRICTED"] :
          environment.variables["INFRASTRUCTURE_EXPORT_PUBLIC_KEY_DIGEST_${environment_name}"]
        ])) == 1
      ) : length(environment.variables) == 0
    ])
    error_message = "Only a ready infrastructure-apply environment may declare its exact CI verifier and bootstrap-qualified P-256 infrastructure-export verifier variables."
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
