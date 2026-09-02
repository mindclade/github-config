variable "rulesets" {
  description = "Organization rulesets keyed by stable catalog identifier."
  type = map(object({
    name         = optional(string)
    target       = string
    enforcement  = string
    repositories = list(string)
    include_refs = list(string)
    exclude_refs = list(string)
    bypass_actors = list(object({
      actor_type = string
      actor      = string
      mode       = string
    }))
    rules = object({
      update                  = optional(bool, false)
      deletion                = optional(bool, false)
      non_fast_forward        = optional(bool, false)
      required_linear_history = optional(bool, false)
      required_signatures     = optional(bool, false)
      creation_restricted     = optional(bool, false)
      merge_queue             = optional(bool, false)
      required_workflow = optional(object({
        repository = string
        path       = string
        ref        = string
      }))
      authorized_creator_integrations = optional(list(string), [])
      pull_request = optional(object({
        required_approving_review_count   = number
        require_code_owner_review         = bool
        dismiss_stale_reviews             = bool
        require_last_push_approval        = bool
        required_review_thread_resolution = bool
        require_distinct_principals       = bool
      }))
      required_status_checks = optional(object({
        strict = bool
        checks = list(object({
          context        = string
          issuer_type    = string
          workflow_path  = string
          triggers       = list(string)
          integration_id = optional(number)
        }))
      }))
    })
  }))

  validation {
    condition = alltrue([
      for ruleset in values(var.rulesets) :
      contains(["branch", "tag"], ruleset.target) &&
      contains(["disabled", "evaluate", "active"], ruleset.enforcement) &&
      length(ruleset.repositories) > 0 &&
      length(ruleset.include_refs) > 0 &&
      alltrue([
        for actor in ruleset.bypass_actors :
        contains(["team", "integration"], actor.actor_type) &&
        contains(["pull_request", "always"], actor.mode) &&
        actor.actor != ""
      ])
    ])
    error_message = "Each organization ruleset requires a supported target/enforcement and non-empty repository/ref conditions."
  }

  validation {
    condition = alltrue([
      for ruleset in values(var.rulesets) :
      ruleset.rules.pull_request == null || (
        ruleset.rules.pull_request.required_approving_review_count >= 1 &&
        ruleset.rules.pull_request.required_approving_review_count <= 10
      )
    ])
    error_message = "Pull-request rules require one to ten approvals."
  }

  validation {
    condition = alltrue([
      for key, ruleset in var.rulesets :
      !(ruleset.target == "tag" && ruleset.rules.creation_restricted) || (
        !contains(keys(var.rulesets), "${key}--creator-gate") &&
        length(coalesce(ruleset.name, key)) <= 87
      )
    ])
    error_message = "Creation-restricted tag rulesets reserve the --creator-gate key suffix and 13 name characters for their physical creator gate."
  }
}

variable "repository_names" {
  description = "Repository names keyed by stable catalog identifier."
  type        = map(string)
}

variable "repository_ids" {
  description = "Numeric repository IDs keyed by stable catalog identifier for organization required workflows."
  type        = map(number)
}

variable "adopted_repository_ruleset_enforcements" {
  description = "Exact observed enforcement for imported repository merge-queue rulesets."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for enforcement in values(var.adopted_repository_ruleset_enforcements) : contains(["disabled", "active"], enforcement)])
    error_message = "Imported repository ruleset enforcement must be disabled or active."
  }
}

variable "team_ids" {
  description = "Numeric team IDs keyed by stable catalog identifier for explicit bypass actors."
  type        = map(number)
}

variable "rollout_phase" {
  description = "Controls whether rulesets are disabled, evaluated, or enforced."
  type        = string

  validation {
    condition     = contains(["adopt", "foundation", "enforce"], var.rollout_phase)
    error_message = "rollout_phase must be adopt, foundation, or enforce."
  }
}

variable "adopted_ruleset_enforcements" {
  description = "Exact observed enforcement for imported organization rulesets."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for enforcement in values(var.adopted_ruleset_enforcements) : contains(["disabled", "evaluate", "active"], enforcement)])
    error_message = "Imported organization ruleset enforcement must be disabled, evaluate, or active."
  }
}

variable "qualified_integration_actor_ids" {
  description = "Observed, preflight-qualified numeric App actor IDs keyed by integration catalog identifier."
  type        = map(number)

  validation {
    condition     = alltrue([for actor_id in values(var.qualified_integration_actor_ids) : actor_id > 0])
    error_message = "Qualified integration actor IDs must be positive GitHub App IDs."
  }
}

variable "qualified_status_check_integration_ids" {
  description = "Observed, preflight-qualified numeric App IDs keyed by check issuer type."
  type        = map(number)

  validation {
    condition     = alltrue([for integration_id in values(var.qualified_status_check_integration_ids) : integration_id > 0])
    error_message = "Qualified status-check integration IDs must be positive GitHub App IDs."
  }
}
