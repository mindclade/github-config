variable "organization_login" {
  description = "GitHub organization login used to construct membership import identities."
  type        = string
}

variable "security_manager_team" {
  description = "Stable team identifier assigned the built-in security_manager organization role."
  type        = string
}

variable "members" {
  description = "Organization memberships managed by this catalog."
  type = list(object({
    login             = string
    principal_id      = string
    role              = optional(string)
    organization_role = optional(string)
    account_type      = optional(string, "human")
    managed           = optional(bool, true)
  }))

  validation {
    condition = alltrue([
      for member in var.members :
      member.login != "" &&
      member.principal_id != "" &&
      contains(["member", "admin"], try(coalesce(member.organization_role, member.role), ""))
    ])
    error_message = "Every member requires a login/principal identity and a valid organization role."
  }

  validation {
    condition     = length(distinct([for member in var.members : lower(member.login)])) == length(var.members)
    error_message = "Organization member logins must be unique after case normalization."
  }
}

variable "teams" {
  description = "Teams keyed by stable catalog identifier."
  type = map(object({
    name        = string
    description = string
    privacy     = string
    parent      = optional(string)
    parent_team = optional(string)
    members = optional(list(object({
      login = string
      role  = string
    })), [])
  }))

  validation {
    condition = alltrue([
      for team in values(var.teams) :
      contains(["closed", "secret"], team.privacy) &&
      team.parent == null &&
      team.parent_team == null &&
      alltrue([for member in team.members : contains(["member", "maintainer"], member.role)])
    ])
    error_message = "Blueprint teams must be independent root teams with closed/secret privacy and valid member roles."
  }

  validation {
    condition = alltrue([
      for team in values(var.teams) :
      length(distinct([for member in team.members : lower(member.login)])) == length(team.members)
    ])
    error_message = "A team may declare each account only once after case normalization."
  }
}

variable "repository_names" {
  description = "Repository names keyed by stable catalog identifier."
  type        = map(string)
}

variable "repository_team_grants" {
  description = "Team permissions keyed first by repository identifier and then team identifier."
  type        = map(map(string))

  validation {
    condition = alltrue(flatten([
      for grants in values(var.repository_team_grants) : [
        for permission in values(grants) :
        contains(["pull", "triage", "push", "maintain"], permission)
      ]
    ]))
    error_message = "Repository team grants may not exceed maintain permission."
  }
}

variable "outside_collaborators" {
  description = "Time-bounded outside-collaborator grants. The initial catalog is empty."
  type = list(object({
    login              = string
    principal_id       = string
    sponsor_login      = string
    approval_reference = string
    justification      = string
    expires_on         = string
    repository_permissions = list(object({
      repository = string
      permission = string
    }))
  }))

  validation {
    condition = alltrue(flatten([
      for collaborator in var.outside_collaborators : [
        collaborator.login != "",
        collaborator.principal_id != "",
        collaborator.sponsor_login != "",
        collaborator.approval_reference != "",
        collaborator.justification != "",
        can(timecmp("${collaborator.expires_on}T23:59:59Z", "1970-01-01T00:00:00Z")),
        alltrue([
          for grant in collaborator.repository_permissions :
          contains(["pull", "triage", "push", "maintain"], grant.permission)
        ]),
      ]
    ]))
    error_message = "Outside collaborators require accountable, expiring, least-privilege repository grants."
  }
}
