variable "catalog" {
  description = "Canonical catalog emitted by github-configctl compile --tofu-var-file."
  type = object({
    api_version           = optional(string, "github.mindclade.io/v1")
    organization          = any
    actions_policy        = any
    security_policy       = any
    oidc_policy           = any
    members               = any
    outside_collaborators = any
    teams                 = any
    repositories          = any
    rulesets              = any
    environments          = any
    integrations          = any
    activation            = optional(any, {})
    source_digest         = string
  })

  validation {
    condition     = var.catalog.api_version == "github.mindclade.io/v1"
    error_message = "Only the github.mindclade.io/v1 compiled catalog is supported."
  }

  validation {
    condition = coalesce(
      try(var.catalog.organization.organization_login, null),
      try(var.catalog.organization.slug, null),
      "",
    ) != ""
    error_message = "The catalog organization object must identify the GitHub organization login."
  }

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.catalog.source_digest))
    error_message = "source_digest must be a lowercase sha256 digest."
  }

  validation {
    condition = (
      can(tolist(var.catalog.members)) &&
      can(tolist(var.catalog.outside_collaborators)) &&
      can(keys(var.catalog.teams)) &&
      can(keys(var.catalog.repositories)) &&
      can(keys(var.catalog.rulesets)) &&
      can(keys(var.catalog.environments)) &&
      can(keys(var.catalog.integrations))
    )
    error_message = "Catalog membership fields must be lists and catalog collections must be maps."
  }
}

variable "rollout_phase" {
  description = "Protected rollout phase: state adoption, non-enforcing foundation, or qualified enforcement."
  type        = string
  default     = "enforce"

  validation {
    condition     = contains(["adopt", "foundation", "enforce"], var.rollout_phase)
    error_message = "rollout_phase must be adopt, foundation, or enforce."
  }
}

variable "qualified_integration_actor_ids" {
  description = "Observed numeric GitHub App actor IDs keyed by ready integration catalog identifier. Never contains credentials."
  type        = map(number)
  default     = {}

  validation {
    condition     = alltrue([for actor_id in values(var.qualified_integration_actor_ids) : actor_id > 0])
    error_message = "Qualified integration actor IDs must be positive GitHub App IDs."
  }

  validation {
    condition = alltrue([
      for integration_key, actor_id in var.qualified_integration_actor_ids :
      try(var.catalog.integrations[integration_key].actor_id == actor_id, false) &&
      try(var.catalog.integrations[integration_key].activation.state == "ready", false) &&
      try(length(var.catalog.integrations[integration_key].activation.blockers) == 0, false) &&
      try(var.catalog.integrations[integration_key].qualification.state == "qualified", false) &&
      try(var.catalog.integrations[integration_key].qualification.authority == "bootstrap", false) &&
      try(can(regex("^sha256:[0-9a-f]{64}$", var.catalog.integrations[integration_key].qualification.evidence_digest)), false) &&
      try(var.catalog.integrations[integration_key].qualification.attestation.authority == "bootstrap", false) &&
      try(can(regex("^[0-9a-f]{40}$", var.catalog.integrations[integration_key].qualification.attestation.source_sha)), false) &&
      try(var.catalog.integrations[integration_key].qualification.attestation.app_id == actor_id, false) &&
      try(var.catalog.integrations[integration_key].qualification.attestation.installation_id > 0, false) &&
      try(var.catalog.integrations[integration_key].qualification.attestation.repository_selection == var.catalog.integrations[integration_key].repository_selection, false) &&
      try(
        sort([for repository in var.catalog.integrations[integration_key].qualification.attestation.repositories : repository.name]) ==
        sort(tolist(var.catalog.integrations[integration_key].repositories)),
        false,
      ) &&
      try(alltrue([
        for repository in var.catalog.integrations[integration_key].qualification.attestation.repositories : repository.id > 0
      ]), false) &&
      try(
        length(toset([
          for repository in var.catalog.integrations[integration_key].qualification.attestation.repositories : lower(repository.name)
        ])) == length(var.catalog.integrations[integration_key].qualification.attestation.repositories),
        false,
      ) &&
      try(
        length(toset([
          for repository in var.catalog.integrations[integration_key].qualification.attestation.repositories : repository.id
        ])) == length(var.catalog.integrations[integration_key].qualification.attestation.repositories),
        false,
      ) &&
      try(
        sort([
          for permission in var.catalog.integrations[integration_key].qualification.attestation.permissions :
          "${permission.name}:${permission.access}"
          ]) == sort([
          for permission in var.catalog.integrations[integration_key].permissions :
          "${permission.name}:${permission.access}"
        ]),
        false,
      ) &&
      try(
        sort(tolist(var.catalog.integrations[integration_key].qualification.attestation.events)) ==
        sort(tolist(var.catalog.integrations[integration_key].events)),
        false,
      ) &&
      try(can(regex("Z$", var.catalog.integrations[integration_key].qualification.attestation.created_at)), false) &&
      try(can(regex("Z$", var.catalog.integrations[integration_key].qualification.attestation.expires_at)), false) &&
      try(timecmp(var.catalog.integrations[integration_key].qualification.attestation.created_at, plantimestamp()) <= 0, false) &&
      try(timecmp(var.catalog.integrations[integration_key].qualification.attestation.expires_at, plantimestamp()) > 0, false) &&
      try(
        timecmp(
          var.catalog.integrations[integration_key].qualification.attestation.expires_at,
          timeadd(var.catalog.integrations[integration_key].qualification.attestation.created_at, "168h"),
        ) <= 0,
        false,
      ) &&
      try(var.catalog.integrations[integration_key].type == "github_app", false) &&
      try(!var.catalog.integrations[integration_key].managed, false) &&
      try(var.catalog.integrations[integration_key].credential_authority == "bootstrap", false) &&
      try(var.catalog.integrations[integration_key].plaintext_credentials_forbidden, false) &&
      try(var.catalog.integrations[integration_key].repository_selection == "selected", false)
    ])
    error_message = "Qualified integration actor IDs must exactly match unexpired, digest-bound structured bootstrap attestations on ready, blocker-free catalog App records."
  }
}

variable "qualified_status_check_integration_ids" {
  description = "Observed numeric GitHub App IDs keyed by catalog status-check issuer type. Never contains credentials."
  type        = map(number)
  default     = {}

  validation {
    condition     = alltrue([for integration_id in values(var.qualified_status_check_integration_ids) : integration_id > 0])
    error_message = "Qualified status-check integration IDs must be positive GitHub App IDs."
  }


  validation {
    condition = alltrue([
      for issuer_type, integration_id in var.qualified_status_check_integration_ids :
      length(flatten([
        for ruleset in values(var.catalog.rulesets) : [
          for check in try(ruleset.rules.required_status_checks.checks, []) : check
          if check.issuer_type == issuer_type
        ]
      ])) > 0 &&
      alltrue(flatten([
        for ruleset in values(var.catalog.rulesets) : [
          for check in try(ruleset.rules.required_status_checks.checks, []) :
          try(check.integration_id == integration_id, false)
          if check.issuer_type == issuer_type
        ]
      ]))
    ])
    error_message = "Qualified status-check integration IDs must exactly match every catalog check for the issuer type."
  }
}

variable "adopted_team_ids" {
  description = "Reviewed numeric IDs for pre-existing teams that foundation should import. Never contains credentials."
  type        = map(number)
  default     = {}

  validation {
    condition = (
      alltrue([for key in keys(var.adopted_team_ids) : contains(keys(var.catalog.teams), key)]) &&
      alltrue([for team_id in values(var.adopted_team_ids) : team_id > 0])
    )
    error_message = "adopted_team_ids may contain only positive IDs keyed by catalog team identifier."
  }
}

variable "adopted_repository_names" {
  description = "Reviewed names for pre-existing catalog repositories that foundation should import."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for repository_key, repository_name in var.adopted_repository_names :
      try(var.catalog.repositories[repository_key].name == repository_name, false)
    ])
    error_message = "Every adopted repository binding must exactly match its catalog identifier and repository name."
  }
}

variable "adopted_repository_actions_access_levels" {
  description = "Reviewed existing repository Actions access-level settings keyed by catalog repository identifier."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for repository_key, import_id in var.adopted_repository_actions_access_levels :
      try(var.catalog.repositories[repository_key].name == import_id, false)
    ])
    error_message = "Repository Actions access-level imports must exactly bind catalog repository identifiers to repository names."
  }
}

variable "adopted_ruleset_ids" {
  description = "Reviewed numeric IDs for pre-existing physical organization rulesets."
  type        = map(number)
  default     = {}

  validation {
    condition = alltrue([
      for ruleset_key, ruleset_id in var.adopted_ruleset_ids :
      ruleset_id > 0 && (
        contains(keys(var.catalog.rulesets), ruleset_key) || (
          endswith(ruleset_key, "--creator-gate") &&
          try(
            var.catalog.rulesets[trimsuffix(ruleset_key, "--creator-gate")].target == "tag" &&
            var.catalog.rulesets[trimsuffix(ruleset_key, "--creator-gate")].rules.creation_restricted,
            false,
          )
        )
      )
    ])
    error_message = "Adopted ruleset IDs must be positive and keyed by a catalog or generated creator-gate ruleset identifier."
  }
}

variable "adopted_repository_ruleset_ids" {
  description = "Reviewed repository:numeric-ID import bindings for pre-existing merge-queue rulesets."
  type        = map(string)
  default     = {}
}

variable "adopted_repository_ruleset_enforcements" {
  description = "Reviewed enforcement modes for imported repository merge-queue rulesets."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for enforcement in values(var.adopted_repository_ruleset_enforcements) : contains(["disabled", "active"], enforcement)])
    error_message = "Imported repository ruleset enforcement must be disabled or active."
  }
}

variable "adopted_ruleset_enforcements" {
  description = "Exact live enforcement values paired with adopted organization ruleset IDs."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for ruleset_key, enforcement in var.adopted_ruleset_enforcements :
      contains(["disabled", "evaluate", "active"], enforcement) && (
        contains(keys(var.catalog.rulesets), ruleset_key) || (
          endswith(ruleset_key, "--creator-gate") &&
          try(var.catalog.rulesets[trimsuffix(ruleset_key, "--creator-gate")].target == "tag", false)
        )
      )
    ])
    error_message = "Adopted organization ruleset enforcement values must be exact and catalog-bound."
  }
}

variable "adopted_environment_ids" {
  description = "Reviewed provider import identities for pre-existing repository environment assignments."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for assignment_key, import_id in var.adopted_environment_ids :
      contains(flatten([
        for environment_key, environment in var.catalog.environments : [
          for repository_reference in environment.repositories :
          "${environment_key}:${repository_reference}=${coalesce(
            try(var.catalog.repositories[repository_reference].name, null),
            try(one([
              for repository in values(var.catalog.repositories) : repository.name
              if repository.name == repository_reference
            ]), null),
            repository_reference,
          )}:${replace(environment.name, ":", "??")}"
        ]
      ]), "${assignment_key}=${import_id}")
    ])
    error_message = "Adopted environment identities must exactly bind a catalog assignment key to repository:environment."
  }
}

variable "adopted_environment_policy_ids" {
  description = "Reviewed existing custom environment deployment-policy IDs keyed by assignment:type:pattern."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for policy_key, import_id in var.adopted_environment_policy_ids :
      length(split(":", import_id)) == 3 &&
      try(tonumber(try(split(":", import_id)[2], "")) > 0, false) &&
      contains(flatten([
        for environment_key, environment in var.catalog.environments : flatten([
          for repository_reference in environment.repositories : concat(
            [
              for pattern in try(environment.deployment_branch_policy.branch_patterns, []) :
              "${environment_key}:${repository_reference}:branch:${pattern}=${coalesce(
                try(var.catalog.repositories[repository_reference].name, null),
                try(one([
                  for repository in values(var.catalog.repositories) : repository.name
                  if repository.name == repository_reference
                ]), null),
                repository_reference,
              )}:${environment.name}:${try(split(":", import_id)[2], "")}"
            ],
            [
              for pattern in try(environment.deployment_branch_policy.tag_patterns, []) :
              "${environment_key}:${repository_reference}:tag:${pattern}=${coalesce(
                try(var.catalog.repositories[repository_reference].name, null),
                try(one([
                  for repository in values(var.catalog.repositories) : repository.name
                  if repository.name == repository_reference
                ]), null),
                repository_reference,
              )}:${environment.name}:${try(split(":", import_id)[2], "")}"
            ],
          )
        ])
      ]), "${policy_key}=${import_id}")
    ])
    error_message = "Adopted deployment policies must exactly bind a declared assignment:type:pattern key to repository:environment:numeric-policy-id."
  }
}

variable "adopted_organization_oidc_templates" {
  description = "Reviewed import binding for an existing organization OIDC subject template."
  type        = map(string)
  default     = {}

  validation {
    condition = (
      length(var.adopted_organization_oidc_templates) <= 1 &&
      alltrue([
        for key, import_id in var.adopted_organization_oidc_templates :
        key == "organization" &&
        import_id == coalesce(
          try(var.catalog.organization.organization_login, null),
          try(var.catalog.organization.slug, null),
          "",
        ) &&
        !try(var.catalog.oidc_policy.use_default_subject, true)
      ])
    )
    error_message = "The organization OIDC import must bind the organization key to the exact catalog login and a custom subject policy."
  }
}

variable "adopted_organization_custom_properties" {
  description = "Reviewed existing organization custom-property definitions keyed by catalog property name."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for property_key, import_id in var.adopted_organization_custom_properties :
      property_key == import_id && contains([
        for property in try(var.catalog.organization.custom_properties, []) : coalesce(
          try(property.name, null),
          try(property.property_name, null),
          "",
        )
      ], property_key)
    ])
    error_message = "Organization custom-property imports must be keyed by and equal an exact catalog property name."
  }
}

variable "adopted_repository_oidc_templates" {
  description = "Reviewed existing repository OIDC templates keyed by catalog repository identifier."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for repository_key, import_id in var.adopted_repository_oidc_templates :
      try(var.catalog.repositories[repository_key].name == import_id, false) &&
      !try(var.catalog.oidc_policy.use_default_subject, true)
    ])
    error_message = "Repository OIDC imports must exactly bind catalog repository identifiers to repository names."
  }
}

variable "adopted_repository_custom_properties" {
  description = "Reviewed existing repository custom-property assignments keyed by repository:property."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for property_key, import_id in var.adopted_repository_custom_properties :
      contains(flatten([
        for repository_key, repository in var.catalog.repositories : [
          for property_name in keys(try(repository.custom_properties, {})) :
          "${repository_key}:${property_name}=${coalesce(
            try(var.catalog.organization.organization_login, null),
            try(var.catalog.organization.slug, null),
            "",
          )}:${repository.name}:${property_name}"
        ]
      ]), "${property_key}=${import_id}")
    ])
    error_message = "Repository custom-property imports must exactly bind repository:property keys to organization:repository:property IDs."
  }
}

variable "adopted_memberships" {
  description = "Reviewed existing organization membership IDs keyed by normalized catalog login."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for membership_key, import_id in var.adopted_memberships :
      contains([
        for member in var.catalog.members :
        "${lower(member.login)}=${coalesce(
          try(var.catalog.organization.organization_login, null),
          try(var.catalog.organization.slug, null),
          "",
        )}:${member.login}"
        if try(member.managed, true)
      ], "${membership_key}=${import_id}")
    ])
    error_message = "Membership imports must exactly bind normalized managed logins to organization:login IDs."
  }
}

variable "adopted_team_memberships" {
  description = "Reviewed existing team membership IDs keyed by team:normalized-login."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for membership_key, import_id in var.adopted_team_memberships :
      contains(flatten([
        for team_key, team in var.catalog.teams : [
          for member in try(team.members, []) :
          "${team_key}:${lower(member.login)}=${try(var.adopted_team_ids[team_key], 0)}:${member.login}"
        ]
      ]), "${membership_key}=${import_id}")
    ])
    error_message = "Team membership imports must exactly bind catalog membership keys to observed-team-id:login IDs."
  }
}

variable "adopted_team_repository_grants" {
  description = "Reviewed existing team repository grants keyed by repository:team."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for grant_key, import_id in var.adopted_team_repository_grants :
      contains(flatten([
        for repository_key, repository in var.catalog.repositories : [
          for team_key in distinct(concat(
            keys(try(repository.team_permissions, {})),
            [for grant in try(repository.team_grants, []) : grant.team],
          )) :
          "${repository_key}:${team_key}=${try(var.adopted_team_ids[team_key], 0)}:${repository.name}"
        ]
      ]), "${grant_key}=${import_id}")
    ])
    error_message = "Team repository imports must exactly bind repository:team keys to observed-team-id:repository IDs."
  }
}

variable "adopted_security_manager_assignments" {
  description = "Reviewed existing security-manager organization-role assignment."
  type        = map(string)
  default     = {}

  validation {
    condition = (
      length(var.adopted_security_manager_assignments) <= 1 &&
      alltrue([
        for assignment_key, import_id in var.adopted_security_manager_assignments :
        assignment_key == "security_manager" &&
        length(split(":", import_id)) == 2 &&
        try(tonumber(element(split(":", import_id), 0)) > 0, false) &&
        try(
          element(split(":", import_id), 1) == var.catalog.teams[var.catalog.security_policy.security_manager_team].name,
          false,
        )
      ])
    )
    error_message = "The security-manager import must bind the built-in positive role ID to the exact catalog security team slug."
  }
}

variable "adopted_outside_collaborator_grants" {
  description = "Reviewed existing outside-collaborator grants keyed by normalized-login:repository."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for grant_key, import_id in var.adopted_outside_collaborator_grants :
      contains(flatten([
        for collaborator in var.catalog.outside_collaborators : [
          for grant in collaborator.repository_permissions :
          "${lower(collaborator.login)}:${grant.repository}=${try(var.catalog.repositories[grant.repository].name, "")}:${collaborator.login}"
        ]
      ]), "${grant_key}=${import_id}")
    ])
    error_message = "Outside-collaborator imports must exactly bind normalized-login:repository keys to repository:login IDs."
  }
}

locals {
  organization_login = coalesce(
    try(var.catalog.organization.organization_login, null),
    try(var.catalog.organization.slug, null),
    "",
  )

  repository_team_grants = {
    for repository_key, repository in var.catalog.repositories :
    repository_key => merge(
      try(repository.team_permissions, {}),
      {
        for grant in try(repository.team_grants, []) :
        grant.team => grant.permission
      },
    )
  }

  catalog_activation_ready = length(var.catalog.activation) > 0 && alltrue([
    for activation in values(var.catalog.activation) :
    try(activation.state == "ready" && length(activation.blockers) == 0, false)
  ])

  ruleset_enforcement_ready = alltrue([
    for ruleset in values(module.rulesets.deployment_preflight) :
    (!ruleset.merge_queue.desired || ruleset.merge_queue.managed) &&
    (!ruleset.distinct_principals.desired || ruleset.distinct_principals.managed) &&
    ruleset.status_check_issuers.managed &&
    ruleset.workflow_provenance.managed &&
    ruleset.authorized_creator_integrations.managed &&
    length(ruleset.bypass_actors.unresolved_integrations) == 0
  ])

  organization_enforcement_ready = (
    module.organization_settings.deployment_preflight.organization_settings.managed &&
    (!module.organization_settings.deployment_preflight.two_factor_requirement.desired || module.organization_settings.deployment_preflight.two_factor_requirement.managed) &&
    !module.organization_settings.deployment_preflight.custom_property_migration.enforcement_blocked &&
    module.organization_settings.deployment_preflight.actions_runner_policy.managed &&
    module.organization_settings.deployment_preflight.security_policy.managed &&
    (length(module.organization_settings.deployment_preflight.oidc_audiences.desired) == 0 || module.organization_settings.deployment_preflight.oidc_audiences.managed) &&
    (length(module.organization_settings.deployment_preflight.oidc_subject_allowlist.desired) == 0 || module.organization_settings.deployment_preflight.oidc_subject_allowlist.managed) &&
    (!module.organization_settings.deployment_preflight.oidc_immutable_subject.desired || module.organization_settings.deployment_preflight.oidc_immutable_subject.managed)
  )

  repository_enforcement_ready = (
    module.repository_governance.deployment_preflight.direct_collaborator_absence.managed &&
    (!module.repository_governance.deployment_preflight.oidc_immutable_subject.desired || module.repository_governance.deployment_preflight.oidc_immutable_subject.managed)
  )

  environment_enforcement_ready = alltrue([
    for environment in values(module.repository_environments.deployment_preflight) :
    environment.approval_composition.managed &&
    (environment.distinct_principals.desired <= 1 || environment.distinct_principals.managed) &&
    (!environment.reviewer_separation.desired || environment.reviewer_separation.managed) &&
    (length(environment.allowed_workflows.desired) == 0 || environment.allowed_workflows.managed) &&
    environment.custom_deployment_policies.managed
  ])

  access_enforcement_ready = (
    module.team_access.deployment_preflight.undeclared_access_absence.managed &&
    module.team_access.deployment_preflight.security_manager_assignment.exclusive_reconcile
  )

  mandatory_managed_gaps_clear = (
    local.organization_enforcement_ready &&
    local.repository_enforcement_ready &&
    local.ruleset_enforcement_ready &&
    local.environment_enforcement_ready &&
    local.access_enforcement_ready
  )

  deployment_preflight_status = (
    var.rollout_phase == "adopt" ? "PASS_ADOPTION_DISCOVERY" :
    !local.catalog_activation_ready ? "BLOCKED_PENDING_SOURCE_AND_CONNECTED_QUALIFICATION" :
    var.rollout_phase == "foundation" ? "PASS_WITH_DEPLOYMENT_PREFLIGHT" :
    local.catalog_activation_ready && local.mandatory_managed_gaps_clear ?
    "READY_FOR_ENFORCEMENT" : "BLOCKED_PENDING_SOURCE_AND_CONNECTED_QUALIFICATION"
  )
}

module "organization_settings" {
  source = "../../modules/organization-settings"

  organization    = var.catalog.organization
  actions_policy  = var.catalog.actions_policy
  security_policy = var.catalog.security_policy
  oidc_policy     = var.catalog.oidc_policy
}

module "repository_governance" {
  source = "../../modules/repository-governance"

  repositories                = var.catalog.repositories
  custom_property_types       = module.organization_settings.custom_property_types
  web_commit_signoff_required = var.catalog.organization.web_commit_signoff_required
  oidc_policy                 = var.catalog.oidc_policy
  rollout_phase               = var.rollout_phase

  depends_on = [module.organization_settings]
}

module "team_access" {
  source = "../../modules/team-access"

  organization_login     = local.organization_login
  security_manager_team  = var.catalog.security_policy.security_manager_team
  members                = var.catalog.members
  teams                  = var.catalog.teams
  repository_names       = module.repository_governance.repository_names
  repository_team_grants = local.repository_team_grants
  outside_collaborators  = var.catalog.outside_collaborators
}

module "rulesets" {
  source = "../../modules/ruleset"

  rulesets                                = var.catalog.rulesets
  repository_names                        = module.repository_governance.repository_names
  repository_ids                          = module.repository_governance.repository_ids
  team_ids                                = module.team_access.team_ids
  rollout_phase                           = var.rollout_phase
  adopted_ruleset_enforcements            = var.adopted_ruleset_enforcements
  adopted_repository_ruleset_enforcements = var.adopted_repository_ruleset_enforcements
  qualified_integration_actor_ids         = var.qualified_integration_actor_ids
  qualified_status_check_integration_ids  = var.qualified_status_check_integration_ids

  depends_on = [module.repository_environments]
}

check "adopted_ruleset_bindings_are_paired" {
  assert {
    condition     = toset(keys(var.adopted_ruleset_ids)) == toset(keys(var.adopted_ruleset_enforcements))
    error_message = "Every adopted ruleset ID must have exactly one observed enforcement value and vice versa."
  }
}

module "repository_environments" {
  source = "../../modules/repository-environment"

  environments           = var.catalog.environments
  repository_names       = module.repository_governance.repository_names
  team_ids               = module.team_access.team_ids
  repository_team_grants = local.repository_team_grants
}
