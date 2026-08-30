output "catalog_source_digest" {
  description = "Digest of the exact canonical desired-state catalog used for this graph."
  value       = var.catalog.source_digest
}

output "managed_resource_ids" {
  description = "Non-sensitive identifiers used to correlate plan and apply evidence."
  value = {
    organization = module.organization_settings.managed_resource_ids
    repositories = module.repository_governance.managed_resource_ids
    access       = module.team_access.managed_resource_ids
    rulesets     = module.rulesets.managed_resource_ids
    environments = module.repository_environments.managed_resource_ids
  }
}

output "principal_identities" {
  description = "Alias-aware principal mappings for evidence without credentials or secret values."
  value       = module.team_access.principal_identities
}

output "integration_audit_contracts" {
  description = "Expected GitHub App/OIDC contracts; App creation and installation remain outside this state."
  value       = var.catalog.integrations
}

output "deployment_preflight" {
  description = "Fail-closed controls that must be qualified before connected enforcement."
  value = {
    status                       = local.deployment_preflight_status
    rollout_phase                = var.rollout_phase
    mandatory_managed_gaps_clear = local.mandatory_managed_gaps_clear
    organization                 = module.organization_settings.deployment_preflight
    repositories                 = module.repository_governance.deployment_preflight
    access                       = module.team_access.deployment_preflight
    rulesets                     = module.rulesets.deployment_preflight
    environments                 = module.repository_environments.deployment_preflight
    membership = {
      managed = false
      desired = {
        administrator_accounts = [
          for member in var.catalog.members : member.login
          if coalesce(
            try(member.organization_role, null),
            try(member.role, null),
            "",
          ) == "admin"
        ]
        distinct_administrator_principals = length(toset([
          for member in var.catalog.members : member.principal_id
          if coalesce(
            try(member.organization_role, null),
            try(member.role, null),
            "",
          ) == "admin"
        ]))
      }
      reason = "GitHub authorizes accounts, while independent-human quorum is enforced against principal_id by policy and connected preflight"
    }
    activation_metadata = {
      required_for_phase = var.rollout_phase != "adopt"
      ready              = local.catalog_activation_ready
      catalog            = var.catalog.activation
      security           = try(var.catalog.security_policy.activation, null)
      oidc               = try(var.catalog.oidc_policy.activation, null)
      teams = {
        for key, team in var.catalog.teams : key => try(team.activation, null)
      }
      environments = {
        for key, environment in var.catalog.environments : key => try(environment.activation, null)
      }
      integrations = {
        for key, integration in var.catalog.integrations : key => try(integration.activation, null)
      }
    }
    integrations = {
      managed                    = false
      desired                    = var.catalog.integrations
      qualified_actor_ids        = var.qualified_integration_actor_ids
      qualified_status_check_ids = var.qualified_status_check_integration_ids
      reason                     = "GitHub App installation identity, repository-selection mode, permissions, and events are observed; exact selected-repository scope is bootstrap-attested and digest-bound, while Apps, secrets, and workload-identity trust are never created from this repository"
    }
    state_adoption = {
      organization_oidc_templates      = var.adopted_organization_oidc_templates
      organization_custom_properties   = var.adopted_organization_custom_properties
      repository_names                 = var.adopted_repository_names
      repository_oidc_templates        = var.adopted_repository_oidc_templates
      repository_custom_properties     = var.adopted_repository_custom_properties
      dependabot_security_updates      = var.adopted_dependabot_security_updates
      team_ids                         = var.adopted_team_ids
      memberships                      = var.adopted_memberships
      team_memberships                 = var.adopted_team_memberships
      team_repository_grants           = var.adopted_team_repository_grants
      outside_collaborator_grants      = var.adopted_outside_collaborator_grants
      security_manager_assignments     = var.adopted_security_manager_assignments
      ruleset_ids                      = var.adopted_ruleset_ids
      environment_ids                  = var.adopted_environment_ids
      environment_policy_ids           = var.adopted_environment_policy_ids
      workflow_permissions_imported_by = local.organization_login
      actions_permissions_imported_by  = local.organization_login
      reason                           = "pre-existing resource identities are accepted only as reviewed bindings that match catalog keys and provider import formats; no live IDs are guessed from source"
    }
  }

  precondition {
    condition = (
      var.rollout_phase == "adopt" ||
      (
        local.catalog_activation_ready &&
        (var.rollout_phase != "enforce" || local.mandatory_managed_gaps_clear)
      )
    )
    error_message = "Foundation and enforcement require every catalog activation to be ready; enforcement additionally requires every mandatory provider/connected-control gap to be managed. Inspect deployment_preflight in adopt mode."
  }
}
