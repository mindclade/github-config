# The provider cannot safely import github_organization_settings because that
# resource requires the deliberately external billing email. The existing
# organization-scoped Actions permissions singleton is the valid org import.
import {
  to = module.organization_settings.github_actions_organization_permissions.this
  id = local.organization_login
}

import {
  to = module.organization_settings.github_actions_organization_workflow_permissions.this
  id = local.organization_login
}

import {
  for_each = var.adopted_organization_oidc_templates

  to = module.organization_settings.github_actions_organization_oidc_subject_claim_customization_template.this[0]
  id = each.value
}

import {
  for_each = var.adopted_organization_custom_properties

  to = module.organization_settings.github_organization_custom_properties.this[each.key]
  id = each.value
}

import {
  for_each = var.adopted_repository_names

  to = module.repository_governance.github_repository.this[each.key]
  id = each.value
}

import {
  for_each = var.adopted_repository_actions_access_levels

  to = module.repository_governance.github_actions_repository_access_level.this[each.key]
  id = each.value
}

import {
  for_each = var.adopted_repository_oidc_templates

  to = module.repository_governance.github_actions_repository_oidc_subject_claim_customization_template.this[each.key]
  id = each.value
}

import {
  for_each = var.adopted_repository_custom_properties

  to = module.repository_governance.github_repository_custom_property.this[each.key]
  id = each.value
}

import {
  for_each = var.adopted_dependabot_security_updates

  to = module.repository_governance.github_repository_dependabot_security_updates.this[each.key]
  id = each.value
}

import {
  for_each = var.adopted_team_ids

  to = module.team_access.github_team.this[each.key]
  id = tostring(each.value)
}

import {
  for_each = var.adopted_memberships

  to = module.team_access.github_membership.this[each.key]
  id = each.value
}

import {
  for_each = var.adopted_team_memberships

  to = module.team_access.github_team_membership.this[each.key]
  id = each.value
}

import {
  for_each = var.adopted_team_repository_grants

  to = module.team_access.github_team_repository.this[each.key]
  id = each.value
}

import {
  for_each = var.adopted_outside_collaborator_grants

  to = module.team_access.github_repository_collaborator.outside[each.key]
  id = each.value
}

import {
  for_each = var.adopted_security_manager_assignments

  to = module.team_access.github_organization_role_team.security_manager
  id = each.value
}

import {
  for_each = var.adopted_ruleset_ids

  to = module.rulesets.github_organization_ruleset.this[each.key]
  id = tostring(each.value)
}

import {
  for_each = var.adopted_repository_ruleset_ids

  to = module.rulesets.github_repository_ruleset.merge_queue[each.key]
  id = each.value
}

import {
  for_each = var.adopted_environment_ids

  to = module.repository_environments.github_repository_environment.this[each.key]
  id = each.value
}

import {
  for_each = var.adopted_environment_policy_ids

  to = module.repository_environments.github_repository_environment_deployment_policy.this[each.key]
  id = each.value
}
