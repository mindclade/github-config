terraform {
  required_providers {
    github = {
      source = "integrations/github"
    }
  }
}

locals {
  organization_login = var.organization.organization_login

  custom_properties = {
    for property in var.organization.custom_properties :
    property.name => merge(property, {
      allowed_values = sort(distinct(concat(
        property.allowed_values,
        var.organization.custom_property_migration.phase == "preserve" ?
        lookup(var.organization.custom_property_migration.legacy_allowed_values, property.name, []) : [],
      )))
    })
  }

  allowed_action_patterns = [
    for action in var.actions_policy.allowed_actions :
    "${action.source}@${action.commit}"
  ]
}

resource "github_actions_organization_permissions" "this" {
  allowed_actions      = var.actions_policy.mode
  enabled_repositories = var.actions_policy.enabled_repositories
  sha_pinning_required = var.actions_policy.required_pin == "commit_sha"

  dynamic "allowed_actions_config" {
    for_each = var.actions_policy.mode == "selected" ? [var.actions_policy] : []

    content {
      github_owned_allowed = allowed_actions_config.value.github_owned_allowed
      patterns_allowed     = local.allowed_action_patterns
      verified_allowed     = allowed_actions_config.value.verified_creator_allowed
    }
  }

  lifecycle {
    prevent_destroy = true

    precondition {
      condition = (
        var.actions_policy.mode != "selected" ||
        length(local.allowed_action_patterns) > 0
      )
      error_message = "Selected Actions mode requires a non-empty allowlist."
    }
  }
}

resource "github_actions_organization_workflow_permissions" "this" {
  organization_slug                = local.organization_login
  default_workflow_permissions     = var.actions_policy.default_workflow_permissions
  can_approve_pull_request_reviews = var.actions_policy.can_approve_pull_request_reviews

  lifecycle {
    prevent_destroy = true
  }
}

resource "github_actions_organization_oidc_subject_claim_customization_template" "this" {
  count = var.oidc_policy.use_default_subject ? 0 : 1

  include_claim_keys = var.oidc_policy.include_claim_keys

  lifecycle {
    prevent_destroy = true
  }
}

resource "github_organization_custom_properties" "this" {
  for_each = local.custom_properties

  property_name      = each.key
  value_type         = each.value.value_type
  required           = each.value.required
  allowed_values     = each.value.allowed_values
  values_editable_by = each.value.values_editable_by

  lifecycle {
    prevent_destroy = true

    # Descriptions and defaults are intentionally outside the source/live
    # contract. Optional+Computed state is preserved until catalog v1 models it.
    ignore_changes = [description, default_value]
  }
}
