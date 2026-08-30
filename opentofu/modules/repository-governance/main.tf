terraform {
  required_providers {
    github = {
      source = "integrations/github"
    }
  }
}

locals {
  repositories = var.repositories

  repository_properties = merge(
    {},
    [
      for repository_key, repository in local.repositories : {
        for property_name, property_value in repository.custom_properties :
        "${repository_key}:${property_name}" => {
          repository_key = repository_key
          property_name  = property_name
          property_type  = lookup(var.custom_property_types, property_name, null)
          property_value = can(tolist(property_value)) ? [for value in tolist(property_value) : tostring(value)] : [tostring(property_value)]
        }
      }
    ]...
  )

  dependabot_repositories = local.repositories
}

resource "github_repository" "this" {
  for_each = local.repositories

  name        = each.value.name
  description = each.value.description
  visibility  = each.value.visibility
  archived    = each.value.archived

  archive_on_destroy          = each.value.archive_on_destroy
  delete_branch_on_merge      = each.value.merge_policy.delete_branch_on_merge
  allow_auto_merge            = each.value.merge_policy.allow_auto_merge
  allow_merge_commit          = each.value.merge_policy.allow_merge_commit
  allow_rebase_merge          = each.value.merge_policy.allow_rebase_merge
  allow_squash_merge          = each.value.merge_policy.allow_squash_merge
  allow_update_branch         = each.value.merge_policy.allow_update_branch
  squash_merge_commit_title   = each.value.merge_policy.squash_merge_commit_title
  squash_merge_commit_message = each.value.merge_policy.squash_merge_commit_message

  has_issues      = each.value.features.issues
  has_projects    = each.value.features.projects
  has_wiki        = each.value.features.wiki
  has_discussions = each.value.features.discussions
  has_downloads   = each.value.features.downloads

  vulnerability_alerts        = each.value.security.vulnerability_alerts
  web_commit_signoff_required = var.web_commit_signoff_required

  dynamic "security_and_analysis" {
    for_each = [each.value.security]

    content {
      advanced_security {
        status = security_and_analysis.value.advanced_security ? "enabled" : "disabled"
      }
      secret_scanning {
        status = security_and_analysis.value.secret_scanning ? "enabled" : "disabled"
      }
      secret_scanning_push_protection {
        status = security_and_analysis.value.secret_scanning_push_protection ? "enabled" : "disabled"
      }
    }
  }

  lifecycle {
    prevent_destroy = true

    # These provider attributes are intentionally absent from the catalog and
    # managed projection. Preserve refreshed state across unrelated updates;
    # create-only/template inputs are not enduring repository settings.
    ignore_changes = [
      auto_init,
      default_branch,
      homepage_url,
      is_template,
      license_template,
      gitignore_template,
      pages,
      topics,
      merge_commit_title,
      merge_commit_message,
      template,
    ]

    precondition {
      condition     = length(each.value.direct_collaborators) == 0
      error_message = "Direct collaborators are prohibited; grant repository access through teams."
    }
  }
}

resource "github_repository_dependabot_security_updates" "this" {
  for_each = local.dependabot_repositories

  repository = github_repository.this[each.key].name
  enabled    = each.value.security.dependabot_security_updates
}

resource "github_actions_repository_access_level" "this" {
  for_each = {
    for key, repository in local.repositories : key => repository
    if repository.visibility != "public"
  }

  repository   = github_repository.this[each.key].name
  access_level = each.value.actions_access_level

  lifecycle {
    prevent_destroy = true
  }
}

resource "github_actions_repository_oidc_subject_claim_customization_template" "this" {
  for_each = local.repositories

  repository         = github_repository.this[each.key].name
  use_default        = false
  include_claim_keys = sort(var.oidc_policy.include_claim_keys)

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = var.rollout_phase != "enforce" || !var.oidc_policy.use_immutable_subject
      error_message = "Provider integrations/github 6.13.0 cannot set use_immutable_subject on repository OIDC templates; enforcement is blocked until exact immutable-subject opt-in is provider-managed and observed."
    }
  }
}

resource "github_repository_custom_property" "this" {
  for_each = local.repository_properties

  repository     = github_repository.this[each.value.repository_key].name
  property_name  = each.value.property_name
  property_type  = each.value.property_type
  property_value = each.value.property_value

  lifecycle {
    precondition {
      condition     = each.value.property_type != null
      error_message = "Repository custom property ${each.value.property_name} has no organization-level definition."
    }
  }
}
