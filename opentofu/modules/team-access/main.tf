terraform {
  required_providers {
    github = {
      source = "integrations/github"
    }
  }
}

locals {
  managed_members = {
    for member in var.members : lower(member.login) => member
    if member.managed
  }

  team_memberships = merge(
    {},
    [
      for team_key, team in var.teams : {
        for member in team.members :
        "${team_key}:${lower(member.login)}" => {
          team_key = team_key
          login    = member.login
          role     = member.role
        }
      }
    ]...
  )

  team_repository_grants = merge(
    {},
    [
      for repository_key, grants in var.repository_team_grants : {
        for team_key, permission in grants :
        "${repository_key}:${team_key}" => {
          repository_key = repository_key
          team_key       = team_key
          permission     = permission
        }
      }
    ]...
  )

  outside_collaborator_grants = merge(
    {},
    [
      for collaborator in var.outside_collaborators : {
        for grant in collaborator.repository_permissions :
        "${lower(collaborator.login)}:${grant.repository}" => {
          login              = collaborator.login
          sponsor            = collaborator.sponsor_login
          approval_reference = collaborator.approval_reference
          justification      = collaborator.justification
          expires_on         = collaborator.expires_on
          repository_key     = grant.repository
          permission         = grant.permission
        }
      }
    ]...
  )
}

data "github_organization_roles" "all" {}

resource "github_membership" "this" {
  for_each = local.managed_members

  username = each.value.login
  role     = coalesce(each.value.organization_role, each.value.role)
}

resource "github_team" "this" {
  for_each = var.teams

  name        = each.value.name
  description = each.value.description
  privacy     = each.value.privacy

  lifecycle {
    # Team notification delivery and Enterprise Server LDAP binding are not
    # catalog controls. Preserve their live values across unrelated updates.
    ignore_changes = [notification_setting, ldap_dn]

    precondition {
      condition     = each.value.parent == null && each.value.parent_team == null
      error_message = "Blueprint governance teams must not inherit access from a parent team."
    }
  }
}

resource "github_organization_role_team" "security_manager" {
  role_id = one([
    for role in data.github_organization_roles.all.roles : role.role_id
    if role.name == "security_manager"
  ])
  team_slug = github_team.this[var.security_manager_team].slug

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = contains(keys(var.teams), var.security_manager_team)
      error_message = "Security-manager assignment references an unknown team."
    }

    precondition {
      condition = length([
        for role in data.github_organization_roles.all.roles : role
        if role.name == "security_manager"
      ]) == 1
      error_message = "GitHub must expose exactly one security_manager organization role."
    }
  }
}

resource "github_team_membership" "this" {
  for_each = local.team_memberships

  team_id  = github_team.this[each.value.team_key].id
  username = each.value.login
  role     = each.value.role

  lifecycle {
    precondition {
      condition     = contains(keys(local.managed_members), lower(each.value.login))
      error_message = "Team members must be managed organization members before team assignment."
    }
  }
}

resource "github_team_repository" "this" {
  for_each = local.team_repository_grants

  team_id    = github_team.this[each.value.team_key].id
  repository = var.repository_names[each.value.repository_key]
  permission = each.value.permission

  lifecycle {
    precondition {
      condition     = contains(keys(var.repository_names), each.value.repository_key)
      error_message = "Team grant references an unknown repository."
    }

    precondition {
      condition     = contains(keys(var.teams), each.value.team_key)
      error_message = "Repository grant references an unknown team."
    }
  }
}

resource "github_repository_collaborator" "outside" {
  for_each = local.outside_collaborator_grants

  repository                  = var.repository_names[each.value.repository_key]
  username                    = each.value.login
  permission                  = each.value.permission
  permission_diff_suppression = false

  lifecycle {
    precondition {
      condition     = contains(keys(var.repository_names), each.value.repository_key)
      error_message = "Outside collaborator grant references an unknown repository."
    }

    precondition {
      condition     = timecmp("${each.value.expires_on}T23:59:59Z", plantimestamp()) > 0
      error_message = "Outside collaborator grant has expired and must not be applied."
    }
  }
}
