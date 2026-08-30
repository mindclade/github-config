output "team_ids" {
  description = "Numeric GitHub team IDs keyed by stable catalog identifier."
  value       = { for key, team in github_team.this : key => tonumber(team.id) }
}

output "team_slugs" {
  description = "GitHub team slugs keyed by stable catalog identifier."
  value       = { for key, team in github_team.this : key => team.slug }
}

output "managed_resource_ids" {
  description = "Non-sensitive access-control resource identifiers for evidence."
  value = {
    memberships          = { for key, membership in github_membership.this : key => membership.id }
    teams                = { for key, team in github_team.this : key => team.id }
    team_memberships     = { for key, membership in github_team_membership.this : key => membership.id }
    repository_grants    = { for key, grant in github_team_repository.this : key => grant.id }
    outside_collaborator = { for key, grant in github_repository_collaborator.outside : key => grant.id }
    security_manager     = github_organization_role_team.security_manager.id
  }
}

output "principal_identities" {
  description = "Alias-aware, non-secret principal mappings retained for evidence and quorum checks."
  value = {
    organization_members = {
      for member in var.members : lower(member.login) => {
        principal_id = member.principal_id
        account_type = member.account_type
        managed      = member.managed
      }
    }
    outside_collaborators = {
      for collaborator in var.outside_collaborators : lower(collaborator.login) => {
        principal_id = collaborator.principal_id
        sponsor      = collaborator.sponsor_login
        expires_on   = collaborator.expires_on
      }
    }
  }
}

output "deployment_preflight" {
  description = "Access controls that need connected closed-world reconciliation in addition to managed declarations."
  value = {
    unmanaged_members = {
      managed = false
      desired = [
        for member in var.members : member.login
        if !member.managed
      ]
      reason = "managed=false membership records are audit-only and are never silently materialized"
    }
    undeclared_access_absence = {
      managed = false
      desired = {
        organization_members = sort([for member in var.members : lower(member.login) if member.managed])
        team_memberships     = sort(keys(local.team_memberships))
        repository_grants    = sort(keys(local.team_repository_grants))
        outside_grants       = sort(keys(local.outside_collaborator_grants))
      }
      reason = "provider resources reconcile declared grants but do not enumerate and revoke undeclared memberships or access; connected observation is the authoritative absence check"
    }
    security_manager_assignment = {
      managed             = true
      desired_team        = var.security_manager_team
      exclusive_reconcile = false
      reason              = "the declared team receives the built-in role; connected observation must reject any additional security-manager assignees"
    }
  }
}
