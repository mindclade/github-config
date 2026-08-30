output "repository_names" {
  description = "Repository names keyed by stable catalog identifier."
  value       = { for key, repository in github_repository.this : key => repository.name }
}

output "repository_ids" {
  description = "Numeric GitHub repository IDs keyed by stable catalog identifier."
  value       = { for key, repository in github_repository.this : key => repository.repo_id }
}

output "repository_node_ids" {
  description = "GraphQL repository node IDs keyed by stable catalog identifier."
  value       = { for key, repository in github_repository.this : key => repository.node_id }
}

output "managed_resource_ids" {
  description = "Non-sensitive repository resource identifiers for evidence."
  value = {
    repositories           = { for key, repository in github_repository.this : key => repository.id }
    custom_properties      = { for key, property in github_repository_custom_property.this : key => property.id }
    dependabot             = { for key, setting in github_repository_dependabot_security_updates.this : key => setting.id }
    actions_access_levels  = { for key, access in github_actions_repository_access_level.this : key => access.id }
    oidc_subject_templates = { for key, template in github_actions_repository_oidc_subject_claim_customization_template.this : key => template.id }
  }
}

output "deployment_preflight" {
  description = "Repository controls that require connected closed-world observation."
  value = {
    direct_collaborator_absence = {
      managed = false
      desired = {
        for key, repository in var.repositories : key => repository.direct_collaborators
      }
      reason = "the provider manages declared collaborator resources but cannot make an empty catalog authoritative; connected observation must reject undeclared direct access"
    }
    actions_access_levels = {
      managed = true
      desired = {
        for key, repository in var.repositories : key => repository.actions_access_level
      }
      reason = "provider 6.13.0 manages each repository's reusable workflow and action sharing boundary"
    }
    oidc_repository_templates = {
      managed = true
      desired = {
        for key, repository in var.repositories : key => {
          repository         = repository.name
          use_default        = false
          include_claim_keys = sort(var.oidc_policy.include_claim_keys)
        }
      }
      reason = "provider 6.13.0 explicitly opts every catalog repository into the reviewed subject claim template"
    }
    oidc_immutable_subject = {
      managed             = false
      enforcement_blocked = var.oidc_policy.use_immutable_subject
      desired             = var.oidc_policy.use_immutable_subject
      reason              = "provider 6.13.0 does not expose the repository API use_immutable_subject field; workflow_sha claim composition alone is not equivalent to immutable repository/owner subject identifiers"
    }
  }
}
