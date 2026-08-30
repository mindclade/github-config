output "organization_login" {
  description = "Organization login used by the provider and organization-scoped resources."
  value       = local.organization_login
}

output "custom_property_types" {
  description = "Property types keyed by property name for repository assignments."
  value = {
    for name, property in github_organization_custom_properties.this :
    name => property.value_type
  }
}

output "managed_resource_ids" {
  description = "Non-sensitive organization resource identifiers for evidence."
  value = {
    actions_permissions          = github_actions_organization_permissions.this.id
    workflow_permissions         = github_actions_organization_workflow_permissions.this.id
    oidc_subject_template        = try(github_actions_organization_oidc_subject_claim_customization_template.this[0].id, null)
    organization_custom_property = { for name, property in github_organization_custom_properties.this : name => property.id }
  }
}

output "deployment_preflight" {
  description = "Desired controls that provider 6.13.0 cannot safely materialize without forbidden state inputs or API support."
  value = {
    organization_settings = {
      managed = false
      reason  = "github_organization_settings requires billing_email; billing identity is intentionally excluded from catalog and state"
      desired = {
        default_repository_permission            = var.organization.default_repository_permission
        members_can_create_repositories          = var.organization.members_can_create_repositories
        members_can_create_public_repositories   = var.organization.members_can_create_public_repositories
        members_can_create_private_repositories  = var.organization.members_can_create_private_repositories
        members_can_create_internal_repositories = var.organization.members_can_create_internal_repositories
        members_can_create_pages                 = var.organization.members_can_create_pages
        members_can_fork_private_repositories    = var.organization.members_can_fork_private_repositories
        web_commit_signoff_required              = var.organization.web_commit_signoff_required
      }
    }
    two_factor_requirement = {
      managed = false
      desired = var.organization.two_factor_requirement
      reason  = "provider 6.13.0 does not expose this organization setting as a writable attribute"
    }
    actions_sha_pinning = {
      managed = true
      desired = var.actions_policy.required_pin == "commit_sha"
      reason  = "provider 6.13.0 manages the organization-wide SHA pinning requirement"
    }
    actions_runner_policy = {
      managed             = false
      enforcement_blocked = true
      desired             = var.actions_policy.runner_policy
      reason              = "provider 6.13.0 has no organization setting that disables all self-hosted runners or public-fork workflow execution; enforce remains blocked pending connected runner-inventory and workflow qualification"
    }
    security_policy = {
      managed = false
      desired = {
        dependency_graph_required                = var.security_policy.dependency_graph_required
        dependabot_alerts_required               = var.security_policy.dependabot_alerts_required
        dependabot_security_updates_required     = var.security_policy.dependabot_security_updates_required
        advanced_security_required               = var.security_policy.advanced_security_required
        code_scanning_default_setup_required     = var.security_policy.code_scanning_default_setup_required
        secret_scanning_required                 = var.security_policy.secret_scanning_required
        secret_scanning_push_protection_required = var.security_policy.secret_scanning_push_protection_required
        private_vulnerability_reporting_required = var.security_policy.private_vulnerability_reporting_required
      }
      reason = "the security-manager team is managed; remaining new-repository defaults are coupled to organization settings or absent from provider 6.13.0"
    }
    security_activation = {
      managed               = false
      required_capabilities = var.security_policy.required_capabilities
      desired               = var.security_policy.activation
      reason                = "capability qualification and activation blockers are preflight evidence, not GitHub provider resources"
    }
    oidc_issuer = {
      managed = false
      desired = var.oidc_policy.issuer
      reason  = "the Actions issuer is fixed by GitHub and validated as an immutable input"
    }
    oidc_audiences = {
      managed = false
      desired = var.oidc_policy.audiences
      reason  = "the GitHub organization OIDC customization API managed by provider 6.13.0 exposes claim keys only"
    }
    oidc_subject_allowlist = {
      managed = false
      desired = var.oidc_policy.subjects
      reason  = "subject allowlists belong to cloud trust policy in bootstrap; GitHub exposes only its subject template here"
    }
    oidc_immutable_subject = {
      managed = false
      desired = var.oidc_policy.use_immutable_subject
      reason  = "provider 6.13.0 exposes claim-key composition but no independent immutable-subject control; cloud trust must require the workflow SHA claim"
    }
    oidc_activation = {
      managed = false
      desired = var.oidc_policy.activation
      reason  = "workload-identity and immutable-workflow qualification are external preflight gates"
    }
  }
}
