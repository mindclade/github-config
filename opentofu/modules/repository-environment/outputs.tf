output "environment_ids" {
  description = "GitHub environment resource IDs keyed by environment/repository assignment."
  value       = { for key, environment in github_repository_environment.this : key => environment.id }
}

output "deployment_preflight" {
  description = "Environment approval and workflow constraints enforced by policy or external trust configuration."
  value = {
    for key, environment in var.environments : key => {
      approval_composition = {
        managed = false
        desired = environment.approval_policy
        reason  = "GitHub manages the declared environment reviewer list, while PR/CODEOWNERS separation and multi-principal composition are enforced by ruleset and preflight policy"
      }
      distinct_principals = {
        managed = false
        desired = environment.approval_policy.minimum_distinct_principals
        reason  = "GitHub environment reviewers are any-of and account-based; independent principal quorum is enforced across PR, CODEOWNERS, and preflight policy"
      }
      reviewer_separation = {
        managed = false
        desired = environment.approval_policy.require_reviewer_different_from_pr_approver
        reason  = "the environment API cannot require its approver to differ from the PR approver"
      }
      allowed_workflows = {
        managed             = false
        enforcement_blocked = length(environment.allowed_workflows) > 0
        desired             = environment.allowed_workflows
        reason              = "provider 6.13.0 cannot materialize an environment workflow allowlist; enforce remains blocked until exact OIDC and bootstrap qualification proves an equivalent workflow/ref/source binding"
      }
      custom_deployment_policies = {
        managed             = true
        enforcement_blocked = false
        desired             = environment.deployment_branch_policy
        reason              = "exact catalog branch and tag patterns are managed as repository environment deployment-policy resources"
      }
      variables = {
        managed = true
        desired = sort(keys(environment.variables))
        reason  = "non-secret connected handoff values are materialized only for a source-qualified ready environment"
      }
    }
  }
}

output "managed_resource_ids" {
  description = "Non-sensitive environment resource identifiers for evidence."
  value = {
    environments        = { for key, environment in github_repository_environment.this : key => environment.id }
    deployment_policies = { for key, policy in github_repository_environment_deployment_policy.this : key => policy.id }
    environment_variables = {
      for key, variable in github_actions_environment_variable.this : key => variable.id
    }
  }
}
