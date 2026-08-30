package github_config.least_privilege

import rego.v1

permitted_integration_writes := {
	"buildkite": {"checks", "statuses"},
	"artifact-signing": {"attestations", "contents"},
	"gitops-controller": set(),
}

managed_organization_member_login(login) if {
	some membership in input.memberships
	membership.spec.scope == "organization_members"
	some member in membership.spec.organization_members
	lower(member.login) == lower(login)
}

active_organization_member_principal(login) := principal_id if {
	some membership in input.memberships
	membership.spec.scope == "organization_members"
	some member in membership.spec.organization_members
	lower(member.login) == lower(login)
	object.get(member, "active", true)
	principal_id := member.principal_id
}

deny contains "organization default repository permission must be none" if {
	input.organization.spec.default_repository_permission != "none"
}

deny contains "members must not create repositories" if {
	input.organization.spec.members_can_create_repositories
}

deny contains sprintf("repository %q has a direct collaborator", [repository.spec.name]) if {
	some repository in input.repositories
	count(repository.spec.direct_collaborators) > 0
}

deny contains sprintf("repository %q grants team %q admin", [repository.spec.name, grant.team]) if {
	some repository in input.repositories
	some grant in repository.spec.team_grants
	grant.permission == "admin"
}

deny contains sprintf("repository %q disables vulnerability alerts", [repository.spec.name]) if {
	some repository in input.repositories
	repository.spec.security.vulnerability_alerts == false
}

deny contains sprintf("repository %q disables Dependabot security updates", [repository.spec.name]) if {
	some repository in input.repositories
	repository.spec.security.dependabot_security_updates == false
}

deny contains sprintf("repository %q disables advanced security", [repository.spec.name]) if {
	some repository in input.repositories
	repository.spec.security.advanced_security == false
}

deny contains sprintf("repository %q disables secret scanning", [repository.spec.name]) if {
	some repository in input.repositories
	repository.spec.security.secret_scanning == false
}

deny contains sprintf("repository %q disables secret-scanning push protection", [repository.spec.name]) if {
	some repository in input.repositories
	repository.spec.security.secret_scanning_push_protection == false
}

deny contains sprintf("outside collaborator %q lacks a sponsor", [collaborator.login]) if {
	some membership in input.memberships
	membership.spec.scope == "outside_collaborators"
	some collaborator in membership.spec.outside_collaborators
	not collaborator.sponsor_login
}

deny contains sprintf("outside collaborator %q lacks an expiry", [collaborator.login]) if {
	some membership in input.memberships
	membership.spec.scope == "outside_collaborators"
	some collaborator in membership.spec.outside_collaborators
	not collaborator.expires_on
}

deny contains sprintf("outside collaborator %q cannot sponsor itself", [collaborator.login]) if {
	some membership in input.memberships
	membership.spec.scope == "outside_collaborators"
	some collaborator in membership.spec.outside_collaborators
	lower(collaborator.login) == lower(collaborator.sponsor_login)
}

deny contains sprintf("outside collaborator %q conflicts with a managed organization member login", [collaborator.login]) if {
	some membership in input.memberships
	membership.spec.scope == "outside_collaborators"
	some collaborator in membership.spec.outside_collaborators
	managed_organization_member_login(collaborator.login)
}

deny contains sprintf("outside collaborator %q sponsor %q is not an active managed organization member", [collaborator.login, collaborator.sponsor_login]) if {
	some membership in input.memberships
	membership.spec.scope == "outside_collaborators"
	some collaborator in membership.spec.outside_collaborators
	not active_organization_member_principal(collaborator.sponsor_login)
}

deny contains sprintf("outside collaborator %q and sponsor %q share a principal", [collaborator.login, collaborator.sponsor_login]) if {
	some membership in input.memberships
	membership.spec.scope == "outside_collaborators"
	some collaborator in membership.spec.outside_collaborators
	sponsor_principal := active_organization_member_principal(collaborator.sponsor_login)
	collaborator.principal_id == sponsor_principal
}

deny contains sprintf("integration %q is not externally managed", [integration.metadata.id]) if {
	some integration in input.integrations
	integration.spec.managed
}

deny contains sprintf("integration %q is not repository-scoped", [integration.metadata.id]) if {
	some integration in input.integrations
	integration.spec.repository_selection != "selected"
}

deny contains sprintf("integration %q has unapproved write permission %q", [integration.metadata.id, permission.name]) if {
	some integration in input.integrations
	some permission in integration.spec.permissions
	permission.access == "write"
	allowed := object.get(permitted_integration_writes, integration.metadata.id, set())
	not permission.name in allowed
}

deny contains sprintf("ready integration %q has no qualified actor ID", [integration.metadata.id]) if {
	some integration in input.integrations
	integration.spec.activation.state == "ready"
	not integration.spec.actor_id
}

deny contains sprintf("ready integration %q lacks bootstrap scope qualification", [integration.metadata.id]) if {
	some integration in input.integrations
	integration.spec.activation.state == "ready"
	integration.spec.qualification.state != "qualified"
}

allow if count(deny) == 0
