package github_config.least_privilege_test

import rego.v1
import data.github_config.least_privilege

test_minimum_privilege_catalog_allowed if {
    denials := least_privilege.deny with input as {
        "organization": {"spec": {"default_repository_permission": "none", "members_can_create_repositories": false}},
        "repositories": [{"spec": {"name": "github-config", "direct_collaborators": [], "team_grants": [{"team": "security", "permission": "maintain"}]}}],
        "memberships": [{"spec": {"scope": "outside_collaborators", "outside_collaborators": []}}],
        "integrations": [{
            "metadata": {"id": "buildkite"},
            "spec": {
                "managed": false,
                "repository_selection": "selected",
                "permissions": [{"name": "checks", "access": "write"}],
            },
        }],
    }
    count(denials) == 0
}

test_direct_collaborator_denied if {
    denials := least_privilege.deny with input as {
        "organization": {"spec": {"default_repository_permission": "none", "members_can_create_repositories": false}},
        "repositories": [{"spec": {"name": "github-config", "direct_collaborators": [{"login": "example", "permission": "push"}], "team_grants": []}}],
        "memberships": [],
        "integrations": [],
    }
    some message in denials
    contains(message, "direct collaborator")
}

test_repository_security_weakening_denied if {
    denials := least_privilege.deny with input as {
        "organization": {"spec": {"default_repository_permission": "none", "members_can_create_repositories": false}},
        "repositories": [{"spec": {
            "name": "github-config",
            "direct_collaborators": [],
            "team_grants": [],
            "security": {
                "vulnerability_alerts": true,
                "dependabot_security_updates": false,
                "advanced_security": true,
                "secret_scanning": true,
                "secret_scanning_push_protection": true,
            },
        }}],
        "memberships": [],
        "integrations": [],
    }
    some message in denials
    contains(message, "Dependabot security updates")
}

test_unapproved_app_write_denied if {
    denials := least_privilege.deny with input as {
        "organization": {"spec": {"default_repository_permission": "none", "members_can_create_repositories": false}},
        "repositories": [],
        "memberships": [],
        "integrations": [{
            "metadata": {"id": "gitops-controller"},
            "spec": {
                "managed": false,
                "repository_selection": "selected",
                "permissions": [{"name": "contents", "access": "write"}],
            },
        }],
    }
    some message in denials
    contains(message, "unapproved write permission")
}

test_repository_scoped_signer_contents_write_allowed if {
    denials := least_privilege.deny with input as {
        "organization": {"spec": {"default_repository_permission": "none", "members_can_create_repositories": false}},
        "repositories": [],
        "memberships": [],
        "integrations": [{
            "metadata": {"id": "artifact-signing"},
            "spec": {
                "managed": false,
                "repository_selection": "selected",
                "permissions": [
                    {"name": "attestations", "access": "write"},
                    {"name": "contents", "access": "write"},
                ],
            },
        }],
    }
    count(denials) == 0
}

test_ready_app_without_actor_id_denied if {
    denials := least_privilege.deny with input as {
        "organization": {"spec": {"default_repository_permission": "none", "members_can_create_repositories": false}},
        "repositories": [],
        "memberships": [],
        "integrations": [{
            "metadata": {"id": "artifact-signing"},
            "spec": {
                "managed": false,
                "repository_selection": "selected",
                "permissions": [],
                "qualification": {"state": "blocked", "authority": "bootstrap"},
                "activation": {"state": "ready", "blockers": []},
            },
        }],
    }
    some message in denials
    contains(message, "no qualified actor ID")
}

test_distinct_managed_member_sponsor_allowed if {
    denials := least_privilege.deny with input as {
        "organization": {"spec": {"default_repository_permission": "none", "members_can_create_repositories": false}},
        "repositories": [],
        "memberships": [
            {"spec": {
                "scope": "organization_members",
                "organization_members": [{"login": "security-owner", "principal_id": "employee-security"}],
            }},
            {"spec": {
                "scope": "outside_collaborators",
                "outside_collaborators": [{
                    "login": "external-reviewer",
                    "principal_id": "contractor-reviewer",
                    "sponsor_login": "security-owner",
                    "expires_on": "2026-12-31",
                }],
            }},
        ],
        "integrations": [],
    }
    count(denials) == 0
}

test_self_sponsorship_denied if {
    denials := least_privilege.deny with input as {
        "organization": {"spec": {"default_repository_permission": "none", "members_can_create_repositories": false}},
        "repositories": [],
        "memberships": [{"spec": {
            "scope": "outside_collaborators",
            "outside_collaborators": [{
                "login": "external-reviewer",
                "principal_id": "contractor-reviewer",
                "sponsor_login": "EXTERNAL-REVIEWER",
                "expires_on": "2026-12-31",
            }],
        }}],
        "integrations": [],
    }
    some message in denials
    contains(message, "cannot sponsor itself")
}

test_outside_sponsor_must_be_active_managed_member if {
    denials := least_privilege.deny with input as {
        "organization": {"spec": {"default_repository_permission": "none", "members_can_create_repositories": false}},
        "repositories": [],
        "memberships": [
            {"spec": {
                "scope": "organization_members",
                "organization_members": [{"login": "former-owner", "principal_id": "employee-former", "active": false}],
            }},
            {"spec": {
                "scope": "outside_collaborators",
                "outside_collaborators": [{
                    "login": "external-reviewer",
                    "principal_id": "contractor-reviewer",
                    "sponsor_login": "former-owner",
                    "expires_on": "2026-12-31",
                }],
            }},
        ],
        "integrations": [],
    }
    some message in denials
    contains(message, "not an active managed organization member")
}

test_outside_collaborator_and_sponsor_principals_must_differ if {
    denials := least_privilege.deny with input as {
        "organization": {"spec": {"default_repository_permission": "none", "members_can_create_repositories": false}},
        "repositories": [],
        "memberships": [
            {"spec": {
                "scope": "organization_members",
                "organization_members": [{"login": "security-owner", "principal_id": "same-human"}],
            }},
            {"spec": {
                "scope": "outside_collaborators",
                "outside_collaborators": [{
                    "login": "external-reviewer",
                    "principal_id": "same-human",
                    "sponsor_login": "security-owner",
                    "expires_on": "2026-12-31",
                }],
            }},
        ],
        "integrations": [],
    }
    some message in denials
    contains(message, "share a principal")
}

test_outside_collaborator_login_must_differ_from_member if {
    denials := least_privilege.deny with input as {
        "organization": {"spec": {"default_repository_permission": "none", "members_can_create_repositories": false}},
        "repositories": [],
        "memberships": [
            {"spec": {
                "scope": "organization_members",
                "organization_members": [
                    {"login": "security-owner", "principal_id": "employee-security"},
                    {"login": "duplicate-login", "principal_id": "employee-duplicate"},
                ],
            }},
            {"spec": {
                "scope": "outside_collaborators",
                "outside_collaborators": [{
                    "login": "DUPLICATE-LOGIN",
                    "principal_id": "contractor-reviewer",
                    "sponsor_login": "security-owner",
                    "expires_on": "2026-12-31",
                }],
            }},
        ],
        "integrations": [],
    }
    some message in denials
    contains(message, "conflicts with a managed organization member login")
}
