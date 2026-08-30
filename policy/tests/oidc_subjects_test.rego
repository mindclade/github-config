package github_config.oidc_subjects_test

import rego.v1
import data.github_config.oidc_subjects

policy := {
    "spec": {
        "issuer": "https://token.actions.githubusercontent.com",
        "use_default_subject": false,
        "use_immutable_subject": true,
        "include_claim_keys": ["repo", "context", "workflow_ref", "workflow_sha"],
        "audiences": ["sts.googleapis.com"],
        "subjects": [{
            "id": "github-config-protected-apply",
            "repository": "github-config",
            "workflow": ".github/workflows/protected-apply.yml",
            "context": {"type": "environment", "value": "infrastructure-apply"},
            "audience": "sts.googleapis.com",
            "require_immutable_workflow_ref": true,
            "workload_identity_provider_ref": "github-config-apply",
            "service_account_ref": "github-config-apply",
        }],
    },
}

valid_token := {
    "id": "apply-token",
    "issuer": "https://token.actions.githubusercontent.com",
    "audience": "sts.googleapis.com",
    "repo": "mindclade@101/github-config@202",
    "repository": "mindclade/github-config",
    "repository_owner": "mindclade",
    "repository_owner_id": 101,
    "repository_id": 202,
    "workflow_ref": "mindclade/github-config/.github/workflows/protected-apply.yml@refs/heads/main",
    "workflow_sha": "0123456789abcdef0123456789abcdef01234567",
    "context": {"type": "environment", "value": "infrastructure-apply"},
    "workload_identity_provider_ref": "github-config-apply",
    "service_account_ref": "github-config-apply",
}

valid_attestation := {
    "authority": "bootstrap",
    "subject_id": "github-config-protected-apply",
    "organization": "mindclade",
    "repository": "github-config",
    "repository_owner_id": 101,
    "repository_id": 202,
    "immutable_repo": "mindclade@101/github-config@202",
    "workflow": ".github/workflows/protected-apply.yml",
    "workflow_ref": "mindclade/github-config/.github/workflows/protected-apply.yml@refs/heads/main",
    "workflow_sha": "0123456789abcdef0123456789abcdef01234567",
    "context": {"type": "environment", "value": "infrastructure-apply"},
    "audience": "sts.googleapis.com",
    "workload_identity_provider_ref": "github-config-apply",
    "service_account_ref": "github-config-apply",
    "created_at": "2027-01-01T00:00:00Z",
    "expires_at": "2027-01-02T00:00:00Z",
}

valid_qualification := {
    "attestation": valid_attestation,
    "evidence_digest": sprintf("sha256:%s", [crypto.sha256(json.marshal(valid_attestation))]),
}

test_exact_immutable_subject_allowed if {
    denials := oidc_subjects.deny with input as {
        "oidc_policy": policy,
        "tokens": [valid_token],
        "workflow_qualifications": [valid_qualification],
    } with time.now_ns as 1798804800000000000
    count(denials) == 0
}

test_missing_workflow_sha_claim_denied if {
    weak_policy := {"spec": object.union(policy.spec, {"include_claim_keys": ["repo", "context", "workflow_ref"]})}
    denials := oidc_subjects.deny with input as {"oidc_policy": weak_policy, "tokens": []}
    some message in denials
    contains(message, "workflow_sha")
}

test_wrong_environment_denied if {
    broad_token := object.union(valid_token, {"context": {"type": "environment", "value": "production-promotion"}})
    denials := oidc_subjects.deny with input as {
        "oidc_policy": policy,
        "tokens": [broad_token],
        "workflow_qualifications": [valid_qualification],
    } with time.now_ns as 1798804800000000000
    some message in denials
    contains(message, "not authorized")
}

test_mutable_workflow_identity_denied if {
    mutable_token := object.union(valid_token, {"workflow_sha": "main"})
    denials := oidc_subjects.deny with input as {
        "oidc_policy": policy,
        "tokens": [mutable_token],
        "workflow_qualifications": [valid_qualification],
    } with time.now_ns as 1798804800000000000
    some message in denials
    contains(message, "not authorized")
}

test_unqualified_well_formed_sha_denied if {
    unqualified_token := object.union(valid_token, {"workflow_sha": "89abcdef0123456789abcdef0123456789abcdef"})
    denials := oidc_subjects.deny with input as {
        "oidc_policy": policy,
        "tokens": [unqualified_token],
        "workflow_qualifications": [valid_qualification],
    } with time.now_ns as 1798804800000000000
    some message in denials
    contains(message, "not authorized")
}

test_expired_qualification_denied if {
    expired_attestation := object.union(valid_attestation, {
        "created_at": "2026-12-01T00:00:00Z",
        "expires_at": "2026-12-02T00:00:00Z",
    })
    expired := {
        "attestation": expired_attestation,
        "evidence_digest": sprintf("sha256:%s", [crypto.sha256(json.marshal(expired_attestation))]),
    }
    denials := oidc_subjects.deny with input as {
        "oidc_policy": policy,
        "tokens": [valid_token],
        "workflow_qualifications": [expired],
    } with time.now_ns as 1798804800000000000
    some message in denials
    contains(message, "not authorized")
}

test_legacy_name_only_repo_denied if {
    legacy := object.union(valid_token, {"repo": "mindclade/github-config"})
    denials := oidc_subjects.deny with input as {
        "oidc_policy": policy,
        "tokens": [legacy],
        "workflow_qualifications": [valid_qualification],
    } with time.now_ns as 1798804800000000000
    some message in denials
    contains(message, "not authorized")
}

test_wrong_owner_id_denied if {
    reused_namespace := object.union(valid_token, {
        "repository_owner_id": 999,
        "repo": "mindclade@999/github-config@202",
    })
    denials := oidc_subjects.deny with input as {
        "oidc_policy": policy,
        "tokens": [reused_namespace],
        "workflow_qualifications": [valid_qualification],
    } with time.now_ns as 1798804800000000000
    some message in denials
    contains(message, "not authorized")
}

test_wrong_repository_id_denied if {
    transferred := object.union(valid_token, {
        "repository_id": 999,
        "repo": "mindclade@101/github-config@999",
    })
    denials := oidc_subjects.deny with input as {
        "oidc_policy": policy,
        "tokens": [transferred],
        "workflow_qualifications": [valid_qualification],
    } with time.now_ns as 1798804800000000000
    some message in denials
    contains(message, "not authorized")
}

test_tampered_attestation_denied if {
    tampered := object.union(valid_qualification, {
        "attestation": object.union(valid_attestation, {"repository_id": 999}),
    })
    denials := oidc_subjects.deny with input as {
        "oidc_policy": policy,
        "tokens": [valid_token],
        "workflow_qualifications": [tampered],
    } with time.now_ns as 1798804800000000000
    some message in denials
    contains(message, "not authorized")
}

test_qualification_longer_than_seven_days_denied if {
    long_attestation := object.union(valid_attestation, {"expires_at": "2027-01-09T00:00:00Z"})
    long_qualification := {
        "attestation": long_attestation,
        "evidence_digest": sprintf("sha256:%s", [crypto.sha256(json.marshal(long_attestation))]),
    }
    denials := oidc_subjects.deny with input as {
        "oidc_policy": policy,
        "tokens": [valid_token],
        "workflow_qualifications": [long_qualification],
    } with time.now_ns as 1798804800000000000
    some message in denials
    contains(message, "not authorized")
}
