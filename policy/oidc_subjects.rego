package github_config.oidc_subjects

import rego.v1

required_claim_keys := {"repo", "context", "workflow_ref", "workflow_sha"}

has_claim_key(key) if {
	input.oidc_policy.spec.include_claim_keys[_] == key
}

is_sha(value) if {
	regex.match("^[0-9a-f]{40}$", value)
}

is_digest(value) if {
	regex.match("^sha256:[0-9a-f]{64}$", value)
}

is_positive_id(value) if {
	is_number(value)
	value > 0
}

attestation_digest(attestation) := sprintf("sha256:%s", [crypto.sha256(json.marshal(attestation))])

audience_matches(subject, audience) if {
	subject.audience != "canonical-provider-resource"
	audience == subject.audience
}

audience_matches(subject, audience) if {
	subject.id == "infrastructure-ci-evidence-verifier"
	subject.audience == "canonical-provider-resource"
	subject.workload_identity_provider_ref == "verifier"
	regex.match("^https://iam\\.googleapis\\.com/projects/[1-9][0-9]*/locations/global/workloadIdentityPools/github-ci-evidence/providers/verifier$", audience)
}

is_bootstrap_qualified(subject, token) if {
	some qualification in input.workflow_qualifications
	attestation := qualification.attestation
	attestation.authority == "bootstrap"
	attestation.subject_id == subject.id
	attestation.organization == "mindclade"
	attestation.repository == subject.repository
	attestation.workflow == subject.workflow
	attestation.workflow_ref == token.workflow_ref
	attestation.workflow_sha == token.workflow_sha
	attestation.context == subject.context
	audience_matches(subject, attestation.audience)
	attestation.workload_identity_provider_ref == subject.workload_identity_provider_ref
	attestation.service_account_ref == subject.service_account_ref
	is_positive_id(attestation.repository_owner_id)
	is_positive_id(attestation.repository_id)
	attestation.repository_owner_id == token.repository_owner_id
	attestation.repository_id == token.repository_id
	immutable_repo := sprintf("mindclade@%d/%s@%d", [attestation.repository_owner_id, subject.repository, attestation.repository_id])
	attestation.immutable_repo == immutable_repo
	token.repo == immutable_repo
	token.repository_owner == "mindclade"
	token.repository == sprintf("mindclade/%s", [subject.repository])
	token.workload_identity_provider_ref == subject.workload_identity_provider_ref
	token.service_account_ref == subject.service_account_ref
	is_digest(qualification.evidence_digest)
	qualification.evidence_digest == attestation_digest(attestation)
	created := time.parse_rfc3339_ns(attestation.created_at)
	expires := time.parse_rfc3339_ns(attestation.expires_at)
	now := time.now_ns()
	created <= now
	now < expires
	created < expires
	expires - created <= 604800000000000
}

subject_matches_token(subject, token) if {
	token.issuer == input.oidc_policy.spec.issuer
	audience_matches(subject, token.audience)
	token.context.type == subject.context.type
	token.context.value == subject.context.value
	startswith(token.workflow_ref, sprintf("mindclade/%s/%s@", [subject.repository, subject.workflow]))
	is_sha(token.workflow_sha)
	is_bootstrap_qualified(subject, token)
}

authorized_token(token) if {
	some subject in input.oidc_policy.spec.subjects
	subject_matches_token(subject, token)
}

deny contains "OIDC issuer must be GitHub Actions" if {
	input.oidc_policy.spec.issuer != "https://token.actions.githubusercontent.com"
}

deny contains "default OIDC subject format must be disabled" if {
	input.oidc_policy.spec.use_default_subject
}

deny contains "immutable OIDC subject format must be enabled" if {
	not input.oidc_policy.spec.use_immutable_subject
}

deny contains sprintf("OIDC subject template omits %q", [claim]) if {
	some claim in required_claim_keys
	not has_claim_key(claim)
}

deny contains sprintf("OIDC subject %q permits a mutable workflow reference", [subject.id]) if {
	some subject in input.oidc_policy.spec.subjects
	not subject.require_immutable_workflow_ref
}

deny contains sprintf("OIDC subject %q uses an unapproved audience", [subject.id]) if {
	some subject in input.oidc_policy.spec.subjects
	not subject.audience in input.oidc_policy.spec.audiences
}

deny contains sprintf("OIDC token %q is not authorized", [token.id]) if {
	some token in input.tokens
	not authorized_token(token)
}

allow if count(deny) == 0
