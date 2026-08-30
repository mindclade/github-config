// Package evidence creates deterministic, redacted receipts for reviewed plans.
package evidence

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/mindclade/github-config/compiler/internal/rendering"
	"github.com/mindclade/github-config/compiler/internal/validation"
)

const maxEvidenceInputBytes = 128 << 20

var allowedActionSets = map[string]string{
	"no-op": "no_op", "read": "read", "create": "create", "update": "update",
	"delete": "delete", "forget": "forget", "delete,create": "replace", "create,delete": "replace",
}

var fundamentalClasses = map[string]struct{}{
	"administrative_grant": {}, "actions_policy_expansion": {}, "destructive": {},
	"authority_replacement": {},
	"direct_collaborator":   {}, "environment_bypass": {}, "oidc_mutation": {},
	"protection_weakening": {}, "public_visibility": {}, "replacement": {},
	"security_weakening": {}, "state_forget": {}, "unknown_action": {}, "unknown_change": {},
}

var permissionReductionDeleteTypes = map[string]struct{}{
	"github_membership": {}, "github_team_membership": {}, "github_team_repository": {},
	"github_repository_collaborator": {},
}

var managedWriteTypes = map[string]struct{}{
	"github_actions_environment_variable":                                   {},
	"github_actions_organization_permissions":                               {},
	"github_actions_organization_workflow_permissions":                      {},
	"github_actions_organization_oidc_subject_claim_customization_template": {},
	"github_actions_repository_access_level":                                {},
	"github_actions_repository_oidc_subject_claim_customization_template":   {},
	"github_membership": {}, "github_organization_custom_properties": {},
	"github_organization_role_team": {},
	"github_organization_ruleset":   {}, "github_organization_settings": {},
	"github_repository_ruleset": {},
	"github_repository":         {}, "github_repository_collaborator": {},
	"github_repository_custom_property": {}, "github_repository_environment": {},
	"github_repository_environment_deployment_policy": {}, "github_team": {},
	"github_repository_dependabot_security_updates": {},
	"github_team_membership":                        {}, "github_team_repository": {},
}

// managedWritePaths is the exact provider argument surface assigned by the
// OpenTofu modules. A provider adding another optional field does not silently
// expand governance authority: a known change outside this tree is denied.
// Numeric Terraform collection indices are normalized to "*".
var managedWritePaths = map[string][]string{
	"github_actions_environment_variable": {"/repository", "/environment", "/variable_name", "/value"},
	"github_actions_organization_permissions": {
		"/allowed_actions", "/enabled_repositories", "/sha_pinning_required",
		"/allowed_actions_config", "/allowed_actions_config/*/github_owned_allowed",
		"/allowed_actions_config/*/patterns_allowed", "/allowed_actions_config/*/patterns_allowed/*",
		"/allowed_actions_config/*/verified_allowed",
	},
	"github_actions_organization_workflow_permissions": {
		"/organization_slug", "/default_workflow_permissions", "/can_approve_pull_request_reviews",
	},
	"github_actions_organization_oidc_subject_claim_customization_template": {
		"/include_claim_keys", "/include_claim_keys/*",
	},
	"github_actions_repository_oidc_subject_claim_customization_template": {
		"/repository", "/use_default", "/include_claim_keys", "/include_claim_keys/*",
	},
	"github_actions_repository_access_level": {"/repository", "/access_level"},
	"github_membership":                      {"/username", "/role"},
	"github_organization_custom_properties": {
		"/property_name", "/value_type", "/required", "/allowed_values", "/allowed_values/*", "/values_editable_by",
	},
	"github_organization_role_team": {"/role_id", "/team_slug"},
	"github_organization_ruleset": {
		"/name", "/target", "/enforcement",
		"/bypass_actors", "/bypass_actors/*/actor_type", "/bypass_actors/*/actor_id", "/bypass_actors/*/bypass_mode",
		"/conditions", "/conditions/*/repository_name", "/conditions/*/repository_name/*/include", "/conditions/*/repository_name/*/include/*",
		"/conditions/*/repository_name/*/exclude", "/conditions/*/repository_name/*/exclude/*", "/conditions/*/repository_name/*/protected",
		"/conditions/*/ref_name", "/conditions/*/ref_name/*/include", "/conditions/*/ref_name/*/include/*",
		"/conditions/*/ref_name/*/exclude", "/conditions/*/ref_name/*/exclude/*",
		"/rules", "/rules/*/creation", "/rules/*/update", "/rules/*/deletion", "/rules/*/non_fast_forward",
		"/rules/*/required_linear_history", "/rules/*/required_signatures", "/rules/*/pull_request",
		"/rules/*/pull_request/*/dismiss_stale_reviews_on_push", "/rules/*/pull_request/*/require_code_owner_review",
		"/rules/*/pull_request/*/require_last_push_approval", "/rules/*/pull_request/*/required_approving_review_count",
		"/rules/*/pull_request/*/required_review_thread_resolution", "/rules/*/required_status_checks",
		"/rules/*/required_status_checks/*/strict_required_status_checks_policy",
		"/rules/*/required_status_checks/*/do_not_enforce_on_create",
		"/rules/*/required_status_checks/*/required_check", "/rules/*/required_status_checks/*/required_check/*/context",
		"/rules/*/required_status_checks/*/required_check/*/integration_id",
	},
	// github_organization_settings is intentionally not instantiated: billing
	// identity is outside catalog v1, so its structural write surface is empty.
	"github_organization_settings": {},
	"github_repository": {
		"/name", "/description", "/visibility", "/archived", "/archive_on_destroy",
		"/delete_branch_on_merge", "/allow_auto_merge", "/allow_merge_commit", "/allow_rebase_merge",
		"/allow_squash_merge", "/allow_update_branch", "/squash_merge_commit_title", "/squash_merge_commit_message",
		"/has_issues", "/has_projects", "/has_wiki", "/has_discussions", "/has_downloads",
		"/vulnerability_alerts", "/web_commit_signoff_required", "/security_and_analysis",
		"/security_and_analysis/*/advanced_security", "/security_and_analysis/*/advanced_security/*/status",
		"/security_and_analysis/*/secret_scanning", "/security_and_analysis/*/secret_scanning/*/status",
		"/security_and_analysis/*/secret_scanning_push_protection", "/security_and_analysis/*/secret_scanning_push_protection/*/status",
	},
	"github_repository_collaborator":    {"/repository", "/username", "/permission", "/permission_diff_suppression"},
	"github_repository_custom_property": {"/repository", "/property_name", "/property_type", "/property_value", "/property_value/*"},
	"github_repository_environment": {
		"/environment", "/repository", "/can_admins_bypass", "/prevent_self_review",
		"/reviewers", "/reviewers/*/teams", "/reviewers/*/teams/*", "/reviewers/*/users", "/reviewers/*/users/*",
		"/deployment_branch_policy", "/deployment_branch_policy/*/protected_branches", "/deployment_branch_policy/*/custom_branch_policies",
	},
	"github_repository_environment_deployment_policy": {
		"/repository", "/environment", "/branch_pattern", "/tag_pattern",
	},
	"github_repository_dependabot_security_updates": {"/repository", "/enabled"},
	"github_team":            {"/name", "/description", "/privacy"},
	"github_team_membership": {"/team_id", "/username", "/role"},
	"github_team_repository": {"/team_id", "/repository", "/permission"},
}

// Known provider-computed paths may be null on create only when Terraform's
// parallel after_unknown tree marks that exact path unknown. They are never
// accepted as caller-known mutations.
var knownComputedWritePaths = map[string][]string{
	"github_actions_environment_variable":                                   {"/id", "/created_at", "/updated_at"},
	"github_actions_organization_permissions":                               {"/id"},
	"github_actions_organization_workflow_permissions":                      {"/id"},
	"github_actions_organization_oidc_subject_claim_customization_template": {"/id"},
	"github_actions_repository_oidc_subject_claim_customization_template":   {"/id"},
	"github_actions_repository_access_level":                                {"/id"},
	"github_membership":                                                     {"/id", "/etag"},
	"github_organization_custom_properties":                                 {"/id"},
	"github_organization_role_team":                                         {"/id"},
	"github_organization_ruleset":                                           {"/id", "/etag", "/node_id", "/ruleset_id"},
	"github_repository_ruleset":                                             {"/id", "/etag", "/node_id", "/ruleset_id"},
	"github_repository": {
		"/id", "/etag", "/full_name", "/git_clone_url", "/html_url", "/http_clone_url", "/node_id",
		"/primary_language", "/repo_id", "/ssh_clone_url", "/svn_url",
	},
	"github_repository_collaborator":                  {"/id", "/invitation_id"},
	"github_repository_custom_property":               {"/id", "/repository_id"},
	"github_repository_environment":                   {"/id", "/repository_id"},
	"github_repository_environment_deployment_policy": {"/id", "/repository_id", "/policy_id"},
	"github_repository_dependabot_security_updates":   {"/id"},
	"github_team":            {"/id", "/etag", "/members_count", "/node_id", "/slug", "/parent_team_read_id", "/parent_team_read_slug"},
	"github_team_membership": {"/id", "/etag"},
	"github_team_repository": {"/id", "/etag"},
}

var organizationLoginPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
var lowercaseHexDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var gitSHA40Pattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var changeIDPattern = regexp.MustCompile(`^change-[0-9]{6}$`)
var changeReferencePattern = regexp.MustCompile(`^https://github\.com/mindclade/github-config/pull/[1-9][0-9]*$`)
var kmsKeyVersionPattern = regexp.MustCompile(`^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/us-central1/keyRings/bootstrap-signing/cryptoKeys/github-config-plan-evidence/cryptoKeyVersions/[1-9][0-9]*$`)
var sensitiveFieldPattern = regexp.MustCompile(`(?i)(^|_)(access[_-]?token|authorization|client[_-]?secret|credential|password|private[_-]?key|secret|token)($|_)`)
var terraformStringInstanceKeyPattern = regexp.MustCompile(`\["((?:[^"\\]|\\.)*)"\]$`)

// Build emits a value-free receipt bound to the exact plan, catalog, rollout
// phase, and caller-provided workflow identity fields.
func Build(
	planJSONPath, planFilePath, catalogPath, observedPath, phase string,
	riskAcknowledged, destructiveAcknowledged bool,
	dependencyAnalysisPath string,
	policyInput map[string]any,
	expectedCatalogDigest string,
	identity map[string]string,
) (map[string]any, error) {
	if phase != "adopt" && phase != "foundation" && phase != "enforce" {
		return nil, errors.New("evidence phase must be adopt, foundation, or enforce")
	}
	planBytes, err := readRegularFile(planJSONPath)
	if err != nil {
		return nil, fmt.Errorf("read plan JSON: %w", err)
	}
	var plan map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(planBytes)))
	decoder.UseNumber()
	if err := decoder.Decode(&plan); err != nil {
		return nil, fmt.Errorf("decode plan JSON: %w", err)
	}
	canonicalPlan, err := rendering.CanonicalJSON(planDigestProjection(plan))
	if err != nil {
		return nil, fmt.Errorf("canonicalize plan JSON: %w", err)
	}
	digests := map[string]any{"plan_json": rendering.Digest(canonicalPlan)}
	workflowSources, ok := policyInput["workflows"].([]any)
	if !ok {
		return nil, errors.New("validated policy input omits workflow sources")
	}
	canonicalWorkflows, err := rendering.CanonicalJSON(workflowSources)
	if err != nil {
		return nil, fmt.Errorf("canonicalize workflow sources: %w", err)
	}
	digests["workflow_sources"] = rendering.Digest(canonicalWorkflows)
	if planFilePath != "" {
		planFileBytes, err := readRegularFile(planFilePath)
		if err != nil {
			return nil, fmt.Errorf("read binary plan: %w", err)
		}
		digests["plan_file"] = rendering.Digest(planFileBytes)
	}
	validatedIdentity, err := validateIdentity(identity)
	if err != nil {
		return nil, err
	}
	catalogSourceDigest := ""
	var catalogForClassification map[string]any
	var observedForClassification map[string]any
	organization := identity["organization"]
	if catalogPath != "" {
		catalogBytes, err := readRegularFile(catalogPath)
		if err != nil {
			return nil, fmt.Errorf("read catalog: %w", err)
		}
		var catalog map[string]any
		if err := json.Unmarshal(catalogBytes, &catalog); err != nil {
			return nil, fmt.Errorf("decode catalog: %w", err)
		}
		catalogForClassification = catalog
		canonicalCatalog, err := rendering.CanonicalJSON(catalog)
		if err != nil {
			return nil, err
		}
		catalogDigest := rendering.Digest(canonicalCatalog)
		if expectedCatalogDigest == "" || catalogDigest != expectedCatalogDigest {
			return nil, errors.New("evidence catalog does not exactly match the validated catalog compiled from --root")
		}
		digests["catalog"] = catalogDigest
		catalogSourceDigest, _ = catalog["source_digest"].(string)
		configuredOrganization, _ := catalog["organization"].(map[string]any)
		configuredLogin, _ := configuredOrganization["organization_login"].(string)
		if organization == "" {
			organization = configuredLogin
		} else if configuredLogin != "" && !strings.EqualFold(organization, configuredLogin) {
			return nil, fmt.Errorf("evidence organization %q does not match catalog organization %q", organization, configuredLogin)
		}
	}
	if observedPath != "" {
		observedBytes, err := readRegularFile(observedPath)
		if err != nil {
			return nil, fmt.Errorf("read observed state: %w", err)
		}
		var observed map[string]any
		decoder := json.NewDecoder(strings.NewReader(string(observedBytes)))
		decoder.UseNumber()
		if err := decoder.Decode(&observed); err != nil {
			return nil, fmt.Errorf("decode observed state: %w", err)
		}
		observedForClassification = observed
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			if err == nil {
				return nil, errors.New("observed state contains multiple JSON values")
			}
			return nil, fmt.Errorf("decode trailing observed state: %w", err)
		}
		coreComplete, _ := observed["core_observation_complete"].(bool)
		if !coreComplete {
			return nil, errors.New("observed state is not a complete authoritative core inventory")
		}
		observedOrganization, _ := observed["organization"].(map[string]any)
		observedLogin, _ := observedOrganization["login"].(string)
		if !organizationLoginPattern.MatchString(observedLogin) {
			return nil, errors.New("observed state omits a valid organization login")
		}
		if organization == "" {
			organization = observedLogin
		} else if !strings.EqualFold(organization, observedLogin) {
			return nil, fmt.Errorf("evidence organization %q does not match observed organization %q", organization, observedLogin)
		}
		organizationID, ok := positiveJSONInteger(observedOrganization["id"])
		if !ok {
			return nil, errors.New("observed state omits a positive immutable organization id")
		}
		validatedIdentity["organization_id"] = organizationID
		canonicalObserved, err := rendering.CanonicalJSON(observed)
		if err != nil {
			return nil, fmt.Errorf("canonicalize observed state: %w", err)
		}
		digests["observed_state"] = rendering.Digest(canonicalObserved)
	}
	protected := identity["plan_app_id"] != "" || identity["apply_app_id"] != ""
	if protected {
		if _, bound := validatedIdentity["organization_id"]; !bound {
			return nil, errors.New("protected evidence requires --observed with a complete immutable organization identity")
		}
		if catalogPath == "" || expectedCatalogDigest == "" {
			return nil, errors.New("protected evidence requires --catalog bound to the compiler-authoritative catalog")
		}
		if planFilePath == "" {
			return nil, errors.New("protected evidence requires --plan-file bound to the reviewed binary plan")
		}
		for _, key := range []string{"run_id", "run_attempt", "created_epoch", "expires_epoch"} {
			if _, ok := positiveJSONInteger(validatedIdentity[key]); !ok {
				return nil, fmt.Errorf("protected evidence requires a valid %s binding", key)
			}
		}
		for _, key := range []string{"catalog", "plan_file", "observed_state", "workflow_sources"} {
			if digest, exists := digests[key].(string); !exists || !validSHA256Digest(digest) {
				return nil, fmt.Errorf("protected evidence requires a valid %s digest", key)
			}
		}
	}
	summary, writes, highRisk, destructive, replacements, sensitive := summarizePlan(plan, catalogForClassification, observedForClassification, policyInput, phase)
	createdEpoch, _ := positiveJSONInteger(validatedIdentity["created_epoch"])
	founderPublicBootstrap := protected && phase == "foundation" && allowsFounderPublicBootstrap(catalogForClassification, createdEpoch)
	if founderPublicBootstrap {
		for _, rawChange := range highRisk {
			change, _ := rawChange.(map[string]any)
			if onlyFounderPublicFundamental(stringSlice(change["classes"])) {
				change["write_class"] = "high_risk"
			}
		}
	}
	destructiveIDs := stringSlice(destructive)
	dependencyAnalysisVerified := false
	if dependencyAnalysisPath != "" {
		analysisDigest, analysisErr := validateDependencyAnalysis(
			dependencyAnalysisPath, fmt.Sprint(digests["plan_json"]),
			identity["change_reference"], destructiveIDs,
		)
		if analysisErr != nil {
			return nil, analysisErr
		}
		digests["dependency_analysis"] = analysisDigest
		dependencyAnalysisVerified = true
	}
	fundamental := false
	privilegeExpansion := false
	for _, rawChange := range highRisk {
		change, _ := rawChange.(map[string]any)
		for _, class := range stringSlice(change["classes"]) {
			if _, denied := fundamentalClasses[class]; denied && !(founderPublicBootstrap && class == "public_visibility") {
				fundamental = true
			}
			if class == "privilege_expansion" {
				privilegeExpansion = true
			}
		}
	}
	blockers := make([]any, 0)
	if fundamental {
		blockers = append(blockers, "plan contains a fundamentally prohibited governance change")
	}
	if phase == "adopt" && len(writes) > 0 {
		blockers = append(blockers, "adopt phase permits read/no-op discovery only")
	}
	if privilegeExpansion && !riskAcknowledged {
		blockers = append(blockers, "privilege expansion requires explicit protected-workflow risk acknowledgement")
	}
	requiresDestructiveReview := len(destructiveIDs) > 0
	if requiresDestructiveReview && !destructiveAcknowledged {
		blockers = append(blockers, "removals require explicit protected-workflow destructive-change acknowledgement")
	}
	if requiresDestructiveReview && !dependencyAnalysisVerified {
		blockers = append(blockers, "removals require exact-plan-bound dependency-analysis evidence")
	}
	if !requiresDestructiveReview && (destructiveAcknowledged || dependencyAnalysisVerified) {
		blockers = append(blockers, "destructive-change acknowledgement and dependency analysis are valid only for a plan containing removals")
	}
	bindings := map[string]any{"organization": organization, "phase": phase, "plan_json": digests["plan_json"]}
	for _, key := range []string{"plan_file", "catalog", "observed_state", "workflow_sources", "dependency_analysis"} {
		if digest, exists := digests[key]; exists {
			bindings[key] = digest
		}
	}
	if catalogSourceDigest != "" {
		bindings["catalog_source"] = catalogSourceDigest
	}
	for key, value := range validatedIdentity {
		if key != "organization" {
			bindings[key] = value
		}
	}
	result := map[string]any{
		"api_version": validation.APIVersion, "kind": "PlanEvidence", "phase": phase,
		"digests": digests, "bindings": bindings,
		"plan": map[string]any{
			"format_version": stringField(plan, "format_version"), "terraform_version": stringField(plan, "terraform_version"),
			"digest_projection":       "terraform-plan-json/v1",
			"resource_change_summary": summary, "writes": writes, "high_risk_changes": highRisk,
			"destructive_change_ids": destructive, "replacement_change_ids": replacements,
			"sensitive_change_count": sensitive,
		},
		"decision": map[string]any{
			"eligible_for_protected_apply": len(blockers) == 0, "risk_acknowledged": riskAcknowledged,
			"founder_bootstrap":             founderBootstrapEvidenceProjection(founderPublicBootstrap),
			"requires_risk_acknowledgement": privilegeExpansion, "blockers": blockers,
			"destructive_change_acknowledged":             destructiveAcknowledged,
			"requires_destructive_change_acknowledgement": requiresDestructiveReview,
			"dependency_analysis_verified":                dependencyAnalysisVerified,
		},
	}
	if catalogSourceDigest != "" {
		result["catalog_source_digest"] = catalogSourceDigest
	}
	canonical, err := rendering.CanonicalJSON(result)
	if err != nil {
		return nil, err
	}
	result["evidence_digest"] = rendering.Digest(canonical)
	return result, nil
}

func onlyFounderPublicFundamental(classes []string) bool {
	publicVisibility := false
	for _, class := range classes {
		if class == "public_visibility" {
			publicVisibility = true
			continue
		}
		if _, denied := fundamentalClasses[class]; denied {
			return false
		}
	}
	return publicVisibility
}

func founderBootstrapEvidenceProjection(applicable bool) map[string]any {
	if !applicable {
		return map[string]any{"applicable": false}
	}
	return map[string]any{
		"applicable":                true,
		"exception_id":              "FBE-0001",
		"scope":                     "founder-bootstrap-only",
		"workflow_ref":              "mindclade/github-config/.github/workflows/protected-apply.yml@refs/heads/main",
		"allowed_operations":        []any{"foundation-plan", "foundation-apply", "foundation-verification"},
		"denied_operations":         []any{"adoption", "enforcement", "production-authority", "exception-replay"},
		"authorized_operation":      "foundation-apply",
		"single_use_initial_state":  "UNUSED",
		"single_use_terminal_state": "CONSUMED",
		"receipt_required":          true,
		"receipt_digest_algorithm":  "sha256",
		"independent_principals":    false,
		"production_authority":      false,
	}
}

func allowsFounderPublicBootstrap(catalog map[string]any, createdEpoch int64) bool {
	const exceptionExpiryEpoch int64 = 1790812799
	if createdEpoch <= 0 || createdEpoch > exceptionExpiryEpoch {
		return false
	}
	organization, _ := catalog["organization"].(map[string]any)
	exception, _ := organization["founder_bootstrap_exception"].(map[string]any)
	independent, independentKnown := exception["independent_principals"].(bool)
	production, productionKnown := exception["production_authority"].(bool)
	minimumAccounts, minimumKnown := positiveJSONInteger(exception["minimum_distinct_actor_accounts"])
	accounts := stringSlice(exception["github_actor_accounts"])
	if fmt.Sprint(organization["estate_profile"]) != "github-free-public" ||
		fmt.Sprint(exception["id"]) != "FBE-0001" || fmt.Sprint(exception["state"]) != "UNUSED" ||
		fmt.Sprint(exception["scope"]) != "founder-bootstrap-only" ||
		fmt.Sprint(exception["workflow_ref"]) != "mindclade/github-config/.github/workflows/protected-apply.yml@refs/heads/main" ||
		!sameExactStrings(stringSlice(exception["allowed_operations"]), []string{"foundation-plan", "foundation-apply", "foundation-verification"}) ||
		!sameExactStrings(stringSlice(exception["denied_operations"]), []string{"adoption", "enforcement", "production-authority", "exception-replay"}) ||
		fmt.Sprint(exception["single_use_initial_state"]) != "UNUSED" || fmt.Sprint(exception["single_use_terminal_state"]) != "CONSUMED" ||
		exception["receipt_required"] != true || fmt.Sprint(exception["receipt_digest_algorithm"]) != "sha256" ||
		fmt.Sprint(exception["principal_id"]) != "founder-primary" ||
		fmt.Sprint(exception["expires_at"]) != "2026-09-30T23:59:59Z" ||
		!independentKnown || independent || !productionKnown || production ||
		!minimumKnown || minimumAccounts != 2 || len(accounts) != 2 ||
		accounts[0] != "mindclade-founder" || accounts[1] != "robpearc" {
		return false
	}
	expectedRepositories := map[string]struct{}{
		"bootstrap": {}, "dot-github": {}, "github-config": {},
		"gitops": {}, "infrastructure-live": {}, "mindclade": {},
	}
	repositories, _ := catalog["repositories"].(map[string]any)
	if len(repositories) != len(expectedRepositories) {
		return false
	}
	for id := range expectedRepositories {
		repository, exists := repositories[id].(map[string]any)
		properties, _ := repository["custom_properties"].(map[string]any)
		if !exists || fmt.Sprint(repository["visibility"]) != "public" || fmt.Sprint(properties["data_classification"]) != "public" ||
			fmt.Sprint(properties["production_authority"]) != "none" {
			return false
		}
	}
	desiredAccounts := map[string]bool{"mindclade-founder": false, "robpearc": false}
	members, _ := catalog["members"].([]any)
	for _, rawMember := range members {
		member, _ := rawMember.(map[string]any)
		login := strings.ToLower(fmt.Sprint(member["login"]))
		if _, expected := desiredAccounts[login]; expected && fmt.Sprint(member["role"]) == "admin" &&
			fmt.Sprint(member["principal_id"]) == "founder-primary" {
			desiredAccounts[login] = true
		}
	}
	return desiredAccounts["mindclade-founder"] && desiredAccounts["robpearc"]
}

func sameExactStrings(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func planDigestProjection(plan map[string]any) map[string]any {
	result := make(map[string]any, 4)
	for _, key := range []string{"format_version", "terraform_version", "resource_changes", "output_changes"} {
		if value, exists := plan[key]; exists {
			result[key] = value
		}
	}
	return result
}

// Verify checks the self-authenticating digest on a previously written
// evidence document. It does not trust or rewrite any embedded field.
func Verify(path string) (map[string]any, error) {
	data, err := readRegularFile(path)
	if err != nil {
		return nil, fmt.Errorf("read evidence: %w", err)
	}
	return verifyEvidenceBytes(data)
}

// verifyEvidenceBytes performs structural and self-digest verification over
// one immutable byte slice. Authenticated verification deliberately shares
// this helper so a pathname cannot be swapped between digest and signature
// verification.
func verifyEvidenceBytes(data []byte) (map[string]any, error) {
	var document map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode evidence: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("evidence contains multiple JSON values")
		}
		return nil, fmt.Errorf("decode trailing evidence: %w", err)
	}
	expected, _ := document["evidence_digest"].(string)
	if !validSHA256Digest(expected) {
		return nil, errors.New("evidence_digest is missing or malformed")
	}
	delete(document, "evidence_digest")
	canonical, err := rendering.CanonicalJSON(document)
	if err != nil {
		return nil, err
	}
	actual := rendering.Digest(canonical)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) != 1 {
		return nil, errors.New("evidence digest verification failed")
	}
	if err := validateProtectedEvidenceDocument(document); err != nil {
		return nil, err
	}
	return map[string]any{
		"api_version":     validation.APIVersion,
		"kind":            "EvidenceVerification",
		"status":          "valid",
		"evidence_digest": expected,
	}, nil
}

// AuthenticationOptions binds protected evidence to one bootstrap-owned GCP
// KMS asymmetric key version and the exact reviewed workflow context. The
// public key is verified offline; no mutable network response participates in
// the apply decision.
type AuthenticationOptions struct {
	SignaturePath, PublicKeyPath, PublicKeyDigest string
	KMSKeyVersion, SignatureAlgorithm             string
	ExpectedBindings                              map[string]string
	AtEpoch                                       int64
	RequireEligible                               bool
}

// VerifyAuthenticated first verifies the evidence's canonical self-digest,
// then verifies a detached KMS signature over the exact on-disk bytes and all
// caller-required issuer/revision/review/freshness bindings.
func VerifyAuthenticated(path string, options AuthenticationOptions) (map[string]any, error) {
	if options.SignatureAlgorithm != "EC_SIGN_P256_SHA256" {
		return nil, errors.New("authenticated evidence requires EC_SIGN_P256_SHA256")
	}
	if !kmsKeyVersionPattern.MatchString(options.KMSKeyVersion) {
		return nil, errors.New("authenticated evidence requires the exact bootstrap-signing/github-config-plan-evidence GCP KMS cryptoKeyVersion resource")
	}
	if !validSHA256Digest(options.PublicKeyDigest) {
		return nil, errors.New("authenticated evidence requires a valid public-key digest")
	}
	evidenceBytes, err := readRegularFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authenticated evidence: %w", err)
	}
	verification, err := verifyEvidenceBytes(evidenceBytes)
	if err != nil {
		return nil, err
	}
	signature, err := readRegularFile(options.SignaturePath)
	if err != nil {
		return nil, fmt.Errorf("read evidence signature: %w", err)
	}
	if len(signature) < 8 || len(signature) > 256 {
		return nil, errors.New("evidence signature has an invalid length")
	}
	publicPEM, err := readRegularFile(options.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read evidence public key: %w", err)
	}
	if len(publicPEM) > 16*1024 {
		return nil, errors.New("evidence public key exceeds 16 KiB")
	}
	publicDigest := sha256.Sum256(publicPEM)
	actualPublicDigest := "sha256:" + hex.EncodeToString(publicDigest[:])
	if subtle.ConstantTimeCompare([]byte(options.PublicKeyDigest), []byte(actualPublicDigest)) != 1 {
		return nil, errors.New("evidence public-key digest verification failed")
	}
	block, trailing := pem.Decode(publicPEM)
	if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(trailing))) != 0 {
		return nil, errors.New("evidence public key must contain exactly one PKIX PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse evidence public key: %w", err)
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve.Params().Name != "P-256" {
		return nil, errors.New("evidence public key must be an ECDSA P-256 key")
	}
	digest := sha256.Sum256(evidenceBytes)
	if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		return nil, errors.New("evidence KMS signature verification failed")
	}

	var document map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(evidenceBytes)))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode authenticated evidence: %w", err)
	}
	bindings, _ := document["bindings"].(map[string]any)
	for key, expected := range options.ExpectedBindings {
		if expected == "" || fmt.Sprint(bindings[key]) != expected {
			return nil, fmt.Errorf("authenticated evidence %s binding does not match the required value", key)
		}
	}
	if bindings["oidc_issuer"] != "https://token.actions.githubusercontent.com" {
		return nil, errors.New("authenticated evidence has an invalid OIDC issuer binding")
	}
	created, createdKnown := positiveJSONInteger(bindings["created_epoch"])
	expires, expiresKnown := positiveJSONInteger(bindings["expires_epoch"])
	if options.AtEpoch <= 0 || !createdKnown || !expiresKnown || created > options.AtEpoch || options.AtEpoch >= expires {
		return nil, errors.New("authenticated evidence is outside its bound execution window")
	}
	decision, _ := document["decision"].(map[string]any)
	eligible, _ := decision["eligible_for_protected_apply"].(bool)
	if options.RequireEligible && !eligible {
		return nil, errors.New("authenticated evidence is not eligible for protected apply")
	}
	verification["authentication"] = map[string]any{
		"type": "gcp-kms-asymmetric-signature", "kms_key_version": options.KMSKeyVersion,
		"algorithm": options.SignatureAlgorithm, "public_key_digest": actualPublicDigest,
	}
	return verification, nil
}

func validateProtectedEvidenceDocument(document map[string]any) error {
	if err := validateDestructiveReviewEvidence(document); err != nil {
		return err
	}
	bindings, _ := document["bindings"].(map[string]any)
	planAppID, hasPlanApp := positiveJSONInteger(bindings["plan_app_id"])
	applyAppID, hasApplyApp := positiveJSONInteger(bindings["apply_app_id"])
	if !hasPlanApp && !hasApplyApp {
		return nil
	}
	if !hasPlanApp || !hasApplyApp || planAppID == applyAppID {
		return errors.New("protected evidence has missing, malformed, or non-distinct GitHub App bindings")
	}
	if document["api_version"] != validation.APIVersion || document["kind"] != "PlanEvidence" {
		return errors.New("protected evidence has an invalid document identity")
	}
	phase, phaseKnown := document["phase"].(string)
	if !phaseKnown || (phase != "adopt" && phase != "foundation" && phase != "enforce") || bindings["phase"] != phase {
		return errors.New("protected evidence has an invalid phase binding")
	}
	digests, digestsKnown := document["digests"].(map[string]any)
	if !digestsKnown {
		return errors.New("protected evidence omits its digest set")
	}
	for _, key := range []string{"plan_json", "plan_file", "catalog", "observed_state", "workflow_sources"} {
		digest, digestKnown := digests[key].(string)
		binding, bindingKnown := bindings[key].(string)
		if !digestKnown || !bindingKnown || !validSHA256Digest(digest) || binding != digest {
			return fmt.Errorf("protected evidence has an invalid %s digest binding", key)
		}
	}
	catalogSource, catalogSourceKnown := document["catalog_source_digest"].(string)
	boundCatalogSource, boundCatalogSourceKnown := bindings["catalog_source"].(string)
	if !catalogSourceKnown || !boundCatalogSourceKnown || !validSHA256Digest(catalogSource) || boundCatalogSource != catalogSource {
		return errors.New("protected evidence has an invalid catalog source binding")
	}
	organization, organizationKnown := bindings["organization"].(string)
	if !organizationKnown || !organizationLoginPattern.MatchString(organization) {
		return errors.New("protected evidence has an invalid organization binding")
	}
	if _, ok := positiveJSONInteger(bindings["organization_id"]); !ok {
		return errors.New("protected evidence omits an immutable organization id")
	}
	for _, key := range []string{"actor_id", "run_id", "run_attempt"} {
		if _, ok := positiveJSONInteger(bindings[key]); !ok {
			return fmt.Errorf("protected evidence has an invalid %s binding", key)
		}
	}
	created, createdKnown := positiveJSONInteger(bindings["created_epoch"])
	expires, expiresKnown := positiveJSONInteger(bindings["expires_epoch"])
	if !createdKnown || !expiresKnown || expires <= created || expires-created > 6*60*60 {
		return errors.New("protected evidence has an invalid execution window binding")
	}
	for _, key := range []string{"source_sha", "workflow_sha"} {
		value, ok := bindings[key].(string)
		if !ok || !gitSHA40Pattern.MatchString(value) {
			return fmt.Errorf("protected evidence has an invalid %s binding", key)
		}
	}
	for _, key := range []string{"change_reference", "workflow_ref", "oidc_issuer"} {
		value, ok := bindings[key].(string)
		if !ok || strings.TrimSpace(value) == "" || len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("protected evidence has an invalid %s binding", key)
		}
	}
	if bindings["oidc_issuer"] != "https://token.actions.githubusercontent.com" {
		return errors.New("protected evidence has an invalid oidc_issuer binding")
	}
	if changeReference, _ := bindings["change_reference"].(string); !changeReferencePattern.MatchString(changeReference) {
		return errors.New("protected evidence change_reference must be a canonical github-config pull request URL")
	}
	for _, key := range []string{"wif_qualification_evidence_digest", "state_backend_digest", "executor_contract_digest", "review_context_digest"} {
		value, ok := bindings[key].(string)
		if !ok || !validSHA256Digest(value) {
			return fmt.Errorf("protected evidence has an invalid %s binding", key)
		}
	}
	decision, decisionKnown := document["decision"].(map[string]any)
	if !decisionKnown {
		return errors.New("protected evidence omits its decision")
	}
	if _, ok := decision["eligible_for_protected_apply"].(bool); !ok {
		return errors.New("protected evidence has a malformed eligibility decision")
	}
	if err := validateFounderBootstrapEvidenceProjection(document, decision); err != nil {
		return err
	}
	return nil
}

func validateFounderBootstrapEvidenceProjection(document, decision map[string]any) error {
	projection, ok := decision["founder_bootstrap"].(map[string]any)
	if !ok {
		return errors.New("evidence omits the founder-bootstrap projection")
	}
	applicable, applicableKnown := projection["applicable"].(bool)
	if !applicableKnown {
		return errors.New("evidence has a malformed founder-bootstrap applicability decision")
	}
	if !applicable {
		if len(projection) != 1 {
			return errors.New("non-applicable founder-bootstrap evidence leaks exception authority")
		}
		return nil
	}
	bindings, _ := document["bindings"].(map[string]any)
	independent, independentKnown := projection["independent_principals"].(bool)
	production, productionKnown := projection["production_authority"].(bool)
	receiptRequired, receiptKnown := projection["receipt_required"].(bool)
	if fmt.Sprint(document["phase"]) != "foundation" ||
		fmt.Sprint(bindings["workflow_ref"]) != "mindclade/github-config/.github/workflows/protected-apply.yml@refs/heads/main" ||
		fmt.Sprint(projection["exception_id"]) != "FBE-0001" ||
		fmt.Sprint(projection["scope"]) != "founder-bootstrap-only" ||
		fmt.Sprint(projection["workflow_ref"]) != "mindclade/github-config/.github/workflows/protected-apply.yml@refs/heads/main" ||
		!sameExactStrings(stringSlice(projection["allowed_operations"]), []string{"foundation-plan", "foundation-apply", "foundation-verification"}) ||
		!sameExactStrings(stringSlice(projection["denied_operations"]), []string{"adoption", "enforcement", "production-authority", "exception-replay"}) ||
		fmt.Sprint(projection["authorized_operation"]) != "foundation-apply" ||
		fmt.Sprint(projection["single_use_initial_state"]) != "UNUSED" ||
		fmt.Sprint(projection["single_use_terminal_state"]) != "CONSUMED" ||
		!receiptKnown || !receiptRequired || fmt.Sprint(projection["receipt_digest_algorithm"]) != "sha256" ||
		!independentKnown || independent || !productionKnown || production {
		return errors.New("evidence has a weak, replayable, or authority-leaking founder-bootstrap projection")
	}
	return nil
}

func validateDestructiveReviewEvidence(document map[string]any) error {
	plan, planKnown := document["plan"].(map[string]any)
	decision, decisionKnown := document["decision"].(map[string]any)
	digests, digestsKnown := document["digests"].(map[string]any)
	bindings, bindingsKnown := document["bindings"].(map[string]any)
	if !planKnown || !decisionKnown || !digestsKnown || !bindingsKnown {
		return errors.New("evidence omits destructive-review structure")
	}
	rawIDs, idsKnown := plan["destructive_change_ids"].([]any)
	if !idsKnown {
		return errors.New("evidence has malformed destructive-change IDs")
	}
	for _, rawID := range rawIDs {
		id, ok := rawID.(string)
		if !ok || !changeIDPattern.MatchString(id) {
			return errors.New("evidence has malformed destructive-change IDs")
		}
	}
	requires, requiresKnown := decision["requires_destructive_change_acknowledgement"].(bool)
	acknowledged, acknowledgedKnown := decision["destructive_change_acknowledged"].(bool)
	analysisVerified, analysisKnown := decision["dependency_analysis_verified"].(bool)
	eligible, eligibleKnown := decision["eligible_for_protected_apply"].(bool)
	if !requiresKnown || !acknowledgedKnown || !analysisKnown || !eligibleKnown || requires != (len(rawIDs) > 0) {
		return errors.New("evidence has malformed destructive-review decision fields")
	}
	digest, hasDigest := digests["dependency_analysis"].(string)
	boundDigest, hasBoundDigest := bindings["dependency_analysis"].(string)
	digestBound := hasDigest && hasBoundDigest && validSHA256Digest(digest) && digest == boundDigest
	if analysisVerified != digestBound {
		return errors.New("evidence has an invalid dependency-analysis binding")
	}
	if eligible && requires && (!acknowledged || !analysisVerified) {
		return errors.New("eligible destructive evidence omits acknowledgement or dependency analysis")
	}
	return nil
}

func validSHA256Digest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && lowercaseHexDigestPattern.MatchString(strings.TrimPrefix(value, "sha256:"))
}

func validateDependencyAnalysis(
	path, planDigest, changeReference string, destructiveIDs []string,
) (string, error) {
	data, err := readRegularFile(path)
	if err != nil {
		return "", fmt.Errorf("read dependency analysis: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return "", fmt.Errorf("decode dependency analysis: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", errors.New("dependency analysis must contain exactly one JSON object")
	}
	if !exactObjectKeys(document, []string{
		"api_version", "kind", "plan_json_digest", "change_reference", "destructive_changes",
	}) {
		return "", errors.New("dependency analysis has an unsupported structure")
	}
	if document["api_version"] != validation.APIVersion || document["kind"] != "DependencyAnalysis" {
		return "", errors.New("dependency analysis has an invalid document identity")
	}
	if !validSHA256Digest(planDigest) || document["plan_json_digest"] != planDigest {
		return "", errors.New("dependency analysis is not bound to the exact plan JSON digest")
	}
	if strings.TrimSpace(changeReference) == "" || document["change_reference"] != changeReference {
		return "", errors.New("dependency analysis is not bound to the reviewed change reference")
	}
	entries, ok := document["destructive_changes"].([]any)
	if !ok || len(entries) != len(destructiveIDs) {
		return "", errors.New("dependency analysis does not cover every destructive change")
	}
	for index, rawEntry := range entries {
		entry, ok := rawEntry.(map[string]any)
		if !ok || !exactObjectKeys(entry, []string{"change_id", "dependencies", "impact", "rollback"}) {
			return "", errors.New("dependency analysis contains a malformed destructive-change entry")
		}
		if entry["change_id"] != destructiveIDs[index] {
			return "", errors.New("dependency analysis destructive-change IDs must exactly match the sorted plan IDs")
		}
		dependencies, ok := entry["dependencies"].([]any)
		if !ok || len(dependencies) > 100 {
			return "", errors.New("dependency analysis contains an invalid dependency list")
		}
		seenDependencies := make(map[string]struct{}, len(dependencies))
		for _, rawDependency := range dependencies {
			dependency, ok := rawDependency.(string)
			if !ok || !boundedEvidenceText(dependency, 512) {
				return "", errors.New("dependency analysis contains an invalid dependency identifier")
			}
			if _, duplicate := seenDependencies[dependency]; duplicate {
				return "", errors.New("dependency analysis contains a duplicate dependency identifier")
			}
			seenDependencies[dependency] = struct{}{}
		}
		for _, field := range []string{"impact", "rollback"} {
			value, ok := entry[field].(string)
			if !ok || !boundedEvidenceText(value, 2048) {
				return "", fmt.Errorf("dependency analysis contains an invalid %s statement", field)
			}
		}
	}
	canonical, err := rendering.CanonicalJSON(document)
	if err != nil {
		return "", fmt.Errorf("canonicalize dependency analysis: %w", err)
	}
	return rendering.Digest(canonical), nil
}

func exactObjectKeys(value map[string]any, expected []string) bool {
	if len(value) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, exists := value[key]; !exists {
			return false
		}
	}
	return true
}

func boundedEvidenceText(value string, maximum int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}

func positiveJSONInteger(value any) (int64, bool) {
	var integer int64
	switch current := value.(type) {
	case json.Number:
		parsed, err := current.Int64()
		if err != nil {
			return 0, false
		}
		integer = parsed
	case float64:
		integer = int64(current)
		if float64(integer) != current {
			return 0, false
		}
	case int64:
		integer = current
	case int:
		integer = int64(current)
	default:
		return 0, false
	}
	return integer, integer > 0
}

func validateIdentity(identity map[string]string) (map[string]any, error) {
	result := make(map[string]any)
	if organization := identity["organization"]; organization != "" && !organizationLoginPattern.MatchString(organization) {
		return nil, errors.New("evidence organization binding is not a valid GitHub organization login")
	}
	for _, key := range []string{"change_reference", "workflow_ref", "oidc_issuer"} {
		if value := identity[key]; value != "" {
			if strings.TrimSpace(value) == "" || len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
				return nil, fmt.Errorf("evidence %s binding is invalid", key)
			}
			result[key] = value
		}
	}
	if issuer := identity["oidc_issuer"]; issuer != "" && issuer != "https://token.actions.githubusercontent.com" {
		return nil, errors.New("evidence oidc_issuer must be the GitHub Actions token issuer")
	}
	if reference := identity["change_reference"]; reference != "" && identity["plan_app_id"] != "" && !changeReferencePattern.MatchString(reference) {
		return nil, errors.New("protected evidence change_reference must be a canonical github-config pull request URL")
	}
	for _, key := range []string{"source_sha", "workflow_sha"} {
		if value := identity[key]; value != "" {
			if !gitSHA40Pattern.MatchString(value) {
				return nil, fmt.Errorf("evidence %s must be a 40-character lowercase hexadecimal digest", key)
			}
			result[key] = value
		}
	}
	for _, key := range []string{"actor_id", "plan_app_id", "apply_app_id", "run_id", "run_attempt"} {
		value := identity[key]
		if value == "" {
			continue
		}
		integer, err := strconv.ParseInt(value, 10, 64)
		if err != nil || integer <= 0 {
			return nil, fmt.Errorf("evidence %s must be a positive integer", key)
		}
		result[key] = integer
	}
	protected := identity["plan_app_id"] != "" || identity["apply_app_id"] != ""
	if protected {
		for _, key := range []string{
			"change_reference", "workflow_ref", "oidc_issuer", "source_sha", "workflow_sha", "actor_id",
			"plan_app_id", "apply_app_id", "wif_qualification_evidence_digest",
			"state_backend_digest", "executor_contract_digest", "review_context_digest",
		} {
			if identity[key] == "" {
				return nil, fmt.Errorf("protected evidence requires %s", key)
			}
		}
		if identity["plan_app_id"] == identity["apply_app_id"] {
			return nil, errors.New("protected evidence requires distinct plan and apply GitHub App IDs")
		}
	}
	for _, key := range []string{"reviewed_plan_digest", "post_apply_drift_digest"} {
		if value := identity[key]; value != "" {
			if !lowercaseHexDigestPattern.MatchString(value) {
				return nil, fmt.Errorf("evidence %s must be a 64-character lowercase hexadecimal digest", key)
			}
			result[key] = value
		}
	}
	for _, key := range []string{
		"reviewed_evidence_digest", "wif_qualification_evidence_digest",
		"state_backend_digest", "executor_contract_digest", "review_context_digest",
	} {
		if value := identity[key]; value != "" {
			if !validSHA256Digest(value) {
				return nil, fmt.Errorf("evidence %s must be a sha256-prefixed lowercase digest", key)
			}
			result[key] = value
		}
	}
	if value := identity["post_apply_drift_exit_code"]; value != "" {
		if value != "0" && value != "2" {
			return nil, errors.New("evidence post_apply_drift_exit_code must be 0 or 2")
		}
		parsed, _ := strconv.ParseInt(value, 10, 64)
		result["post_apply_drift_exit_code"] = parsed
	}
	if err := validateAttemptBindings(identity, result); err != nil {
		return nil, err
	}
	createdText := identity["created_epoch"]
	expiresText := identity["expires_epoch"]
	if createdText != "" || expiresText != "" {
		created, createdErr := strconv.ParseInt(createdText, 10, 64)
		expires, expiresErr := strconv.ParseInt(expiresText, 10, 64)
		if createdErr != nil || expiresErr != nil || created <= 0 || expires <= created || expires-created > 6*60*60 {
			return nil, errors.New("evidence execution window must be positive, ordered, and no longer than six hours")
		}
		result["created_epoch"] = created
		result["expires_epoch"] = expires
	}
	return result, nil
}

func validateAttemptBindings(identity map[string]string, result map[string]any) error {
	status := identity["attempt_status"]
	applyStartedText := identity["apply_started"]
	failureStage := identity["failure_stage"]
	applyExitCodeText := identity["apply_exit_code"]
	if status == "" {
		if applyStartedText != "" || failureStage != "" || applyExitCodeText != "" {
			return errors.New("evidence attempt_status is required when attempt bindings are supplied")
		}
		return nil
	}
	if status != "started" && status != "succeeded" && status != "failed" {
		return errors.New("evidence attempt_status must be started, succeeded, or failed")
	}
	if applyStartedText != "true" && applyStartedText != "false" {
		return errors.New("evidence apply_started must be explicitly true or false")
	}
	applyStarted := applyStartedText == "true"
	allowedFailureStages := map[string]struct{}{
		"preflight": {}, "plan": {}, "approval": {}, "apply": {},
		"post_apply_drift": {}, "receipt": {},
	}
	if failureStage != "" {
		if _, allowed := allowedFailureStages[failureStage]; !allowed {
			return errors.New("evidence failure_stage is not a supported safe stage")
		}
		if status != "failed" {
			return errors.New("evidence failure_stage is valid only for a failed attempt")
		}
	}
	var applyExitCode int64
	hasApplyExitCode := applyExitCodeText != ""
	if hasApplyExitCode {
		parsed, err := strconv.ParseInt(applyExitCodeText, 10, 64)
		if err != nil || parsed < 0 || parsed > 255 {
			return errors.New("evidence apply_exit_code must be an integer from 0 through 255")
		}
		if !applyStarted {
			return errors.New("evidence apply_exit_code requires apply_started=true")
		}
		applyExitCode = parsed
	}
	switch status {
	case "started":
		if failureStage != "" || hasApplyExitCode {
			return errors.New("started attempt evidence cannot contain a failure stage or apply exit code")
		}
	case "succeeded":
		if !applyStarted || !hasApplyExitCode || applyExitCode != 0 || failureStage != "" {
			return errors.New("succeeded attempt evidence requires apply_started=true, apply_exit_code=0, and no failure stage")
		}
	case "failed":
		if failureStage == "" {
			return errors.New("failed attempt evidence requires failure_stage")
		}
	}
	result["attempt_status"] = status
	result["apply_started"] = applyStarted
	if failureStage != "" {
		result["failure_stage"] = failureStage
	}
	if hasApplyExitCode {
		result["apply_exit_code"] = applyExitCode
	}
	return nil
}

func summarizePlan(plan, catalog, observed, policyInput map[string]any, phase string) (map[string]any, []any, []any, []any, []any, int64) {
	counts := map[string]any{"create": int64(0), "update": int64(0), "delete": int64(0), "replace": int64(0), "forget": int64(0), "read": int64(0), "no_op": int64(0), "unknown": int64(0)}
	writes := make([]map[string]any, 0)
	highRisk := make([]map[string]any, 0)
	destructive := make([]string, 0)
	replacements := make([]string, 0)
	var sensitiveCount int64
	governedRevocationDeleteObserved := false
	addressesByChangeID := make(map[string]string)
	changes, _ := plan["resource_changes"].([]any)
	for index, resource := range sortedResourceChanges(changes) {
		changeID := fmt.Sprintf("change-%06d", index+1)
		address, _ := resource["address"].(string)
		addressesByChangeID[changeID] = address
		resourceType, _ := resource["type"].(string)
		if resourceType == "" {
			resourceType = resourceTypeFromAddress(address)
		}
		change, _ := resource["change"].(map[string]any)
		actions := stringSlice(change["actions"])
		actionClass, knownActions := allowedActionSets[strings.Join(actions, ",")]
		if !knownActions {
			actionClass = "unknown"
		}
		counts[actionClass] = counts[actionClass].(int64) + 1
		_, permissionReduction := permissionReductionDeleteTypes[strings.ToLower(resourceType)]
		if actionClass == "delete" &&
			(permissionReduction || governedRetirementAddress(strings.ToLower(resourceType), address)) {
			governedRevocationDeleteObserved = true
		}
		if actionClass == "delete" || actionClass == "replace" || actionClass == "forget" {
			destructive = append(destructive, changeID)
		}
		if actionClass == "replace" {
			replacements = append(replacements, changeID)
		}
		if containsSensitive(change["after_sensitive"]) || containsSensitive(change["before_sensitive"]) {
			sensitiveCount++
		}
		if actionClass == "read" || actionClass == "no_op" {
			continue
		}
		classes, reasons := classifyChange(resourceType, address, actionClass, change, catalog, observed, policyInput, phase)
		writes = append(writes, map[string]any{
			"change_id": changeID, "resource_type": resourceType, "actions": stringsToAny(actions),
			"change_class": writeClass(classes), "classes": stringsToAny(classes),
			"changed_fields": changedFieldProjection(
				resourceType, strings.Join(actions, ","),
				change["before"], change["after"], change["before_sensitive"], change["after_sensitive"],
			),
		})
		if len(reasons) > 0 {
			highRisk = append(highRisk, map[string]any{
				"change_id": changeID, "resource_type": resourceType,
				"classes": stringsToAny(classes), "reasons": stringsToAny(reasons),
			})
		}
	}
	// Permission-reduction and governed-retirement deletes are safe only in a
	// delete-only revocation plan. A simultaneous create/update/replace/forget can
	// disguise a key rename, authority replacement, or grant behind an apparently
	// safe offboarding operation. Governed environment/ruleset/team retirements
	// remain bound to explicit acknowledgement and complete dependency analysis.
	allWritesAreGovernedRevocations := len(writes) > 0
	for _, write := range writes {
		resourceType, _ := write["resource_type"].(string)
		changeID, _ := write["change_id"].(string)
		address := addressesByChangeID[changeID]
		actions := stringSlice(write["actions"])
		actionClass := allowedActionSets[strings.Join(actions, ",")]
		_, permissionReduction := permissionReductionDeleteTypes[strings.ToLower(resourceType)]
		governedRetirement := governedRetirementAddress(strings.ToLower(resourceType), address)
		if actionClass != "delete" || (!permissionReduction && !governedRetirement) {
			allWritesAreGovernedRevocations = false
			break
		}
	}
	if governedRevocationDeleteObserved && !allWritesAreGovernedRevocations {
		for _, write := range writes {
			classes := stringSlice(write["classes"])
			classes = append(classes, "authority_replacement")
			sort.Strings(classes)
			write["classes"] = stringsToAny(uniqueStrings(classes))
			write["change_class"] = "fundamental_deny"
			addHighRiskClass(&highRisk, write, "authority_replacement", "governed revocations must be the only writes in a retirement plan")
		}
	}
	sort.Slice(writes, func(i, j int) bool {
		return fmt.Sprint(writes[i]["change_id"]) < fmt.Sprint(writes[j]["change_id"])
	})
	sort.Slice(highRisk, func(i, j int) bool {
		return fmt.Sprint(highRisk[i]["change_id"]) < fmt.Sprint(highRisk[j]["change_id"])
	})
	sort.Strings(destructive)
	sort.Strings(replacements)
	return counts, mapsToAny(writes), mapsToAny(highRisk), stringsToAny(destructive), stringsToAny(replacements), sensitiveCount
}

type planFieldValue struct {
	present bool
	value   any
}

func managedChangedFieldsAllowed(resourceType, actionClass string, before, after map[string]any, afterUnknown any) bool {
	patterns, knownResource := managedWritePaths[resourceType]
	if !knownResource || after == nil || (actionClass == "update" && before == nil) {
		return false
	}
	if !afterUnknownPathsAllowed(resourceType, after, afterUnknown) {
		return false
	}
	paths := make(map[string]struct{})
	collectChangedPlanPaths(
		planFieldValue{present: before != nil, value: before},
		planFieldValue{present: after != nil, value: after},
		"", paths,
	)
	for path := range paths {
		normalized := normalizePlanFieldPath(path)
		allowed := false
		for _, pattern := range patterns {
			if pattern == normalized {
				allowed = true
				break
			}
		}
		if !allowed && !(actionClass == "create" && knownComputedUnknownPath(resourceType, path, after, afterUnknown)) {
			return false
		}
	}
	return true
}

func afterUnknownPathsAllowed(resourceType string, after map[string]any, afterUnknown any) bool {
	paths := make([]string, 0)
	collectTrueUnknownPaths(afterUnknown, "", &paths)
	for _, path := range paths {
		if !knownComputedUnknownPath(resourceType, path, after, afterUnknown) {
			return false
		}
	}
	return true
}

func collectTrueUnknownPaths(value any, path string, result *[]string) {
	if unknown, ok := value.(bool); ok {
		if unknown {
			*result = append(*result, displayFieldPath(path))
		}
		return
	}
	switch current := value.(type) {
	case map[string]any:
		for _, key := range sortedObjectKeys(current) {
			collectTrueUnknownPaths(current[key], path+"/"+escapeEvidencePointer(key), result)
		}
	case []any:
		for index, item := range current {
			collectTrueUnknownPaths(item, fmt.Sprintf("%s/%d", path, index), result)
		}
	}
}

func sortedObjectKeys(values map[string]any) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func collectChangedPlanPaths(before, after planFieldValue, path string, result map[string]struct{}) {
	if equalPlanFieldValue(before, after) {
		return
	}
	beforeMap, beforeMapOK := before.value.(map[string]any)
	afterMap, afterMapOK := after.value.(map[string]any)
	if (beforeMapOK || !before.present) && (afterMapOK || !after.present) && (beforeMapOK || afterMapOK) {
		keys := make(map[string]struct{}, len(beforeMap)+len(afterMap))
		for key := range beforeMap {
			keys[key] = struct{}{}
		}
		for key := range afterMap {
			keys[key] = struct{}{}
		}
		if len(keys) == 0 {
			result[displayFieldPath(path)] = struct{}{}
			return
		}
		for _, key := range sortedKeys(keys) {
			beforeValue, beforeExists := beforeMap[key]
			afterValue, afterExists := afterMap[key]
			collectChangedPlanPaths(
				planFieldValue{present: before.present && beforeExists, value: beforeValue},
				planFieldValue{present: after.present && afterExists, value: afterValue},
				path+"/"+escapeEvidencePointer(key), result,
			)
		}
		return
	}
	beforeList, beforeListOK := before.value.([]any)
	afterList, afterListOK := after.value.([]any)
	if (beforeListOK || !before.present) && (afterListOK || !after.present) && (beforeListOK || afterListOK) {
		maximum := len(beforeList)
		if len(afterList) > maximum {
			maximum = len(afterList)
		}
		if maximum == 0 {
			result[displayFieldPath(path)] = struct{}{}
			return
		}
		for index := 0; index < maximum; index++ {
			var beforeValue, afterValue any
			beforeExists := before.present && index < len(beforeList)
			afterExists := after.present && index < len(afterList)
			if beforeExists {
				beforeValue = beforeList[index]
			}
			if afterExists {
				afterValue = afterList[index]
			}
			collectChangedPlanPaths(
				planFieldValue{present: beforeExists, value: beforeValue},
				planFieldValue{present: afterExists, value: afterValue},
				fmt.Sprintf("%s/%d", path, index), result,
			)
		}
		return
	}
	result[displayFieldPath(path)] = struct{}{}
}

func equalPlanFieldValue(before, after planFieldValue) bool {
	if before.present != after.present {
		return false
	}
	if !before.present {
		return true
	}
	beforeJSON, beforeErr := rendering.CanonicalJSON(before.value)
	afterJSON, afterErr := rendering.CanonicalJSON(after.value)
	return beforeErr == nil && afterErr == nil && string(beforeJSON) == string(afterJSON)
}

func normalizePlanFieldPath(path string) string {
	if path == "" {
		return "/"
	}
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, segment := range segments {
		if _, err := strconv.Atoi(segment); err == nil {
			segments[index] = "*"
		}
	}
	return "/" + strings.Join(segments, "/")
}

func knownComputedUnknownPath(resourceType, path string, after map[string]any, afterUnknown any) bool {
	allowed := false
	for _, pattern := range knownComputedWritePaths[resourceType] {
		if pattern == normalizePlanFieldPath(path) {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}
	value, exists := planValueAtPath(after, path)
	return exists && value == nil && planUnknownAtPath(afterUnknown, path)
}

func planValueAtPath(root any, path string) (any, bool) {
	current := root
	if path == "" || path == "/" {
		return current, true
	}
	for _, rawSegment := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		segment := strings.ReplaceAll(strings.ReplaceAll(rawSegment, "~1", "/"), "~0", "~")
		switch value := current.(type) {
		case map[string]any:
			var exists bool
			current, exists = value[segment]
			if !exists {
				return nil, false
			}
		case []any:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(value) {
				return nil, false
			}
			current = value[index]
		default:
			return nil, false
		}
	}
	return current, true
}

func planUnknownAtPath(root any, path string) bool {
	current := root
	if current == true {
		return true
	}
	if path == "" || path == "/" {
		unknown, _ := current.(bool)
		return unknown
	}
	for _, rawSegment := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if unknown, _ := current.(bool); unknown {
			return true
		}
		segment := strings.ReplaceAll(strings.ReplaceAll(rawSegment, "~1", "/"), "~0", "~")
		switch value := current.(type) {
		case map[string]any:
			var exists bool
			current, exists = value[segment]
			if !exists {
				return false
			}
		case []any:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(value) {
				return false
			}
			current = value[index]
		default:
			return false
		}
	}
	unknown, _ := current.(bool)
	return unknown
}

// sortedResourceChanges keeps raw Terraform addresses wholly inside the
// compiler. Stable, opaque ordinals are assigned only after this canonical
// ordering, so evidence can correlate a write with its risk classification
// without publishing a dictionary-testable address pseudonym.
func sortedResourceChanges(changes []any) []map[string]any {
	type sortableChange struct {
		resource  map[string]any
		address   string
		canonical string
	}
	sorted := make([]sortableChange, 0, len(changes))
	for _, raw := range changes {
		resource, ok := raw.(map[string]any)
		if !ok {
			resource = map[string]any{}
		}
		address, _ := resource["address"].(string)
		canonical, err := rendering.CanonicalJSON(raw)
		if err != nil {
			canonical = []byte(fmt.Sprintf("%T", raw))
		}
		sorted = append(sorted, sortableChange{resource: resource, address: address, canonical: string(canonical)})
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].address != sorted[j].address {
			return sorted[i].address < sorted[j].address
		}
		return sorted[i].canonical < sorted[j].canonical
	})
	result := make([]map[string]any, 0, len(sorted))
	for _, change := range sorted {
		result = append(result, change.resource)
	}
	return result
}

// changedFieldProjection produces a deterministic, value-free semantic view
// for approvers. Values are represented only by domain-separated hashes, and
// Terraform-sensitive, credential, identity, and access-topology fields carry
// no hashes at all. Numeric list positions are structural plan paths, never
// resource addresses or identity values.
func changedFieldProjection(resourceType, actionContext string, before, after, beforeSensitive, afterSensitive any) []any {
	changes := make([]map[string]any, 0)
	collectChangedFields(
		fieldState{present: before != nil, value: before, sensitive: beforeSensitive},
		fieldState{present: after != nil, value: after, sensitive: afterSensitive},
		resourceType, actionContext, "", sensitivePlanResource(resourceType), &changes,
	)
	sort.Slice(changes, func(i, j int) bool {
		return fmt.Sprint(changes[i]["path"]) < fmt.Sprint(changes[j]["path"])
	})
	return mapsToAny(changes)
}

type fieldState struct {
	present   bool
	value     any
	sensitive any
}

func collectChangedFields(before, after fieldState, resourceType, actionContext, path string, inheritedSensitive bool, result *[]map[string]any) {
	if equalFieldState(before, after) {
		return
	}
	sensitive := inheritedSensitive || sensitivityTrue(before.sensitive) || sensitivityTrue(after.sensitive) || sensitivePlanField(resourceType, path)
	if sensitive {
		*result = append(*result, map[string]any{"path": displayFieldPath(path), "sensitive": true})
		return
	}

	beforeMap, beforeMapOK := before.value.(map[string]any)
	afterMap, afterMapOK := after.value.(map[string]any)
	if (beforeMapOK || !before.present) && (afterMapOK || !after.present) && (beforeMapOK || afterMapOK) {
		keys := make(map[string]struct{}, len(beforeMap)+len(afterMap))
		for key := range beforeMap {
			keys[key] = struct{}{}
		}
		for key := range afterMap {
			keys[key] = struct{}{}
		}
		if len(keys) == 0 {
			appendHashedField(result, resourceType, actionContext, path, before, after)
			return
		}
		for _, key := range sortedKeys(keys) {
			beforeValue, beforeExists := beforeMap[key]
			afterValue, afterExists := afterMap[key]
			childPath := path + "/" + escapeEvidencePointer(key)
			collectChangedFields(
				fieldState{present: before.present && beforeExists, value: beforeValue, sensitive: sensitivityChild(before.sensitive, key, -1)},
				fieldState{present: after.present && afterExists, value: afterValue, sensitive: sensitivityChild(after.sensitive, key, -1)},
				resourceType, actionContext, childPath, sensitiveFieldName(key), result,
			)
		}
		return
	}

	beforeList, beforeListOK := before.value.([]any)
	afterList, afterListOK := after.value.([]any)
	if (beforeListOK || !before.present) && (afterListOK || !after.present) && (beforeListOK || afterListOK) {
		maximum := len(beforeList)
		if len(afterList) > maximum {
			maximum = len(afterList)
		}
		if maximum == 0 {
			appendHashedField(result, resourceType, actionContext, path, before, after)
			return
		}
		for index := 0; index < maximum; index++ {
			var beforeValue, afterValue any
			beforeExists := before.present && index < len(beforeList)
			afterExists := after.present && index < len(afterList)
			if beforeExists {
				beforeValue = beforeList[index]
			}
			if afterExists {
				afterValue = afterList[index]
			}
			collectChangedFields(
				fieldState{present: beforeExists, value: beforeValue, sensitive: sensitivityChild(before.sensitive, "", index)},
				fieldState{present: afterExists, value: afterValue, sensitive: sensitivityChild(after.sensitive, "", index)},
				resourceType, actionContext, fmt.Sprintf("%s/%d", path, index), false, result,
			)
		}
		return
	}

	appendHashedField(result, resourceType, actionContext, path, before, after)
}

func appendHashedField(result *[]map[string]any, resourceType, actionContext, path string, before, after fieldState) {
	*result = append(*result, map[string]any{
		"path":        displayFieldPath(path),
		"sensitive":   false,
		"before_hash": fieldStateDigest(resourceType, actionContext, path, "before", before),
		"after_hash":  fieldStateDigest(resourceType, actionContext, path, "after", after),
	})
}

func equalFieldState(before, after fieldState) bool {
	if before.present != after.present {
		return false
	}
	if !before.present {
		return true
	}
	beforeJSON, beforeErr := rendering.CanonicalJSON(before.value)
	afterJSON, afterErr := rendering.CanonicalJSON(after.value)
	return beforeErr == nil && afterErr == nil && string(beforeJSON) == string(afterJSON)
}

func fieldStateDigest(resourceType, actionContext, path, side string, state fieldState) string {
	projection := map[string]any{
		"domain":         "github-config/plan-field/v1",
		"resource_type":  resourceType,
		"action_context": actionContext,
		"path":           displayFieldPath(path),
		"side":           side,
		"present":        state.present,
	}
	if state.present {
		projection["value"] = state.value
	}
	canonical, err := rendering.CanonicalJSON(projection)
	if err != nil {
		// Terraform JSON has already been decoded into JSON-compatible values;
		// retain a deterministic fail-closed marker if that invariant changes.
		return rendering.Digest([]byte(fmt.Sprintf(
			"github-config/plan-field/v1\n%s\n%s\n%s\n%s\nunhashable\n",
			resourceType, actionContext, displayFieldPath(path), side,
		)))
	}
	return rendering.Digest(canonical)
}

func sensitivePlanResource(resourceType string) bool {
	resourceType = strings.ToLower(resourceType)
	for _, exact := range []string{
		"github_membership", "github_team_membership", "github_team_repository",
		"github_repository_collaborator", "github_organization_role_team",
		"github_repository_custom_property", "github_organization_custom_properties",
	} {
		if resourceType == exact {
			return true
		}
	}
	return false
}

func sensitivePlanField(resourceType, path string) bool {
	if path == "" {
		return false
	}
	resourceType = strings.ToLower(resourceType)
	for _, rawSegment := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		segment := strings.ReplaceAll(strings.ToLower(rawSegment), "-", "_")
		if segment == "id" || segment == "name" || segment == "slug" || strings.HasSuffix(segment, "_id") {
			return true
		}
		for _, fragment := range []string{
			"username", "login", "email", "member", "team", "repository", "environment", "collaborator",
			"custom_propert", "principal", "sponsor", "reviewer", "bypass_actor",
			"owner", "permission", "role", "values_editable_by",
		} {
			if strings.Contains(segment, fragment) {
				return true
			}
		}
		if (segment == "value" || segment == "default_value" || segment == "allowed_values") &&
			strings.Contains(resourceType, "custom_propert") {
			return true
		}
	}
	return false
}

func sensitivityTrue(value any) bool {
	sensitive, _ := value.(bool)
	return sensitive
}

func sensitivityChild(value any, key string, index int) any {
	if sensitivityTrue(value) {
		return true
	}
	if key != "" {
		if object, ok := value.(map[string]any); ok {
			return object[key]
		}
		return nil
	}
	if index >= 0 {
		if items, ok := value.([]any); ok && index < len(items) {
			return items[index]
		}
	}
	return nil
}

func sensitiveFieldName(name string) bool {
	normalized := strings.ReplaceAll(strings.ToLower(name), "-", "_")
	if strings.HasPrefix(normalized, "secret_scanning") {
		return false
	}
	return sensitiveFieldPattern.MatchString(normalized) &&
		!strings.HasSuffix(normalized, "_ref") &&
		!strings.HasSuffix(normalized, "_reference") &&
		!strings.HasSuffix(normalized, "_resource") &&
		!strings.HasSuffix(normalized, "_name") &&
		!strings.HasSuffix(normalized, "_authority") &&
		normalized != "secret_manager"
}

func escapeEvidencePointer(value string) string {
	value = strings.ReplaceAll(value, "~", "~0")
	return strings.ReplaceAll(value, "/", "~1")
}

func displayFieldPath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func addHighRiskClass(highRisk *[]map[string]any, write map[string]any, class, reason string) {
	changeID, _ := write["change_id"].(string)
	for _, change := range *highRisk {
		if change["change_id"] != changeID {
			continue
		}
		classes := append(stringSlice(change["classes"]), class)
		reasons := append(stringSlice(change["reasons"]), reason)
		sort.Strings(classes)
		sort.Strings(reasons)
		change["classes"] = stringsToAny(uniqueStrings(classes))
		change["reasons"] = stringsToAny(uniqueStrings(reasons))
		return
	}
	*highRisk = append(*highRisk, map[string]any{
		"change_id":     changeID,
		"resource_type": write["resource_type"],
		"classes":       []any{class},
		"reasons":       []any{reason},
	})
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func classifyChange(resourceType, address, actionClass string, change, catalog, observed, policyInput map[string]any, phase string) ([]string, []string) {
	classes := make(map[string]struct{})
	reasons := make(map[string]struct{})
	add := func(class, reason string) {
		classes[class] = struct{}{}
		if reason != "" {
			reasons[reason] = struct{}{}
		}
	}
	switch actionClass {
	case "unknown":
		add("unknown_action", "Terraform/OpenTofu emitted an unrecognized action sequence")
	case "delete":
		if _, reduction := permissionReductionDeleteTypes[strings.ToLower(resourceType)]; reduction {
			add("permission_reduction", "access authority is revoked")
		} else if governedRetirementAddress(strings.ToLower(resourceType), address) {
			add("governed_retirement", "catalog retirement requires exact-plan acknowledgement and complete dependency analysis")
		} else {
			add("destructive", "resource deletion is prohibited")
		}
	case "replace":
		add("replacement", "resource replacement includes deletion")
	case "forget":
		add("state_forget", "resource removal from state is prohibited")
	case "create":
		add("privilege_expansion", "resource creation expands the managed authority surface")
	}
	if actionClass != "create" && actionClass != "update" && containsAuthorityUnknown(change["after_unknown"], "") {
		add("unknown_change", "one or more security- or authority-relevant post-change values are unknown")
	}
	resourceName := strings.ToLower(resourceType)
	// Environment, environment-variable, deployment-policy,
	// organization-ruleset, and team retirement are the only non-access
	// deletions that the normal convergence path may govern. Build still requires
	// explicit acknowledgement plus an exact-plan, complete DependencyAnalysis
	// for every such deletion. Returning here keeps generic before-to-null field
	// walkers from misclassifying the reviewed retirement itself as an
	// unreviewable protection weakening. Repository deletion, replacement,
	// state-forget, and unknown addresses remain denied.
	if actionClass == "delete" && governedRetirementAddress(resourceName, address) {
		return sortedKeys(classes), sortedKeys(reasons)
	}
	oidcCatalogAuthorized := false
	if _, managed := managedWriteTypes[resourceName]; !managed {
		add("unknown_change", "resource type is outside the reviewed governance write allowlist")
	}
	before, _ := change["before"].(map[string]any)
	after, _ := change["after"].(map[string]any)
	if (actionClass == "create" || actionClass == "update") &&
		!managedChangedFieldsAllowed(resourceName, actionClass, before, after, change["after_unknown"]) {
		add("unknown_change", "one or more changed provider fields are outside the exact catalog-managed write contract")
	}
	if catalog != nil && (actionClass == "create" || actionClass == "update") && !equalPlanMaps(before, after) {
		switch resourceName {
		case "github_membership", "github_team_membership", "github_team_repository":
			if !catalogAccessAfterState(resourceName, address, after, catalog, observed) {
				add("administrative_grant", "access resource after-state does not exactly match a unique compiled-catalog grant")
			}
		case "github_repository_custom_property":
			if !catalogRepositoryPropertyAfterState(address, after, catalog) {
				add("unknown_change", "repository custom-property after-state does not exactly match the compiled catalog")
			}
		case "github_organization_custom_properties":
			if !catalogOrganizationPropertyAfterState(address, after, catalog, observed) {
				add("unknown_change", "organization custom-property after-state does not exactly match the compiled catalog")
			}
		case "github_repository_environment":
			if !catalogEnvironmentAfterState(address, after, catalog, observed) {
				add("unknown_change", "repository environment after-state does not exactly match a unique compiled-catalog assignment")
			}
		case "github_repository_environment_deployment_policy":
			if !catalogEnvironmentDeploymentPolicyAfterState(address, after, catalog) {
				add("unknown_change", "environment deployment-policy after-state does not exactly match a unique compiled-catalog branch or tag pattern")
			}
		case "github_actions_environment_variable":
			if !catalogEnvironmentVariableAfterState(address, after, catalog) {
				add("unknown_change", "environment variable after-state does not exactly match one source-qualified compiled-catalog handoff")
			}
		case "github_repository_dependabot_security_updates":
			if !catalogDependabotAfterState(address, after, catalog) {
				add("unknown_change", "Dependabot security-updates after-state does not exactly match the compiled catalog")
			}
		case "github_actions_repository_access_level":
			if !catalogRepositoryActionsAccessAfterState(address, after, catalog) {
				add("unknown_change", "repository Actions access after-state does not exactly match the compiled catalog")
			}
		case "github_actions_organization_permissions", "github_actions_organization_workflow_permissions":
			if !catalogActionsAfterState(resourceName, address, after, catalog) {
				add("unknown_change", "organization Actions after-state does not exactly match the compiled catalog")
			}
		case "github_team":
			if !catalogTeamAfterState(address, after, catalog) {
				add("unknown_change", "team after-state does not exactly match the compiled catalog")
			}
		case "github_repository":
			if !catalogRepositoryAfterState(address, after, catalog) {
				add("unknown_change", "repository after-state does not exactly match the compiled catalog")
			}
		case "github_organization_ruleset":
			if !catalogRulesetAfterState(address, after, catalog, observed, phase) {
				add("unknown_change", "physical ruleset after-state does not exactly match the phase-specific compiled catalog projection")
			}
		}
	}
	if catalog != nil && actionClass == "delete" {
		if _, reduction := permissionReductionDeleteTypes[resourceName]; reduction &&
			!catalogAccessRevocationAllowed(resourceName, address, before, catalog, observed) {
			add("authority_replacement", "access deletion is not a canonical catalog-justified revocation")
		}
	}
	actionPinRotationAuthorized := resourceName == "github_actions_organization_permissions" &&
		catalogActionPinRotation(before, after, catalog, policyInput)
	if actionPinRotationAuthorized {
		add("privilege_expansion", "catalog- and workflow-authorized immutable action pin rotation")
	}
	if resourceName == "github_repository_collaborator" && actionClass != "delete" {
		if catalogOutsideCollaboratorGrant(address, after, catalog) {
			add("privilege_expansion", "catalog-authorized expiring outside-collaborator access is established or reconciled")
		} else {
			add("direct_collaborator", "repository collaborator mutation is not an exact catalog outside-collaborator grant")
			add("privilege_expansion", "repository access may expand")
		}
	}
	if resourceName == "github_organization_role_team" && actionClass != "delete" {
		if catalogSecurityManagerAssignment(address, after, catalog, observed) {
			add("privilege_expansion", "catalog-authorized security_manager team assignment is established or reconciled")
		} else {
			add("administrative_grant", "organization role assignment is not the exact catalog security_manager team grant")
			add("privilege_expansion", "organization role authority may expand")
		}
	}
	if strings.Contains(resourceName, "oidc") && actionClass != "delete" && actionClass != "replace" && actionClass != "forget" {
		oidcCatalogAuthorized = oidcChangeMatchesCatalog(resourceName, address, after, catalog)
		if oidcCatalogAuthorized {
			add("privilege_expansion", "catalog-authorized OIDC subject template is established or reconciled")
		} else {
			add("oidc_mutation", "OIDC subject template does not exactly match the compiled catalog authority")
		}
	}
	if strings.Contains(resourceName, "environment") && (transitionedBool(before, after, "can_admins_bypass", false, true) || transitionedBool(before, after, "prevent_self_review", true, false)) {
		add("environment_bypass", "environment approval bypass or self-review protection is weakened")
	}
	if resourceName == "github_repository_environment" && (actionClass == "create" || actionClass == "update") {
		if canAdminsBypass, known := after["can_admins_bypass"].(bool); !known || canAdminsBypass {
			add("environment_bypass", "protected-environment after-state permits or ambiguously permits administrator bypass")
		}
		if preventSelfReview, known := after["prevent_self_review"].(bool); !known || !preventSelfReview {
			add("environment_bypass", "protected-environment after-state permits or ambiguously permits self-review")
		}
	}
	if resourceName == "github_repository_dependabot_security_updates" && (actionClass == "create" || actionClass == "update") {
		if enabled, known := after["enabled"].(bool); !known || !enabled {
			add("security_weakening", "Dependabot security updates are disabled or unknown in the resource after-state")
		}
	}
	if resourceName == "github_actions_repository_access_level" && actionClass == "update" && !equalPlanMaps(before, after) {
		oldRank, oldKnown := repositoryActionsAccessRank(before["access_level"])
		newRank, newKnown := repositoryActionsAccessRank(after["access_level"])
		if !oldKnown || !newKnown {
			add("unknown_change", "repository Actions access transition is missing or malformed")
		} else if newRank > oldRank {
			add("privilege_expansion", "catalog-authorized reusable workflow audience expands")
		} else if newRank < oldRank {
			add("permission_reduction", "reusable workflow sharing authority is narrowed")
		}
	}
	if resourceName == "github_repository_custom_property" && actionClass == "update" && !equalPlanMaps(before, after) {
		classifyRepositoryPropertySemantic(before, after, add)
	}
	if resourceName == "github_repository_environment" {
		classifyEnvironmentReviewerChange(actionClass, before, after, add)
		classifyEnvironmentBranchPolicyChange(actionClass, before, after, add)
	}
	if resourceName == "github_repository_environment_deployment_policy" && !equalPlanMaps(before, after) {
		classifyEnvironmentDeploymentPolicyChange(actionClass, before, after, add)
	}
	if resourceName == "github_actions_environment_variable" && actionClass != "delete" && !equalPlanMaps(before, after) {
		add("privilege_expansion", "connected workload-identity or archive handoff authority is established or changed")
	}
	visitFieldChanges(before, after, func(key string, oldValue, newValue any) {
		lowerKey := strings.ToLower(key)
		if lowerKey == "visibility" {
			oldVisibility := fmt.Sprint(oldValue)
			newVisibility := fmt.Sprint(newValue)
			if visibilityRank(newVisibility) > visibilityRank(oldVisibility) {
				add("privilege_expansion", "repository audience expands")
			}
			if strings.EqualFold(newVisibility, "public") && !strings.EqualFold(oldVisibility, "public") {
				add("public_visibility", "repository visibility expands to public")
			}
		}
		if lowerKey == "private" && boolTransition(oldValue, newValue, true, false) {
			add("privilege_expansion", "repository audience expands beyond private")
			if !strings.EqualFold(fmt.Sprint(after["visibility"]), "internal") {
				add("public_visibility", "private repository protection is removed without an internal-visibility constraint")
			}
		}
		if lowerKey == "enabled_repositories" && strings.EqualFold(fmt.Sprint(newValue), "all") && !strings.EqualFold(fmt.Sprint(oldValue), "all") {
			add("actions_policy_expansion", "GitHub Actions execution expands to all repositories")
		}
		if lowerKey == "enabled_repositories" && resourceName == "github_actions_organization_permissions" && actionClass == "update" {
			oldScope, oldScopeKnown := normalizedActionsRepositoryScope(oldValue)
			newScope, newScopeKnown := normalizedActionsRepositoryScope(newValue)
			if !oldScopeKnown || !newScopeKnown {
				add("unknown_change", "GitHub Actions repository execution scope is missing or malformed")
			}
			if newScope == "none" && oldScope != "none" {
				add("destructive", "GitHub Actions is disabled organization-wide, including governance recovery workflows")
			}
		}
		if (lowerKey == "allowed_actions" || lowerKey == "mode") && strings.EqualFold(fmt.Sprint(newValue), "all") && !strings.EqualFold(fmt.Sprint(oldValue), "all") {
			add("actions_policy_expansion", "GitHub Actions allow policy expands to all actions")
		}
		if (lowerKey == "allowed_actions" || lowerKey == "mode") &&
			strings.EqualFold(fmt.Sprint(oldValue), "selected") &&
			strings.EqualFold(fmt.Sprint(newValue), "local_only") {
			add("actions_policy_expansion", "GitHub Actions allow policy expands from reviewed pins to every local action")
		}
		if lowerKey == "default_workflow_permissions" && strings.EqualFold(fmt.Sprint(newValue), "write") && !strings.EqualFold(fmt.Sprint(oldValue), "write") {
			add("actions_policy_expansion", "default workflow token permission expands to write")
		}
		if (lowerKey == "github_owned_allowed" || lowerKey == "verified_allowed" || lowerKey == "verified_creator_allowed" || lowerKey == "can_approve_pull_request_reviews") && boolTransition(oldValue, newValue, false, true) {
			add("actions_policy_expansion", "GitHub Actions trust or workflow-token authority expands")
		}
		if lowerKey == "include_claim_keys" && !oidcCatalogAuthorized {
			add("oidc_mutation", "OIDC subject claim keys change")
		}
		if lowerKey == "bypass_actors" && containsNewElements(oldValue, newValue) {
			add("protection_weakening", "a ruleset bypass actor is added")
		}
		if (lowerKey == "required_status_checks" || lowerKey == "required_reviewers") && containsRemovedElements(oldValue, newValue) {
			add("protection_weakening", "a required check or reviewer is removed")
		}
		if lowerKey == "type" && strings.Contains(resourceName, "ruleset") && oldValue != nil && newValue == nil {
			add("protection_weakening", "a ruleset protection rule is removed")
		}
		if lowerKey == "patterns_allowed" && containsNewElements(oldValue, newValue) {
			if !actionPinRotationAuthorized {
				add("actions_policy_expansion", "the selected Actions allowlist expands or does not match reviewed pin rotation authority")
			}
		}
		if lowerKey == "selected_repository_ids" && containsNewElements(oldValue, newValue) {
			add("actions_policy_expansion", "the selected Actions repository scope expands")
		}
		if (lowerKey == "include" || lowerKey == "include_refs") && containsRemovedElements(oldValue, newValue) {
			add("protection_weakening", "a protected ref or repository is removed from ruleset scope")
		}
		if (lowerKey == "exclude" || lowerKey == "exclude_refs") && containsNewElements(oldValue, newValue) {
			add("protection_weakening", "a ruleset exclusion is added")
		}
		if lowerKey == "permission" || lowerKey == "role" || strings.HasSuffix(lowerKey, "_permission") {
			if accessRank(fmt.Sprint(newValue)) > accessRank(fmt.Sprint(oldValue)) {
				add("privilege_expansion", "an access permission increases")
			}
			if strings.EqualFold(fmt.Sprint(newValue), "admin") && !strings.EqualFold(fmt.Sprint(oldValue), "admin") {
				add("administrative_grant", "an administrative grant is introduced")
			}
		}
		if lowerKey == "privacy" && resourceName == "github_team" &&
			strings.EqualFold(fmt.Sprint(oldValue), "secret") &&
			strings.EqualFold(fmt.Sprint(newValue), "closed") {
			add("privilege_expansion", "team visibility expands from secret to organization-discoverable")
		}
		if lowerKey == "archived" && resourceName == "github_repository" && actionClass == "update" {
			oldArchived, oldArchivedKnown := oldValue.(bool)
			newArchived, newArchivedKnown := newValue.(bool)
			if !oldArchivedKnown || !newArchivedKnown {
				add("unknown_change", "repository archival state is missing or malformed")
			}
			if oldArchivedKnown && newArchivedKnown && !oldArchived && newArchived {
				add("destructive", "an active governed repository is archived")
			}
			if oldArchivedKnown && newArchivedKnown && oldArchived && !newArchived {
				add("privilege_expansion", "an archived repository is reactivated")
			}
		}
		if lowerKey == "parent_team_id" && resourceName == "github_team" {
			newParent, newParentKnown := positiveJSONInteger(newValue)
			oldParent, oldParentKnown := positiveJSONInteger(oldValue)
			if newParentKnown && (!oldParentKnown || oldParent != newParent) {
				add("privilege_expansion", "team inheritance changes to a positive parent team and may widen inherited access")
			}
		}
		if lowerKey == "do_not_enforce_on_create" && boolTransition(oldValue, newValue, false, true) {
			add("protection_weakening", "required status checks stop applying when protected references are created")
		}
		if lowerKey == "creation" && strings.Contains(resourceName, "ruleset") && actionClass == "update" {
			oldCreation, oldCreationKnown := oldValue.(bool)
			newCreation, newCreationKnown := newValue.(bool)
			if oldCreationKnown && oldCreation && (!newCreationKnown || !newCreation) {
				add("protection_weakening", "ruleset protection no longer restricts protected reference creation")
			} else if !oldCreationKnown || !newCreationKnown {
				add("unknown_change", "ruleset creation-protection state is missing or malformed")
			}
		}
		if lowerKey == "values_editable_by" && resourceName == "github_organization_custom_properties" &&
			!strings.EqualFold(fmt.Sprint(newValue), "org_actors") {
			add("protection_weakening", "repository actors gain authority to edit organization-governed custom-property values")
		}
		if (strings.Contains(lowerKey, "approving_review_count") || strings.Contains(lowerKey, "minimum_required_reviewers")) && numericValue(newValue) < numericValue(oldValue) {
			add("protection_weakening", "required approval count decreases")
		}
		if lowerKey == "enforcement" && enforcementRank(fmt.Sprint(newValue)) < enforcementRank(fmt.Sprint(oldValue)) {
			add("protection_weakening", "ruleset enforcement weakens")
		}
		if isProtectiveBoolean(lowerKey) && boolTransition(oldValue, newValue, true, false) {
			class := "protection_weakening"
			if strings.Contains(lowerKey, "security") || strings.Contains(lowerKey, "scanning") || strings.Contains(lowerKey, "vulnerability") || strings.Contains(lowerKey, "dependabot") {
				class = "security_weakening"
			}
			add(class, "a required protection changes from enabled to disabled")
		}
		if lowerKey == "status" && resourceName == "github_repository" && strings.EqualFold(fmt.Sprint(oldValue), "enabled") && !strings.EqualFold(fmt.Sprint(newValue), "enabled") {
			add("security_weakening", "a repository security-and-analysis control is disabled")
		}
		if lowerKey == "enabled" && resourceName == "github_repository_dependabot_security_updates" && boolTransition(oldValue, newValue, true, false) {
			add("security_weakening", "Dependabot security updates are disabled")
		}
		if (strings.HasPrefix(lowerKey, "members_can_") || strings.HasPrefix(lowerKey, "allow_")) && boolTransition(oldValue, newValue, false, true) {
			add("privilege_expansion", "an organization or repository capability expands")
		}
	})
	if len(classes) == 0 {
		classes["routine_write"] = struct{}{}
	}
	return sortedKeys(classes), sortedKeys(reasons)
}

func governedRetirementAddress(resourceType, address string) bool {
	key, ok := terraformInstanceKey(address)
	if !ok {
		return false
	}
	base := ""
	switch resourceType {
	case "github_actions_environment_variable":
		base = "module.repository_environments.github_actions_environment_variable.this"
	case "github_repository_environment":
		base = "module.repository_environments.github_repository_environment.this"
	case "github_repository_environment_deployment_policy":
		base = "module.repository_environments.github_repository_environment_deployment_policy.this"
	case "github_organization_ruleset":
		base = "module.rulesets.github_organization_ruleset.this"
	case "github_team":
		base = "module.team_access.github_team.this"
	default:
		return false
	}
	return exactIndexedAddress(address, base, key)
}

// classifyEnvironmentReviewerChange models GitHub environment reviewers as
// OR-authorities. Adding an authority to an established reviewer gate expands
// who can approve, while removing only some authorities narrows access. The
// last removal eliminates the gate and is therefore a fundamental bypass.
func classifyEnvironmentReviewerChange(actionClass string, before, after map[string]any, add func(string, string)) {
	if actionClass != "create" && actionClass != "update" {
		return
	}
	if after == nil || (actionClass == "update" && before == nil) {
		add("unknown_change", "protected-environment reviewer authority state is missing or malformed")
		return
	}
	afterAuthorities, afterKnown := environmentReviewerAuthorities(after["reviewers"])
	if !afterKnown {
		add("unknown_change", "protected-environment reviewer authority state is missing or malformed")
		return
	}
	if actionClass == "create" {
		if len(afterAuthorities) == 0 {
			add("environment_bypass", "protected environment is created without a reviewer approval authority")
		}
		return
	}
	beforeAuthorities, beforeKnown := environmentReviewerAuthorities(before["reviewers"])
	if !beforeKnown {
		add("unknown_change", "protected-environment reviewer authority state is missing or malformed")
		return
	}
	added := setContainsNewAuthority(beforeAuthorities, afterAuthorities)
	removed := setContainsNewAuthority(afterAuthorities, beforeAuthorities)
	if added {
		add("environment_bypass", "a protected-environment reviewer OR-authority is added")
	}
	if len(beforeAuthorities) > 0 && len(afterAuthorities) == 0 {
		add("environment_bypass", "the final protected-environment reviewer authority is removed")
		return
	}
	if removed && !added {
		add("permission_reduction", "protected-environment reviewer authority is narrowed while retaining an approval gate")
	}
}

type environmentBranchPolicy struct {
	present              bool
	protectedBranches    bool
	customBranchPolicies bool
}

func classifyEnvironmentBranchPolicyChange(actionClass string, before, after map[string]any, add func(string, string)) {
	if actionClass != "create" && actionClass != "update" {
		return
	}
	if after == nil || (actionClass == "update" && before == nil) {
		add("unknown_change", "protected-environment deployment branch policy is missing or malformed")
		return
	}
	afterPolicy, afterKnown := parseEnvironmentBranchPolicy(after["deployment_branch_policy"])
	if !afterKnown {
		add("unknown_change", "protected-environment deployment branch policy is missing or malformed")
		return
	}
	if actionClass == "create" {
		if !afterPolicy.present {
			add("environment_bypass", "protected environment is created without a deployment branch policy")
		}
		return
	}
	beforePolicy, beforeKnown := parseEnvironmentBranchPolicy(before["deployment_branch_policy"])
	if !beforeKnown {
		add("unknown_change", "protected-environment deployment branch policy is missing or malformed")
		return
	}
	if beforePolicy.present && !afterPolicy.present {
		add("environment_bypass", "protected-environment deployment branch policy is removed")
		return
	}
	if beforePolicy.present && afterPolicy.present && beforePolicy != afterPolicy {
		add("environment_bypass", "protected-environment deployment branch policy changes without a provable narrowing")
	}
}

func parseEnvironmentBranchPolicy(value any) (environmentBranchPolicy, bool) {
	if value == nil {
		return environmentBranchPolicy{}, true
	}
	blocks, ok := value.([]any)
	if !ok {
		return environmentBranchPolicy{}, false
	}
	if len(blocks) == 0 {
		return environmentBranchPolicy{}, true
	}
	if len(blocks) != 1 {
		return environmentBranchPolicy{}, false
	}
	block, ok := blocks[0].(map[string]any)
	if !ok || len(block) != 2 {
		return environmentBranchPolicy{}, false
	}
	protectedBranches, protectedKnown := block["protected_branches"].(bool)
	customBranchPolicies, customKnown := block["custom_branch_policies"].(bool)
	if !protectedKnown || !customKnown {
		return environmentBranchPolicy{}, false
	}
	return environmentBranchPolicy{
		present:              true,
		protectedBranches:    protectedBranches,
		customBranchPolicies: customBranchPolicies,
	}, true
}

func classifyEnvironmentDeploymentPolicyChange(
	actionClass string, before, after map[string]any, add func(string, string),
) {
	if actionClass != "create" && actionClass != "update" {
		return
	}
	_, _, afterKnown := environmentDeploymentPolicyPattern(after)
	if !afterKnown {
		add("unknown_change", "environment deployment-policy branch or tag pattern is missing or malformed")
		if actionClass == "update" {
			add("protection_weakening", "environment deployment-policy protection is removed or becomes ambiguous")
		}
		return
	}
	if actionClass == "create" {
		return
	}
	beforeType, beforePattern, beforeKnown := environmentDeploymentPolicyPattern(before)
	afterType, afterPattern, _ := environmentDeploymentPolicyPattern(after)
	if !beforeKnown {
		add("unknown_change", "prior environment deployment-policy branch or tag pattern is missing or malformed")
		return
	}
	if beforeType != afterType || beforePattern != afterPattern {
		add("protection_weakening", "environment deployment-policy ref type or pattern changes without a provable narrowing")
	}
}

func environmentDeploymentPolicyPattern(value map[string]any) (string, string, bool) {
	if value == nil {
		return "", "", false
	}
	branchPattern, branchKnown := optionalPattern(value["branch_pattern"])
	tagPattern, tagKnown := optionalPattern(value["tag_pattern"])
	if !branchKnown || !tagKnown || (branchPattern == "") == (tagPattern == "") {
		return "", "", false
	}
	if branchPattern != "" {
		return "branch", branchPattern, true
	}
	return "tag", tagPattern, true
}

func optionalPattern(value any) (string, bool) {
	if value == nil {
		return "", true
	}
	pattern, ok := value.(string)
	return pattern, ok
}

func environmentReviewerAuthorities(value any) (map[string]struct{}, bool) {
	result := make(map[string]struct{})
	if value == nil {
		return result, true
	}
	blocks, ok := value.([]any)
	if !ok {
		return nil, false
	}
	for _, rawBlock := range blocks {
		block, ok := rawBlock.(map[string]any)
		if !ok {
			return nil, false
		}
		for key := range block {
			if key != "teams" && key != "users" {
				return nil, false
			}
		}
		for _, authorityType := range []string{"teams", "users"} {
			rawAuthorities, exists := block[authorityType]
			if !exists || rawAuthorities == nil {
				continue
			}
			authorities, ok := rawAuthorities.([]any)
			if !ok {
				return nil, false
			}
			for _, rawAuthority := range authorities {
				authorityID, ok := positiveJSONInteger(rawAuthority)
				if !ok {
					return nil, false
				}
				identity := strings.TrimSuffix(authorityType, "s") + ":" + strconv.FormatInt(authorityID, 10)
				if _, duplicate := result[identity]; duplicate {
					return nil, false
				}
				result[identity] = struct{}{}
			}
		}
	}
	return result, true
}

func setContainsNewAuthority(before, after map[string]struct{}) bool {
	for authority := range after {
		if _, exists := before[authority]; !exists {
			return true
		}
	}
	return false
}

func normalizedActionsRepositoryScope(value any) (string, bool) {
	scope, ok := value.(string)
	if !ok {
		return "", false
	}
	scope = strings.ToLower(scope)
	switch scope {
	case "all", "selected", "none":
		return scope, true
	default:
		return scope, false
	}
}

func equalPlanMaps(before, after map[string]any) bool {
	beforeJSON, beforeErr := rendering.CanonicalJSON(before)
	afterJSON, afterErr := rendering.CanonicalJSON(after)
	return beforeErr == nil && afterErr == nil && string(beforeJSON) == string(afterJSON)
}

func terraformInstanceKey(address string) (string, bool) {
	matches := terraformStringInstanceKeyPattern.FindStringSubmatch(address)
	if len(matches) != 2 {
		return "", false
	}
	decoded, err := strconv.Unquote(`"` + matches[1] + `"`)
	return decoded, err == nil && decoded != ""
}

func exactIndexedAddress(address, base, key string) bool {
	return key != "" && address == base+"["+strconv.Quote(key)+"]"
}

func catalogAccessAfterState(resourceType, address string, after, catalog, observed map[string]any) bool {
	if after == nil || catalog == nil {
		return false
	}
	key, ok := terraformInstanceKey(address)
	if !ok {
		return false
	}
	switch resourceType {
	case "github_membership":
		if !exactIndexedAddress(address, "module.team_access.github_membership.this", key) {
			return false
		}
		for _, rawMember := range anySlice(catalog["members"]) {
			member, _ := rawMember.(map[string]any)
			login, _ := member["login"].(string)
			role, _ := member["role"].(string)
			if strings.EqualFold(login, key) && strings.EqualFold(login, stringMapField(after, "username")) && role == stringMapField(after, "role") {
				return true
			}
		}
		return false
	case "github_team_membership":
		if !exactIndexedAddress(address, "module.team_access.github_team_membership.this", key) {
			return false
		}
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			return false
		}
		teamKey, login := parts[0], parts[1]
		teams, _ := catalog["teams"].(map[string]any)
		team, _ := teams[teamKey].(map[string]any)
		if team == nil || !strings.EqualFold(login, stringMapField(after, "username")) {
			return false
		}
		memberMatches := 0
		for _, rawMember := range anySlice(team["members"]) {
			member, _ := rawMember.(map[string]any)
			if strings.EqualFold(stringMapField(member, "login"), login) && stringMapField(member, "role") == stringMapField(after, "role") {
				memberMatches++
			}
		}
		expectedTeamID, idKnown := observedTeamID(observed, teamKey, stringMapField(team, "name"))
		actualTeamID, actualKnown := positiveProviderTeamID(after["team_id"])
		return memberMatches == 1 && idKnown && actualKnown && expectedTeamID == actualTeamID
	case "github_team_repository":
		if !exactIndexedAddress(address, "module.team_access.github_team_repository.this", key) {
			return false
		}
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			return false
		}
		repositoryKey, teamKey := parts[0], parts[1]
		repositories, _ := catalog["repositories"].(map[string]any)
		repository, _ := repositories[repositoryKey].(map[string]any)
		teams, _ := catalog["teams"].(map[string]any)
		team, _ := teams[teamKey].(map[string]any)
		if repository == nil || team == nil || stringMapField(after, "repository") != stringMapField(repository, "name") {
			return false
		}
		grantMatches := 0
		for _, rawGrant := range anySlice(repository["team_grants"]) {
			grant, _ := rawGrant.(map[string]any)
			if stringMapField(grant, "team") == teamKey && stringMapField(grant, "permission") == stringMapField(after, "permission") {
				grantMatches++
			}
		}
		expectedTeamID, idKnown := observedTeamID(observed, teamKey, stringMapField(team, "name"))
		actualTeamID, actualKnown := positiveProviderTeamID(after["team_id"])
		return grantMatches == 1 && idKnown && actualKnown && expectedTeamID == actualTeamID
	default:
		return false
	}
}

// catalogAccessRevocationAllowed proves that a permission-reduction delete is
// the exact removal of an observed grant that no longer exists in the desired
// catalog. This prevents a for_each key rename or forged address from being
// treated as safe offboarding.
func catalogAccessRevocationAllowed(resourceType, address string, before, catalog, observed map[string]any) bool {
	if before == nil || catalog == nil || observed == nil {
		return false
	}
	key, ok := terraformInstanceKey(address)
	if !ok {
		return false
	}
	switch resourceType {
	case "github_membership":
		if !exactIndexedAddress(address, "module.team_access.github_membership.this", key) ||
			!strings.EqualFold(key, stringMapField(before, "username")) {
			return false
		}
		role := stringMapField(before, "role")
		if role != "member" && role != "admin" {
			return false
		}
		for _, rawMember := range anySlice(catalog["members"]) {
			member, _ := rawMember.(map[string]any)
			if strings.EqualFold(stringMapField(member, "login"), key) {
				return false
			}
		}
		observedRole, observedKnown := observedOrganizationMemberRole(observed, key)
		return observedKnown && observedRole == role
	case "github_team_membership":
		if !exactIndexedAddress(address, "module.team_access.github_team_membership.this", key) {
			return false
		}
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[1], stringMapField(before, "username")) {
			return false
		}
		teamKey, login := parts[0], parts[1]
		teams, _ := catalog["teams"].(map[string]any)
		team, _ := teams[teamKey].(map[string]any)
		if team == nil {
			return false
		}
		for _, rawMember := range anySlice(team["members"]) {
			member, _ := rawMember.(map[string]any)
			if strings.EqualFold(stringMapField(member, "login"), login) {
				return false
			}
		}
		expectedTeamID, idKnown := observedTeamID(observed, teamKey, stringMapField(team, "name"))
		actualTeamID, actualKnown := positiveProviderTeamID(before["team_id"])
		role := stringMapField(before, "role")
		return idKnown && actualKnown && expectedTeamID == actualTeamID &&
			observedTeamMembershipMatches(observed, teamKey, stringMapField(team, "name"), login, role)
	case "github_team_repository":
		if !exactIndexedAddress(address, "module.team_access.github_team_repository.this", key) {
			return false
		}
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			return false
		}
		repositoryKey, teamKey := parts[0], parts[1]
		repositories, _ := catalog["repositories"].(map[string]any)
		repository, _ := repositories[repositoryKey].(map[string]any)
		teams, _ := catalog["teams"].(map[string]any)
		team, _ := teams[teamKey].(map[string]any)
		if repository == nil || team == nil || stringMapField(before, "repository") != stringMapField(repository, "name") {
			return false
		}
		for _, rawGrant := range anySlice(repository["team_grants"]) {
			grant, _ := rawGrant.(map[string]any)
			if stringMapField(grant, "team") == teamKey {
				return false
			}
		}
		expectedTeamID, idKnown := observedTeamID(observed, teamKey, stringMapField(team, "name"))
		actualTeamID, actualKnown := positiveProviderTeamID(before["team_id"])
		return idKnown && actualKnown && expectedTeamID == actualTeamID && observedRepositoryTeamGrantMatches(
			observed, stringMapField(repository, "name"), stringMapField(team, "name"), expectedTeamID,
			stringMapField(before, "permission"),
		)
	case "github_repository_collaborator":
		if !exactIndexedAddress(address, "module.team_access.github_repository_collaborator.outside", key) {
			return false
		}
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], stringMapField(before, "username")) {
			return false
		}
		login, repositoryKey := parts[0], parts[1]
		repositories, _ := catalog["repositories"].(map[string]any)
		repository, _ := repositories[repositoryKey].(map[string]any)
		if repository == nil || stringMapField(before, "repository") != stringMapField(repository, "name") {
			return false
		}
		for _, rawCollaborator := range anySlice(catalog["outside_collaborators"]) {
			collaborator, _ := rawCollaborator.(map[string]any)
			if !strings.EqualFold(stringMapField(collaborator, "login"), login) {
				continue
			}
			for _, rawGrant := range anySlice(collaborator["repository_permissions"]) {
				grant, _ := rawGrant.(map[string]any)
				if stringMapField(grant, "repository") == repositoryKey {
					return false
				}
			}
		}
		return observedRepositoryCollaboratorMatches(
			observed, stringMapField(repository, "name"), login, stringMapField(before, "permission"),
		)
	default:
		return false
	}
}

func observedOrganizationMemberRole(observed map[string]any, login string) (string, bool) {
	matches := 0
	for _, rawMember := range anySlice(observed["members"]) {
		member, _ := rawMember.(map[string]any)
		if strings.EqualFold(stringMapField(member, "login"), login) {
			matches++
		}
	}
	if matches != 1 {
		return "", false
	}
	role := "member"
	adminMatches := 0
	for _, rawAdmin := range anySlice(observed["organization_admins"]) {
		admin, _ := rawAdmin.(map[string]any)
		if strings.EqualFold(stringMapField(admin, "login"), login) {
			adminMatches++
		}
	}
	if adminMatches > 1 {
		return "", false
	}
	if adminMatches == 1 {
		role = "admin"
	}
	return role, true
}

func observedTeamMembershipMatches(observed map[string]any, teamKey, teamName, login, role string) bool {
	if role != "member" && role != "maintainer" {
		return false
	}
	teamMembers, _ := observed["team_members"].(map[string]any)
	for _, key := range []string{teamName, teamKey} {
		matches := 0
		for _, rawMember := range anySlice(teamMembers[key]) {
			member, _ := rawMember.(map[string]any)
			if strings.EqualFold(stringMapField(member, "login"), login) && stringMapField(member, "role") == role {
				matches++
			}
		}
		if matches == 1 {
			return true
		}
	}
	return false
}

func observedRepositoryTeamGrantMatches(observed map[string]any, repository, team string, teamID int64, permission string) bool {
	if repository == "" || team == "" || permission == "" {
		return false
	}
	grantsByRepository, _ := observed["repository_team_grants"].(map[string]any)
	matches := 0
	for _, rawGrant := range anySlice(grantsByRepository[repository]) {
		grant, _ := rawGrant.(map[string]any)
		observedTeam := stringMapField(grant, "slug")
		if observedTeam == "" {
			observedTeam = stringMapField(grant, "name")
		}
		observedPermission := stringMapField(grant, "permission")
		if observedPermission == "" {
			observedPermission = stringMapField(grant, "role_name")
		}
		observedID, idKnown := positiveJSONInteger(grant["id"])
		if observedTeam == team && observedPermission == permission && idKnown && observedID == teamID {
			matches++
		}
	}
	return matches == 1
}

func observedRepositoryCollaboratorMatches(observed map[string]any, repository, login, permission string) bool {
	if repository == "" || login == "" || permission == "" {
		return false
	}
	collaboratorsByRepository, _ := observed["repository_direct_collaborators"].(map[string]any)
	matches := 0
	for _, rawCollaborator := range anySlice(collaboratorsByRepository[repository]) {
		collaborator, _ := rawCollaborator.(map[string]any)
		observedPermission := stringMapField(collaborator, "role_name")
		if observedPermission == "" {
			observedPermission = stringMapField(collaborator, "permission")
		}
		if strings.EqualFold(stringMapField(collaborator, "login"), login) && observedPermission == permission {
			matches++
		}
	}
	return matches == 1
}

func observedTeamID(observed map[string]any, teamKey, teamName string) (int64, bool) {
	if observed == nil {
		return 0, false
	}
	teams, _ := observed["teams"].(map[string]any)
	for _, key := range []string{teamName, teamKey} {
		team, _ := teams[key].(map[string]any)
		if id, ok := positiveJSONInteger(team["id"]); ok {
			return id, true
		}
	}
	return 0, false
}

func positiveProviderTeamID(value any) (int64, bool) {
	text, ok := value.(string)
	if !ok || text == "" || text[0] == '0' {
		return 0, false
	}
	for _, character := range text {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseInt(text, 10, 64)
	return parsed, err == nil && parsed > 0
}

func catalogRepositoryPropertyAfterState(address string, after, catalog map[string]any) bool {
	if after == nil || catalog == nil {
		return false
	}
	key, ok := terraformInstanceKey(address)
	if !ok || !exactIndexedAddress(address, "module.repository_governance.github_repository_custom_property.this", key) {
		return false
	}
	parts := strings.SplitN(key, ":", 2)
	if len(parts) != 2 {
		return false
	}
	repositoryKey, propertyName := parts[0], parts[1]
	repositories, _ := catalog["repositories"].(map[string]any)
	repository, _ := repositories[repositoryKey].(map[string]any)
	properties, _ := repository["custom_properties"].(map[string]any)
	expectedValue, exists := properties[propertyName]
	if repository == nil || !exists || stringMapField(after, "repository") != stringMapField(repository, "name") ||
		stringMapField(after, "property_name") != propertyName {
		return false
	}
	propertyType := ""
	organization, _ := catalog["organization"].(map[string]any)
	for _, rawProperty := range anySlice(organization["custom_properties"]) {
		property, _ := rawProperty.(map[string]any)
		if stringMapField(property, "name") == propertyName {
			propertyType = stringMapField(property, "value_type")
			break
		}
	}
	if propertyType == "" || stringMapField(after, "property_type") != propertyType {
		return false
	}
	expectedValues, expectedKnown := normalizedPropertyValues(expectedValue)
	actualValues, actualKnown := normalizedPropertyValues(after["property_value"])
	return expectedKnown && actualKnown && equalStringSlices(expectedValues, actualValues)
}

func catalogRepositoryActionsAccessAfterState(address string, after, catalog map[string]any) bool {
	if after == nil || catalog == nil {
		return false
	}
	key, ok := terraformInstanceKey(address)
	if !ok || !exactIndexedAddress(address, "module.repository_governance.github_actions_repository_access_level.this", key) {
		return false
	}
	repositories, _ := catalog["repositories"].(map[string]any)
	repository, _ := repositories[key].(map[string]any)
	return repository != nil &&
		exactStringField(after, "repository", stringMapField(repository, "name")) &&
		exactStringField(after, "access_level", stringMapField(repository, "actions_access_level"))
}

func catalogOrganizationPropertyAfterState(address string, after, catalog, observed map[string]any) bool {
	if after == nil || catalog == nil {
		return false
	}
	key, ok := terraformInstanceKey(address)
	if !ok || !exactIndexedAddress(address, "module.organization_settings.github_organization_custom_properties.this", key) {
		return false
	}
	organization, _ := catalog["organization"].(map[string]any)
	migration, _ := organization["custom_property_migration"].(map[string]any)
	if stringMapField(migration, "phase") == "retire" && !catalogCustomPropertyAssignmentsConverged(catalog, observed) {
		return false
	}
	matches := 0
	for _, rawProperty := range anySlice(organization["custom_properties"]) {
		property, _ := rawProperty.(map[string]any)
		if stringMapField(property, "name") != key {
			continue
		}
		matches++
		expectedValues, expectedKnown := normalizedStringList(effectiveOrganizationPropertyAllowedValues(organization, property))
		actualValues, actualKnown := normalizedStringList(after["allowed_values"])
		if !expectedKnown || !actualKnown || !equalStringSlices(expectedValues, actualValues) ||
			!exactStringField(after, "property_name", key) ||
			!exactStringField(after, "value_type", stringMapField(property, "value_type")) ||
			!exactBoolField(after, "required", boolMapField(property, "required")) ||
			!exactStringField(after, "values_editable_by", stringMapField(property, "values_editable_by")) {
			return false
		}
	}
	return matches == 1
}

func catalogCustomPropertyAssignmentsConverged(catalog, observed map[string]any) bool {
	if catalog == nil || observed == nil {
		return false
	}
	repositories, _ := catalog["repositories"].(map[string]any)
	liveRepositories, _ := observed["repositories"].(map[string]any)
	liveProperties, _ := observed["repository_custom_properties"].(map[string]any)
	if len(repositories) == 0 || len(liveRepositories) != len(repositories) {
		return false
	}
	for _, rawRepository := range repositories {
		repository, _ := rawRepository.(map[string]any)
		name := stringMapField(repository, "name")
		liveRepository, exists := liveRepositories[name].(map[string]any)
		if name == "" || !exists || stringMapField(liveRepository, "name") != name {
			return false
		}
		desiredProperties, _ := repository["custom_properties"].(map[string]any)
		for propertyName, desiredValue := range desiredProperties {
			liveValue, found := evidenceRepositoryPropertyValue(liveProperties[name], propertyName)
			if !found || !canonicalSemanticEqual(desiredValue, liveValue) {
				return false
			}
		}
	}
	return true
}

func evidenceRepositoryPropertyValue(value any, propertyName string) (any, bool) {
	for _, rawProperty := range anySlice(value) {
		property, _ := rawProperty.(map[string]any)
		if stringMapField(property, "property_name") == propertyName {
			liveValue, exists := property["value"]
			return liveValue, exists
		}
	}
	return nil, false
}

func effectiveOrganizationPropertyAllowedValues(organization, property map[string]any) any {
	values, known := normalizedStringList(property["allowed_values"])
	if !known {
		return property["allowed_values"]
	}
	migration, _ := organization["custom_property_migration"].(map[string]any)
	if stringMapField(migration, "phase") != "preserve" {
		return stringsToAny(values)
	}
	legacy, _ := migration["legacy_allowed_values"].(map[string]any)
	legacyValues, legacyKnown := normalizedStringList(legacy[stringMapField(property, "name")])
	if legacy[stringMapField(property, "name")] != nil && !legacyKnown {
		return nil
	}
	values = append(values, legacyValues...)
	sort.Strings(values)
	unique := values[:0]
	for _, value := range values {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return stringsToAny(unique)
}

func catalogTeamAfterState(address string, after, catalog map[string]any) bool {
	if after == nil || catalog == nil {
		return false
	}
	key, ok := terraformInstanceKey(address)
	if !ok || !exactIndexedAddress(address, "module.team_access.github_team.this", key) {
		return false
	}
	teams, _ := catalog["teams"].(map[string]any)
	team, _ := teams[key].(map[string]any)
	return team != nil &&
		exactStringField(after, "name", stringMapField(team, "name")) &&
		exactStringField(after, "description", stringMapField(team, "description")) &&
		exactStringField(after, "privacy", stringMapField(team, "privacy"))
}

func catalogRepositoryAfterState(address string, after, catalog map[string]any) bool {
	if after == nil || catalog == nil {
		return false
	}
	key, ok := terraformInstanceKey(address)
	if !ok || !exactIndexedAddress(address, "module.repository_governance.github_repository.this", key) {
		return false
	}
	repositories, _ := catalog["repositories"].(map[string]any)
	repository, _ := repositories[key].(map[string]any)
	if repository == nil ||
		!exactStringField(after, "name", stringMapField(repository, "name")) ||
		!exactStringField(after, "description", stringMapField(repository, "description")) ||
		!exactStringField(after, "visibility", stringMapField(repository, "visibility")) ||
		!exactBoolField(after, "archived", boolMapField(repository, "archived")) ||
		!exactBoolField(after, "archive_on_destroy", boolMapField(repository, "archive_on_destroy")) {
		return false
	}
	mergePolicy, _ := repository["merge_policy"].(map[string]any)
	for _, field := range []string{
		"delete_branch_on_merge", "allow_auto_merge", "allow_merge_commit", "allow_rebase_merge",
		"allow_squash_merge", "allow_update_branch",
	} {
		if !exactBoolField(after, field, boolMapField(mergePolicy, field)) {
			return false
		}
	}
	for _, field := range []string{"squash_merge_commit_title", "squash_merge_commit_message"} {
		if !exactStringField(after, field, stringMapField(mergePolicy, field)) {
			return false
		}
	}
	features, _ := repository["features"].(map[string]any)
	for providerField, catalogField := range map[string]string{
		"has_issues": "issues", "has_projects": "projects", "has_wiki": "wiki",
		"has_discussions": "discussions", "has_downloads": "downloads",
	} {
		if !exactBoolField(after, providerField, boolMapField(features, catalogField)) {
			return false
		}
	}
	security, _ := repository["security"].(map[string]any)
	if !exactBoolField(after, "vulnerability_alerts", boolMapField(security, "vulnerability_alerts")) {
		return false
	}
	organization, _ := catalog["organization"].(map[string]any)
	if !exactBoolField(after, "web_commit_signoff_required", boolMapField(organization, "web_commit_signoff_required")) {
		return false
	}
	return exactRepositorySecurityBlock(after["security_and_analysis"], security)
}

func exactRepositorySecurityBlock(value any, security map[string]any) bool {
	blocks, ok := value.([]any)
	if !ok || len(blocks) != 1 {
		return false
	}
	block, _ := blocks[0].(map[string]any)
	if block == nil || len(block) != 3 {
		return false
	}
	for providerField, catalogField := range map[string]string{
		"advanced_security": "advanced_security", "secret_scanning": "secret_scanning",
		"secret_scanning_push_protection": "secret_scanning_push_protection",
	} {
		settings, ok := block[providerField].([]any)
		if !ok || len(settings) != 1 {
			return false
		}
		setting, _ := settings[0].(map[string]any)
		expected := "disabled"
		if boolMapField(security, catalogField) {
			expected = "enabled"
		}
		if setting == nil || len(setting) != 1 || !exactStringField(setting, "status", expected) {
			return false
		}
	}
	return true
}

func catalogRulesetAfterState(address string, after, catalog, observed map[string]any, phase string) bool {
	if after == nil || catalog == nil {
		return false
	}
	physicalKey, ok := terraformInstanceKey(address)
	if !ok || !exactIndexedAddress(address, "module.rulesets.github_organization_ruleset.this", physicalKey) {
		return false
	}
	logicalKey := strings.TrimSuffix(physicalKey, "--creator-gate")
	creatorGate := logicalKey != physicalKey
	rulesets, _ := catalog["rulesets"].(map[string]any)
	ruleset, _ := rulesets[logicalKey].(map[string]any)
	if ruleset == nil {
		return false
	}
	rules, _ := ruleset["rules"].(map[string]any)
	creationRestricted := boolMapField(rules, "creation_restricted")
	if creatorGate && !(stringMapField(ruleset, "target") == "tag" && creationRestricted) {
		return false
	}
	effectiveName := stringMapField(ruleset, "name")
	if effectiveName == "" {
		effectiveName = logicalKey
	}
	if creatorGate {
		effectiveName += "-creator-gate"
	}
	enforcement := stringMapField(ruleset, "enforcement")
	switch phase {
	case "adopt":
		enforcement = observedRulesetEnforcement(observed, "", effectiveName, "disabled")
	case "foundation":
		enforcement = observedRulesetEnforcement(observed, "", effectiveName, "evaluate")
	case "enforce":
	default:
		return false
	}
	repositoryNames := make([]any, 0)
	for _, rawReference := range anySlice(ruleset["repositories"]) {
		reference, _ := rawReference.(string)
		name := catalogRepositoryName(reference, catalog)
		if name == "" {
			return false
		}
		repositoryNames = append(repositoryNames, name)
	}
	expectedRules, rulesKnown := physicalRulesetRules(rules, creatorGate, phase)
	if !rulesKnown {
		return false
	}
	expectedActors, actorsKnown := physicalRulesetActors(ruleset, rules, creatorGate, phase, catalog, observed)
	if !actorsKnown {
		return false
	}
	expected := map[string]any{
		"name":          effectiveName,
		"target":        ruleset["target"],
		"enforcement":   enforcement,
		"bypass_actors": expectedActors,
		"conditions": []any{map[string]any{
			"repository_name": []any{map[string]any{
				"include": repositoryNames, "exclude": []any{}, "protected": true,
			}},
			"ref_name": []any{map[string]any{
				"include": anySlice(ruleset["include_refs"]), "exclude": anySlice(ruleset["exclude_refs"]),
			}},
		}},
		"rules": []any{expectedRules},
	}
	afterProjection := make(map[string]any, len(expected))
	for key := range expected {
		value, exists := after[key]
		if !exists {
			return false
		}
		afterProjection[key] = value
	}
	return canonicalSemanticEqual(afterProjection, expected)
}

func observedRulesetEnforcement(observed map[string]any, repositoryName, rulesetName, fallback string) string {
	if observed == nil || rulesetName == "" {
		return fallback
	}
	var rulesets map[string]any
	if repositoryName == "" {
		rulesets, _ = observed["rulesets"].(map[string]any)
	} else {
		byRepository, _ := observed["repository_rulesets"].(map[string]any)
		rulesets, _ = byRepository[repositoryName].(map[string]any)
	}
	ruleset, _ := rulesets[rulesetName].(map[string]any)
	enforcement := stringMapField(ruleset, "enforcement")
	if enforcement == "disabled" || enforcement == "evaluate" || enforcement == "active" {
		return enforcement
	}
	return fallback
}

func physicalRulesetRules(source map[string]any, creatorGate bool, phase string) (map[string]any, bool) {
	if source == nil {
		return nil, false
	}
	sourceCreation := boolMapField(source, "creation_restricted")
	creation := phase == "enforce" && sourceCreation
	update := boolMapField(source, "update")
	deletion := boolMapField(source, "deletion")
	nonFastForward := boolMapField(source, "non_fast_forward")
	linearHistory := boolMapField(source, "required_linear_history")
	signatures := boolMapField(source, "required_signatures")
	pullRequest := source["pull_request"]
	statusChecks := source["required_status_checks"]
	if creatorGate {
		creation = phase == "enforce"
		update = false
		deletion = false
		nonFastForward = false
		linearHistory = false
		signatures = false
		pullRequest = nil
		statusChecks = nil
	} else if sourceCreation {
		creation = false
		linearHistory = false
		signatures = false
		pullRequest = nil
		statusChecks = nil
	}
	expected := map[string]any{
		"creation": creation, "update": update, "deletion": deletion,
		"non_fast_forward": nonFastForward, "required_linear_history": linearHistory,
		"required_signatures": signatures,
		"pull_request":        []any{}, "required_status_checks": []any{},
	}
	if pull, ok := pullRequest.(map[string]any); ok {
		expected["pull_request"] = []any{map[string]any{
			"dismiss_stale_reviews_on_push":     pull["dismiss_stale_reviews"],
			"require_code_owner_review":         pull["require_code_owner_review"],
			"require_last_push_approval":        pull["require_last_push_approval"],
			"required_approving_review_count":   pull["required_approving_review_count"],
			"required_review_thread_resolution": pull["required_review_thread_resolution"],
		}}
	} else if pullRequest != nil {
		return nil, false
	}
	if checks, ok := statusChecks.(map[string]any); ok {
		requiredChecks := make([]any, 0)
		for _, rawCheck := range anySlice(checks["checks"]) {
			check, _ := rawCheck.(map[string]any)
			if check == nil || stringMapField(check, "context") == "" {
				return nil, false
			}
			requiredChecks = append(requiredChecks, map[string]any{
				"context": check["context"], "integration_id": check["integration_id"],
			})
		}
		expected["required_status_checks"] = []any{map[string]any{
			"strict_required_status_checks_policy": checks["strict"],
			"do_not_enforce_on_create":             false,
			"required_check":                       requiredChecks,
		}}
	} else if statusChecks != nil {
		return nil, false
	}
	return expected, true
}

func physicalRulesetActors(ruleset, rules map[string]any, creatorGate bool, phase string, catalog, observed map[string]any) ([]any, bool) {
	result := make([]any, 0)
	if !creatorGate {
		for _, rawActor := range anySlice(ruleset["bypass_actors"]) {
			actor, _ := rawActor.(map[string]any)
			resolved, ok := resolveRulesetActor(actor, catalog, observed)
			if !ok {
				return nil, false
			}
			result = append(result, resolved)
		}
	}
	if creatorGate && phase == "enforce" {
		for _, rawIntegration := range anySlice(rules["authorized_creator_integrations"]) {
			integration, _ := rawIntegration.(string)
			resolved, ok := resolveRulesetActor(map[string]any{
				"actor_type": "integration", "actor": integration, "mode": "always",
			}, catalog, observed)
			if !ok {
				return nil, false
			}
			result = append(result, resolved)
		}
	}
	return result, true
}

func resolveRulesetActor(actor, catalog, observed map[string]any) (map[string]any, bool) {
	actorType := stringMapField(actor, "actor_type")
	actorKey := stringMapField(actor, "actor")
	mode := stringMapField(actor, "mode")
	if actorKey == "" || mode == "" || observed == nil {
		return nil, false
	}
	switch actorType {
	case "team":
		teams, _ := catalog["teams"].(map[string]any)
		team, _ := teams[actorKey].(map[string]any)
		id, ok := observedTeamID(observed, actorKey, stringMapField(team, "name"))
		if !ok {
			return nil, false
		}
		return map[string]any{"actor_type": "Team", "actor_id": id, "bypass_mode": mode}, true
	case "integration":
		integrations, _ := observed["integrations"].(map[string]any)
		integration, _ := integrations[actorKey].(map[string]any)
		id, ok := positiveJSONInteger(integration["actor_id"])
		if !ok {
			return nil, false
		}
		return map[string]any{"actor_type": "Integration", "actor_id": id, "bypass_mode": mode}, true
	default:
		return nil, false
	}
}

func canonicalSemanticEqual(left, right any) bool {
	leftJSON, leftErr := rendering.CanonicalJSON(normalizeSemanticCollections(left))
	rightJSON, rightErr := rendering.CanonicalJSON(normalizeSemanticCollections(right))
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func normalizeSemanticCollections(value any) any {
	switch current := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(current))
		for key, child := range current {
			result[key] = normalizeSemanticCollections(child)
		}
		return result
	case []any:
		result := make([]any, 0, len(current))
		for _, child := range current {
			result = append(result, normalizeSemanticCollections(child))
		}
		sort.SliceStable(result, func(i, j int) bool {
			left, _ := rendering.CanonicalJSON(result[i])
			right, _ := rendering.CanonicalJSON(result[j])
			return string(left) < string(right)
		})
		return result
	default:
		return value
	}
}

func normalizedPropertyValues(value any) ([]string, bool) {
	var result []string
	switch current := value.(type) {
	case string:
		if current == "" {
			return nil, false
		}
		result = []string{current}
	case []any:
		result = make([]string, 0, len(current))
		for _, raw := range current {
			item, ok := raw.(string)
			if !ok || item == "" {
				return nil, false
			}
			result = append(result, item)
		}
	default:
		return nil, false
	}
	sort.Strings(result)
	for index := 1; index < len(result); index++ {
		if result[index] == result[index-1] {
			return nil, false
		}
	}
	return result, len(result) > 0
}

func classifyRepositoryPropertySemantic(before, after map[string]any, add func(string, string)) {
	propertyName := stringMapField(after, "property_name")
	if propertyName == "" || propertyName != stringMapField(before, "property_name") {
		add("unknown_change", "repository custom-property identity changes or is malformed")
		return
	}
	beforeValues, beforeKnown := normalizedPropertyValues(before["property_value"])
	afterValues, afterKnown := normalizedPropertyValues(after["property_value"])
	if !beforeKnown || !afterKnown || len(beforeValues) != 1 || len(afterValues) != 1 {
		add("unknown_change", "repository custom-property value transition is missing or malformed")
		return
	}
	oldValue, newValue := beforeValues[0], afterValues[0]
	if oldValue == newValue {
		return
	}
	switch propertyName {
	case "data_classification":
		if classificationRank(newValue) < classificationRank(oldValue) {
			add("protection_weakening", "repository data-classification authority is downgraded")
		}
	case "criticality":
		if criticalityRank(newValue) < criticalityRank(oldValue) {
			add("protection_weakening", "repository criticality authority is downgraded")
		}
	case "production_authority", "owner_team", "repository_class":
		add("protection_weakening", "repository governance authority or ownership classification changes")
	}
}

func classificationRank(value string) int {
	switch value {
	case "public":
		return 0
	case "internal":
		return 1
	case "confidential":
		return 2
	case "restricted":
		return 3
	default:
		return -1
	}
}

func criticalityRank(value string) int {
	switch value {
	case "low":
		return 0
	case "medium":
		return 1
	case "high":
		return 2
	case "critical":
		return 3
	default:
		return -1
	}
}

func catalogEnvironmentVariableAfterState(address string, after, catalog map[string]any) bool {
	if after == nil || catalog == nil {
		return false
	}
	physicalKey, ok := terraformInstanceKey(address)
	if !ok || !exactIndexedAddress(
		address, "module.repository_environments.github_actions_environment_variable.this", physicalKey,
	) {
		return false
	}
	environments, _ := catalog["environments"].(map[string]any)
	matches := 0
	for environmentKey, rawEnvironment := range environments {
		environment, _ := rawEnvironment.(map[string]any)
		activation, _ := environment["activation"].(map[string]any)
		if stringMapField(activation, "state") != "ready" {
			continue
		}
		variables, _ := environment["variables"].(map[string]any)
		for _, rawRepositoryReference := range anySlice(environment["repositories"]) {
			repositoryReference, _ := rawRepositoryReference.(string)
			repositoryName := catalogRepositoryName(repositoryReference, catalog)
			if repositoryName == "" {
				continue
			}
			for variableName, rawValue := range variables {
				value, _ := rawValue.(string)
				if physicalKey != environmentKey+":"+repositoryReference+":"+variableName {
					continue
				}
				matches++
				if value == "" ||
					!exactStringField(after, "repository", repositoryName) ||
					!exactStringField(after, "environment", stringMapField(environment, "name")) ||
					!exactStringField(after, "variable_name", variableName) ||
					!exactStringField(after, "value", value) {
					return false
				}
			}
		}
	}
	return matches == 1
}

func catalogEnvironmentDeploymentPolicyAfterState(address string, after, catalog map[string]any) bool {
	if after == nil || catalog == nil {
		return false
	}
	physicalKey, ok := terraformInstanceKey(address)
	if !ok || !exactIndexedAddress(
		address, "module.repository_environments.github_repository_environment_deployment_policy.this", physicalKey,
	) {
		return false
	}
	environments, _ := catalog["environments"].(map[string]any)
	matches := 0
	for environmentKey, rawEnvironment := range environments {
		environment, _ := rawEnvironment.(map[string]any)
		branchPolicy, _ := environment["deployment_branch_policy"].(map[string]any)
		for _, rawRepositoryReference := range anySlice(environment["repositories"]) {
			repositoryReference, _ := rawRepositoryReference.(string)
			repositoryName := catalogRepositoryName(repositoryReference, catalog)
			if repositoryName == "" {
				continue
			}
			for _, policyType := range []string{"branch", "tag"} {
				patterns := branchPolicy[policyType+"_patterns"]
				for _, rawPattern := range anySlice(patterns) {
					pattern, _ := rawPattern.(string)
					expectedKey := environmentKey + ":" + repositoryReference + ":" + policyType + ":" + pattern
					if expectedKey != physicalKey {
						continue
					}
					matches++
					actualType, actualPattern, known := environmentDeploymentPolicyPattern(after)
					if !known || actualType != policyType || actualPattern != pattern ||
						!exactStringField(after, "repository", repositoryName) ||
						!exactStringField(after, "environment", stringMapField(environment, "name")) {
						return false
					}
				}
			}
		}
	}
	return matches == 1
}

func catalogEnvironmentAfterState(address string, after, catalog, observed map[string]any) bool {
	if after == nil || catalog == nil || observed == nil {
		return false
	}
	key, ok := terraformInstanceKey(address)
	if !ok || !exactIndexedAddress(address, "module.repository_environments.github_repository_environment.this", key) {
		return false
	}
	parts := strings.SplitN(key, ":", 2)
	if len(parts) != 2 {
		return false
	}
	environmentKey, repositoryReference := parts[0], parts[1]
	environments, _ := catalog["environments"].(map[string]any)
	environment, _ := environments[environmentKey].(map[string]any)
	repositories, _ := catalog["repositories"].(map[string]any)
	repository, _ := repositories[repositoryReference].(map[string]any)
	if repository == nil {
		for _, rawRepository := range repositories {
			candidate, _ := rawRepository.(map[string]any)
			if stringMapField(candidate, "name") == repositoryReference {
				if repository != nil {
					return false
				}
				repository = candidate
			}
		}
	}
	if environment == nil || repository == nil ||
		!stringListContains(environment["repositories"], repositoryReference) ||
		stringMapField(after, "environment") != stringMapField(environment, "name") ||
		stringMapField(after, "repository") != stringMapField(repository, "name") ||
		after["can_admins_bypass"] != environment["can_admins_bypass"] ||
		after["prevent_self_review"] != environment["prevent_self_review"] {
		return false
	}
	actualPolicy, actualPolicyKnown := parseEnvironmentBranchPolicy(after["deployment_branch_policy"])
	expectedPolicyMap, _ := environment["deployment_branch_policy"].(map[string]any)
	expectedPolicy := environmentBranchPolicy{
		present:              true,
		protectedBranches:    boolMapField(expectedPolicyMap, "protected_branches"),
		customBranchPolicies: boolMapField(expectedPolicyMap, "custom_branch_policies"),
	}
	if !actualPolicyKnown || actualPolicy != expectedPolicy {
		return false
	}
	actualReviewers, actualReviewersKnown := environmentReviewerAuthorities(after["reviewers"])
	if !actualReviewersKnown {
		return false
	}
	expectedReviewers := make(map[string]struct{})
	teams, _ := catalog["teams"].(map[string]any)
	for _, rawReviewer := range anySlice(environment["required_reviewers"]) {
		reviewer, _ := rawReviewer.(map[string]any)
		teamKey := stringMapField(reviewer, "team")
		team, _ := teams[teamKey].(map[string]any)
		teamID, known := observedTeamID(observed, teamKey, stringMapField(team, "name"))
		if !known {
			return false
		}
		expectedReviewers["team:"+strconv.FormatInt(teamID, 10)] = struct{}{}
	}
	return equalAuthoritySets(expectedReviewers, actualReviewers)
}

func catalogDependabotAfterState(address string, after, catalog map[string]any) bool {
	if after == nil || catalog == nil {
		return false
	}
	key, ok := terraformInstanceKey(address)
	if !ok || !exactIndexedAddress(address, "module.repository_governance.github_repository_dependabot_security_updates.this", key) {
		return false
	}
	repositories, _ := catalog["repositories"].(map[string]any)
	repository, _ := repositories[key].(map[string]any)
	security, _ := repository["security"].(map[string]any)
	expectedEnabled, expectedKnown := security["dependabot_security_updates"].(bool)
	actualEnabled, actualKnown := after["enabled"].(bool)
	return repository != nil && expectedKnown && actualKnown && expectedEnabled == actualEnabled &&
		stringMapField(after, "repository") == stringMapField(repository, "name")
}

func catalogActionsAfterState(resourceType, address string, after, catalog map[string]any) bool {
	if after == nil || catalog == nil {
		return false
	}
	policy, _ := catalog["actions_policy"].(map[string]any)
	organization, _ := catalog["organization"].(map[string]any)
	switch resourceType {
	case "github_actions_organization_permissions":
		if address != "module.organization_settings.github_actions_organization_permissions.this" {
			return false
		}
		if stringMapField(after, "allowed_actions") != stringMapField(policy, "mode") ||
			stringMapField(after, "enabled_repositories") != stringMapField(policy, "enabled_repositories") ||
			!exactBoolField(after, "sha_pinning_required", stringMapField(policy, "required_pin") == "commit_sha") {
			return false
		}
		configs, ok := after["allowed_actions_config"].([]any)
		if stringMapField(policy, "mode") != "selected" {
			return ok && len(configs) == 0
		}
		if !ok || len(configs) != 1 {
			return false
		}
		config, _ := configs[0].(map[string]any)
		if config == nil || !exactBoolField(config, "github_owned_allowed", boolMapField(policy, "github_owned_allowed")) ||
			!exactBoolField(config, "verified_allowed", boolMapField(policy, "verified_creator_allowed")) {
			return false
		}
		expectedPatterns := make([]string, 0)
		for _, rawAction := range anySlice(policy["allowed_actions"]) {
			action, _ := rawAction.(map[string]any)
			expectedPatterns = append(expectedPatterns, stringMapField(action, "source")+"@"+stringMapField(action, "commit"))
		}
		actualPatterns, actualKnown := normalizedPropertyValues(config["patterns_allowed"])
		sort.Strings(expectedPatterns)
		return actualKnown && equalStringSlices(expectedPatterns, actualPatterns)
	case "github_actions_organization_workflow_permissions":
		return address == "module.organization_settings.github_actions_organization_workflow_permissions.this" &&
			exactStringField(after, "organization_slug", stringMapField(organization, "organization_login")) &&
			exactStringField(after, "default_workflow_permissions", stringMapField(policy, "default_workflow_permissions")) &&
			exactBoolField(after, "can_approve_pull_request_reviews", boolMapField(policy, "can_approve_pull_request_reviews"))
	default:
		return false
	}
}

func stringMapField(value map[string]any, key string) string {
	result, _ := value[key].(string)
	return result
}

func exactStringField(value map[string]any, key, expected string) bool {
	actual, ok := value[key].(string)
	return ok && actual == expected
}

func exactBoolField(value map[string]any, key string, expected bool) bool {
	actual, ok := value[key].(bool)
	return ok && actual == expected
}

func boolMapField(value map[string]any, key string) bool {
	result, _ := value[key].(bool)
	return result
}

func normalizedStringList(value any) ([]string, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	result := make([]string, 0, len(items))
	for _, raw := range items {
		item, ok := raw.(string)
		if !ok {
			return nil, false
		}
		result = append(result, item)
	}
	sort.Strings(result)
	for index := 1; index < len(result); index++ {
		if result[index] == result[index-1] {
			return nil, false
		}
	}
	return result, true
}

func stringListContains(value any, expected string) bool {
	for _, raw := range anySlice(value) {
		if item, _ := raw.(string); item == expected {
			return true
		}
	}
	return false
}

func equalAuthoritySets(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if _, exists := right[value]; !exists {
			return false
		}
	}
	return true
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func catalogActionPinRotation(before, after, catalog, policyInput map[string]any) bool {
	if before == nil || after == nil || catalog == nil || policyInput == nil {
		return false
	}
	beforePatterns, beforeShapeKnown := actionPinPatterns(before)
	afterPatterns, afterShapeKnown := actionPinPatterns(after)
	beforePins, beforeOK := actionPinMap(beforePatterns)
	afterPins, afterOK := actionPinMap(afterPatterns)
	if !beforeShapeKnown || !afterShapeKnown || !beforeOK || !afterOK || len(beforePins) != len(afterPins) || len(afterPins) == 0 {
		return false
	}
	actionsPolicy, _ := catalog["actions_policy"].(map[string]any)
	catalogPins := make(map[string]string)
	for _, rawAction := range anySlice(actionsPolicy["allowed_actions"]) {
		action, _ := rawAction.(map[string]any)
		source, _ := action["source"].(string)
		commit, _ := action["commit"].(string)
		if source == "" || !gitSHA40Pattern.MatchString(commit) {
			return false
		}
		if _, duplicate := catalogPins[source]; duplicate {
			return false
		}
		catalogPins[source] = commit
	}
	if !equalStringMaps(afterPins, catalogPins) {
		return false
	}
	changedSources := make(map[string]string)
	for source, afterCommit := range afterPins {
		beforeCommit, exists := beforePins[source]
		if !exists {
			return false
		}
		if beforeCommit != afterCommit {
			changedSources[source] = afterCommit
		}
	}
	if len(changedSources) == 0 {
		return false
	}
	usesBySource := make(map[string][]string)
	for _, rawWorkflow := range anySlice(policyInput["workflows"]) {
		workflow, _ := rawWorkflow.(map[string]any)
		for _, use := range stringSlice(workflow["uses"]) {
			source, commit, ok := parseWorkflowActionPin(use)
			if !ok {
				continue
			}
			usesBySource[source] = append(usesBySource[source], commit)
		}
	}
	for source, expectedCommit := range changedSources {
		commits := usesBySource[source]
		if len(commits) == 0 {
			return false
		}
		for _, commit := range commits {
			if commit != expectedCommit {
				return false
			}
		}
	}
	return true
}

func actionPinPatterns(state map[string]any) (any, bool) {
	blocks, ok := state["allowed_actions_config"].([]any)
	if !ok || len(blocks) != 1 {
		return nil, false
	}
	block, ok := blocks[0].(map[string]any)
	if !ok || block == nil {
		return nil, false
	}
	patterns, exists := block["patterns_allowed"]
	return patterns, exists
}

func actionPinMap(value any) (map[string]string, bool) {
	patterns := stringSlice(value)
	if len(patterns) == 0 {
		return nil, false
	}
	result := make(map[string]string, len(patterns))
	for _, pattern := range patterns {
		source, commit, ok := parseActionPin(pattern)
		if !ok {
			return nil, false
		}
		if _, duplicate := result[source]; duplicate {
			return nil, false
		}
		result[source] = commit
	}
	return result, true
}

func parseActionPin(value string) (string, string, bool) {
	separator := strings.LastIndex(value, "@")
	if separator <= 0 || separator == len(value)-1 {
		return "", "", false
	}
	source := value[:separator]
	commit := value[separator+1:]
	if strings.HasPrefix(source, "./") || strings.Count(source, "/") != 1 ||
		strings.ContainsAny(source, "*?[]{} ") || !gitSHA40Pattern.MatchString(commit) {
		return "", "", false
	}
	return source, commit, true
}

// parseWorkflowActionPin accepts an action subpath such as
// github/codeql-action/init@<sha> and binds it to the owner/repository pin in
// the catalog. Provider-side allowed-action patterns remain exact owner/repo
// references and continue to use parseActionPin.
func parseWorkflowActionPin(value string) (string, string, bool) {
	separator := strings.LastIndex(value, "@")
	if separator <= 0 || separator == len(value)-1 {
		return "", "", false
	}
	path := strings.Split(value[:separator], "/")
	commit := value[separator+1:]
	if !validWorkflowActionPath(path) ||
		strings.ContainsAny(value[:separator], "*?[]{} ") || !gitSHA40Pattern.MatchString(commit) {
		return "", "", false
	}
	return path[0] + "/" + path[1], commit, true
}

func validWorkflowActionPath(path []string) bool {
	if len(path) < 2 {
		return false
	}
	for _, segment := range path {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, character := range segment {
			if (character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') &&
				character != '_' && character != '.' && character != '-' {
				return false
			}
		}
	}
	return true
}

// oidcChangeMatchesCatalog permits only the exact OIDC authority described by
// the validated compiled catalog. The GitHub provider does not currently
// expose use_immutable_subject, so absence of that field in a plan is accepted
// only when the catalog itself requires immutable subjects. If a future
// provider exposes it, a false value remains a fundamental mismatch.
func oidcChangeMatchesCatalog(resourceType, address string, after, catalog map[string]any) bool {
	if after == nil || catalog == nil {
		return false
	}
	desired, ok := catalog["oidc_policy"].(map[string]any)
	if !ok {
		return false
	}
	useDefault, defaultKnown := desired["use_default_subject"].(bool)
	useImmutable, immutableKnown := desired["use_immutable_subject"].(bool)
	if !defaultKnown || useDefault || !immutableKnown || !useImmutable {
		return false
	}
	desiredClaims, ok := exactStringSet(desired["include_claim_keys"])
	if !ok || len(desiredClaims) == 0 {
		return false
	}
	afterClaims, ok := exactStringSet(after["include_claim_keys"])
	if !ok || !equalStrings(desiredClaims, afterClaims) {
		return false
	}
	if plannedImmutable, exists := after["use_immutable_subject"]; exists {
		value, known := plannedImmutable.(bool)
		if !known || !value {
			return false
		}
	}
	if plannedDefault, exists := after["use_default"]; exists {
		value, known := plannedDefault.(bool)
		if !known || value {
			return false
		}
	}
	switch resourceType {
	case "github_actions_organization_oidc_subject_claim_customization_template":
		return address == "module.organization_settings.github_actions_organization_oidc_subject_claim_customization_template.this[0]"
	case "github_actions_repository_oidc_subject_claim_customization_template":
		key, keyKnown := terraformInstanceKey(address)
		if !keyKnown || !exactIndexedAddress(address, "module.repository_governance.github_actions_repository_oidc_subject_claim_customization_template.this", key) {
			return false
		}
		repository, ok := after["repository"].(string)
		if !ok || repository == "" {
			return false
		}
		repositories, ok := catalog["repositories"].(map[string]any)
		if !ok {
			return false
		}
		matches := 0
		for repositoryKey, raw := range repositories {
			spec, _ := raw.(map[string]any)
			name, _ := spec["name"].(string)
			if repositoryKey == key && name == repository {
				matches++
			}
		}
		return matches == 1
	default:
		return false
	}
}

func catalogOutsideCollaboratorGrant(address string, after, catalog map[string]any) bool {
	if after == nil || catalog == nil {
		return false
	}
	login, loginOK := after["username"].(string)
	repository, repositoryOK := after["repository"].(string)
	permission, permissionOK := after["permission"].(string)
	if !loginOK || login == "" || !repositoryOK || repository == "" || !permissionOK || permission == "" {
		return false
	}
	if suppression, exists := after["permission_diff_suppression"]; exists {
		value, ok := suppression.(bool)
		if !ok || value {
			return false
		}
	}
	key, keyKnown := terraformInstanceKey(address)
	if !keyKnown || !exactIndexedAddress(address, "module.team_access.github_repository_collaborator.outside", key) {
		return false
	}
	keyParts := strings.SplitN(key, ":", 2)
	if len(keyParts) != 2 || !strings.EqualFold(keyParts[0], login) || catalogRepositoryName(keyParts[1], catalog) != repository {
		return false
	}
	matches := 0
	for _, rawCollaborator := range anySlice(catalog["outside_collaborators"]) {
		collaborator, _ := rawCollaborator.(map[string]any)
		if !strings.EqualFold(fmt.Sprint(collaborator["login"]), login) {
			continue
		}
		for _, rawGrant := range anySlice(collaborator["repository_permissions"]) {
			grant, _ := rawGrant.(map[string]any)
			catalogRepository := catalogRepositoryName(fmt.Sprint(grant["repository"]), catalog)
			if catalogRepository == repository && fmt.Sprint(grant["permission"]) == permission {
				matches++
			}
		}
	}
	return matches == 1
}

func catalogSecurityManagerAssignment(address string, after, catalog, observed map[string]any) bool {
	if after == nil || catalog == nil || observed == nil {
		return false
	}
	if address != "module.team_access.github_organization_role_team.security_manager" {
		return false
	}
	roleID, roleKnown := positiveJSONInteger(after["role_id"])
	teamSlug, teamKnown := after["team_slug"].(string)
	if !roleKnown || roleID <= 0 || !teamKnown || teamSlug == "" {
		return false
	}
	if roleName, exists := after["role_name"]; exists && fmt.Sprint(roleName) != "security_manager" {
		return false
	}
	securityPolicy, _ := catalog["security_policy"].(map[string]any)
	teamID, _ := securityPolicy["security_manager_team"].(string)
	teams, _ := catalog["teams"].(map[string]any)
	team, _ := teams[teamID].(map[string]any)
	configuredSlug, _ := team["name"].(string)
	if configuredSlug == "" || teamSlug != configuredSlug {
		return false
	}
	rolesContainer, _ := observed["organization_roles"].(map[string]any)
	securityManagerRoles := 0
	matches := 0
	for _, raw := range anySlice(rolesContainer["roles"]) {
		role, _ := raw.(map[string]any)
		if fmt.Sprint(role["name"]) != "security_manager" {
			continue
		}
		securityManagerRoles++
		observedRoleID, ok := positiveJSONInteger(role["role_id"])
		if !ok {
			observedRoleID, ok = positiveJSONInteger(role["id"])
		}
		if ok && observedRoleID == roleID {
			matches++
		}
	}
	return securityManagerRoles == 1 && matches == 1
}

func catalogRepositoryName(reference string, catalog map[string]any) string {
	repositories, _ := catalog["repositories"].(map[string]any)
	if raw, exists := repositories[reference]; exists {
		repository, _ := raw.(map[string]any)
		if name, _ := repository["name"].(string); name != "" {
			return name
		}
	}
	matches := 0
	name := ""
	for _, raw := range repositories {
		repository, _ := raw.(map[string]any)
		candidate, _ := repository["name"].(string)
		if candidate == reference {
			matches++
			name = candidate
		}
	}
	if matches == 1 {
		return name
	}
	return ""
}

func anySlice(value any) []any {
	items, _ := value.([]any)
	return items
}

func exactStringSet(value any) ([]string, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	result := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok || text == "" {
			return nil, false
		}
		if _, duplicate := seen[text]; duplicate {
			return nil, false
		}
		seen[text] = struct{}{}
		result = append(result, text)
	}
	sort.Strings(result)
	return result, true
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalStringMaps(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func containsNewElements(oldValue, newValue any) bool {
	oldItems, oldOK := oldValue.([]any)
	newItems, newOK := newValue.([]any)
	if !oldOK || !newOK {
		return false
	}
	oldSet := make(map[string]struct{}, len(oldItems))
	for _, item := range oldItems {
		canonical, _ := rendering.CanonicalJSON(item)
		oldSet[string(canonical)] = struct{}{}
	}
	for _, item := range newItems {
		canonical, _ := rendering.CanonicalJSON(item)
		if _, exists := oldSet[string(canonical)]; !exists {
			return true
		}
	}
	return false
}

func containsRemovedElements(oldValue, newValue any) bool {
	return containsNewElements(newValue, oldValue)
}

func visitFieldChanges(before, after map[string]any, visit func(string, any, any)) {
	keys := make(map[string]struct{}, len(before)+len(after))
	for key := range before {
		keys[key] = struct{}{}
	}
	for key := range after {
		keys[key] = struct{}{}
	}
	for _, key := range sortedKeys(keys) {
		oldValue, oldExists := before[key]
		newValue, newExists := after[key]
		if !oldExists || !newExists {
			visit(key, oldValue, newValue)
			continue
		}
		oldJSON, _ := rendering.CanonicalJSON(oldValue)
		newJSON, _ := rendering.CanonicalJSON(newValue)
		if string(oldJSON) == string(newJSON) {
			continue
		}
		visit(key, oldValue, newValue)
		oldMap, oldMapOK := oldValue.(map[string]any)
		newMap, newMapOK := newValue.(map[string]any)
		if oldMapOK || newMapOK {
			if !oldMapOK {
				oldMap = map[string]any{}
			}
			if !newMapOK {
				newMap = map[string]any{}
			}
			visitFieldChanges(oldMap, newMap, visit)
			continue
		}
		oldList, oldListOK := oldValue.([]any)
		newList, newListOK := newValue.([]any)
		if oldListOK || newListOK {
			visitListChanges(oldList, newList, visit)
		}
	}
}

func visitListChanges(before, after []any, visit func(string, any, any)) {
	beforeByIdentity, beforeIdentified := listByIdentity(before)
	afterByIdentity, afterIdentified := listByIdentity(after)
	if beforeIdentified && afterIdentified {
		identities := make(map[string]struct{}, len(beforeByIdentity)+len(afterByIdentity))
		for identity := range beforeByIdentity {
			identities[identity] = struct{}{}
		}
		for identity := range afterByIdentity {
			identities[identity] = struct{}{}
		}
		for _, identity := range sortedKeys(identities) {
			oldMap := beforeByIdentity[identity]
			newMap := afterByIdentity[identity]
			if oldMap == nil {
				oldMap = map[string]any{}
			}
			if newMap == nil {
				newMap = map[string]any{}
			}
			visitFieldChanges(oldMap, newMap, visit)
		}
		return
	}
	maximum := len(before)
	if len(after) > maximum {
		maximum = len(after)
	}
	for index := 0; index < maximum; index++ {
		var oldValue, newValue any
		if index < len(before) {
			oldValue = before[index]
		}
		if index < len(after) {
			newValue = after[index]
		}
		oldMap, oldOK := oldValue.(map[string]any)
		newMap, newOK := newValue.(map[string]any)
		if oldOK || newOK {
			if !oldOK {
				oldMap = map[string]any{}
			}
			if !newOK {
				newMap = map[string]any{}
			}
			visitFieldChanges(oldMap, newMap, visit)
		}
	}
}

func listByIdentity(values []any) (map[string]map[string]any, bool) {
	result := make(map[string]map[string]any, len(values))
	if len(values) == 0 {
		return result, true
	}
	for _, value := range values {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		identity := ""
		for _, key := range []string{"type", "context", "name", "id", "actor_id"} {
			if candidate := fmt.Sprint(object[key]); candidate != "" && candidate != "<nil>" {
				identity = key + ":" + candidate
				break
			}
		}
		if identity == "" {
			return nil, false
		}
		if _, duplicate := result[identity]; duplicate {
			return nil, false
		}
		result[identity] = object
	}
	return result, true
}

func transitionedBool(before, after map[string]any, key string, oldExpected, newExpected bool) bool {
	return boolTransition(before[key], after[key], oldExpected, newExpected)
}

func boolTransition(oldValue, newValue any, oldExpected, newExpected bool) bool {
	oldBoolean, oldOK := oldValue.(bool)
	newBoolean, newOK := newValue.(bool)
	return oldOK && newOK && oldBoolean == oldExpected && newBoolean == newExpected
}

func isProtectiveBoolean(key string) bool {
	for _, fragment := range []string{"required", "require_", "dismiss_stale", "protected", "prevent_", "two_factor", "signatures", "non_fast_forward", "deletion", "update", "advanced_security", "secret_scanning", "vulnerability", "dependabot", "code_scanning", "web_commit_signoff"} {
		if strings.Contains(key, fragment) {
			return true
		}
	}
	return false
}

func accessRank(value string) int {
	switch strings.ToLower(value) {
	case "none", "":
		return 0
	case "read", "pull", "member":
		return 1
	case "triage", "maintainer":
		return 2
	case "write", "push":
		return 3
	case "maintain":
		return 4
	case "admin":
		return 5
	default:
		return -1
	}
}

func repositoryActionsAccessRank(value any) (int, bool) {
	switch strings.ToLower(fmt.Sprint(value)) {
	case "none":
		return 0, true
	case "organization":
		return 1, true
	default:
		return -1, false
	}
}

func visibilityRank(value string) int {
	switch strings.ToLower(value) {
	case "private":
		return 0
	case "internal":
		return 1
	case "public":
		return 2
	default:
		return -1
	}
}

func enforcementRank(value string) int {
	switch strings.ToLower(value) {
	case "active":
		return 2
	case "evaluate":
		return 1
	case "disabled":
		return 0
	default:
		return -1
	}
}

func numericValue(value any) float64 {
	switch number := value.(type) {
	case float64:
		return number
	case json.Number:
		parsed, _ := number.Float64()
		return parsed
	case int:
		return float64(number)
	case int64:
		return float64(number)
	default:
		return 0
	}
}

func writeClass(classes []string) string {
	for _, class := range classes {
		if _, denied := fundamentalClasses[class]; denied {
			return "fundamental_deny"
		}
	}
	for _, class := range classes {
		if class == "privilege_expansion" {
			return "privilege_expansion"
		}
	}
	return "routine_write"
}

func resourceTypeFromAddress(address string) string {
	for _, component := range strings.Split(address, ".") {
		if strings.HasPrefix(component, "github_") {
			return strings.Split(component, "[")[0]
		}
	}
	return "unknown"
}

func readRegularFile(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("path is required")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("input must be a regular, non-symlink file")
	}
	if pathInfo.Size() > maxEvidenceInputBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxEvidenceInputBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return nil, errors.New("input path changed before it could be read")
	}
	if openedInfo.Size() > maxEvidenceInputBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxEvidenceInputBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxEvidenceInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxEvidenceInputBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxEvidenceInputBytes)
	}
	postReadInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	finalPathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("input path changed while it was read")
	}
	if !finalPathInfo.Mode().IsRegular() || finalPathInfo.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(openedInfo, postReadInfo) || !os.SameFile(openedInfo, finalPathInfo) ||
		openedInfo.Size() != postReadInfo.Size() || openedInfo.ModTime() != postReadInfo.ModTime() ||
		int64(len(data)) != openedInfo.Size() {
		return nil, errors.New("input changed while it was read")
	}
	return data, nil
}

func containsSensitive(value any) bool {
	switch current := value.(type) {
	case bool:
		return current
	case map[string]any:
		for _, child := range current {
			if containsSensitive(child) {
				return true
			}
		}
	case []any:
		for _, child := range current {
			if containsSensitive(child) {
				return true
			}
		}
	}
	return false
}

func containsAuthorityUnknown(value any, path string) bool {
	switch current := value.(type) {
	case bool:
		if !current {
			return false
		}
		if path == "" {
			return true
		}
		for _, fragment := range []string{
			"permission", "role", "visibility", "private", "public", "action", "workflow",
			"oidc", "claim", "review", "approval", "bypass", "protected", "security",
			"scanning", "vulnerability", "dependabot", "enforcement", "rules", "member",
			"collaborator", "repository", "team", "two_factor",
		} {
			if strings.Contains(path, fragment) {
				return true
			}
		}
	case map[string]any:
		for key, child := range current {
			childPath := strings.ToLower(key)
			if path != "" {
				childPath = path + "." + childPath
			}
			if containsAuthorityUnknown(child, childPath) {
				return true
			}
		}
	case []any:
		for _, child := range current {
			if containsAuthorityUnknown(child, path) {
				return true
			}
		}
	}
	return false
}

func stringField(value map[string]any, key string) string {
	text, _ := value[key].(string)
	return text
}

func stringSlice(value any) []string {
	items, _ := value.([]any)
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func stringsToAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func mapsToAny(values []map[string]any) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
