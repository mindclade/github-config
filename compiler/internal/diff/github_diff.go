// Package diff observes GitHub and computes deterministic desired/observed drift.
package diff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mindclade/github-config/compiler/internal/rendering"
	"github.com/mindclade/github-config/compiler/internal/validation"
)

const (
	maxJSONBytes     = 32 << 20
	maxPages         = 10
	pageSize         = 100
	maxChanges       = 10_000
	githubAPIVersion = "2026-03-10"
)

var organizationPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
var driftCredentialFieldPattern = regexp.MustCompile(`(?i)(^|_)(access[_-]?token|authorization|client[_-]?secret|credential|password|private[_-]?key|secret|token)($|_)`)

var volatileKeys = map[string]struct{}{
	"archive_url": {}, "assignees_url": {}, "blobs_url": {}, "branches_url": {},
	"clone_url": {}, "collaborators_url": {}, "comments_url": {}, "commits_url": {},
	"compare_url": {}, "contents_url": {}, "contributors_url": {}, "created_at": {},
	"deployments_url": {}, "downloads_url": {}, "events_url": {}, "forks_url": {},
	"git_commits_url": {}, "git_refs_url": {}, "git_tags_url": {}, "git_url": {},
	"hooks_url": {}, "html_url": {}, "issue_comment_url": {}, "issue_events_url": {},
	"issues_url": {}, "keys_url": {}, "labels_url": {}, "languages_url": {},
	"merges_url": {}, "milestones_url": {}, "node_id": {}, "notifications_url": {},
	"observed_at": {}, "pushed_at": {}, "releases_url": {}, "ssh_url": {},
	"stargazers_url": {}, "statuses_url": {}, "subscribers_url": {},
	"subscription_url": {}, "svn_url": {}, "tags_url": {}, "teams_url": {},
	"trees_url": {}, "updated_at": {}, "url": {},
}

// ReadJSON reads one bounded JSON document and rejects trailing content.
func ReadJSON(reader io.Reader) (map[string]any, error) {
	limited := io.LimitReader(reader, maxJSONBytes+1)
	decoder := json.NewDecoder(limited)
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("JSON input contains multiple values")
		}
		return nil, fmt.Errorf("decode trailing JSON: %w", err)
	}
	return value, nil
}

// Report returns a stable, redacted drift report.
func Report(desired, observed map[string]any) map[string]any {
	if managed, ok := observed["managed_projection"].(map[string]any); ok {
		desired = ManagedProjection(desired)
		observed = managed
	}
	changes := make([]map[string]any, 0)
	compare(normalize(desired), normalize(observed), "", &changes)
	sort.Slice(changes, func(i, j int) bool {
		left := changes[i]["path"].(string) + "\x00" + changes[i]["kind"].(string)
		right := changes[j]["path"].(string) + "\x00" + changes[j]["kind"].(string)
		return left < right
	})
	counts := map[string]any{"missing": int64(0), "extra": int64(0), "changed": int64(0), "unknown": int64(0)}
	for _, change := range changes {
		kind := change["kind"].(string)
		counts[kind] = counts[kind].(int64) + 1
	}
	status := "clean"
	if len(changes) > 0 {
		status = "drift"
	}
	return map[string]any{
		"api_version": validation.APIVersion,
		"kind":        "GitHubDriftReport",
		"status":      status,
		"summary":     counts,
		"changes":     changes,
	}
}

// ManagedProjection is the explicit desired/observed convergence contract.
// Catalog-only controls (activation blockers, recovery behavior, policy source
// metadata, and external App qualification) are intentionally evaluated by
// policy/preflight instead of being compared to unrelated GitHub REST fields.
func ManagedProjection(catalog map[string]any) map[string]any {
	result := map[string]any{"projection_version": "github-rest/v1"}
	organization, _ := catalog["organization"].(map[string]any)
	result["organization"] = pick(organization, []string{
		"organization_login", "default_repository_permission",
		"members_can_create_repositories", "members_can_create_public_repositories",
		"members_can_create_private_repositories", "members_can_create_internal_repositories",
		"members_can_create_pages", "members_can_fork_private_repositories",
		"web_commit_signoff_required", "two_factor_requirement", "custom_properties",
	})
	actions, _ := catalog["actions_policy"].(map[string]any)
	projectedActions := pick(actions, []string{
		"mode", "github_owned_allowed", "verified_creator_allowed",
		"default_workflow_permissions", "can_approve_pull_request_reviews", "required_pin", "runner_policy",
	})
	if enabledRepositories, exists := actions["enabled_repositories"]; exists {
		projectedActions["enabled_repositories"] = enabledRepositories
	} else {
		projectedActions["enabled_repositories"] = "all"
	}
	allowedPatterns := make([]any, 0)
	for _, action := range objectArray(actions["allowed_actions"]) {
		source, _ := action["source"].(string)
		commit, _ := action["commit"].(string)
		allowedPatterns = append(allowedPatterns, source+"@"+commit)
	}
	projectedActions["allowed_patterns"] = allowedPatterns
	result["actions_policy"] = projectedActions
	security, _ := catalog["security_policy"].(map[string]any)
	result["security_policy"] = pick(security, []string{
		"security_manager_team", "dependency_graph_required", "dependabot_alerts_required",
		"dependabot_security_updates_required", "advanced_security_required",
		"code_scanning_default_setup_required", "secret_scanning_required",
		"secret_scanning_push_protection_required", "private_vulnerability_reporting_required",
	})
	oidc, _ := catalog["oidc_policy"].(map[string]any)
	projectedOIDC := pick(oidc, []string{"use_default_subject", "use_immutable_subject", "include_claim_keys"})
	repositoryTemplates := make(map[string]any)
	repositories, _ := catalog["repositories"].(map[string]any)
	for id := range repositories {
		repositoryTemplates[id] = map[string]any{
			"use_default":           false,
			"include_claim_keys":    oidc["include_claim_keys"],
			"use_immutable_subject": oidc["use_immutable_subject"],
		}
	}
	projectedOIDC["repository_subject_templates"] = repositoryTemplates
	result["oidc_policy"] = projectedOIDC
	result["members"] = projectObjectList(catalog["members"], []string{"login", "role"})
	result["outside_collaborators"] = projectObjectList(catalog["outside_collaborators"], []string{"login"})
	result["teams"] = projectCollection(catalog["teams"], func(spec map[string]any) map[string]any {
		projected := pick(spec, []string{"name", "description", "privacy", "parent_team"})
		projected["members"] = projectObjectList(spec["members"], []string{"login", "role"})
		return projected
	})
	declaredOutsideGrants := make(map[string][]any)
	for _, collaborator := range objectArray(catalog["outside_collaborators"]) {
		login, _ := collaborator["login"].(string)
		for _, grant := range objectArray(collaborator["repository_permissions"]) {
			reference, _ := grant["repository"].(string)
			repositoryName := reference
			if rawRepository, exists := repositories[reference]; exists {
				repositorySpec, _ := rawRepository.(map[string]any)
				if configuredName, _ := repositorySpec["name"].(string); configuredName != "" {
					repositoryName = configuredName
				}
			}
			declaredOutsideGrants[repositoryName] = append(declaredOutsideGrants[repositoryName], map[string]any{
				"login": login, "permission": grant["permission"],
			})
		}
	}
	result["repositories"] = projectCollection(catalog["repositories"], func(spec map[string]any) map[string]any {
		projected := pick(spec, []string{"name", "description", "visibility", "archived", "features", "merge_policy", "custom_properties"})
		projected["web_commit_signoff_required"] = organization["web_commit_signoff_required"]
		security, _ := spec["security"].(map[string]any)
		projected["security"] = pick(security, []string{
			"vulnerability_alerts", "dependabot_security_updates", "advanced_security",
			"secret_scanning", "secret_scanning_push_protection",
		})
		projected["team_grants"] = projectObjectList(spec["team_grants"], []string{"team", "permission"})
		directCollaborators := projectObjectList(spec["direct_collaborators"], []string{"login", "permission"})
		if repositoryName, _ := spec["name"].(string); len(declaredOutsideGrants[repositoryName]) > 0 {
			directCollaborators = append(directCollaborators, declaredOutsideGrants[repositoryName]...)
			directCollaborators = normalize(directCollaborators).([]any)
		}
		projected["direct_collaborators"] = directCollaborators
		return projected
	})
	result["rulesets"] = projectCollection(catalog["rulesets"], func(spec map[string]any) map[string]any {
		return projectDesiredRuleset(spec)
	})
	result["environments"] = projectCollection(catalog["environments"], func(spec map[string]any) map[string]any {
		return projectDesiredEnvironment(spec)
	})
	return result
}

func compare(desired, observed any, path string, changes *[]map[string]any) {
	if len(*changes) >= maxChanges {
		return
	}
	if isUnknown(observed) {
		appendDriftChange(changes, path, "unknown", desired, true, nil, false)
		return
	}
	desiredMap, desiredIsMap := desired.(map[string]any)
	observedMap, observedIsMap := observed.(map[string]any)
	if desiredIsMap && observedIsMap {
		keySet := make(map[string]struct{}, len(desiredMap)+len(observedMap))
		for key := range desiredMap {
			if !isVolatile(key) {
				keySet[key] = struct{}{}
			}
		}
		for key := range observedMap {
			if !isVolatile(key) {
				keySet[key] = struct{}{}
			}
		}
		keys := make([]string, 0, len(keySet))
		for key := range keySet {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			desiredValue, desiredExists := desiredMap[key]
			observedValue, observedExists := observedMap[key]
			childPath := path + "/" + escapePointer(key)
			switch {
			case desiredExists && !observedExists:
				appendDriftChange(changes, childPath, "missing", desiredValue, true, nil, false)
			case !desiredExists && observedExists:
				appendDriftChange(changes, childPath, "extra", nil, false, observedValue, true)
			default:
				compare(desiredValue, observedValue, childPath, changes)
			}
		}
		return
	}
	desiredBytes, desiredErr := rendering.CanonicalJSON(desired)
	observedBytes, observedErr := rendering.CanonicalJSON(observed)
	if desiredErr == nil && observedErr == nil && bytes.Equal(desiredBytes, observedBytes) {
		return
	}
	appendDriftChange(changes, path, "changed", desired, true, observed, true)
}

func appendDriftChange(changes *[]map[string]any, path, kind string, desired any, desiredPresent bool, observed any, observedPresent bool) {
	path = pointerOrRoot(path)
	sensitive := driftSensitivePath(path) ||
		(desiredPresent && containsDriftSensitiveData(desired)) ||
		(observedPresent && containsDriftSensitiveData(observed))
	entry := map[string]any{
		"path":      safeDriftPath(path, sensitive),
		"kind":      kind,
		"sensitive": sensitive,
	}
	if !sensitive {
		if desiredPresent {
			entry["desired_hash"] = driftValueDigest(path, kind, "desired", desired)
		}
		if observedPresent {
			entry["observed_hash"] = driftValueDigest(path, kind, "observed", observed)
		}
	}
	*changes = append(*changes, entry)
}

func driftValueDigest(path, kind, side string, value any) string {
	projection := map[string]any{
		"domain": "github-config/drift-value/v1",
		"path":   path,
		"kind":   kind,
		"side":   side,
		"value":  value,
	}
	canonical, err := rendering.CanonicalJSON(projection)
	if err != nil {
		return rendering.Digest([]byte("github-config/drift-value/v1/unhashable\n"))
	}
	return rendering.Digest(canonical)
}

func driftSensitivePath(path string) bool {
	for _, rawSegment := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		segment := strings.ReplaceAll(strings.ToLower(rawSegment), "-", "_")
		if driftSensitiveField(segment) {
			return true
		}
	}
	return false
}

func containsDriftSensitiveData(value any) bool {
	switch current := value.(type) {
	case map[string]any:
		for key, child := range current {
			if driftSensitiveField(strings.ReplaceAll(strings.ToLower(key), "-", "_")) || containsDriftSensitiveData(child) {
				return true
			}
		}
	case []any:
		for _, child := range current {
			if containsDriftSensitiveData(child) {
				return true
			}
		}
	}
	return false
}

func driftSensitiveField(field string) bool {
	if strings.HasPrefix(field, "secret_scanning") {
		return false
	}
	switch field {
	case "members", "organization_members", "outside_collaborators", "teams",
		"team_grants", "direct_collaborators", "required_reviewers", "bypass_actors",
		"custom_properties", "organization_login", "login", "name", "slug", "email",
		"principal_id", "sponsor_login", "owner_team", "security_manager_team",
		"actor", "actor_id", "integration_id", "reviewer", "reviewers", "description":
		return true
	}
	return driftCredentialFieldPattern.MatchString(field)
}

func safeDriftPath(path string, sensitive bool) string {
	if !sensitive || path == "/" {
		return path
	}
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	redactNext := false
	for index, segment := range segments {
		if redactNext {
			segments[index] = "*"
			redactNext = false
			continue
		}
		switch strings.ToLower(segment) {
		case "teams", "repositories", "rulesets", "environments", "members",
			"outside_collaborators", "repository_subject_templates", "custom_properties",
			"team_grants", "direct_collaborators", "required_reviewers", "bypass_actors":
			redactNext = true
		}
	}
	return "/" + strings.Join(segments, "/")
}

func normalize(value any) any {
	switch current := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(current))
		for key, child := range current {
			if !isVolatile(key) {
				result[key] = normalize(child)
			}
		}
		return result
	case []any:
		result := make([]any, len(current))
		for index, child := range current {
			result[index] = normalize(child)
		}
		sort.SliceStable(result, func(i, j int) bool {
			left, _ := rendering.CanonicalJSON(result[i])
			right, _ := rendering.CanonicalJSON(result[j])
			return bytes.Compare(left, right) < 0
		})
		return result
	default:
		return current
	}
}

func isUnknown(value any) bool {
	object, ok := value.(map[string]any)
	if !ok {
		return false
	}
	status, _ := object["status"].(string)
	unknown, _ := object["unknown"].(bool)
	return strings.EqualFold(status, "unknown") || unknown
}

func isVolatile(key string) bool {
	_, ok := volatileKeys[key]
	return ok
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

// Observe performs bounded, read-only GitHub REST calls. Responses are reduced
// to governance-relevant fields and recursively redacted before serialization.
func Observe(ctx context.Context, organization, apiBase, token string, repositoryNames []string, desired map[string]any) (map[string]any, error) {
	if !organizationPattern.MatchString(organization) {
		return nil, errors.New("organization is not a valid GitHub organization login")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("GITHUB_TOKEN is required for observation")
	}
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	base, err := url.Parse(apiBase)
	pathIsRoot := err == nil && (base.EscapedPath() == "" || base.EscapedPath() == "/")
	officialAPI := err == nil && base.Scheme == "https" && strings.EqualFold(base.Host, "api.github.com") && pathIsRoot
	loopbackHTTP := err == nil && base.Scheme == "http" && isLoopbackHost(base.Hostname()) && pathIsRoot
	if err != nil || (!officialAPI && !loopbackHTTP) || base.Host == "" || base.User != nil || base.Fragment != "" || base.RawQuery != "" {
		return nil, errors.New("GITHUB_API_URL must be exactly https://api.github.com (HTTP loopback is allowed only for tests)")
	}
	client := &githubClient{
		base: strings.TrimRight(base.String(), "/"), token: token,
		http: &http.Client{
			Timeout: 20 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	escapedOrg := url.PathEscape(organization)
	organizationRaw, err := client.getObject(ctx, "/orgs/"+escapedOrg)
	if err != nil {
		return nil, fmt.Errorf("observe organization: %w", err)
	}
	capabilityErrors := make([]any, 0)
	recordCapabilityError := func(section string, err error) {
		capabilityErrors = append(capabilityErrors, map[string]any{"section": section, "error": sanitizedAPIError(err)})
	}
	customPropertiesRaw, err := client.getList(ctx, "/orgs/"+escapedOrg+"/properties/schema")
	customPropertiesKnown := err == nil
	if err != nil {
		recordCapabilityError("organization_custom_properties", err)
		customPropertiesRaw = nil
	}
	organizationRolesContainer, err := client.getObject(ctx, "/orgs/"+escapedOrg+"/organization-roles")
	securityManagersKnown := false
	var securityManagersRaw []any
	if err != nil {
		recordCapabilityError("organization_roles", err)
		organizationRolesContainer = map[string]any{"roles": unknownValue()}
	} else {
		securityManagerRoleID, roleErr := uniqueSecurityManagerRoleID(organizationRolesContainer)
		if roleErr != nil {
			recordCapabilityError("security_manager_role", roleErr)
		} else {
			securityManagersRaw, err = client.getList(
				ctx,
				"/orgs/"+escapedOrg+"/organization-roles/"+strconv.FormatInt(securityManagerRoleID, 10)+"/teams",
			)
			securityManagersKnown = err == nil
			if err != nil {
				recordCapabilityError("security_manager_teams", err)
				securityManagersRaw = nil
			}
		}
	}
	actionsRaw, err := client.getObject(ctx, "/orgs/"+escapedOrg+"/actions/permissions")
	if err != nil {
		return nil, fmt.Errorf("observe Actions policy: %w", err)
	}
	selectedActionsRaw, err := client.getObject(ctx, "/orgs/"+escapedOrg+"/actions/permissions/selected-actions")
	if err != nil {
		return nil, fmt.Errorf("observe selected Actions policy: %w", err)
	}
	workflowPolicyRaw, err := client.getObject(ctx, "/orgs/"+escapedOrg+"/actions/permissions/workflow")
	if err != nil {
		return nil, fmt.Errorf("observe workflow token policy: %w", err)
	}
	runnersRaw, err := client.getObject(ctx, "/orgs/"+escapedOrg+"/actions/runners")
	runnersKnown := err == nil
	if err != nil {
		recordCapabilityError("organization_actions_runners", err)
		runnersRaw = nil
	}
	selfHostedPolicyRaw, err := client.getObject(ctx, "/orgs/"+escapedOrg+"/actions/permissions/self-hosted-runners")
	selfHostedPolicyKnown := err == nil
	if err != nil {
		recordCapabilityError("organization_self_hosted_runner_policy", err)
		selfHostedPolicyRaw = nil
	}
	forkApprovalRaw, err := client.getObject(ctx, "/orgs/"+escapedOrg+"/actions/permissions/fork-pr-contributor-approval")
	if err != nil {
		recordCapabilityError("organization_fork_pull_request_approval", err)
		forkApprovalRaw = map[string]any{"status": "unknown"}
	}
	oidcRaw, err := client.getObject(ctx, "/orgs/"+escapedOrg+"/actions/oidc/customization/sub")
	if err != nil {
		recordCapabilityError("oidc_subject_customization", err)
		oidcRaw = map[string]any{"status": "unknown"}
	}
	repositoriesRaw, err := client.getList(ctx, "/orgs/"+escapedOrg+"/repos?type=all")
	if err != nil {
		return nil, fmt.Errorf("observe repositories: %w", err)
	}
	repositoryInventory := repositoryInventoryProof(organizationRaw, repositoriesRaw)
	repositoryInventoryComplete, _ := repositoryInventory["complete"].(bool)
	teamsRaw, err := client.getList(ctx, "/orgs/"+escapedOrg+"/teams")
	if err != nil {
		return nil, fmt.Errorf("observe teams: %w", err)
	}
	teamMembers := make(map[string][]any, len(teamsRaw))
	for _, team := range objectArrayFromList(teamsRaw) {
		slug, _ := team["slug"].(string)
		if slug == "" {
			continue
		}
		members, err := client.getList(ctx, "/orgs/"+escapedOrg+"/teams/"+url.PathEscape(slug)+"/members?role=all")
		if err != nil {
			return nil, fmt.Errorf("observe members for team %q: %w", slug, err)
		}
		projected := make([]any, 0, len(members))
		for _, member := range objectArrayFromList(members) {
			login, _ := member["login"].(string)
			if login == "" {
				continue
			}
			membership, err := client.getObject(ctx, "/orgs/"+escapedOrg+"/teams/"+url.PathEscape(slug)+"/memberships/"+url.PathEscape(login))
			if err != nil {
				return nil, fmt.Errorf("observe membership for team %q login %q: %w", slug, login, err)
			}
			role, _ := membership["role"].(string)
			projected = append(projected, map[string]any{"login": login, "role": role})
		}
		teamMembers[slug] = projected
	}
	membersRaw, err := client.getList(ctx, "/orgs/"+escapedOrg+"/members?filter=all&role=all")
	if err != nil {
		return nil, fmt.Errorf("observe members: %w", err)
	}
	adminsRaw, err := client.getList(ctx, "/orgs/"+escapedOrg+"/members?filter=all&role=admin")
	if err != nil {
		return nil, fmt.Errorf("observe organization administrators: %w", err)
	}
	outsideRaw, err := client.getList(ctx, "/orgs/"+escapedOrg+"/outside_collaborators?filter=all")
	if err != nil {
		return nil, fmt.Errorf("observe outside collaborators: %w", err)
	}
	rulesetsRaw, err := client.getList(ctx, "/orgs/"+escapedOrg+"/rulesets")
	rulesetsKnown := err == nil
	if err != nil {
		recordCapabilityError("organization_rulesets", err)
		rulesetsRaw = nil
	}
	rulesetsDetailed := make([]any, 0, len(rulesetsRaw))
	for _, ruleset := range objectArrayFromList(rulesetsRaw) {
		identifier := fmt.Sprint(ruleset["id"])
		if identifier == "" || identifier == "<nil>" {
			return nil, errors.New("observe organization rulesets: response omitted ruleset id")
		}
		detail, err := client.getObject(ctx, "/orgs/"+escapedOrg+"/rulesets/"+url.PathEscape(identifier))
		if err != nil {
			rulesetsKnown = false
			recordCapabilityError("organization_ruleset:"+identifier, err)
			continue
		}
		rulesetsDetailed = append(rulesetsDetailed, detail)
	}
	installationsList, installationTotal, err := client.getNestedListWithTotal(
		ctx, "/orgs/"+escapedOrg+"/installations", "installations", "total_count",
	)
	installationsRequestComplete := err == nil
	if err != nil {
		recordCapabilityError("github_app_installations", err)
		installationsList = nil
	}
	installationInventory := installationInventoryProof(
		installationsList, installationTotal, installationsRequestComplete, desired,
	)
	environments := make(map[string]any, len(repositoryNames))
	repositoryTeams := make(map[string][]any, len(repositoryNames))
	directCollaborators := make(map[string][]any, len(repositoryNames))
	vulnerabilityAlerts := make(map[string]any, len(repositoryNames))
	dependencyGraph := make(map[string]any, len(repositoryNames))
	dependabotSecurityUpdates := make(map[string]any, len(repositoryNames))
	codeScanningDefaultSetup := make(map[string]any, len(repositoryNames))
	privateVulnerabilityReporting := make(map[string]any, len(repositoryNames))
	repositoryCustomProperties := make(map[string]any, len(repositoryNames))
	repositoryOIDCPolicies := make(map[string]any, len(repositoryNames))
	liveRepositoryNames := make(map[string]struct{}, len(repositoriesRaw))
	for _, repository := range objectArrayFromList(repositoriesRaw) {
		if name, _ := repository["name"].(string); name != "" {
			liveRepositoryNames[name] = struct{}{}
		}
	}
	sort.Strings(repositoryNames)
	for _, repository := range repositoryNames {
		if _, exists := liveRepositoryNames[repository]; !exists {
			continue
		}
		repositoryPath := "/repos/" + escapedOrg + "/" + url.PathEscape(repository)
		repositoryOIDC, oidcErr := client.getObject(ctx, repositoryPath+"/actions/oidc/customization/sub")
		if oidcErr != nil {
			recordCapabilityError("repository_oidc_subject_customization:"+repository, oidcErr)
			repositoryOIDCPolicies[repository] = unknownValue()
		} else {
			repositoryOIDCPolicies[repository] = reduceObject(repositoryOIDC, []string{
				"use_default", "include_claim_keys", "use_immutable_subject",
			})
		}
		value, err := client.getObject(ctx, repositoryPath+"/environments")
		if err != nil {
			recordCapabilityError("repository_environments:"+repository, err)
			environments[repository] = unknownValue()
		} else {
			for _, environment := range objectArray(value["environments"]) {
				branchPolicy, _ := environment["deployment_branch_policy"].(map[string]any)
				customPolicies, _ := branchPolicy["custom_branch_policies"].(bool)
				if !customPolicies {
					environment["deployment_branch_policies"] = []any{}
					continue
				}
				environmentName, _ := environment["name"].(string)
				policies, policyErr := client.getNestedList(
					ctx,
					repositoryPath+"/environments/"+url.PathEscape(environmentName)+"/deployment-branch-policies",
					"branch_policies",
				)
				if policyErr != nil {
					recordCapabilityError("environment_deployment_policies:"+repository+":"+environmentName, policyErr)
					environment["deployment_branch_policies"] = unknownValue()
				} else {
					environment["deployment_branch_policies"] = policies
				}
			}
			environments[repository] = reduceObject(value, nil)
		}
		repositoryTeams[repository], err = client.getList(ctx, repositoryPath+"/teams")
		if err != nil {
			return nil, fmt.Errorf("observe team grants for repository %q: %w", repository, err)
		}
		directCollaborators[repository], err = client.getList(ctx, repositoryPath+"/collaborators?affiliation=direct")
		if err != nil {
			return nil, fmt.Errorf("observe direct collaborators for repository %q: %w", repository, err)
		}
		vulnerabilityAlerts[repository], err = client.checkEnabled(ctx, repositoryPath+"/vulnerability-alerts")
		if err != nil {
			return nil, fmt.Errorf("observe vulnerability alerts for repository %q: %w", repository, err)
		}
		dependencyGraph[repository], err = client.checkEnabled(ctx, repositoryPath+"/dependency-graph/sbom")
		if err != nil {
			recordCapabilityError("dependency_graph:"+repository, err)
			dependencyGraph[repository] = unknownValue()
		}
		dependabotSecurityUpdates[repository], err = client.checkEnabled(ctx, repositoryPath+"/automated-security-fixes")
		if err != nil {
			recordCapabilityError("dependabot_security_updates:"+repository, err)
			dependabotSecurityUpdates[repository] = unknownValue()
		}
		propertyValues, propertyErr := client.getList(ctx, repositoryPath+"/properties/values")
		if propertyErr != nil {
			recordCapabilityError("repository_custom_properties:"+repository, propertyErr)
			repositoryCustomProperties[repository] = unknownValue()
		} else {
			repositoryCustomProperties[repository] = propertyValues
		}
		codeScanningEnabled, codeScanningKnown, stateErr := client.objectState(ctx, repositoryPath+"/code-scanning/default-setup", "state", "configured")
		err = stateErr
		if err != nil {
			recordCapabilityError("code_scanning_default_setup:"+repository, err)
			codeScanningDefaultSetup[repository] = unknownValue()
		} else if !codeScanningKnown {
			recordCapabilityError("code_scanning_default_setup:"+repository, errors.New("endpoint returned 404 Not Found"))
			codeScanningDefaultSetup[repository] = unknownValue()
		} else {
			codeScanningDefaultSetup[repository] = codeScanningEnabled
		}
		privateReportingEnabled, stateErr := client.checkEnabled(ctx, repositoryPath+"/private-vulnerability-reporting")
		err = stateErr
		if err != nil {
			recordCapabilityError("private_vulnerability_reporting:"+repository, err)
			privateVulnerabilityReporting[repository] = unknownValue()
		} else {
			privateVulnerabilityReporting[repository] = privateReportingEnabled
		}
	}
	repositories := indexObjects(repositoriesRaw, "name", repositoryFields)
	teams := indexObjects(teamsRaw, "slug", teamFields)
	rulesets := indexObjects(rulesetsDetailed, "name", nil)
	integrations := make(map[string]any)
	for _, installation := range objectArrayFromList(installationsList) {
		appSlug, _ := installation["app_slug"].(string)
		if appSlug != "" {
			integrations[appSlug] = map[string]any{
				"installed": true, "qualified": false,
				"actor_id":                  installation["app_id"],
				"installation_id":           installation["id"],
				"app_slug":                  appSlug,
				"events":                    installation["events"],
				"suspended_at":              installation["suspended_at"],
				"repository_selection":      installation["repository_selection"],
				"permissions":               rendering.Redact(installation["permissions"]),
				"repository_scope_observed": false,
			}
		}
	}
	plan, _ := organizationRaw["plan"].(map[string]any)
	planName, _ := plan["name"].(string)
	result := map[string]any{
		"api_version":                    validation.APIVersion,
		"kind":                           "GitHubObservedState",
		"core_observation_complete":      repositoryInventoryComplete,
		"observation_complete":           repositoryInventoryComplete && len(capabilityErrors) == 0,
		"errors":                         capabilityErrors,
		"installation_inventory":         installationInventory,
		"repository_inventory":           repositoryInventory,
		"repository_inventory_complete":  repositoryInventoryComplete,
		"organization":                   reduceObject(organizationRaw, organizationFields),
		"organization_custom_properties": reduceArray(customPropertiesRaw, nil),
		"security_manager_teams":         reduceArray(securityManagersRaw, []string{"id", "name", "slug"}),
		"organization_roles":             reduceObject(organizationRolesContainer, []string{"roles"}),
		"actions_policy": map[string]any{
			"permissions":      reduceObject(actionsRaw, nil),
			"selected_actions": reduceObject(selectedActionsRaw, nil),
			"workflow":         reduceObject(workflowPolicyRaw, nil),
			"runners":          reduceObject(runnersRaw, []string{"total_count"}),
			"self_hosted":      reduceObject(selfHostedPolicyRaw, []string{"enabled_repositories"}),
			"fork_approval":    reduceObject(forkApprovalRaw, nil),
		},
		"oidc_policy":              reduceObject(oidcRaw, nil),
		"repository_oidc_policies": repositoryOIDCPolicies,
		"members":                  reduceArray(membersRaw, []string{"login", "type", "site_admin"}),
		"organization_admins":      reduceArray(adminsRaw, []string{"login", "type", "site_admin"}),
		"outside_collaborators":    reduceArray(outsideRaw, []string{"login", "type"}),
		"teams":                    teams, "repositories": repositories, "rulesets": rulesets,
		"environments": environments, "integrations": integrations,
		"team_members":                           teamMembers,
		"repository_team_grants":                 repositoryTeams,
		"repository_direct_collaborators":        directCollaborators,
		"repository_custom_properties":           repositoryCustomProperties,
		"repository_dependabot_security_updates": dependabotSecurityUpdates,
		"capabilities": map[string]any{
			"enterprise_cloud":                 strings.Contains(strings.ToLower(planName), "enterprise"),
			"advanced_security":                repositoriesHaveAdvancedSecurity(repositories),
			"advanced_security_available":      repositoriesExposeAdvancedSecurity(repositories),
			"protected_environments":           protectedEnvironmentsObserved(desired, environments),
			"protected_environments_available": environmentCollectionsReadable(environments),
		},
	}
	managedProjection := observedManagedProjection(
		desired, organizationRaw, actionsRaw, selectedActionsRaw, workflowPolicyRaw,
		oidcRaw, membersRaw, adminsRaw, outsideRaw, teams, repositories, rulesets, environments,
		observationDetails{
			customProperties: customPropertiesRaw, securityManagers: securityManagersRaw,
			customPropertiesKnown: customPropertiesKnown, securityManagersKnown: securityManagersKnown,
			rulesetsKnown: rulesetsKnown,
			runners:       runnersRaw, runnersKnown: runnersKnown,
			selfHostedPolicy: selfHostedPolicyRaw, selfHostedPolicyKnown: selfHostedPolicyKnown,
			teamMembers: teamMembers, repositoryTeams: repositoryTeams,
			directCollaborators: directCollaborators, vulnerabilityAlerts: vulnerabilityAlerts,
			dependencyGraph: dependencyGraph, dependabotSecurityUpdates: dependabotSecurityUpdates,
			codeScanningDefaultSetup:      codeScanningDefaultSetup,
			privateVulnerabilityReporting: privateVulnerabilityReporting,
			repositoryCustomProperties:    repositoryCustomProperties,
			repositoryOIDCPolicies:        repositoryOIDCPolicies,
		},
	)
	result["managed_projection"] = managedProjection
	desiredProjectionJSON, desiredProjectionErr := rendering.CanonicalJSON(ManagedProjection(desired))
	observedProjectionJSON, observedProjectionErr := rendering.CanonicalJSON(managedProjection)
	if desiredProjectionErr != nil || observedProjectionErr != nil {
		return nil, errors.New("canonicalize managed observation")
	}
	result["desired_managed_projection_digest"] = rendering.Digest(desiredProjectionJSON)
	result["observed_managed_projection_digest"] = rendering.Digest(observedProjectionJSON)
	result["managed_state_matches_desired"] = Report(
		desired, map[string]any{"managed_projection": managedProjection},
	)["status"] == "clean"
	redacted, _ := rendering.Redact(result).(map[string]any)
	return redacted, nil
}

type githubClient struct {
	base  string
	token string
	http  *http.Client
}

type observationDetails struct {
	customProperties              []any
	customPropertiesKnown         bool
	securityManagers              []any
	securityManagersKnown         bool
	rulesetsKnown                 bool
	runners                       map[string]any
	runnersKnown                  bool
	selfHostedPolicy              map[string]any
	selfHostedPolicyKnown         bool
	teamMembers                   map[string][]any
	repositoryTeams               map[string][]any
	directCollaborators           map[string][]any
	vulnerabilityAlerts           map[string]any
	dependencyGraph               map[string]any
	dependabotSecurityUpdates     map[string]any
	codeScanningDefaultSetup      map[string]any
	privateVulnerabilityReporting map[string]any
	repositoryCustomProperties    map[string]any
	repositoryOIDCPolicies        map[string]any
}

func (client *githubClient) getObject(ctx context.Context, path string) (map[string]any, error) {
	var value map[string]any
	if err := client.get(ctx, path, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func (client *githubClient) getList(ctx context.Context, path string) ([]any, error) {
	result := make([]any, 0)
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	for page := 1; page <= maxPages; page++ {
		var values []any
		pagePath := fmt.Sprintf("%s%sper_page=%d&page=%d", path, separator, pageSize, page)
		if err := client.get(ctx, pagePath, &values); err != nil {
			return nil, err
		}
		result = append(result, values...)
		if len(values) < pageSize {
			return result, nil
		}
	}
	return nil, fmt.Errorf("pagination exceeded %d pages", maxPages)
}

func (client *githubClient) getNestedList(ctx context.Context, path, field string) ([]any, error) {
	result := make([]any, 0)
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	for page := 1; page <= maxPages; page++ {
		var container map[string]any
		pagePath := fmt.Sprintf("%s%sper_page=%d&page=%d", path, separator, pageSize, page)
		if err := client.get(ctx, pagePath, &container); err != nil {
			return nil, err
		}
		values, ok := container[field].([]any)
		if !ok {
			return nil, fmt.Errorf("GitHub API response omitted list field %q", field)
		}
		result = append(result, values...)
		if len(values) < pageSize {
			return result, nil
		}
	}
	return nil, fmt.Errorf("pagination exceeded %d pages", maxPages)
}

func (client *githubClient) getNestedListWithTotal(ctx context.Context, path, field, totalField string) ([]any, int64, error) {
	result := make([]any, 0)
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	expectedTotal := int64(-1)
	for page := 1; page <= maxPages; page++ {
		var container map[string]any
		pagePath := fmt.Sprintf("%s%sper_page=%d&page=%d", path, separator, pageSize, page)
		if err := client.get(ctx, pagePath, &container); err != nil {
			return nil, expectedTotal, err
		}
		pageTotal := integerJSONValue(container[totalField])
		if pageTotal < 0 {
			return nil, pageTotal, fmt.Errorf("GitHub API response omitted nonnegative %q", totalField)
		}
		if expectedTotal < 0 {
			expectedTotal = pageTotal
		} else if pageTotal != expectedTotal {
			return nil, expectedTotal, fmt.Errorf("GitHub API %q changed across pagination", totalField)
		}
		values, ok := container[field].([]any)
		if !ok {
			return nil, expectedTotal, fmt.Errorf("GitHub API response omitted list field %q", field)
		}
		result = append(result, values...)
		if int64(len(result)) == expectedTotal {
			return result, expectedTotal, nil
		}
		if int64(len(result)) > expectedTotal || len(values) < pageSize {
			return nil, expectedTotal, fmt.Errorf("GitHub API %q=%d does not match enumerated count %d", totalField, expectedTotal, len(result))
		}
	}
	return nil, expectedTotal, fmt.Errorf("pagination exceeded %d pages", maxPages)
}

func (client *githubClient) get(ctx context.Context, path string, destination any) error {
	request, err := client.request(ctx, path)
	if err != nil {
		return err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		requestID := response.Header.Get("X-GitHub-Request-Id")
		return fmt.Errorf("GitHub API returned %s (request_id=%q)", response.Status, requestID)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxJSONBytes+1))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode GitHub response: %w", err)
	}
	return nil
}

func (client *githubClient) checkEnabled(ctx context.Context, path string) (bool, error) {
	request, err := client.request(ctx, path)
	if err != nil {
		return false, err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return false, fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("GitHub API returned %s (request_id=%q)", response.Status, response.Header.Get("X-GitHub-Request-Id"))
	}
}

func (client *githubClient) objectState(ctx context.Context, path, field string, expected any) (bool, bool, error) {
	request, err := client.request(ctx, path)
	if err != nil {
		return false, false, err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return false, false, fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return false, false, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return false, false, fmt.Errorf("GitHub API returned %s (request_id=%q)", response.Status, response.Header.Get("X-GitHub-Request-Id"))
	}
	var value map[string]any
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxJSONBytes+1))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return false, false, fmt.Errorf("decode GitHub response: %w", err)
	}
	return fmt.Sprint(value[field]) == fmt.Sprint(expected), true, nil
}

func (client *githubClient) request(ctx context.Context, path string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.base+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("User-Agent", "mindclade-github-configctl/1")
	request.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	return request, nil
}

var organizationFields = []string{
	"id", "login", "name", "company", "blog", "location", "email", "twitter_username",
	"public_repos", "total_private_repos",
	"is_verified", "has_organization_projects", "has_repository_projects",
	"default_repository_permission", "members_can_create_repositories",
	"members_can_create_public_repositories", "members_can_create_private_repositories",
	"members_can_create_internal_repositories", "members_can_create_pages",
	"members_can_create_public_pages", "members_can_create_private_pages",
	"members_can_fork_private_repositories", "web_commit_signoff_required",
	"two_factor_requirement_enabled", "plan",
}

var repositoryFields = []string{
	"id", "name", "description", "visibility", "private", "archived", "disabled", "fork", "default_branch",
	"has_issues", "has_projects", "has_wiki", "has_pages", "has_discussions", "has_downloads",
	"allow_forking", "is_template", "allow_squash_merge", "allow_merge_commit",
	"allow_rebase_merge", "allow_auto_merge", "allow_update_branch", "delete_branch_on_merge",
	"use_squash_pr_title_as_default", "squash_merge_commit_title",
	"squash_merge_commit_message", "web_commit_signoff_required", "security_and_analysis", "custom_properties",
}

var teamFields = []string{"id", "name", "slug", "description", "privacy", "notification_setting", "parent"}

func reduceObject(value map[string]any, fields []string) map[string]any {
	if fields == nil {
		result := make(map[string]any, len(value))
		for key, child := range value {
			if !isVolatile(key) {
				result[key] = rendering.Redact(child)
			}
		}
		return result
	}
	result := make(map[string]any, len(fields))
	for _, key := range fields {
		if child, exists := value[key]; exists {
			result[key] = rendering.Redact(child)
		}
	}
	return result
}

func reduceArray(values []any, fields []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		if object, ok := value.(map[string]any); ok {
			result = append(result, reduceObject(object, fields))
		}
	}
	return normalize(result).([]any)
}

func indexObjects(values []any, key string, fields []string) map[string]any {
	result := make(map[string]any, len(values))
	for _, value := range values {
		object, ok := value.(map[string]any)
		if !ok {
			continue
		}
		identifier, _ := object[key].(string)
		if identifier != "" {
			result[identifier] = reduceObject(object, fields)
		}
	}
	return result
}

func objectArray(value any) []map[string]any {
	items, _ := value.([]any)
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if object, ok := item.(map[string]any); ok {
			result = append(result, object)
		}
	}
	return result
}

func repositoriesHaveAdvancedSecurity(repositories map[string]any) bool {
	if len(repositories) == 0 {
		return false
	}
	for _, value := range repositories {
		repository, _ := value.(map[string]any)
		security, _ := repository["security_and_analysis"].(map[string]any)
		advanced, _ := security["advanced_security"].(map[string]any)
		status, _ := advanced["status"].(string)
		if status != "enabled" {
			return false
		}
	}
	return true
}

func repositoriesExposeAdvancedSecurity(repositories map[string]any) bool {
	if len(repositories) == 0 {
		return false
	}
	for _, value := range repositories {
		repository, _ := value.(map[string]any)
		security, _ := repository["security_and_analysis"].(map[string]any)
		advanced, _ := security["advanced_security"].(map[string]any)
		if _, known := advanced["status"].(string); !known {
			return false
		}
	}
	return true
}

func environmentCollectionsReadable(environments map[string]any) bool {
	for _, value := range environments {
		if isUnknown(value) {
			return false
		}
	}
	return true
}

func protectedEnvironmentsObserved(desired, observedByRepository map[string]any) bool {
	desiredEnvironments, _ := desired["environments"].(map[string]any)
	if len(desiredEnvironments) == 0 {
		return false
	}
	for _, rawSpec := range desiredEnvironments {
		spec, _ := rawSpec.(map[string]any)
		name, _ := spec["name"].(string)
		expectedReviewers := make(map[string]struct{})
		for _, reviewer := range objectArray(spec["required_reviewers"]) {
			if team, _ := reviewer["team"].(string); team != "" {
				expectedReviewers[strings.ToLower(team)] = struct{}{}
			}
		}
		for _, rawRepository := range valueList(spec["repositories"]) {
			repository, _ := rawRepository.(string)
			container, _ := observedByRepository[repository].(map[string]any)
			var matched map[string]any
			for _, environment := range objectArray(container["environments"]) {
				if observedName, _ := environment["name"].(string); observedName == name {
					matched = environment
					break
				}
			}
			if matched == nil {
				return false
			}
			observedReviewers := make(map[string]struct{})
			for _, rule := range objectArray(matched["protection_rules"]) {
				for _, reviewer := range objectArray(rule["reviewers"]) {
					reviewerObject, _ := reviewer["reviewer"].(map[string]any)
					slug, _ := reviewerObject["slug"].(string)
					if slug == "" {
						slug, _ = reviewerObject["name"].(string)
					}
					if slug != "" {
						observedReviewers[strings.ToLower(slug)] = struct{}{}
					}
				}
			}
			for reviewer := range expectedReviewers {
				if _, exists := observedReviewers[reviewer]; !exists {
					return false
				}
			}
			if preventSelfReview, known := environmentPreventSelfReview(matched).(bool); !known || !preventSelfReview {
				return false
			}
		}
	}
	return true
}

func observedManagedProjection(
	desired, organizationRaw, actionsRaw, selectedActionsRaw, workflowPolicyRaw, oidcRaw map[string]any,
	membersRaw, adminsRaw, outsideRaw []any,
	teams, repositories, rulesets, environments map[string]any,
	details observationDetails,
) map[string]any {
	desiredProjection := ManagedProjection(desired)
	result := map[string]any{"projection_version": "github-rest/v1"}
	desiredOrganization, _ := desiredProjection["organization"].(map[string]any)
	observedOrganization := make(map[string]any, len(desiredOrganization))
	for key := range desiredOrganization {
		if key == "custom_properties" {
			if details.customPropertiesKnown {
				observedOrganization[key] = projectObservedCustomProperties(details.customProperties)
			} else {
				observedOrganization[key] = unknownValue()
			}
			continue
		}
		apiKey := key
		switch key {
		case "organization_login":
			apiKey = "login"
		case "two_factor_requirement":
			apiKey = "two_factor_requirement_enabled"
		}
		setObserved(observedOrganization, key, organizationRaw, apiKey)
	}
	result["organization"] = observedOrganization

	desiredActions, _ := desiredProjection["actions_policy"].(map[string]any)
	observedActions := make(map[string]any, len(desiredActions))
	for key := range desiredActions {
		switch key {
		case "mode":
			setObserved(observedActions, key, actionsRaw, "allowed_actions")
		case "enabled_repositories":
			setObserved(observedActions, key, actionsRaw, "enabled_repositories")
		case "github_owned_allowed":
			setObserved(observedActions, key, selectedActionsRaw, "github_owned_allowed")
		case "verified_creator_allowed":
			setObserved(observedActions, key, selectedActionsRaw, "verified_allowed")
		case "default_workflow_permissions", "can_approve_pull_request_reviews":
			setObserved(observedActions, key, workflowPolicyRaw, key)
		case "allowed_patterns":
			setObserved(observedActions, key, selectedActionsRaw, "patterns_allowed")
		case "required_pin":
			if required, known := actionsRaw["sha_pinning_required"].(bool); known {
				if required {
					observedActions[key] = "commit_sha"
				} else {
					observedActions[key] = "unrestricted"
				}
			} else {
				observedActions[key] = unknownValue()
			}
		case "runner_policy":
			// Runner inventory proves the self-hosted prohibition. GitHub does not
			// expose an organization switch equivalent to the catalog's hosted and
			// public-fork fields, so those remain explicit provider/API gaps.
			runnerPolicy := map[string]any{
				"github_hosted": unknownValue(), "public_fork_pull_requests": unknownValue(),
			}
			if details.runnersKnown && details.selfHostedPolicyKnown {
				if total, exists := details.runners["total_count"]; exists && integerJSONValue(total) >= 0 {
					enabledRepositories, policyKnown := details.selfHostedPolicy["enabled_repositories"].(string)
					if policyKnown {
						runnerPolicy["self_hosted"] = integerJSONValue(total) == 0 && enabledRepositories == "none"
					} else {
						runnerPolicy["self_hosted"] = unknownValue()
					}
				} else {
					runnerPolicy["self_hosted"] = unknownValue()
				}
			} else {
				runnerPolicy["self_hosted"] = unknownValue()
			}
			observedActions[key] = runnerPolicy
		}
	}
	result["actions_policy"] = observedActions
	result["security_policy"] = observedSecurityProjection(desired, repositories, details)

	desiredOIDC, _ := desiredProjection["oidc_policy"].(map[string]any)
	observedOIDC := make(map[string]any, len(desiredOIDC))
	if claims, exists := oidcRaw["include_claim_keys"]; exists {
		observedOIDC["include_claim_keys"] = claims
		values, _ := claims.([]any)
		observedOIDC["use_default_subject"] = len(values) == 0
		setObserved(observedOIDC, "use_immutable_subject", oidcRaw, "use_immutable_subject")
	} else {
		observedOIDC["include_claim_keys"] = unknownValue()
		observedOIDC["use_default_subject"] = unknownValue()
		observedOIDC["use_immutable_subject"] = unknownValue()
	}
	desiredRepositoryTemplates, _ := desiredOIDC["repository_subject_templates"].(map[string]any)
	observedRepositoryTemplates := make(map[string]any, len(desiredRepositoryTemplates))
	desiredRepositorySpecs, _ := desired["repositories"].(map[string]any)
	for id := range desiredRepositoryTemplates {
		spec, _ := desiredRepositorySpecs[id].(map[string]any)
		name, _ := spec["name"].(string)
		if name == "" {
			name = id
		}
		raw, exists := details.repositoryOIDCPolicies[name]
		if !exists {
			// A repository missing from the authoritative organization repository
			// collection is a known absence and remains missing in the projection.
			continue
		}
		if isUnknown(raw) {
			observedRepositoryTemplates[id] = unknownValue()
			continue
		}
		policy, _ := raw.(map[string]any)
		projected := make(map[string]any, 3)
		setObserved(projected, "use_default", policy, "use_default")
		setObserved(projected, "include_claim_keys", policy, "include_claim_keys")
		setObserved(projected, "use_immutable_subject", policy, "use_immutable_subject")
		observedRepositoryTemplates[id] = projected
	}
	observedOIDC["repository_subject_templates"] = observedRepositoryTemplates
	result["oidc_policy"] = observedOIDC

	adminLogins := make(map[string]struct{})
	for _, admin := range objectArrayFromList(adminsRaw) {
		if login, _ := admin["login"].(string); login != "" {
			adminLogins[strings.ToLower(login)] = struct{}{}
		}
	}
	observedMembers := make([]any, 0, len(membersRaw))
	for _, member := range objectArrayFromList(membersRaw) {
		login, _ := member["login"].(string)
		if login == "" {
			continue
		}
		role := "member"
		if _, admin := adminLogins[strings.ToLower(login)]; admin {
			role = "admin"
		}
		observedMembers = append(observedMembers, map[string]any{"login": login, "role": role})
	}
	result["members"] = normalize(observedMembers)
	result["outside_collaborators"] = projectObjectList(outsideRaw, []string{"login"})

	desiredTeams, _ := desired["teams"].(map[string]any)
	observedTeams := make(map[string]any, len(desiredTeams))
	consumedTeams := make(map[string]struct{}, len(desiredTeams))
	for id, rawSpec := range desiredTeams {
		spec, _ := rawSpec.(map[string]any)
		name, _ := spec["name"].(string)
		matchedKey := name
		team, exists := teams[name]
		if !exists {
			matchedKey = id
			team, exists = teams[id]
		}
		teamMap, _ := team.(map[string]any)
		if !exists || teamMap == nil {
			continue
		}
		consumedTeams[matchedKey] = struct{}{}
		observedTeams[id] = projectObservedTeam(teamMap, details.teamMembers[matchedKey])
	}
	for liveKey, rawTeam := range teams {
		if _, consumed := consumedTeams[liveKey]; consumed {
			continue
		}
		team, _ := rawTeam.(map[string]any)
		observedTeams[liveKey] = projectObservedTeam(team, details.teamMembers[liveKey])
	}
	result["teams"] = observedTeams

	desiredRepositories, _ := desired["repositories"].(map[string]any)
	observedRepositories := make(map[string]any, len(desiredRepositories))
	consumedRepositories := make(map[string]struct{}, len(desiredRepositories))
	for id, rawSpec := range desiredRepositories {
		spec, _ := rawSpec.(map[string]any)
		name, _ := spec["name"].(string)
		rawRepository, exists := repositories[name]
		repository, _ := rawRepository.(map[string]any)
		if !exists || repository == nil {
			continue
		}
		consumedRepositories[name] = struct{}{}
		observedRepositories[id] = projectObservedRepository(repository, name, details, true)
	}
	for liveName, rawRepository := range repositories {
		if _, consumed := consumedRepositories[liveName]; consumed {
			continue
		}
		repository, _ := rawRepository.(map[string]any)
		observedRepositories[liveName] = projectObservedRepository(repository, liveName, details, false)
	}
	result["repositories"] = observedRepositories

	desiredRulesets, _ := desired["rulesets"].(map[string]any)
	desiredTeamsForActors, _ := desired["teams"].(map[string]any)
	desiredIntegrationsForActors, _ := desired["integrations"].(map[string]any)
	actorNames := rulesetActorNames(desiredTeamsForActors, desiredIntegrationsForActors, teams)
	observedRulesets := make(map[string]any, len(desiredRulesets))
	consumedRulesets := make(map[string]struct{}, len(desiredRulesets))
	for id, desiredRaw := range desiredRulesets {
		desiredSpec, _ := desiredRaw.(map[string]any)
		logicalName := id
		if configuredName, _ := desiredSpec["name"].(string); configuredName != "" {
			logicalName = configuredName
		}
		rawRuleset, exists := rulesets[logicalName]
		ruleset, _ := rawRuleset.(map[string]any)
		if !exists || ruleset == nil {
			if !details.rulesetsKnown {
				observedRulesets[id] = unknownValue()
			}
			continue
		}
		consumedRulesets[logicalName] = struct{}{}
		desiredRules, _ := desiredSpec["rules"].(map[string]any)
		creationRestricted, _ := desiredRules["creation_restricted"].(bool)
		if desiredSpec["target"] == "tag" && creationRestricted {
			creatorGate, _ := rulesets[logicalName+"-creator-gate"].(map[string]any)
			if creatorGate != nil {
				consumedRulesets[logicalName+"-creator-gate"] = struct{}{}
			}
			observedRulesets[id] = projectObservedSplitTagRuleset(
				ruleset, creatorGate, projectDesiredRuleset(desiredSpec), actorNames,
			)
			continue
		}
		observedRulesets[id] = projectObservedRuleset(ruleset, projectDesiredRuleset(desiredSpec), actorNames)
	}
	if details.rulesetsKnown {
		for liveName, rawRuleset := range rulesets {
			if _, consumed := consumedRulesets[liveName]; consumed {
				continue
			}
			ruleset, _ := rawRuleset.(map[string]any)
			observedRulesets[liveName] = projectObservedRulesetRaw(ruleset, actorNames)
		}
	}
	result["rulesets"] = observedRulesets

	desiredEnvironments, _ := desired["environments"].(map[string]any)
	observedEnvironments := make(map[string]any, len(desiredEnvironments))
	desiredEnvironmentNames := make(map[string]struct{}, len(desiredEnvironments))
	for id, rawSpec := range desiredEnvironments {
		spec, _ := rawSpec.(map[string]any)
		name, _ := spec["name"].(string)
		desiredEnvironmentNames[name] = struct{}{}
		matchingRepositories := make([]any, 0)
		repositorySettings := make(map[string]any)
		repositoryNames := make([]string, 0, len(environments))
		for repositoryName := range environments {
			repositoryNames = append(repositoryNames, repositoryName)
		}
		sort.Strings(repositoryNames)
		unreadable := false
		for _, repositoryName := range repositoryNames {
			rawEnvironments := environments[repositoryName]
			if isUnknown(rawEnvironments) {
				unreadable = true
				continue
			}
			container, _ := rawEnvironments.(map[string]any)
			for _, environment := range objectArray(container["environments"]) {
				if observedName, _ := environment["name"].(string); observedName == name {
					matchingRepositories = append(matchingRepositories, repositoryName)
					repositorySettings[repositoryName] = projectObservedEnvironmentSettings(environment)
					break
				}
			}
		}
		if unreadable {
			observedEnvironments[id] = unknownValue()
			continue
		}
		if len(matchingRepositories) == 0 {
			continue
		}
		entry := map[string]any{
			"name": name, "repositories": matchingRepositories,
			"repository_settings": repositorySettings,
		}
		observedEnvironments[id] = entry
	}
	extraEnvironments := make(map[string]map[string]any)
	allEnvironmentCollectionsReadable := true
	repositoryNames := make([]string, 0, len(environments))
	for repositoryName := range environments {
		repositoryNames = append(repositoryNames, repositoryName)
	}
	sort.Strings(repositoryNames)
	for _, repositoryName := range repositoryNames {
		rawEnvironments := environments[repositoryName]
		if isUnknown(rawEnvironments) {
			allEnvironmentCollectionsReadable = false
			continue
		}
		container, _ := rawEnvironments.(map[string]any)
		for _, environment := range objectArray(container["environments"]) {
			name, _ := environment["name"].(string)
			if name == "" {
				continue
			}
			if _, desired := desiredEnvironmentNames[name]; desired {
				continue
			}
			entry := extraEnvironments[name]
			if entry == nil {
				entry = map[string]any{
					"name": name, "repositories": []any{},
					"repository_settings": map[string]any{},
				}
				extraEnvironments[name] = entry
			}
			entry["repositories"] = append(entry["repositories"].([]any), repositoryName)
			entry["repository_settings"].(map[string]any)[repositoryName] = projectObservedEnvironmentSettings(environment)
		}
	}
	if allEnvironmentCollectionsReadable {
		for name, entry := range extraEnvironments {
			key := name
			if _, collision := observedEnvironments[key]; collision {
				key = "unmanaged-" + name
			}
			observedEnvironments[key] = entry
		}
	}
	result["environments"] = observedEnvironments
	return result
}

func setObserved(destination map[string]any, destinationKey string, source map[string]any, sourceKey string) {
	if value, exists := source[sourceKey]; exists {
		destination[destinationKey] = value
	} else {
		destination[destinationKey] = unknownValue()
	}
}

func unknownValue() map[string]any { return map[string]any{"status": "unknown"} }

func mappedObject(source map[string]any, fields map[string]string) map[string]any {
	result := make(map[string]any, len(fields))
	for desiredKey, sourceKey := range fields {
		setObserved(result, desiredKey, source, sourceKey)
	}
	return result
}

func statusEnabledOrUnknown(source map[string]any, key string) any {
	value, exists := source[key]
	object, _ := value.(map[string]any)
	status, ok := object["status"].(string)
	if !exists || !ok {
		return unknownValue()
	}
	return status == "enabled"
}

func observedActionPinPolicy(value any) any {
	patterns, ok := value.([]any)
	if !ok || len(patterns) == 0 {
		return unknownValue()
	}
	commitPattern := regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$`)
	for _, rawPattern := range patterns {
		pattern, _ := rawPattern.(string)
		if !commitPattern.MatchString(pattern) {
			return "unrestricted"
		}
	}
	return "commit_sha"
}

func projectObservedCustomProperties(values []any) []any {
	result := make([]any, 0, len(values))
	for _, property := range objectArrayFromList(values) {
		entry := map[string]any{}
		setObserved(entry, "name", property, "property_name")
		for _, key := range []string{"value_type", "required", "allowed_values", "values_editable_by"} {
			if value, exists := property[key]; exists {
				entry[key] = value
			}
		}
		result = append(result, entry)
	}
	return normalize(result).([]any)
}

func projectObservedTeam(team map[string]any, members []any) map[string]any {
	entry := pick(team, []string{"name", "description", "privacy"})
	if parent, exists := team["parent"]; exists {
		if parent == nil {
			entry["parent_team"] = nil
		} else if parentMap, ok := parent.(map[string]any); ok {
			if slug, ok := parentMap["slug"].(string); ok {
				entry["parent_team"] = slug
			} else {
				entry["parent_team"] = unknownValue()
			}
		}
	} else {
		entry["parent_team"] = unknownValue()
	}
	if members == nil {
		entry["members"] = unknownValue()
	} else {
		entry["members"] = projectObjectList(members, []string{"login", "role"})
	}
	return entry
}

func projectObservedRepository(
	repository map[string]any,
	name string,
	details observationDetails,
	includeDetailedState bool,
) map[string]any {
	entry := pick(repository, []string{"name", "description", "visibility", "archived", "web_commit_signoff_required"})
	entry["features"] = mappedObject(repository, map[string]string{
		"issues": "has_issues", "projects": "has_projects", "wiki": "has_wiki", "discussions": "has_discussions",
		"downloads": "has_downloads",
	})
	entry["merge_policy"] = mappedObject(repository, map[string]string{
		"allow_squash_merge": "allow_squash_merge", "allow_merge_commit": "allow_merge_commit",
		"allow_rebase_merge": "allow_rebase_merge", "allow_auto_merge": "allow_auto_merge",
		"allow_update_branch": "allow_update_branch", "delete_branch_on_merge": "delete_branch_on_merge",
		"squash_merge_commit_title":   "squash_merge_commit_title",
		"squash_merge_commit_message": "squash_merge_commit_message",
	})
	if !includeDetailedState {
		if properties, exists := repository["custom_properties"]; exists {
			entry["custom_properties"] = properties
		}
		return entry
	}
	entry["custom_properties"] = projectObservedRepositoryProperties(details.repositoryCustomProperties[name])
	securityRaw, _ := repository["security_and_analysis"].(map[string]any)
	entry["security"] = map[string]any{
		"vulnerability_alerts":            details.vulnerabilityAlerts[name],
		"dependabot_security_updates":     details.dependabotSecurityUpdates[name],
		"advanced_security":               statusEnabledOrUnknown(securityRaw, "advanced_security"),
		"secret_scanning":                 statusEnabledOrUnknown(securityRaw, "secret_scanning"),
		"secret_scanning_push_protection": statusEnabledOrUnknown(securityRaw, "secret_scanning_push_protection"),
	}
	entry["team_grants"] = projectObservedTeamGrants(details.repositoryTeams[name])
	entry["direct_collaborators"] = projectObservedCollaborators(details.directCollaborators[name])
	return entry
}

func projectObservedRepositoryProperties(value any) any {
	if isUnknown(value) || value == nil {
		return unknownValue()
	}
	result := make(map[string]any)
	items, _ := value.([]any)
	for _, item := range objectArrayFromList(items) {
		name, _ := item["property_name"].(string)
		if name == "" {
			return unknownValue()
		}
		result[name] = item["value"]
	}
	return result
}

func observedSecurityProjection(desired map[string]any, repositories map[string]any, details observationDetails) map[string]any {
	desiredSecurity, _ := desired["security_policy"].(map[string]any)
	result := make(map[string]any)
	if _, expected := desiredSecurity["security_manager_team"]; expected {
		if !details.securityManagersKnown {
			result["security_manager_team"] = unknownValue()
		} else {
			managers := make([]string, 0, len(details.securityManagers))
			for _, manager := range objectArrayFromList(details.securityManagers) {
				slug, _ := manager["slug"].(string)
				if slug == "" {
					slug, _ = manager["name"].(string)
				}
				if slug != "" {
					managers = append(managers, slug)
				}
			}
			sort.Strings(managers)
			if len(managers) == 1 {
				result["security_manager_team"] = managers[0]
			} else {
				result["security_manager_team"] = unknownValue()
			}
		}
	}
	desiredRepositories, _ := desired["repositories"].(map[string]any)
	checkStatus := func(key string) any {
		for _, rawSpec := range desiredRepositories {
			spec, _ := rawSpec.(map[string]any)
			name, _ := spec["name"].(string)
			repository, _ := repositories[name].(map[string]any)
			security, _ := repository["security_and_analysis"].(map[string]any)
			value := statusEnabledOrUnknown(security, key)
			if _, unknown := value.(map[string]any); unknown {
				return unknownValue()
			}
			if enabled, _ := value.(bool); !enabled {
				return false
			}
		}
		return len(desiredRepositories) > 0
	}
	checks := map[string]func() any{
		"dependency_graph_required": func() any {
			return allRepositoryBools(desiredRepositories, details.dependencyGraph)
		},
		"dependabot_alerts_required": func() any {
			return allRepositoryBools(desiredRepositories, details.vulnerabilityAlerts)
		},
		"dependabot_security_updates_required": func() any {
			return allRepositoryBools(desiredRepositories, details.dependabotSecurityUpdates)
		},
		"advanced_security_required": func() any { return checkStatus("advanced_security") },
		"code_scanning_default_setup_required": func() any {
			return allRepositoryBools(desiredRepositories, details.codeScanningDefaultSetup)
		},
		"secret_scanning_required":                 func() any { return checkStatus("secret_scanning") },
		"secret_scanning_push_protection_required": func() any { return checkStatus("secret_scanning_push_protection") },
		"private_vulnerability_reporting_required": func() any {
			return allRepositoryBools(desiredRepositories, details.privateVulnerabilityReporting)
		},
	}
	for key, check := range checks {
		if _, expected := desiredSecurity[key]; expected {
			result[key] = check()
		}
	}
	return result
}

func allRepositoryBools(desiredRepositories map[string]any, observed map[string]any) any {
	if len(desiredRepositories) == 0 {
		return false
	}
	for _, rawSpec := range desiredRepositories {
		spec, _ := rawSpec.(map[string]any)
		name, _ := spec["name"].(string)
		value, exists := observed[name]
		if !exists {
			return unknownValue()
		}
		if _, unknown := value.(map[string]any); unknown {
			return unknownValue()
		}
		enabled, _ := value.(bool)
		if !enabled {
			return false
		}
	}
	return true
}

func projectObservedTeamGrants(values []any) []any {
	result := make([]any, 0, len(values))
	for _, grant := range objectArrayFromList(values) {
		team, _ := grant["slug"].(string)
		if team == "" {
			team, _ = grant["name"].(string)
		}
		permission, _ := grant["permission"].(string)
		if permission == "" {
			permission, _ = grant["role_name"].(string)
		}
		result = append(result, map[string]any{"team": team, "permission": permission})
	}
	return normalize(result).([]any)
}

func projectObservedCollaborators(values []any) []any {
	result := make([]any, 0, len(values))
	for _, collaborator := range objectArrayFromList(values) {
		login, _ := collaborator["login"].(string)
		permission, _ := collaborator["role_name"].(string)
		if permission == "" {
			permission, _ = collaborator["permission"].(string)
		}
		result = append(result, map[string]any{"login": login, "permission": permission})
	}
	return normalize(result).([]any)
}

func projectObservedRuleset(ruleset, desiredShape map[string]any, actorNames map[string]string) map[string]any {
	return alignShape(desiredShape, projectObservedRulesetRaw(ruleset, actorNames)).(map[string]any)
}

func projectObservedRulesetRaw(ruleset map[string]any, actorNames map[string]string) map[string]any {
	result := pick(ruleset, []string{"target", "enforcement"})
	result["bypass_actors"] = projectObservedBypassActors(ruleset["bypass_actors"], actorNames)
	conditions, _ := ruleset["conditions"].(map[string]any)
	repositoryCondition, _ := conditions["repository_name"].(map[string]any)
	refCondition, _ := conditions["ref_name"].(map[string]any)
	result["repositories"] = repositoryCondition["include"]
	result["include_refs"] = refCondition["include"]
	result["exclude_refs"] = refCondition["exclude"]
	projectedRepositoryCondition := make(map[string]any, 2)
	setObserved(projectedRepositoryCondition, "exclude", repositoryCondition, "exclude")
	setObserved(projectedRepositoryCondition, "protected", repositoryCondition, "protected")
	result["conditions"] = map[string]any{"repository_name": projectedRepositoryCondition}
	projectedRules := make(map[string]any)
	observedRuleTypes := make([]string, 0)
	for _, rule := range objectArray(ruleset["rules"]) {
		typeName, _ := rule["type"].(string)
		if typeName != "" {
			observedRuleTypes = append(observedRuleTypes, typeName)
		}
		parameters, _ := rule["parameters"].(map[string]any)
		switch typeName {
		case "update", "deletion", "non_fast_forward", "required_linear_history", "required_signatures", "merge_queue":
			projectedRules[typeName] = true
		case "creation":
			projectedRules["creation_restricted"] = true
		case "pull_request":
			pullRequest := pick(parameters, []string{
				"required_approving_review_count", "require_code_owner_review",
				"require_last_push_approval", "required_review_thread_resolution",
			})
			if value, exists := parameters["dismiss_stale_reviews_on_push"]; exists {
				pullRequest["dismiss_stale_reviews"] = value
			}
			projectedRules["pull_request"] = pullRequest
		case "required_status_checks":
			checks := make([]any, 0)
			for _, check := range objectArray(parameters["required_status_checks"]) {
				if context, ok := check["context"].(string); ok {
					projectedCheck := map[string]any{"context": context}
					if integrationID, exists := check["integration_id"]; exists && integrationID != nil {
						projectedCheck["integration_id"] = integrationID
					}
					checks = append(checks, projectedCheck)
				}
			}
			requiredStatusChecks := map[string]any{"checks": checks}
			setObserved(requiredStatusChecks, "strict", parameters, "strict_required_status_checks_policy")
			setObserved(requiredStatusChecks, "do_not_enforce_on_create", parameters, "do_not_enforce_on_create")
			projectedRules["required_status_checks"] = requiredStatusChecks
		}
	}
	sort.Strings(observedRuleTypes)
	result["rule_types"] = stringsAsAny(observedRuleTypes)
	result["rules"] = projectedRules
	return result
}

func projectObservedSplitTagRuleset(
	immutability, creatorGate, desiredShape map[string]any,
	actorNames map[string]string,
) map[string]any {
	result := projectObservedRulesetRaw(immutability, actorNames)
	rules, _ := result["rules"].(map[string]any)
	if creatorGate == nil {
		rules["creation_restricted"] = false
		rules["authorized_creator_integrations"] = []any{}
		result["rules"] = rules
		return alignShape(desiredShape, result).(map[string]any)
	}
	gate := projectObservedRulesetRaw(creatorGate, actorNames)
	for _, field := range []string{"target", "enforcement", "repositories", "include_refs", "exclude_refs", "conditions"} {
		left, _ := rendering.CanonicalJSON(result[field])
		right, _ := rendering.CanonicalJSON(gate[field])
		if !bytes.Equal(left, right) {
			result[field] = map[string]any{
				"status":       "physical_ruleset_mismatch",
				"immutability": result[field], "creator_gate": gate[field],
			}
		}
	}
	gateRules, _ := gate["rules"].(map[string]any)
	combinedRuleTypes := make(map[string]struct{})
	for _, source := range []any{result["rule_types"], gate["rule_types"]} {
		for _, ruleType := range stringValues(source) {
			combinedRuleTypes[ruleType] = struct{}{}
		}
	}
	logicalRuleTypes := make([]string, 0, len(combinedRuleTypes))
	for ruleType := range combinedRuleTypes {
		logicalRuleTypes = append(logicalRuleTypes, ruleType)
	}
	sort.Strings(logicalRuleTypes)
	result["rule_types"] = stringsAsAny(logicalRuleTypes)
	creationRestricted, _ := gateRules["creation_restricted"].(bool)
	rules["creation_restricted"] = creationRestricted
	rules["authorized_creator_integrations"] = authorizedCreatorIntegrations(
		creatorGate["bypass_actors"], actorNames,
	)
	result["rules"] = rules
	return alignShape(desiredShape, result).(map[string]any)
}

func projectObservedBypassActors(value any, actorNames map[string]string) []any {
	result := make([]any, 0)
	for _, actor := range objectArray(value) {
		actorType := strings.ToLower(textValue(actor["actor_type"]))
		actorID := fmt.Sprint(actor["actor_id"])
		actorName := actorNames[actorType+":"+actorID]
		if actorName == "" {
			actorName = "unresolved-" + actorType + "-" + actorID
		}
		result = append(result, map[string]any{
			"actor_type": actorType,
			"actor":      actorName,
			"mode":       actor["bypass_mode"],
		})
	}
	return normalize(result).([]any)
}

func authorizedCreatorIntegrations(value any, actorNames map[string]string) []any {
	result := make([]any, 0)
	for _, actor := range objectArray(value) {
		actorType := strings.ToLower(textValue(actor["actor_type"]))
		actorID := fmt.Sprint(actor["actor_id"])
		actorName := actorNames[actorType+":"+actorID]
		if actorType != "integration" || actorName == "" {
			actorName = "unresolved-" + actorType + "-" + actorID
		}
		result = append(result, actorName)
	}
	return normalize(result).([]any)
}

func rulesetActorNames(
	desiredTeams, desiredIntegrations, observedTeams map[string]any,
) map[string]string {
	result := make(map[string]string)
	for id, rawSpec := range desiredTeams {
		spec, _ := rawSpec.(map[string]any)
		name, _ := spec["name"].(string)
		rawTeam, exists := observedTeams[name]
		if !exists {
			rawTeam = observedTeams[id]
		}
		team, _ := rawTeam.(map[string]any)
		if actorID := fmt.Sprint(team["id"]); actorID != "" && actorID != "<nil>" {
			result["team:"+actorID] = id
		}
	}
	for id, rawSpec := range desiredIntegrations {
		spec, _ := rawSpec.(map[string]any)
		if actorID := fmt.Sprint(spec["actor_id"]); actorID != "" && actorID != "<nil>" {
			result["integration:"+actorID] = id
		}
	}
	return result
}

func alignShape(shape, observed any) any {
	shapeMap, shapeIsMap := shape.(map[string]any)
	observedMap, observedIsMap := observed.(map[string]any)
	if !shapeIsMap {
		if observed == nil {
			return unknownValue()
		}
		return observed
	}
	if !observedIsMap {
		return unknownValue()
	}
	result := make(map[string]any, len(shapeMap))
	for key, childShape := range shapeMap {
		child, exists := observedMap[key]
		if !exists {
			result[key] = unknownValue()
			continue
		}
		result[key] = alignShape(childShape, child)
	}
	return result
}

func environmentReviewers(environment map[string]any) []any {
	result := make([]any, 0)
	for _, rule := range objectArray(environment["protection_rules"]) {
		for _, reviewer := range objectArray(rule["reviewers"]) {
			reviewerType, _ := reviewer["type"].(string)
			reviewerObject, _ := reviewer["reviewer"].(map[string]any)
			team, _ := reviewerObject["slug"].(string)
			if team == "" {
				team, _ = reviewerObject["name"].(string)
			}
			result = append(result, map[string]any{"type": strings.ToLower(reviewerType), "team": team})
		}
	}
	return normalize(result).([]any)
}

func projectObservedEnvironmentSettings(environment map[string]any) map[string]any {
	result := make(map[string]any)
	setObserved(result, "deployment_branch_policy", environment, "deployment_branch_policy")
	result["prevent_self_review"] = environmentPreventSelfReview(environment)
	setObserved(result, "can_admins_bypass", environment, "can_admins_bypass")
	result["required_reviewers"] = environmentReviewers(environment)
	return result
}

func environmentPreventSelfReview(environment map[string]any) any {
	for _, rule := range objectArray(environment["protection_rules"]) {
		if value, exists := rule["prevent_self_review"]; exists {
			return value
		}
	}
	return unknownValue()
}

func objectArrayFromList(items []any) []map[string]any {
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if object, ok := item.(map[string]any); ok {
			result = append(result, object)
		}
	}
	return result
}

func valueList(value any) []any {
	items, _ := value.([]any)
	return items
}

func pick(source map[string]any, fields []string) map[string]any {
	result := make(map[string]any, len(fields))
	for _, field := range fields {
		if value, exists := source[field]; exists {
			result[field] = value
		}
	}
	return result
}

func projectDesiredRuleset(spec map[string]any) map[string]any {
	result := pick(spec, []string{
		"target", "enforcement", "repositories", "include_refs", "exclude_refs", "bypass_actors",
	})
	result["conditions"] = map[string]any{
		"repository_name": map[string]any{"exclude": []any{}, "protected": true},
	}
	rules, _ := spec["rules"].(map[string]any)
	ruleTypes := make([]string, 0)
	for _, ruleType := range []string{
		"update", "deletion", "non_fast_forward", "required_linear_history", "required_signatures", "merge_queue",
	} {
		if enabled, _ := rules[ruleType].(bool); enabled {
			ruleTypes = append(ruleTypes, ruleType)
		}
	}
	if enabled, _ := rules["creation_restricted"].(bool); enabled {
		ruleTypes = append(ruleTypes, "creation")
	}
	if _, exists := rules["pull_request"].(map[string]any); exists {
		ruleTypes = append(ruleTypes, "pull_request")
	}
	if _, exists := rules["required_status_checks"].(map[string]any); exists {
		ruleTypes = append(ruleTypes, "required_status_checks")
	}
	sort.Strings(ruleTypes)
	result["rule_types"] = stringsAsAny(ruleTypes)
	projectedRules := pick(rules, []string{
		"update", "deletion", "non_fast_forward", "required_linear_history", "required_signatures",
		"merge_queue", "creation_restricted", "authorized_creator_integrations",
	})
	if pullRequest, ok := rules["pull_request"].(map[string]any); ok {
		projectedRules["pull_request"] = pick(pullRequest, []string{
			"required_approving_review_count", "require_code_owner_review", "dismiss_stale_reviews",
			"require_last_push_approval", "required_review_thread_resolution",
		})
	}
	if requiredChecks, ok := rules["required_status_checks"].(map[string]any); ok {
		checks := make([]any, 0)
		for _, check := range objectArray(requiredChecks["checks"]) {
			if context, ok := check["context"].(string); ok {
				projectedCheck := map[string]any{"context": context}
				if integrationID, exists := check["integration_id"]; exists {
					projectedCheck["integration_id"] = integrationID
				}
				checks = append(checks, projectedCheck)
			}
		}
		projectedRules["required_status_checks"] = map[string]any{
			"strict": requiredChecks["strict"], "do_not_enforce_on_create": false, "checks": checks,
		}
	}
	result["rules"] = projectedRules
	return result
}

func projectDesiredEnvironment(spec map[string]any) map[string]any {
	result := pick(spec, []string{"name", "repositories"})
	settings := pick(spec, []string{"prevent_self_review", "can_admins_bypass", "deployment_branch_policy"})
	settings["required_reviewers"] = projectObjectList(spec["required_reviewers"], []string{"type", "team"})
	repositories := stringValues(spec["repositories"])
	repositorySettings := make(map[string]any, len(repositories))
	for _, repository := range repositories {
		repositorySettings[repository] = settings
	}
	result["repository_settings"] = repositorySettings
	return result
}

func stringValues(value any) []string {
	items, _ := value.([]any)
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func stringsAsAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func textValue(value any) string {
	text, _ := value.(string)
	return text
}

func integerJSONValue(value any) int64 {
	switch number := value.(type) {
	case json.Number:
		integer, _ := number.Int64()
		return integer
	case float64:
		return int64(number)
	case int64:
		return number
	case int:
		return int64(number)
	default:
		return -1
	}
}

func repositoryInventoryProof(organization map[string]any, repositories []any) map[string]any {
	publicRepositories := integerJSONValue(organization["public_repos"])
	privateRepositories := integerJSONValue(organization["total_private_repos"])
	totalsKnown := publicRepositories >= 0 && privateRepositories >= 0
	names := make(map[string]struct{}, len(repositories))
	entriesValid := true
	for _, item := range repositories {
		repository, ok := item.(map[string]any)
		if !ok {
			entriesValid = false
			continue
		}
		name, _ := repository["name"].(string)
		if name == "" {
			entriesValid = false
			continue
		}
		names[strings.ToLower(name)] = struct{}{}
	}
	authoritativeTotal := int64(-1)
	if totalsKnown {
		authoritativeTotal = publicRepositories + privateRepositories
	}
	complete := totalsKnown && entriesValid && int64(len(names)) == authoritativeTotal
	return map[string]any{
		"complete":                  complete,
		"totals_known":              totalsKnown,
		"public_repositories":       publicRepositories,
		"private_repositories":      privateRepositories,
		"authoritative_total_count": authoritativeTotal,
		"enumerated_unique_count":   int64(len(names)),
		"entries_valid":             entriesValid,
	}
}

func installationInventoryProof(installations []any, total int64, requestComplete bool, desired map[string]any) map[string]any {
	identifiers := make(map[int64]struct{}, len(installations))
	observedSlugs := make(map[string]struct{}, len(installations))
	entriesValid := true
	for _, item := range installations {
		installation, ok := item.(map[string]any)
		if !ok {
			entriesValid = false
			continue
		}
		identifier := integerJSONValue(installation["id"])
		slug, _ := installation["app_slug"].(string)
		if identifier <= 0 || slug == "" {
			entriesValid = false
			continue
		}
		if _, duplicate := identifiers[identifier]; duplicate {
			entriesValid = false
		}
		identifiers[identifier] = struct{}{}
		observedSlugs[strings.ToLower(slug)] = struct{}{}
	}
	apiComplete := requestComplete && total >= 0 && entriesValid && int64(len(identifiers)) == total
	desiredIntegrations, _ := desired["integrations"].(map[string]any)
	dispositionComplete := apiComplete && len(observedSlugs) == len(desiredIntegrations)
	if dispositionComplete {
		for id := range desiredIntegrations {
			if _, exists := observedSlugs[strings.ToLower(id)]; !exists {
				dispositionComplete = false
				break
			}
		}
	}
	return map[string]any{
		"api_inventory_complete":       apiComplete,
		"catalog_disposition_complete": dispositionComplete,
		"bootstrap_qualified":          false,
		"total_count":                  total,
		"enumerated_unique_count":      int64(len(identifiers)),
		"entries_valid":                entriesValid,
	}
}

func uniqueSecurityManagerRoleID(container map[string]any) (int64, error) {
	roles, ok := container["roles"].([]any)
	if !ok {
		return 0, errors.New("organization roles response omitted roles")
	}
	identifiers := make([]int64, 0, 1)
	for _, item := range roles {
		role, ok := item.(map[string]any)
		if !ok || textValue(role["name"]) != "security_manager" {
			continue
		}
		identifier := integerJSONValue(role["id"])
		if identifier <= 0 {
			identifier = integerJSONValue(role["role_id"])
		}
		if identifier <= 0 {
			return 0, errors.New("security_manager organization role omitted a positive id")
		}
		identifiers = append(identifiers, identifier)
	}
	if len(identifiers) != 1 {
		return 0, fmt.Errorf("expected exactly one security_manager organization role, observed %d", len(identifiers))
	}
	return identifiers[0], nil
}

func projectObjectList(value any, fields []string) []any {
	items, _ := value.([]any)
	result := make([]any, 0, len(items))
	for _, item := range items {
		if object, ok := item.(map[string]any); ok {
			result = append(result, pick(object, fields))
		}
	}
	return normalize(result).([]any)
}

func projectCollection(value any, projector func(map[string]any) map[string]any) map[string]any {
	collection, _ := value.(map[string]any)
	result := make(map[string]any, len(collection))
	for id, item := range collection {
		if spec, ok := item.(map[string]any); ok {
			result[id] = projector(spec)
		}
	}
	return result
}

func pointerOrRoot(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func escapePointer(value string) string {
	value = strings.ReplaceAll(value, "~", "~0")
	return strings.ReplaceAll(value, "/", "~1")
}

func sanitizedAPIError(err error) string {
	if err == nil {
		return "unknown capability error"
	}
	message := err.Error()
	if len(message) > 512 {
		message = message[:512]
	}
	if redacted, ok := rendering.Redact(message).(string); ok {
		return redacted
	}
	return "capability observation failed"
}
