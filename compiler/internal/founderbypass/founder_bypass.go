// Package founderbypass renders the public, nonsecret PR bypass policy contract.
package founderbypass

import (
	"errors"
	"fmt"
	"sort"

	"github.com/mindclade/github-config/compiler/internal/catalog"
	"github.com/mindclade/github-config/compiler/internal/rendering"
	"github.com/mindclade/github-config/compiler/internal/validation"
)

// Policy builds a deterministic artifact for required-workflow consumers. The
// artifact grants no GitHub or cloud credential and is not published here.
func Policy(compiled *catalog.Catalog) (map[string]any, error) {
	configured, _ := compiled.Organization["founder_pull_request_bypass"].(map[string]any)
	if configured == nil || configured["contract"] != "founder-pr-bypass.v1" {
		return nil, errors.New("founder-pr-bypass.v1 is not configured")
	}
	accounts := stringList(configured["github_actor_accounts"])
	principalByLogin := make(map[string]string)
	for _, raw := range compiled.Members {
		member, _ := raw.(map[string]any)
		login, _ := member["login"].(string)
		principal, _ := member["principal_id"].(string)
		principalByLogin[login] = principal
	}
	identities := make([]any, 0, len(accounts))
	for _, login := range accounts {
		principal := principalByLogin[login]
		if principal != "founder-primary" {
			return nil, fmt.Errorf("founder bypass login %q is not mapped to founder-primary", login)
		}
		identities = append(identities, map[string]any{"login": login, "principal_id": principal})
	}
	repositories := make([]string, 0, len(compiled.Repositories))
	for id, raw := range compiled.Repositories {
		repository, _ := raw.(map[string]any)
		name, _ := repository["name"].(string)
		if name == "" {
			name = id
		}
		repositories = append(repositories, name)
	}
	sort.Strings(repositories)
	base := map[string]any{
		"api_version": validation.APIVersion,
		"kind":        "FounderPullRequestBypassPolicy",
		"contract":    "founder-pr-bypass.v1",
		"entitlement": map[string]any{
			"id": "founder-pr-bypass", "team": "founder-pr-bypass",
			"durable": true, "bypass_mode": "pull_request", "self_authored_pull_requests": true,
			"repositories": stringsToAny(repositories),
			"paths":        []any{"**"}, "foundation_authority": false, "production_authority": false,
		},
		"identities": identities,
		"evidence": map[string]any{
			"label": "founder-bypass", "comment_marker": "<!-- founder-pr-bypass:v1 -->",
			"comment_format": "<!-- founder-pr-bypass:v1 -->\nhead-sha: <40-lowercase-hex>\nreason: <1-500 characters>",
			"head_sha_field": "head-sha", "reason_field": "reason", "reason_max_length": 500,
			"head_sha_required": true, "reason_required": true, "exact_comment_shape_required": true,
			"comment_author_must_map_to_principal": "founder-primary",
			"new_commit_invalidates_evidence":      true,
		},
		"source_digest": compiled.SourceDigest,
	}
	canonical, err := rendering.CanonicalJSON(base)
	if err != nil {
		return nil, err
	}
	base["policy_digest"] = rendering.Digest(canonical)
	return base, nil
}

func stringList(value any) []string {
	values, _ := value.([]any)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
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
