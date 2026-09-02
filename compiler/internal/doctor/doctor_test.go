package doctor

import (
	"strings"
	"testing"

	githubdiff "github.com/mindclade/github-config/compiler/internal/diff"
	"github.com/mindclade/github-config/compiler/internal/workflowcontract"
)

func TestHealthyAndIncompletePrecedence(t *testing.T) {
	desired := minimalDesired()
	observed := map[string]any{
		"observation_complete": true,
		"managed_projection":   githubdiff.ManagedProjection(desired),
		"founder_pr_bypass_audit": map[string]any{
			"status": "healthy",
		},
		"actions_sensitive_inventory": map[string]any{"status": "healthy"},
	}
	contract := &workflowcontract.Report{Status: "valid", Violations: []workflowcontract.Violation{}}
	report := Build(desired, observed, contract)
	if report.Status != "healthy" {
		t.Fatalf("expected healthy report, got %#v", report)
	}

	observed["observation_complete"] = false
	observed["managed_projection"] = map[string]any{"projection_version": "github-rest/v1"}
	report = Build(desired, observed, contract)
	if report.Status != "degraded" || report.Summary.Drift == 0 {
		t.Fatalf("incomplete observation must take precedence over drift: %#v", report)
	}
	if markdown := string(Markdown(report)); !strings.Contains(markdown, "## Drift") {
		t.Fatalf("Markdown omitted confirmed drift details: %s", markdown)
	}
}

func TestMarkdownIsDeterministicAndConcise(t *testing.T) {
	report := OperationalFailure("sha256:abc", "mindclade", "observation")
	first := string(Markdown(report))
	second := string(Markdown(report))
	if first != second || first == "" {
		t.Fatalf("Markdown output is not deterministic")
	}
}

func TestMissingRequiredWorkflowAuthorityIsDegraded(t *testing.T) {
	desired := minimalDesired()
	observed := map[string]any{
		"observation_complete": true,
		"managed_projection":   githubdiff.ManagedProjection(desired),
		"founder_pr_bypass_audit": map[string]any{
			"status": "healthy",
		},
		"actions_sensitive_inventory": map[string]any{"status": "healthy"},
	}
	contract := &workflowcontract.Report{
		Status: "invalid",
		CheckedAuthorities: []workflowcontract.Authority{{
			Repository: ".github", Status: "missing",
		}},
		Violations: []workflowcontract.Violation{{Code: "AUTHORITY_UNAVAILABLE"}},
	}
	report := Build(desired, observed, contract)
	if report.Status != "degraded" || report.Summary.Degraded == 0 {
		t.Fatalf("missing authority must take precedence as incomplete: %#v", report)
	}
}

func minimalDesired() map[string]any {
	return map[string]any{
		"source_digest": "sha256:abc",
		"organization": map[string]any{
			"organization_login": "mindclade",
			"founder_pull_request_bypass": map[string]any{
				"contract": "founder-pr-bypass.v1", "team": "founder-pr-bypass",
				"principal_id": "founder-primary", "bypass_mode": "pull_request",
				"durable": true, "self_authored_pull_requests": true,
				"label": "founder-bypass", "comment_marker": "<!-- founder-pr-bypass:v1 -->",
				"all_repositories": true, "all_paths": true, "head_sha_required": true,
				"reason_required": true,
			},
		},
		"actions_policy":        map[string]any{"allowed_actions": []any{}},
		"security_policy":       map[string]any{},
		"oidc_policy":           map[string]any{},
		"members":               []any{},
		"outside_collaborators": []any{},
		"teams": map[string]any{
			"founder-pr-bypass": map[string]any{"privacy": "closed", "members": []any{}},
		},
		"repositories": map[string]any{},
		"rulesets": map[string]any{
			"governance": map[string]any{
				"target": "branch", "repositories": []any{"github-config"},
				"bypass_actors": []any{map[string]any{
					"actor_type": "team", "actor": "founder-pr-bypass", "mode": "pull_request",
				}},
				"rules": map[string]any{},
			},
		},
		"environments": map[string]any{},
	}
}
