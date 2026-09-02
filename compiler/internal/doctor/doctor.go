// Package doctor composes catalog, observation, drift, and workflow diagnostics.
package doctor

import (
	"fmt"
	"sort"
	"strings"

	githubdiff "github.com/mindclade/github-config/compiler/internal/diff"
	"github.com/mindclade/github-config/compiler/internal/validation"
	"github.com/mindclade/github-config/compiler/internal/workflowcontract"
)

// Check is one deterministic operator-facing diagnostic.
type Check struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Summary string `json:"summary"`
}

// Summary counts diagnostic outcomes without exposing sensitive values.
type Summary struct {
	Healthy  int `json:"healthy"`
	Drift    int `json:"drift"`
	Degraded int `json:"degraded"`
}

// Report is the versioned doctor JSON contract.
type Report struct {
	APIVersion       string                   `json:"api_version"`
	Kind             string                   `json:"kind"`
	Status           string                   `json:"status"`
	SourceDigest     string                   `json:"source_digest,omitempty"`
	Organization     string                   `json:"organization,omitempty"`
	Summary          Summary                  `json:"summary"`
	Checks           []Check                  `json:"checks"`
	Drift            map[string]any           `json:"drift,omitempty"`
	WorkflowContract *workflowcontract.Report `json:"workflow_contract,omitempty"`
}

// Build evaluates a complete observation. Incomplete information takes
// precedence over confirmed drift so a partial token can never report clean.
func Build(
	desired, observed map[string]any, contract *workflowcontract.Report,
) *Report {
	organizationSpec, _ := desired["organization"].(map[string]any)
	report := &Report{
		APIVersion: validation.APIVersion, Kind: "DoctorReport",
		Status: "healthy", SourceDigest: stringValue(desired["source_digest"]),
		Organization: stringValue(organizationSpec["organization_login"]),
		Checks:       []Check{}, WorkflowContract: contract,
	}
	add(report, "catalog", "healthy", "catalog source is schema-valid and deterministic")
	observationComplete, _ := observed["observation_complete"].(bool)
	if observationComplete {
		add(report, "observation", "healthy", "all required GitHub capabilities were observed")
	} else {
		add(report, "observation", "degraded", "GitHub observation is incomplete or capability-limited")
	}
	report.Drift = githubdiff.Report(desired, observed)
	if report.Drift["status"] == "drift" {
		add(report, "effective_state", "drift", "effective GitHub state differs from the managed catalog")
	} else {
		add(report, "effective_state", "healthy", "effective GitHub state matches the managed catalog")
	}
	if contract == nil {
		add(report, "workflow_contract", "degraded", "workflow contract result is unavailable")
	} else if workflowContractIncomplete(contract) {
		add(report, "workflow_contract", "degraded", "reviewed workflow authority evidence is incomplete")
	} else if contract.Status == "valid" {
		add(report, "workflow_contract", "healthy", "reviewed workflow calls and permissions satisfy the contract")
	} else {
		add(report, "workflow_contract", "drift", "workflow contract contains confirmed violations")
	}
	if founderPolicyValid(desired) {
		add(report, "founder_bypass_policy", "healthy", "founder bypass is confined to pull-request governance")
	} else {
		add(report, "founder_bypass_policy", "drift", "founder bypass policy is missing or exceeds its entitlement")
	}
	addObservedCheck(report, observed, "founder_pr_bypass_audit", "founder_bypass_audit",
		"labeled founder-bypass pull requests have current head-bound evidence")
	addObservedCheck(report, observed, "actions_sensitive_inventory", "secret_metadata",
		"secret metadata was inventoried without reading values")
	finalize(report)
	return report
}

func workflowContractIncomplete(contract *workflowcontract.Report) bool {
	for _, authority := range contract.CheckedAuthorities {
		if authority.Status == "missing" || authority.Status == "not_provided" {
			return true
		}
	}
	for _, violation := range contract.Violations {
		if violation.Code == "AUTHORITY_UNAVAILABLE" {
			return true
		}
	}
	return false
}

// OperationalFailure returns a deterministic degraded report without copying
// a possibly sensitive provider error into generated evidence.
func OperationalFailure(sourceDigest, organization, checkID string) *Report {
	report := &Report{
		APIVersion: validation.APIVersion, Kind: "DoctorReport", Status: "degraded",
		SourceDigest: sourceDigest, Organization: organization, Checks: []Check{},
	}
	add(report, checkID, "degraded", "diagnostic operation failed before a complete result was available")
	finalize(report)
	return report
}

// Markdown renders a concise, deterministic, redacted operator summary.
func Markdown(report *Report) []byte {
	var builder strings.Builder
	builder.WriteString("# Estate CI doctor\n\n")
	builder.WriteString("- Status: **" + report.Status + "**\n")
	if report.Organization != "" {
		builder.WriteString("- Organization: `" + report.Organization + "`\n")
	}
	if report.SourceDigest != "" {
		builder.WriteString("- Source: `" + report.SourceDigest + "`\n")
	}
	_, _ = fmt.Fprintf(&builder, "- Checks: %d healthy, %d drift, %d degraded\n\n",
		report.Summary.Healthy, report.Summary.Drift, report.Summary.Degraded)
	builder.WriteString("| Check | Status | Summary |\n|---|---|---|\n")
	for _, check := range report.Checks {
		builder.WriteString("| `" + check.ID + "` | " + check.Status + " | " + markdownText(check.Summary) + " |\n")
	}
	if report.WorkflowContract != nil && len(report.WorkflowContract.Violations) > 0 {
		builder.WriteString("\n## Workflow violations\n\n")
		limit := min(len(report.WorkflowContract.Violations), 20)
		for _, violation := range report.WorkflowContract.Violations[:limit] {
			location := violation.Repository + "/.github/workflows/" + violation.Workflow
			builder.WriteString("- `" + violation.Code + "` in `" + location + "`: " + markdownText(violation.Message) + "\n")
		}
	}
	if changes := driftChanges(report.Drift["changes"]); len(changes) > 0 {
		builder.WriteString("\n## Drift\n\n")
		limit := min(len(changes), 20)
		for _, change := range changes[:limit] {
			builder.WriteString("- `" + stringValue(change["kind"]) + "` at `" + stringValue(change["path"]) + "`\n")
		}
	}
	return []byte(builder.String())
}

func driftChanges(value any) []map[string]any {
	switch changes := value.(type) {
	case []map[string]any:
		return changes
	case []any:
		result := make([]map[string]any, 0, len(changes))
		for _, raw := range changes {
			if change, ok := raw.(map[string]any); ok {
				result = append(result, change)
			}
		}
		return result
	default:
		return nil
	}
}

func founderPolicyValid(desired map[string]any) bool {
	organization, _ := desired["organization"].(map[string]any)
	policy, _ := organization["founder_pull_request_bypass"].(map[string]any)
	if stringValue(policy["contract"]) != "founder-pr-bypass.v1" ||
		stringValue(policy["label"]) != "founder-bypass" ||
		stringValue(policy["comment_marker"]) != "<!-- founder-pr-bypass:v1 -->" ||
		stringValue(policy["principal_id"]) != "founder-primary" ||
		stringValue(policy["team"]) != "founder-pr-bypass" ||
		stringValue(policy["bypass_mode"]) != "pull_request" || !boolValue(policy["durable"]) ||
		!boolValue(policy["self_authored_pull_requests"]) || !boolValue(policy["all_repositories"]) ||
		!boolValue(policy["all_paths"]) || !boolValue(policy["head_sha_required"]) ||
		!boolValue(policy["reason_required"]) {
		return false
	}
	teams, _ := desired["teams"].(map[string]any)
	team, _ := teams["founder-pr-bypass"].(map[string]any)
	if stringValue(team["privacy"]) != "closed" {
		return false
	}
	rulesets, _ := desired["rulesets"].(map[string]any)
	branchCount := 0
	for _, raw := range rulesets {
		ruleset, _ := raw.(map[string]any)
		if stringValue(ruleset["target"]) != "branch" {
			continue
		}
		branchCount++
		actors, _ := ruleset["bypass_actors"].([]any)
		if len(actors) != 1 {
			return false
		}
		actor, _ := actors[0].(map[string]any)
		if stringValue(actor["actor_type"]) != "team" || stringValue(actor["actor"]) != "founder-pr-bypass" ||
			stringValue(actor["mode"]) != "pull_request" {
			return false
		}
	}
	return branchCount > 0
}

func addObservedCheck(report *Report, observed map[string]any, sourceKey, checkID, healthySummary string) {
	value, _ := observed[sourceKey].(map[string]any)
	status := stringValue(value["status"])
	switch status {
	case "healthy", "clean":
		add(report, checkID, "healthy", healthySummary)
	case "drift", "invalid":
		add(report, checkID, "drift", "connected audit found confirmed policy violations")
	default:
		add(report, checkID, "degraded", "connected audit evidence is unavailable or incomplete")
	}
}

func add(report *Report, id, status, summary string) {
	report.Checks = append(report.Checks, Check{ID: id, Status: status, Summary: summary})
}

func finalize(report *Report) {
	sort.Slice(report.Checks, func(left, right int) bool { return report.Checks[left].ID < report.Checks[right].ID })
	report.Summary = Summary{}
	for _, check := range report.Checks {
		switch check.Status {
		case "healthy":
			report.Summary.Healthy++
		case "drift":
			report.Summary.Drift++
		default:
			report.Summary.Degraded++
		}
	}
	switch {
	case report.Summary.Degraded > 0:
		report.Status = "degraded"
	case report.Summary.Drift > 0:
		report.Status = "drift"
	default:
		report.Status = "healthy"
	}
}

func markdownText(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	return strings.ReplaceAll(value, "\n", " ")
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func boolValue(value any) bool {
	result, _ := value.(bool)
	return result
}
