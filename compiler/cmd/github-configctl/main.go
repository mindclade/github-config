// github-configctl validates, compiles, observes, and safely compares Mindclade
// GitHub governance state. It performs no write operation against GitHub.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mindclade/github-config/compiler/internal/catalog"
	githubdiff "github.com/mindclade/github-config/compiler/internal/diff"
	"github.com/mindclade/github-config/compiler/internal/evidence"
	"github.com/mindclade/github-config/compiler/internal/rendering"
	"github.com/mindclade/github-config/compiler/internal/validation"
)

const usage = `Usage:
  github-configctl [--root REPOSITORY] validate
  github-configctl [--root REPOSITORY] compile --output PATH [--tofu-var-file PATH]
  github-configctl [--root REPOSITORY] policy-input --output PATH
  github-configctl [--root REPOSITORY] observe --organization ORG --output PATH
  github-configctl [--root REPOSITORY] diff --desired PATH --observed PATH [--output PATH]
  github-configctl [--root REPOSITORY] evidence --plan PATH [--plan-file PATH] [--catalog PATH] [--observed PATH] [--phase PHASE] --output PATH
  github-configctl [--root REPOSITORY] verify-evidence --input PATH
  github-configctl [--root REPOSITORY] preflight --desired PATH --observed PATH [--phase adopt|foundation|enforce] [--output PATH]

The --root flag may appear before or after the command. PATH may be - for stdout
where an output flag accepts it. Exit code 2 means drift or a blocked preflight.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	root, arguments, err := extractRoot(arguments)
	if err != nil {
		fmt.Fprintf(stderr, "github-configctl: %v\n", err)
		return 1
	}
	if len(arguments) == 0 || arguments[0] == "help" || arguments[0] == "--help" || arguments[0] == "-h" {
		fmt.Fprint(stdout, usage)
		if len(arguments) == 0 {
			return 1
		}
		return 0
	}
	command := arguments[0]
	commandArguments := arguments[1:]
	switch command {
	case "validate":
		return runValidate(root, commandArguments, stdout, stderr)
	case "compile":
		return runCompile(root, commandArguments, stdout, stderr)
	case "policy-input":
		return runPolicyInput(root, commandArguments, stdout, stderr)
	case "observe":
		return runObserve(root, commandArguments, stdout, stderr)
	case "diff":
		return runDiff(commandArguments, stdout, stderr)
	case "evidence":
		return runEvidence(root, commandArguments, stdout, stderr)
	case "verify-evidence":
		return runVerifyEvidence(commandArguments, stdout, stderr)
	case "preflight":
		return runPreflight(commandArguments, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "github-configctl: unknown command %q\n%s", command, usage)
		return 1
	}
}

func runPolicyInput(root string, arguments []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("policy-input", stderr)
	output := flags.String("output", "", "Rego input JSON output path")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 1
	}
	if *output == "" {
		return reportError(stderr, errors.New("policy-input requires --output"))
	}
	input, err := catalog.PolicyInput(root)
	if err != nil {
		return reportError(stderr, err)
	}
	if err := rendering.WriteJSON(*output, input, stdout); err != nil {
		return reportError(stderr, err)
	}
	return 0
}

func runValidate(root string, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) != 0 {
		fmt.Fprintln(stderr, "github-configctl: validate accepts no command flags")
		return 1
	}
	compiled, err := catalog.Compile(root)
	if err != nil {
		return reportError(stderr, err)
	}
	result := map[string]any{
		"api_version": validation.APIVersion,
		"kind":        "ValidationResult", "status": "valid",
		"source_digest": compiled.SourceDigest,
	}
	if err := rendering.WriteJSON("-", result, stdout); err != nil {
		return reportError(stderr, err)
	}
	return 0
}

func runCompile(root string, arguments []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("compile", stderr)
	output := flags.String("output", "", "catalog output path")
	tofuVariableFile := flags.String("tofu-var-file", "", "optional OpenTofu variable JSON output")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 1
	}
	if *output == "" {
		return reportError(stderr, errors.New("compile requires --output"))
	}
	if *tofuVariableFile != "" {
		if *output == "-" && *tofuVariableFile == "-" {
			return reportError(stderr, errors.New("catalog and OpenTofu outputs cannot both use stdout"))
		}
		if *output != "-" && *tofuVariableFile != "-" {
			catalogOutput, _ := filepath.Abs(*output)
			tofuOutput, _ := filepath.Abs(*tofuVariableFile)
			if catalogOutput == tofuOutput {
				return reportError(stderr, errors.New("catalog and OpenTofu outputs must use different paths"))
			}
		}
	}
	compiled, err := catalog.Compile(root)
	if err != nil {
		return reportError(stderr, err)
	}
	if err := rendering.WriteJSON(*output, compiled, stdout); err != nil {
		return reportError(stderr, err)
	}
	if *tofuVariableFile != "" {
		if err := rendering.WriteJSON(*tofuVariableFile, map[string]any{"catalog": compiled.AsMap()}, stdout); err != nil {
			return reportError(stderr, err)
		}
	}
	return 0
}

func runObserve(root string, arguments []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("observe", stderr)
	organization := flags.String("organization", "", "GitHub organization login")
	output := flags.String("output", "", "observed state output path")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 1
	}
	if *organization == "" || *output == "" {
		return reportError(stderr, errors.New("observe requires --organization and --output"))
	}
	compiled, err := catalog.Compile(root)
	if err != nil {
		return reportError(stderr, err)
	}
	repositories := make([]string, 0, len(compiled.Repositories))
	for id, value := range compiled.Repositories {
		spec, _ := value.(map[string]any)
		name, _ := spec["name"].(string)
		if name == "" {
			name = id
		}
		repositories = append(repositories, name)
	}
	sort.Strings(repositories)
	contextWithTimeout, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	observed, err := githubdiff.Observe(
		contextWithTimeout, *organization, os.Getenv("GITHUB_API_URL"),
		os.Getenv("GITHUB_TOKEN"), repositories, compiled.AsMap(),
	)
	if err != nil {
		return reportError(stderr, err)
	}
	if err := rendering.WriteJSON(*output, observed, stdout); err != nil {
		return reportError(stderr, err)
	}
	return 0
}

func runDiff(arguments []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("diff", stderr)
	desiredPath := flags.String("desired", "", "compiled desired JSON path")
	observedPath := flags.String("observed", "", "observed JSON path")
	output := flags.String("output", "-", "drift report path")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 1
	}
	if *desiredPath == "" || *observedPath == "" {
		return reportError(stderr, errors.New("diff requires --desired and --observed"))
	}
	desired, err := readJSONPath(*desiredPath)
	if err != nil {
		return reportError(stderr, fmt.Errorf("read desired state: %w", err))
	}
	observed, err := readJSONPath(*observedPath)
	if err != nil {
		return reportError(stderr, fmt.Errorf("read observed state: %w", err))
	}
	report := githubdiff.Report(desired, observed)
	if err := rendering.WriteJSON(*output, report, stdout); err != nil {
		return reportError(stderr, err)
	}
	if report["status"] == "drift" {
		return 2
	}
	return 0
}

func runEvidence(root string, arguments []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("evidence", stderr)
	plan := flags.String("plan", "", "OpenTofu plan JSON path")
	planFile := flags.String("plan-file", "", "optional binary plan path")
	catalogPath := flags.String("catalog", "", "optional compiled catalog path")
	observedPath := flags.String("observed", "", "optional connected observed-state JSON path for immutable organization identity binding")
	output := flags.String("output", "", "evidence output path")
	phase := flags.String("phase", "enforce", "rollout phase: adopt, foundation, or enforce")
	riskAcknowledged := flags.Bool("risk-acknowledged", false, "attest protected review of privilege-expanding changes")
	organization := flags.String("organization", "", "expected organization login binding")
	changeReference := flags.String("change-reference", "", "reviewed change-reference binding")
	workflowRef := flags.String("workflow-ref", os.Getenv("GITHUB_WORKFLOW_REF"), "immutable workflow-ref binding")
	sourceSHA := flags.String("source-sha", os.Getenv("GITHUB_SHA"), "checked-out catalog/compiler source SHA binding")
	workflowSHA := flags.String("workflow-sha", os.Getenv("GITHUB_WORKFLOW_SHA"), "workflow-file source SHA binding")
	actorID := flags.String("actor-id", os.Getenv("GITHUB_ACTOR_ID"), "initiating GitHub actor ID binding")
	planAppID := flags.String("plan-app-id", "", "plan GitHub App ID binding")
	applyAppID := flags.String("apply-app-id", "", "apply GitHub App ID binding")
	runID := flags.String("run-id", os.Getenv("GITHUB_RUN_ID"), "GitHub workflow run ID binding")
	runAttempt := flags.String("run-attempt", os.Getenv("GITHUB_RUN_ATTEMPT"), "GitHub workflow run attempt binding")
	createdEpoch := flags.String("created-epoch", "", "evidence creation epoch binding")
	expiresEpoch := flags.String("expires-epoch", "", "evidence expiration epoch binding (maximum six hours)")
	reviewedEvidenceDigest := flags.String("reviewed-evidence-digest", "", "reviewed PlanEvidence sha256-prefixed digest binding")
	wifQualificationEvidenceDigest := flags.String("wif-qualification-evidence-digest", "", "bootstrap WIF qualification sha256-prefixed digest binding")
	stateBackendDigest := flags.String("state-backend-digest", "", "reviewed state-backend contract sha256-prefixed digest binding")
	executorContractDigest := flags.String("executor-contract-digest", "", "reviewed plan/apply executor contract sha256-prefixed digest binding")
	reviewedPlanDigest := flags.String("reviewed-plan-digest", "", "reviewed applied-plan SHA-256 binding without prefix")
	postApplyDriftDigest := flags.String("post-apply-drift-digest", "", "post-apply drift report SHA-256 binding without prefix")
	postApplyDriftExitCode := flags.String("post-apply-drift-exit-code", "", "post-apply drift exit-code binding: 0 or 2")
	attemptStatus := flags.String("attempt-status", "", "optional attempt status: started, succeeded, or failed")
	applyStarted := flags.String("apply-started", "", "optional explicit apply-started boolean")
	failureStage := flags.String("failure-stage", "", "optional failure stage: preflight, plan, approval, apply, post_apply_drift, or receipt")
	applyExitCode := flags.String("apply-exit-code", "", "optional bounded apply process exit code (0-255)")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 1
	}
	if *plan == "" || *output == "" {
		return reportError(stderr, errors.New("evidence requires --plan and --output"))
	}
	if *phase != "adopt" && *phase != "foundation" && *phase != "enforce" {
		return reportError(stderr, errors.New("evidence --phase must be adopt, foundation, or enforce"))
	}
	policyInput, err := catalog.PolicyInput(root)
	if err != nil {
		return reportError(stderr, fmt.Errorf("validate evidence workflow sources: %w", err))
	}
	expectedCatalogDigest := ""
	if *catalogPath != "" {
		compiledCatalog, err := catalog.Compile(root)
		if err != nil {
			return reportError(stderr, fmt.Errorf("compile evidence catalog authority: %w", err))
		}
		serializedCatalog, err := json.Marshal(compiledCatalog)
		if err != nil {
			return reportError(stderr, err)
		}
		var compiledCatalogMap map[string]any
		if err := json.Unmarshal(serializedCatalog, &compiledCatalogMap); err != nil {
			return reportError(stderr, err)
		}
		canonicalCatalog, err := rendering.CanonicalJSON(compiledCatalogMap)
		if err != nil {
			return reportError(stderr, err)
		}
		expectedCatalogDigest = rendering.Digest(canonicalCatalog)
	}
	receipt, err := evidence.Build(*plan, *planFile, *catalogPath, *observedPath, *phase, *riskAcknowledged, policyInput, expectedCatalogDigest, map[string]string{
		"organization": *organization, "change_reference": *changeReference,
		"workflow_ref": *workflowRef, "source_sha": *sourceSHA, "workflow_sha": *workflowSHA, "actor_id": *actorID,
		"plan_app_id": *planAppID, "apply_app_id": *applyAppID,
		"run_id": *runID, "run_attempt": *runAttempt,
		"created_epoch": *createdEpoch, "expires_epoch": *expiresEpoch,
		"reviewed_evidence_digest":          *reviewedEvidenceDigest,
		"wif_qualification_evidence_digest": *wifQualificationEvidenceDigest,
		"state_backend_digest":              *stateBackendDigest,
		"executor_contract_digest":          *executorContractDigest,
		"reviewed_plan_digest":              *reviewedPlanDigest,
		"post_apply_drift_digest":           *postApplyDriftDigest,
		"post_apply_drift_exit_code":        *postApplyDriftExitCode,
		"attempt_status":                    *attemptStatus,
		"apply_started":                     *applyStarted,
		"failure_stage":                     *failureStage,
		"apply_exit_code":                   *applyExitCode,
	})
	if err != nil {
		return reportError(stderr, err)
	}
	if err := rendering.WriteJSON(*output, receipt, stdout); err != nil {
		return reportError(stderr, err)
	}
	return 0
}

func runVerifyEvidence(arguments []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("verify-evidence", stderr)
	input := flags.String("input", "", "PlanEvidence JSON path")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 1
	}
	if *input == "" {
		return reportError(stderr, errors.New("verify-evidence requires --input"))
	}
	verification, err := evidence.Verify(*input)
	if err != nil {
		return reportError(stderr, err)
	}
	if err := rendering.WriteJSON("-", verification, stdout); err != nil {
		return reportError(stderr, err)
	}
	return 0
}

func runPreflight(arguments []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("preflight", stderr)
	desiredPath := flags.String("desired", "", "compiled desired JSON path")
	observedPath := flags.String("observed", "", "observed JSON path")
	output := flags.String("output", "-", "preflight report path")
	phase := flags.String("phase", "enforce", "activation phase: adopt, foundation, or enforce")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 1
	}
	if *desiredPath == "" || *observedPath == "" {
		return reportError(stderr, errors.New("preflight requires --desired and --observed"))
	}
	if *phase != "adopt" && *phase != "foundation" && *phase != "enforce" {
		return reportError(stderr, errors.New("preflight --phase must be adopt, foundation, or enforce"))
	}
	desired, err := readJSONPath(*desiredPath)
	if err != nil {
		return reportError(stderr, fmt.Errorf("read desired state: %w", err))
	}
	observed, err := readJSONPath(*observedPath)
	if err != nil {
		return reportError(stderr, fmt.Errorf("read observed state: %w", err))
	}
	report := validation.PreflightReport(desired, observed, *phase)
	if err := rendering.WriteJSON(*output, report, stdout); err != nil {
		return reportError(stderr, err)
	}
	if eligible, _ := report["eligible"].(bool); !eligible {
		return 2
	}
	return 0
}

func extractRoot(arguments []string) (string, []string, error) {
	root := "."
	seen := false
	remaining := make([]string, 0, len(arguments))
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		switch {
		case argument == "--root":
			if index+1 >= len(arguments) {
				return "", nil, errors.New("--root requires a value")
			}
			if seen {
				return "", nil, errors.New("--root may be specified only once")
			}
			index++
			root = arguments[index]
			seen = true
		case strings.HasPrefix(argument, "--root="):
			if seen {
				return "", nil, errors.New("--root may be specified only once")
			}
			root = strings.TrimPrefix(argument, "--root=")
			seen = true
		default:
			remaining = append(remaining, argument)
		}
	}
	if root == "" {
		return "", nil, errors.New("--root must not be empty")
	}
	return root, remaining, nil
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	return flags
}

func readJSONPath(path string) (map[string]any, error) {
	if path == "-" {
		return nil, errors.New("stdin is not supported for desired or observed state")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("JSON input must be a regular, non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return githubdiff.ReadJSON(file)
}

func reportError(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "github-configctl: %v\n", err)
	return 1
}
