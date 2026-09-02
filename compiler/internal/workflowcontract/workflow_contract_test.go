package workflowcontract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestReusableContractRejectsMissingInputSecretAndPermission(t *testing.T) {
	callee := &workflowFile{
		repository: ".github", name: "callee.yml", revision: testRevision,
		root: map[string]any{
			"on": map[string]any{"workflow_call": map[string]any{
				"inputs":  map[string]any{"source_revision": map[string]any{"required": true, "type": "string"}},
				"secrets": map[string]any{"deployment_key": map[string]any{"required": true}},
			}},
			"permissions": map[string]any{"id-token": "write"},
			"jobs":        map[string]any{},
		},
	}
	callee.call = reusableInterface(callee.root)
	caller := &workflowFile{
		repository: "application", name: "pull-request.yml", revision: testRevision,
		root: map[string]any{
			"permissions": map[string]any{"contents": "read"},
			"jobs": map[string]any{"call": map[string]any{
				"uses": "mindclade/.github/.github/workflows/callee.yml@" + testRevision,
			}},
		},
	}
	report := &Report{Violations: []Violation{}}
	index := indexWorkflows([]*workflowFile{callee, caller})
	authorities := []authoritySpec{{
		repository: ".github", implementationRevision: testRevision, revision: strings.Repeat("b", 40),
		state: "reviewed", workflows: []string{"callee.yml"},
	}}
	validateWorkflow(caller, index, authorities, map[string]string{}, report)
	codes := map[string]bool{}
	for _, violation := range report.Violations {
		codes[violation.Code] = true
	}
	for _, expected := range []string{
		"REUSABLE_REQUIRED_INPUT_MISSING", "REUSABLE_REQUIRED_SECRET_MISSING", "REUSABLE_PERMISSION_CEILING",
	} {
		if !codes[expected] {
			t.Fatalf("missing violation %s in %#v", expected, report.Violations)
		}
	}
}

func TestGitHeadResolvesWorktreeIndirection(t *testing.T) {
	root := t.TempDir()
	common := filepath.Join(root, "common")
	gitDirectory := filepath.Join(root, "metadata", "worktree")
	if err := os.MkdirAll(filepath.Join(common, "refs", "heads"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(gitDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]string{
		filepath.Join(root, ".git"):                    "gitdir: " + gitDirectory + "\n",
		filepath.Join(gitDirectory, "HEAD"):            "ref: refs/heads/main\n",
		filepath.Join(gitDirectory, "commondir"):       filepath.Join("..", "..", "common") + "\n",
		filepath.Join(common, "refs", "heads", "main"): testRevision + "\n",
	} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if revision := gitHead(root); revision != testRevision {
		t.Fatalf("expected %s, got %s", testRevision, revision)
	}
}

func TestActionAllowlistAndSemanticPermissions(t *testing.T) {
	file := &workflowFile{
		repository: "application", name: "release.yml", revision: testRevision,
		root: map[string]any{
			"permissions": map[string]any{"contents": "read"},
			"jobs": map[string]any{"release": map[string]any{
				"steps": []any{
					map[string]any{"uses": "google-github-actions/auth@" + testRevision},
					map[string]any{"uses": "unknown/action@" + testRevision},
				},
			}},
		},
	}
	report := &Report{Violations: []Violation{}}
	validateWorkflow(file, map[string]*workflowFile{}, nil, map[string]string{
		"google-github-actions/auth": testRevision,
	}, report)
	codes := map[string]bool{}
	for _, violation := range report.Violations {
		codes[violation.Code] = true
	}
	if !codes["SEMANTIC_PERMISSION_MISSING"] || !codes["ACTION_NOT_ALLOWED"] {
		t.Fatalf("expected semantic and allowlist failures, got %#v", report.Violations)
	}
}

func TestCodeQLPermissionDependsOnUploadMode(t *testing.T) {
	offline := semanticPermissions("github/codeql-action/analyze", map[string]any{
		"with": map[string]any{"upload": "never"},
	})
	if offline["security-events"] != 0 {
		t.Fatalf("offline CodeQL analysis must not require upload authority: %#v", offline)
	}
	upload := semanticPermissions("github/codeql-action/analyze", map[string]any{
		"with": map[string]any{"upload": "always"},
	})
	if upload["security-events"] != 2 {
		t.Fatalf("CodeQL upload must require security-events write: %#v", upload)
	}
}

func TestReusableCycleIsRejected(t *testing.T) {
	left := &workflowFile{repository: ".github", name: "left.yml", revision: testRevision}
	right := &workflowFile{repository: ".github", name: "right.yml", revision: testRevision}
	left.root = map[string]any{"jobs": map[string]any{"right": map[string]any{"uses": "./.github/workflows/right.yml"}}}
	right.root = map[string]any{"jobs": map[string]any{"left": map[string]any{"uses": "./.github/workflows/left.yml"}}}
	index := indexWorkflows([]*workflowFile{left, right})
	report := &Report{Violations: []Violation{}}
	validateCycles([]*workflowFile{left, right}, index, report)
	if len(report.Violations) == 0 || report.Violations[0].Code != "REUSABLE_WORKFLOW_CYCLE" {
		t.Fatalf("expected cycle violation, got %#v", report.Violations)
	}
}

func TestReusableWorkflowMustResolveAndDeclareWorkflowCall(t *testing.T) {
	caller := &workflowFile{
		repository: "application", name: "pull-request.yml", revision: testRevision,
		root: map[string]any{"jobs": map[string]any{"call": map[string]any{
			"uses": "mindclade/.github/.github/workflows/missing.yml@" + testRevision,
		}}},
	}
	authoritySpecs := []authoritySpec{{
		repository: ".github", implementationRevision: testRevision, state: "reviewed",
	}}
	report := &Report{
		CheckedAuthorities: []Authority{{Repository: ".github", Revision: testRevision, Status: "checked"}},
		Violations:         []Violation{},
	}
	validateWorkflow(caller, indexWorkflows([]*workflowFile{caller}), authoritySpecs, nil, report)
	if len(report.Violations) != 1 || report.Violations[0].Code != "REUSABLE_WORKFLOW_UNRESOLVED" {
		t.Fatalf("expected unresolved workflow violation, got %#v", report.Violations)
	}

	callee := &workflowFile{
		repository: ".github", name: "missing.yml", revision: testRevision,
		root: map[string]any{"on": map[string]any{"push": map[string]any{}}, "jobs": map[string]any{}},
	}
	callee.call = reusableInterface(callee.root)
	report.Violations = []Violation{}
	validateWorkflow(caller, indexWorkflows([]*workflowFile{caller, callee}), authoritySpecs, nil, report)
	if len(report.Violations) != 1 || report.Violations[0].Code != "REUSABLE_WORKFLOW_CALL_UNDECLARED" {
		t.Fatalf("expected workflow_call violation, got %#v", report.Violations)
	}
}

func TestInvalidLocalActionPrefixCannotBypassTheAllowlist(t *testing.T) {
	file := &workflowFile{repository: "application", name: "pull-request.yml"}
	report := &Report{Violations: []Violation{}}
	validateActionReference(file, "check", "jobs.check.steps[0].uses", "$/unreviewed/action", nil, report)
	if len(report.Violations) == 0 || report.Violations[0].Code != "LOCAL_ACTION_PATH_INVALID" {
		t.Fatalf("invalid local action prefix bypassed validation: %#v", report.Violations)
	}
}
