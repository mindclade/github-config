// Package workflowcontract validates the closed reusable-workflow trust graph.
package workflowcontract

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/mindclade/github-config/compiler/internal/catalog"
	"github.com/mindclade/github-config/compiler/internal/rendering"
	"github.com/mindclade/github-config/compiler/internal/validation"
)

const maxWorkflowBytes = 4 << 20

var (
	commitPattern               = regexp.MustCompile(`^[0-9a-f]{40}$`)
	outputPattern               = regexp.MustCompile(`needs\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)`)
	authorityLocalActionPattern = regexp.MustCompile(
		`^\$/\.github/actions/[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$`,
	)
)

// Options defines the immutable authority checkouts used for validation.
type Options struct {
	Root                string
	AuthorityRoot       string
	CandidateRepository string
	CandidateRoot       string
	RequireAuthorities  bool
}

// Violation is a stable, secret-free workflow contract failure.
type Violation struct {
	Code       string `json:"code"`
	Repository string `json:"repository"`
	Workflow   string `json:"workflow"`
	Job        string `json:"job,omitempty"`
	Callee     string `json:"callee,omitempty"`
	Field      string `json:"field,omitempty"`
	Message    string `json:"message"`
}

// Authority records an inventory checkout admitted to the validation graph.
type Authority struct {
	Repository string `json:"repository"`
	Revision   string `json:"revision,omitempty"`
	Status     string `json:"status"`
	Candidate  bool   `json:"candidate,omitempty"`
}

// Report is the deterministic workflow validation result.
type Report struct {
	APIVersion         string      `json:"api_version"`
	Kind               string      `json:"kind"`
	Status             string      `json:"status"`
	SourceDigest       string      `json:"source_digest"`
	CheckedAuthorities []Authority `json:"checked_authorities"`
	CheckedWorkflows   int         `json:"checked_workflows"`
	Violations         []Violation `json:"violations"`
}

type authoritySpec struct {
	repository             string
	revision               string
	implementationRevision string
	state                  string
	workflows              []string
}

type workflowFile struct {
	repository string
	name       string
	path       string
	revision   string
	root       map[string]any
	call       callInterface
}

type callInterface struct {
	enabled bool
	inputs  map[string]parameter
	secrets map[string]parameter
	outputs map[string]struct{}
}

type parameter struct {
	required   bool
	hasDefault bool
}

type permissionSet map[string]int

// Validate resolves and checks every available reviewed workflow authority.
func Validate(options Options) (*Report, error) {
	if strings.TrimSpace(options.Root) == "" {
		return nil, errors.New("workflow contract root must not be empty")
	}
	compiled, err := catalog.Compile(options.Root)
	if err != nil {
		return nil, fmt.Errorf("compile workflow contract authority: %w", err)
	}
	authorities, err := authoritySpecs(compiled.ActionsPolicy)
	if err != nil {
		return nil, err
	}
	allowedActions := allowedActionPins(compiled.ActionsPolicy)
	report := &Report{
		APIVersion: validation.APIVersion, Kind: "WorkflowContractReport",
		Status: "valid", CheckedAuthorities: []Authority{}, Violations: []Violation{},
	}
	files := make([]*workflowFile, 0)
	digestInputs := map[string]any{"catalog": compiled.SourceDigest, "authorities": map[string]any{}}
	digestAuthorities := digestInputs["authorities"].(map[string]any)

	localRoot := options.Root
	if options.CandidateRepository == "github-config" && options.CandidateRoot != "" {
		localRoot = options.CandidateRoot
	}
	localRevision := gitHead(localRoot)
	if !commitPattern.MatchString(localRevision) {
		return nil, errors.New("github-config workflow source must be an exact Git checkout")
	}
	localFiles, loadErr := loadWorkflowDirectory("github-config", localRoot, localRevision)
	if loadErr != nil {
		return nil, loadErr
	}
	files = append(files, localFiles...)
	report.CheckedAuthorities = append(report.CheckedAuthorities, Authority{
		Repository: "github-config", Revision: localRevision, Status: "checked",
	})
	digestAuthorities["github-config"] = map[string]any{"revision": localRevision, "files": fileDigests(localFiles)}

	for _, authority := range authorities {
		if authority.repository == "github-config" {
			continue
		}
		if authority.state != "reviewed" {
			report.CheckedAuthorities = append(report.CheckedAuthorities, Authority{
				Repository: authority.repository, Status: "blocked",
			})
			continue
		}
		root := ""
		revision := authority.revision
		if options.AuthorityRoot != "" {
			root = filepath.Join(options.AuthorityRoot, authority.repository)
			if authority.repository == ".github" {
				root = filepath.Join(options.AuthorityRoot, ".github-implementation")
				revision = authority.implementationRevision
			}
		}
		if root == "" {
			status := "not_provided"
			if options.RequireAuthorities {
				status = "missing"
				appendViolation(report, Violation{
					Code: "AUTHORITY_UNAVAILABLE", Repository: authority.repository,
					Message: "reviewed workflow authority checkout is required but unavailable",
				})
			}
			report.CheckedAuthorities = append(report.CheckedAuthorities, Authority{
				Repository: authority.repository, Revision: revision, Status: status,
			})
			continue
		}
		actualRevision := gitHead(root)
		if actualRevision != revision {
			appendViolation(report, Violation{
				Code: "AUTHORITY_REVISION_MISMATCH", Repository: authority.repository,
				Field: "revision", Message: "authority checkout does not match its exact reviewed revision",
			})
			report.CheckedAuthorities = append(report.CheckedAuthorities, Authority{
				Repository: authority.repository, Revision: actualRevision, Status: "mismatch",
			})
			continue
		}
		authorityFiles, loadErr := loadWorkflowInventory(
			authority.repository, root, revision, authority.workflows,
		)
		if loadErr != nil {
			return nil, loadErr
		}
		files = append(files, authorityFiles...)
		report.CheckedAuthorities = append(report.CheckedAuthorities, Authority{
			Repository: authority.repository, Revision: revision, Status: "checked",
		})
		digestAuthorities[authority.repository] = map[string]any{
			"revision": revision, "files": fileDigests(authorityFiles),
		}
	}

	if options.CandidateRepository != "" && options.CandidateRoot != "" && options.CandidateRepository != "github-config" {
		if !catalogRepository(compiled, options.CandidateRepository) {
			return nil, fmt.Errorf("candidate repository %q is outside the managed catalog", options.CandidateRepository)
		}
		candidateRevision := gitHead(options.CandidateRoot)
		if !commitPattern.MatchString(candidateRevision) {
			return nil, fmt.Errorf("candidate repository %q must be an exact Git checkout", options.CandidateRepository)
		}
		candidateFiles, loadErr := loadWorkflowDirectory(
			options.CandidateRepository, options.CandidateRoot, candidateRevision,
		)
		if loadErr != nil {
			return nil, loadErr
		}
		files = withoutWorkflowRevision(files, options.CandidateRepository, candidateRevision)
		files = append(files, candidateFiles...)
		report.CheckedAuthorities = append(report.CheckedAuthorities, Authority{
			Repository: options.CandidateRepository, Revision: candidateRevision,
			Status: "checked", Candidate: true,
		})
		digestInputs["candidate"] = map[string]any{
			"repository": options.CandidateRepository, "revision": candidateRevision,
			"files": fileDigests(candidateFiles),
		}
	}

	sort.Slice(files, func(left, right int) bool {
		if files[left].repository != files[right].repository {
			return files[left].repository < files[right].repository
		}
		return files[left].name < files[right].name
	})
	report.CheckedWorkflows = len(files)
	index := indexWorkflows(files)
	for _, file := range files {
		validateWorkflow(file, index, authorities, allowedActions, report)
	}
	validateCycles(files, index, report)
	sortReport(report)
	canonicalDigestInput, err := rendering.CanonicalJSON(digestInputs)
	if err != nil {
		return nil, err
	}
	report.SourceDigest = rendering.Digest(canonicalDigestInput)
	if len(report.Violations) > 0 {
		report.Status = "invalid"
	}
	return report, nil
}

func withoutWorkflowRevision(files []*workflowFile, repository, revision string) []*workflowFile {
	result := make([]*workflowFile, 0, len(files))
	for _, file := range files {
		if file.repository != repository || file.revision != revision {
			result = append(result, file)
		}
	}
	return result
}

func authoritySpecs(policy map[string]any) ([]authoritySpec, error) {
	result := make([]authoritySpec, 0)
	values, _ := policy["authority_inventories"].([]any)
	for _, raw := range values {
		value, _ := raw.(map[string]any)
		activation, _ := value["activation"].(map[string]any)
		result = append(result, authoritySpec{
			repository: stringValue(value["repository"]), revision: stringValue(value["revision"]),
			implementationRevision: stringValue(value["implementation_revision"]),
			state:                  stringValue(activation["state"]), workflows: stringList(value["workflows"]),
		})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].repository < result[right].repository })
	if len(result) == 0 {
		return nil, errors.New("ActionsPolicy has no workflow authority inventories")
	}
	return result, nil
}

func allowedActionPins(policy map[string]any) map[string]string {
	result := make(map[string]string)
	values, _ := policy["allowed_actions"].([]any)
	for _, raw := range values {
		value, _ := raw.(map[string]any)
		result[stringValue(value["source"])] = stringValue(value["commit"])
	}
	return result
}

func loadWorkflowDirectory(repository, root, revision string) ([]*workflowFile, error) {
	directory := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read %s workflow directory: %w", repository, err)
	}
	names := make([]string, 0)
	for _, entry := range entries {
		if entry.Type().IsRegular() && (strings.HasSuffix(entry.Name(), ".yml") || strings.HasSuffix(entry.Name(), ".yaml")) {
			names = append(names, entry.Name())
		}
	}
	return loadWorkflowInventory(repository, root, revision, names)
}

func loadWorkflowInventory(repository, root, revision string, names []string) ([]*workflowFile, error) {
	ordered := append([]string(nil), names...)
	sort.Strings(ordered)
	result := make([]*workflowFile, 0, len(ordered))
	for _, name := range ordered {
		if filepath.Base(name) != name || strings.Contains(name, "..") {
			return nil, fmt.Errorf("%s workflow inventory contains invalid path %q", repository, name)
		}
		path := filepath.Join(root, ".github", "workflows", name)
		rootValue, err := readWorkflow(path)
		if err != nil {
			return nil, fmt.Errorf("%s/.github/workflows/%s: %w", repository, name, err)
		}
		result = append(result, &workflowFile{
			repository: repository, name: name, path: path, revision: revision,
			root: rootValue, call: reusableInterface(rootValue),
		})
	}
	return result, nil
}

func readWorkflow(path string) (map[string]any, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxWorkflowBytes {
		return nil, errors.New("workflow must be a bounded regular non-symlink file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err := yaml.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("decode YAML: %w", err)
	}
	if value == nil {
		return nil, errors.New("workflow root must be an object")
	}
	return value, nil
}

func reusableInterface(root map[string]any) callInterface {
	result := callInterface{inputs: map[string]parameter{}, secrets: map[string]parameter{}, outputs: map[string]struct{}{}}
	on, _ := root["on"].(map[string]any)
	result.enabled = hasKey(on, "workflow_call")
	workflowCall, _ := on["workflow_call"].(map[string]any)
	for name, raw := range objectValue(workflowCall["inputs"]) {
		definition := objectValue(raw)
		result.inputs[name] = parameter{required: boolValue(definition["required"]), hasDefault: hasKey(definition, "default")}
	}
	for name, raw := range objectValue(workflowCall["secrets"]) {
		definition := objectValue(raw)
		result.secrets[name] = parameter{required: boolValue(definition["required"])}
	}
	for name := range objectValue(workflowCall["outputs"]) {
		result.outputs[name] = struct{}{}
	}
	return result
}

func indexWorkflows(files []*workflowFile) map[string]*workflowFile {
	result := make(map[string]*workflowFile)
	for _, file := range files {
		result[workflowKey(file.repository, file.name, file.revision)] = file
	}
	return result
}

func workflowKey(repository, name, revision string) string {
	return repository + "/.github/workflows/" + name + "@" + revision
}

func validateWorkflow(
	file *workflowFile, index map[string]*workflowFile, authorities []authoritySpec,
	allowedActions map[string]string, report *Report,
) {
	topPermissions := parsePermissions(file.root["permissions"])
	jobs := objectValue(file.root["jobs"])
	jobNames := sortedKeys(jobs)
	for _, jobName := range jobNames {
		job := objectValue(jobs[jobName])
		permissions := topPermissions
		if hasKey(job, "permissions") {
			permissions = parsePermissions(job["permissions"])
		}
		uses := stringValue(job["uses"])
		if uses != "" {
			validateReusableCall(file, jobName, job, uses, permissions, index, authorities, report)
		}
		steps, _ := job["steps"].([]any)
		for stepIndex, raw := range steps {
			step := objectValue(raw)
			stepUses := stringValue(step["uses"])
			if stepUses == "" {
				continue
			}
			field := fmt.Sprintf("jobs.%s.steps[%d].uses", jobName, stepIndex)
			validateActionReference(file, jobName, field, stepUses, allowedActions, report)
			validateSemanticPermissions(file, jobName, field, stepUses, step, permissions, report)
		}
	}
	validateOutputReferences(file, jobs, index, report)
}

func validateReusableCall(
	file *workflowFile, jobName string, job map[string]any, uses string, callerPermissions permissionSet,
	index map[string]*workflowFile, authorities []authoritySpec, report *Report,
) {
	calleeKey, ok := canonicalReusableReference(file, uses)
	if !ok {
		appendViolation(report, Violation{
			Code: "REUSABLE_WORKFLOW_PIN_INVALID", Repository: file.repository, Workflow: file.name,
			Job: jobName, Callee: safeReference(uses), Field: "jobs." + jobName + ".uses",
			Message: "reusable workflow must use an exact 40-character commit SHA",
		})
		return
	}
	if !referenceMatchesAuthority(calleeKey, file, authorities) {
		appendViolation(report, Violation{
			Code: "REUSABLE_WORKFLOW_AUTHORITY_MISMATCH", Repository: file.repository, Workflow: file.name,
			Job: jobName, Callee: calleeKey, Field: "jobs." + jobName + ".uses",
			Message: "reusable workflow pin does not match its reviewed authority revision",
		})
	}
	callee := index[calleeKey]
	if callee == nil {
		if referenceExpectedLoaded(calleeKey, file, report.CheckedAuthorities) {
			appendViolation(report, Violation{
				Code: "REUSABLE_WORKFLOW_UNRESOLVED", Repository: file.repository, Workflow: file.name,
				Job: jobName, Callee: calleeKey, Field: "jobs." + jobName + ".uses",
				Message: "reusable workflow does not exist in its exact authority checkout",
			})
		}
		return
	}
	if !callee.call.enabled {
		appendViolation(report, Violation{
			Code: "REUSABLE_WORKFLOW_CALL_UNDECLARED", Repository: file.repository, Workflow: file.name,
			Job: jobName, Callee: calleeKey, Field: "jobs." + jobName + ".uses",
			Message: "referenced workflow does not declare on.workflow_call",
		})
		return
	}
	providedInputs := objectValue(job["with"])
	providedSecrets := objectValue(job["secrets"])
	if text, ok := job["secrets"].(string); ok && strings.EqualFold(text, "inherit") {
		appendViolation(report, Violation{
			Code: "SECRETS_INHERIT_FORBIDDEN", Repository: file.repository, Workflow: file.name,
			Job: jobName, Callee: calleeKey, Field: "jobs." + jobName + ".secrets",
			Message: "secrets: inherit crosses the reusable-workflow trust boundary",
		})
	}
	validateParameters(file, jobName, calleeKey, "with", providedInputs, callee.call.inputs, report)
	validateParameters(file, jobName, calleeKey, "secrets", providedSecrets, callee.call.secrets, report)
	calleePermissions := requiredPermissions(callee)
	for scope, requiredLevel := range calleePermissions {
		if callerPermissions[scope] < requiredLevel {
			appendViolation(report, Violation{
				Code: "REUSABLE_PERMISSION_CEILING", Repository: file.repository, Workflow: file.name,
				Job: jobName, Callee: calleeKey, Field: "jobs." + jobName + ".permissions." + scope,
				Message: fmt.Sprintf("caller permission must grant %s: %s", scope, permissionName(requiredLevel)),
			})
		}
	}
}

func validateParameters(
	file *workflowFile, jobName, callee, field string, provided map[string]any,
	declared map[string]parameter, report *Report,
) {
	contractField := strings.TrimSuffix(field, "s")
	if field == "with" {
		contractField = "input"
	}
	for _, name := range sortedKeys(provided) {
		if _, exists := declared[name]; !exists {
			appendViolation(report, Violation{
				Code: "REUSABLE_UNKNOWN_" + strings.ToUpper(contractField), Repository: file.repository,
				Workflow: file.name, Job: jobName, Callee: callee,
				Field:   "jobs." + jobName + "." + field + "." + name,
				Message: "caller supplies a field not declared by the reusable workflow",
			})
		}
	}
	for _, name := range sortedParameterKeys(declared) {
		definition := declared[name]
		if definition.required && !definition.hasDefault {
			if _, exists := provided[name]; !exists {
				appendViolation(report, Violation{
					Code:       "REUSABLE_REQUIRED_" + strings.ToUpper(contractField) + "_MISSING",
					Repository: file.repository, Workflow: file.name, Job: jobName, Callee: callee,
					Field:   "jobs." + jobName + "." + field + "." + name,
					Message: "caller omits a required reusable-workflow field",
				})
			}
		}
	}
}

func validateActionReference(
	file *workflowFile, jobName, field, uses string, allowed map[string]string, report *Report,
) {
	if strings.HasPrefix(uses, "$/") {
		if !authorityLocalActionPattern.MatchString(uses) {
			appendViolation(report, Violation{
				Code: "LOCAL_ACTION_PATH_INVALID", Repository: file.repository, Workflow: file.name,
				Job: jobName, Field: field, Message: "authority-root local action path is not canonical",
			})
		}
		return
	}
	if strings.HasPrefix(uses, "./") {
		clean := path.Clean(strings.TrimPrefix(uses, "./"))
		if uses != "./"+clean || clean == "." || strings.HasPrefix(clean, "../") ||
			strings.Contains(uses, "@") || strings.Contains(uses, "\\") {
			appendViolation(report, Violation{
				Code: "LOCAL_ACTION_PATH_INVALID", Repository: file.repository, Workflow: file.name,
				Job: jobName, Field: field, Message: "local action path is not canonical",
			})
		}
		return
	}
	separator := strings.LastIndex(uses, "@")
	if separator <= 0 || !commitPattern.MatchString(uses[separator+1:]) {
		appendViolation(report, Violation{
			Code: "ACTION_PIN_INVALID", Repository: file.repository, Workflow: file.name,
			Job: jobName, Field: field, Message: "external action must use an exact 40-character commit SHA",
		})
		return
	}
	parts := strings.Split(uses[:separator], "/")
	if len(parts) < 2 {
		appendViolation(report, Violation{
			Code: "ACTION_SOURCE_INVALID", Repository: file.repository, Workflow: file.name,
			Job: jobName, Field: field, Message: "external action source is malformed",
		})
		return
	}
	source := parts[0] + "/" + parts[1]
	expected, exists := allowed[source]
	if !exists {
		appendViolation(report, Violation{
			Code: "ACTION_NOT_ALLOWED", Repository: file.repository, Workflow: file.name,
			Job: jobName, Field: field, Message: "external action is absent from the canonical allowlist",
		})
	} else if expected != uses[separator+1:] {
		appendViolation(report, Violation{
			Code: "ACTION_PIN_MISMATCH", Repository: file.repository, Workflow: file.name,
			Job: jobName, Field: field, Message: "external action pin differs from the canonical allowlist",
		})
	}
}

func validateSemanticPermissions(
	file *workflowFile, jobName, field, uses string, step map[string]any,
	permissions permissionSet, report *Report,
) {
	path := uses
	if separator := strings.LastIndex(path, "@"); separator > 0 {
		path = path[:separator]
	}
	required := semanticPermissions(path, step)
	for scope, level := range required {
		if permissions[scope] < level {
			appendViolation(report, Violation{
				Code: "SEMANTIC_PERMISSION_MISSING", Repository: file.repository, Workflow: file.name,
				Job: jobName, Field: field, Message: fmt.Sprintf("action requires %s: %s", scope, permissionName(level)),
			})
		}
	}
}

func requiredPermissions(file *workflowFile) permissionSet {
	result := permissionSet{}
	top := parsePermissions(file.root["permissions"])
	mergePermissions(result, top)
	for _, raw := range objectValue(file.root["jobs"]) {
		job := objectValue(raw)
		effective := top
		if hasKey(job, "permissions") {
			effective = parsePermissions(job["permissions"])
		}
		mergePermissions(result, effective)
		steps, _ := job["steps"].([]any)
		for _, rawStep := range steps {
			step := objectValue(rawStep)
			uses := stringValue(step["uses"])
			path := strings.Split(uses, "@")[0]
			mergePermissions(result, semanticPermissions(path, step))
		}
	}
	return result
}

func semanticPermissions(path string, step map[string]any) permissionSet {
	result := permissionSet{}
	with := objectValue(step["with"])
	switch {
	case path == "google-github-actions/auth":
		result["id-token"] = 2
	case path == "github/codeql-action/upload-sarif":
		result["security-events"] = 2
	case path == "github/codeql-action/analyze" && stringValue(with["upload"]) != "never":
		result["security-events"] = 2
	case path == "actions/attest-build-provenance":
		result["id-token"] = 2
		result["attestations"] = 2
	case path == "actions/download-artifact" && hasKey(with, "run-id"):
		result["actions"] = 1
	}
	return result
}

func validateOutputReferences(file *workflowFile, jobs map[string]any, index map[string]*workflowFile, report *Report) {
	text := fmt.Sprint(file.root)
	for _, match := range outputPattern.FindAllStringSubmatch(text, -1) {
		jobName, outputName := match[1], match[2]
		job := objectValue(jobs[jobName])
		uses := stringValue(job["uses"])
		calleeKey, ok := canonicalReusableReference(file, uses)
		if !ok || index[calleeKey] == nil {
			continue
		}
		if _, exists := index[calleeKey].call.outputs[outputName]; !exists {
			appendViolation(report, Violation{
				Code: "REUSABLE_OUTPUT_UNDECLARED", Repository: file.repository, Workflow: file.name,
				Job: jobName, Callee: calleeKey, Field: "needs." + jobName + ".outputs." + outputName,
				Message: "caller references an output not declared by the reusable workflow",
			})
		}
	}
}

func validateCycles(files []*workflowFile, index map[string]*workflowFile, report *Report) {
	state := make(map[string]int)
	stack := make([]string, 0)
	var visit func(string)
	visit = func(key string) {
		if state[key] == 2 {
			return
		}
		if state[key] == 1 {
			cycle := append([]string(nil), stack...)
			cycle = append(cycle, key)
			file := index[key]
			appendViolation(report, Violation{
				Code: "REUSABLE_WORKFLOW_CYCLE", Repository: file.repository, Workflow: file.name,
				Callee: key, Message: "reusable workflow call graph contains a cycle: " + strings.Join(cycle, " -> "),
			})
			return
		}
		state[key] = 1
		stack = append(stack, key)
		file := index[key]
		jobs := objectValue(file.root["jobs"])
		for _, jobName := range sortedKeys(jobs) {
			uses := stringValue(objectValue(jobs[jobName])["uses"])
			callee, ok := canonicalReusableReference(file, uses)
			if ok && index[callee] != nil {
				visit(callee)
			}
		}
		stack = stack[:len(stack)-1]
		state[key] = 2
	}
	keys := make([]string, 0, len(index))
	for key := range index {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		visit(key)
	}
}

func canonicalReusableReference(caller *workflowFile, uses string) (string, bool) {
	if strings.HasPrefix(uses, "./.github/workflows/") {
		name := strings.TrimPrefix(uses, "./.github/workflows/")
		if filepath.Base(name) != name {
			return "", false
		}
		return workflowKey(caller.repository, name, caller.revision), true
	}
	separator := strings.LastIndex(uses, "@")
	if separator <= 0 || !commitPattern.MatchString(uses[separator+1:]) {
		return "", false
	}
	if !strings.HasPrefix(uses[:separator], "mindclade/") {
		return "", false
	}
	referencePath := strings.TrimPrefix(uses[:separator], "mindclade/")
	parts := strings.Split(referencePath, "/")
	if len(parts) != 4 || parts[1] != ".github" || parts[2] != "workflows" || filepath.Base(parts[3]) != parts[3] {
		return "", false
	}
	return workflowKey(parts[0], parts[3], uses[separator+1:]), true
}

func referenceMatchesAuthority(reference string, caller *workflowFile, authorities []authoritySpec) bool {
	if strings.HasPrefix(reference, caller.repository+"/.github/workflows/") &&
		strings.HasSuffix(reference, "@"+caller.revision) {
		return true
	}
	for _, authority := range authorities {
		prefix := authority.repository + "/.github/workflows/"
		if !strings.HasPrefix(reference, prefix) {
			continue
		}
		revision := authority.revision
		if authority.repository == ".github" {
			revision = authority.implementationRevision
		}
		return strings.HasSuffix(reference, "@"+revision) && authority.state == "reviewed"
	}
	return false
}

func referenceExpectedLoaded(reference string, caller *workflowFile, authorities []Authority) bool {
	repository := strings.SplitN(reference, "/.github/workflows/", 2)[0]
	if repository == caller.repository && strings.HasSuffix(reference, "@"+caller.revision) {
		return true
	}
	for _, authority := range authorities {
		if authority.Repository == repository && authority.Status == "checked" && !authority.Candidate {
			return true
		}
	}
	return false
}

func parsePermissions(value any) permissionSet {
	result := permissionSet{}
	if text, ok := value.(string); ok {
		level := 0
		switch text {
		case "read-all":
			level = 1
		case "write-all":
			level = 2
		}
		for _, scope := range []string{"actions", "attestations", "checks", "contents", "deployments", "id-token", "issues", "packages", "pull-requests", "security-events", "statuses"} {
			result[scope] = level
		}
		return result
	}
	for scope, raw := range objectValue(value) {
		switch stringValue(raw) {
		case "read":
			result[scope] = 1
		case "write":
			result[scope] = 2
		default:
			result[scope] = 0
		}
	}
	return result
}

func mergePermissions(destination, source permissionSet) {
	for scope, level := range source {
		destination[scope] = max(destination[scope], level)
	}
}

func permissionName(level int) string {
	if level >= 2 {
		return "write"
	}
	if level == 1 {
		return "read"
	}
	return "none"
}

func appendViolation(report *Report, violation Violation) {
	report.Violations = append(report.Violations, violation)
}

func sortReport(report *Report) {
	sort.Slice(report.CheckedAuthorities, func(left, right int) bool {
		leftAuthority, rightAuthority := report.CheckedAuthorities[left], report.CheckedAuthorities[right]
		if leftAuthority.Repository != rightAuthority.Repository {
			return leftAuthority.Repository < rightAuthority.Repository
		}
		if leftAuthority.Candidate != rightAuthority.Candidate {
			return !leftAuthority.Candidate
		}
		return leftAuthority.Status < rightAuthority.Status
	})
	sort.Slice(report.Violations, func(left, right int) bool {
		a, b := report.Violations[left], report.Violations[right]
		leftKey := strings.Join([]string{a.Repository, a.Workflow, a.Job, a.Code, a.Callee, a.Field, a.Message}, "\x00")
		rightKey := strings.Join([]string{b.Repository, b.Workflow, b.Job, b.Code, b.Callee, b.Field, b.Message}, "\x00")
		return leftKey < rightKey
	})
}

func fileDigests(files []*workflowFile) map[string]any {
	result := make(map[string]any, len(files))
	for _, file := range files {
		data, _ := os.ReadFile(file.path)
		sum := sha256.Sum256(data)
		result[file.name] = "sha256:" + hex.EncodeToString(sum[:])
	}
	return result
}

func gitHead(root string) string {
	gitPath := filepath.Join(root, ".git")
	gitDirectory := gitPath
	if info, err := os.Lstat(gitPath); err != nil {
		return ""
	} else if info.Mode().IsRegular() {
		data, readErr := readSmallRegular(gitPath)
		if readErr != nil || !strings.HasPrefix(strings.TrimSpace(string(data)), "gitdir: ") {
			return ""
		}
		gitDirectory = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(data)), "gitdir: "))
		if !filepath.IsAbs(gitDirectory) {
			gitDirectory = filepath.Join(root, gitDirectory)
		}
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ""
	}
	data, err := readSmallRegular(filepath.Join(gitDirectory, "HEAD"))
	if err != nil {
		return ""
	}
	value := strings.TrimSpace(string(data))
	if commitPattern.MatchString(value) {
		return value
	}
	if !strings.HasPrefix(value, "ref: refs/") {
		return ""
	}
	reference := strings.TrimPrefix(value, "ref: ")
	if filepath.Clean(reference) != reference || strings.Contains(reference, "..") {
		return ""
	}
	directories := []string{gitDirectory}
	if commonData, commonErr := readSmallRegular(filepath.Join(gitDirectory, "commondir")); commonErr == nil {
		commonDirectory := strings.TrimSpace(string(commonData))
		if !filepath.IsAbs(commonDirectory) {
			commonDirectory = filepath.Join(gitDirectory, commonDirectory)
		}
		directories = append(directories, filepath.Clean(commonDirectory))
	}
	for _, directory := range directories {
		if referenceData, referenceErr := readSmallRegular(filepath.Join(directory, filepath.FromSlash(reference))); referenceErr == nil {
			revision := strings.TrimSpace(string(referenceData))
			if commitPattern.MatchString(revision) {
				return revision
			}
		}
		if packedData, packedErr := readSmallRegular(filepath.Join(directory, "packed-refs")); packedErr == nil {
			for _, line := range strings.Split(string(packedData), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 2 && fields[1] == reference && commitPattern.MatchString(fields[0]) {
					return fields[0]
				}
			}
		}
	}
	return ""
}

func readSmallRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 1<<20 {
		return nil, errors.New("git metadata is not a bounded regular file")
	}
	return os.ReadFile(path)
}

func catalogRepository(compiled *catalog.Catalog, repository string) bool {
	for id, raw := range compiled.Repositories {
		spec, _ := raw.(map[string]any)
		name := stringValue(spec["name"])
		if repository == id || repository == name {
			return true
		}
	}
	return false
}

func safeReference(value string) string {
	if len(value) > 256 {
		return value[:256]
	}
	return value
}

func objectValue(value any) map[string]any {
	result, _ := value.(map[string]any)
	if result == nil {
		return map[string]any{}
	}
	return result
}

func sortedKeys(values map[string]any) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func sortedParameterKeys(values map[string]parameter) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func stringList(value any) []string {
	items, _ := value.([]any)
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text := stringValue(item); text != "" {
			result = append(result, text)
		}
	}
	sort.Strings(result)
	return result
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func boolValue(value any) bool {
	result, _ := value.(bool)
	return result
}

func hasKey(value map[string]any, key string) bool {
	_, exists := value[key]
	return exists
}
