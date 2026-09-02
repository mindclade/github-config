// Package catalog loads the authoritative YAML tree into a deterministic,
// schema-validated catalog consumed by policy and OpenTofu.
package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/mindclade/github-config/compiler/internal/rendering"
	"github.com/mindclade/github-config/compiler/internal/validation"
)

const (
	maxYAMLBytes                   = 4 << 20
	maxGeneratedPolicyBytes        = 4 << 20
	generatedPolicyAuthority       = "mindclade/.github"
	generatedPolicyAuthorityCommit = "49a015c2c0cdd6a75a5756eb8c1e95b49d117917"
)

var generatedPolicyFiles = map[string]string{
	"generated/bazelrc.common":                   "e030d15a440dd58298a6189677876f91a24b3dbde9f1c2ec77d1591deb6555f7",
	"generated/nix-bazel-policy.lock.json":       "845d49667310d831801fef34ff25987030208897218d6a5e4e7588db410b9738",
	"generated/nix-bazel-policy.nix":             "94de498e988895621a349236a1cea5b8937ea318d8b985e7fec7ac3bcb414c19",
	"generated/toolchain-manifest.defaults.json": "bc423d86c527398dd6c8c72131e63bd54961380809fbb0712982b2dae3ee8c2f",
}

// Catalog is the public compiler contract. Source envelopes are intentionally
// removed: singleton and collection values contain only their schema-validated
// spec, while collection keys are immutable metadata.id values.
type Catalog struct {
	APIVersion           string         `json:"api_version"`
	Activation           map[string]any `json:"activation"`
	Organization         map[string]any `json:"organization"`
	ActionsPolicy        map[string]any `json:"actions_policy"`
	SecurityPolicy       map[string]any `json:"security_policy"`
	OIDCPolicy           map[string]any `json:"oidc_policy"`
	Members              []any          `json:"members"`
	OutsideCollaborators []any          `json:"outside_collaborators"`
	Teams                map[string]any `json:"teams"`
	Repositories         map[string]any `json:"repositories"`
	Rulesets             map[string]any `json:"rulesets"`
	Environments         map[string]any `json:"environments"`
	Integrations         map[string]any `json:"integrations"`
	SourceDigest         string         `json:"source_digest,omitempty"`
}

type sourceDefinition struct {
	path        string
	schema      string
	kind        string
	destination string
}

var sourceDefinitions = []sourceDefinition{
	{"config/organization.yaml", "organization.schema.json", "Organization", "organization"},
	{"config/actions-policy.yaml", "actions_policy.schema.json", "ActionsPolicy", "actions_policy"},
	{"config/security-policy.yaml", "security_policy.schema.json", "SecurityPolicy", "security_policy"},
	{"config/oidc-policy.yaml", "oidc_policy.schema.json", "OidcPolicy", "oidc_policy"},
	{"config/members.yaml", "membership.schema.json", "Membership", "members"},
	{"config/outside-collaborators.yaml", "membership.schema.json", "Membership", "outside_collaborators"},
	{"config/teams/architecture.yaml", "team.schema.json", "Team", "teams"},
	{"config/teams/biological-safety.yaml", "team.schema.json", "Team", "teams"},
	{"config/teams/computational-biology.yaml", "team.schema.json", "Team", "teams"},
	{"config/teams/data-platform.yaml", "team.schema.json", "Team", "teams"},
	{"config/teams/developer-platform.yaml", "team.schema.json", "Team", "teams"},
	{"config/teams/founder-pr-bypass.yaml", "team.schema.json", "Team", "teams"},
	{"config/teams/ml-systems.yaml", "team.schema.json", "Team", "teams"},
	{"config/teams/platform-operations.yaml", "team.schema.json", "Team", "teams"},
	{"config/teams/product-engineering.yaml", "team.schema.json", "Team", "teams"},
	{"config/teams/release-engineering.yaml", "team.schema.json", "Team", "teams"},
	{"config/teams/security.yaml", "team.schema.json", "Team", "teams"},
	{"config/repositories/dot-github.yaml", "repository.schema.json", "Repository", "repositories"},
	{"config/repositories/estate-ci.yaml", "repository.schema.json", "Repository", "repositories"},
	{"config/repositories/github-config.yaml", "repository.schema.json", "Repository", "repositories"},
	{"config/repositories/bootstrap.yaml", "repository.schema.json", "Repository", "repositories"},
	{"config/repositories/infrastructure-live.yaml", "repository.schema.json", "Repository", "repositories"},
	{"config/repositories/gitops.yaml", "repository.schema.json", "Repository", "repositories"},
	{"config/repositories/mindclade.yaml", "repository.schema.json", "Repository", "repositories"},
	{"config/rulesets/application-source.yaml", "ruleset.schema.json", "Ruleset", "rulesets"},
	{"config/rulesets/governance-source.yaml", "ruleset.schema.json", "Ruleset", "rulesets"},
	{"config/rulesets/infrastructure-source.yaml", "ruleset.schema.json", "Ruleset", "rulesets"},
	{"config/rulesets/deployment-source.yaml", "ruleset.schema.json", "Ruleset", "rulesets"},
	{"config/rulesets/release-tags.yaml", "ruleset.schema.json", "Ruleset", "rulesets"},
	{"config/environments/trusted-build.yaml", "environment.schema.json", "Environment", "environments"},
	{"config/environments/release-signing.yaml", "environment.schema.json", "Environment", "environments"},
	{"config/environments/infrastructure-apply.yaml", "environment.schema.json", "Environment", "environments"},
	{"config/environments/production-promotion.yaml", "environment.schema.json", "Environment", "environments"},
	{"config/integrations/buildkite.yaml", "integration.schema.json", "Integration", "integrations"},
	{"config/integrations/artifact-signing.yaml", "integration.schema.json", "Integration", "integrations"},
	{"config/integrations/gitops-controller.yaml", "integration.schema.json", "Integration", "integrations"},
}

var schemaFiles = []string{
	"actions_policy.schema.json",
	"ci_usage_report.schema.json",
	"environment.schema.json",
	"founder_pr_bypass_evidence.schema.json",
	"integration.schema.json",
	"membership.schema.json",
	"oidc_policy.schema.json",
	"organization.schema.json",
	"repository.schema.json",
	"ruleset.schema.json",
	"security_policy.schema.json",
	"team.schema.json",
}

// canonicalWorkflowInventories are the closed operational workflow surfaces
// whose external Action pins are governed by config/actions-policy.yaml.
var canonicalWorkflowInventories = map[string][]string{
	"github-config": {
		"ci-usage-report.yml", "drift-detection.yml", "protected-apply.yml",
		"pull-request.yml", "renovate.yml",
	},
	".github": {
		"reusable-buildkite-dispatch.yml", "reusable-required-check.yml",
		"reusable-nix-validation.yml",
		"reusable-metadata-validation.yml", "reusable-documentation-check.yml",
		"reusable-dependency-review.yml", "reusable-codeql.yml",
		"reusable-scorecard.yml", "pull-request.yml",
	},
	"bootstrap": {
		"pull-request.yml", "recovery-verification.yml", "protected-apply.yml",
	},
	"infrastructure-live": {
		"pull-request.yml", "drift-detection.yml", "protected-apply.yml",
		"disaster-recovery.yml",
	},
	"gitops": {
		"pull-request.yml", "promotion.yml", "drift-detection.yml", "rollback-verification.yml",
	},
	"mindclade": {
		"pr-metadata.yml", "buildkite-dispatch.yml", "required-check.yml", "docs.yml",
		"dependency-review.yml", "codeql.yml", "scorecard.yml", "mirror-verification.yml",
	},
}

// canonicalWorkflowTemplateInventories are reviewed catalog interfaces whose
// immutable reusable-workflow implementation pin can differ from the catalog
// commit that publishes the templates. This is necessary because a catalog
// commit cannot recursively pin its own reusable workflows to itself.
var canonicalWorkflowTemplateInventories = map[string][]string{
	".github": {
		"workflow-templates/buildkite-bridge.yml",
		"workflow-templates/repository-metadata.yml",
	},
}

// Compile reads the exact blueprint inventory and returns a flattened catalog.
func Compile(root string) (*Catalog, error) {
	_, documents, err := validatedDocuments(root)
	if err != nil {
		return nil, err
	}
	result := &Catalog{
		APIVersion:           validation.APIVersion,
		Activation:           make(map[string]any),
		Teams:                make(map[string]any),
		Repositories:         make(map[string]any),
		Rulesets:             make(map[string]any),
		Environments:         make(map[string]any),
		Integrations:         make(map[string]any),
		Members:              []any{},
		OutsideCollaborators: []any{},
	}
	for index, document := range documents {
		destination := sourceDefinitions[index].destination
		spec, isObject := document.Spec.(map[string]any)
		if isObject {
			if activation, exists := spec["activation"]; exists {
				activationRecord, _ := activation.(map[string]any)
				preserved := make(map[string]any, len(activationRecord)+5)
				for key, value := range activationRecord {
					preserved[key] = value
				}
				if document.Kind == "Membership" {
					for _, key := range []string{
						"scope", "minimum_distinct_admin_principals", "require_sponsor",
						"require_expiry", "max_permission",
					} {
						if value, exists := spec[key]; exists {
							preserved[key] = value
						}
					}
				}
				result.Activation[document.ID] = preserved
			}
		}
		switch destination {
		case "organization":
			result.Organization = spec
		case "actions_policy":
			result.ActionsPolicy = spec
		case "security_policy":
			result.SecurityPolicy = spec
		case "oidc_policy":
			result.OIDCPolicy = spec
		case "members":
			result.Members = extractMembership(document.Spec, "members")
		case "outside_collaborators":
			result.OutsideCollaborators = extractMembership(document.Spec, "outside_collaborators")
		case "teams":
			result.Teams[document.ID] = document.Spec
		case "repositories":
			result.Repositories[document.ID] = document.Spec
		case "rulesets":
			result.Rulesets[document.ID] = document.Spec
		case "environments":
			result.Environments[document.ID] = document.Spec
		case "integrations":
			result.Integrations[document.ID] = document.Spec
		}
		if strings.HasSuffix(destination, "policy") || destination == "organization" {
			if !isObject {
				return nil, fmt.Errorf("%s: singleton spec must be an object", document.Path)
			}
		}
	}
	generatedPolicyDigest, err := validateGeneratedPolicyArtifacts(root)
	if err != nil {
		return nil, err
	}
	baseBytes, err := rendering.CanonicalJSON(map[string]any{
		"catalog": result, "generated_policy_lock_digest": generatedPolicyDigest,
	})
	if err != nil {
		return nil, err
	}
	result.SourceDigest = rendering.Digest(baseBytes)
	return result, nil
}

func validatedDocuments(root string) (string, []*validation.Document, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", nil, fmt.Errorf("resolve repository root: %w", err)
	}
	if err := validateInventory(absoluteRoot); err != nil {
		return "", nil, err
	}
	if err := validateComponentMetadata(absoluteRoot); err != nil {
		return "", nil, fmt.Errorf("component.yaml: %w", err)
	}
	documents := make([]*validation.Document, 0, len(sourceDefinitions))
	for _, definition := range sourceDefinitions {
		document, err := loadDocument(absoluteRoot, definition)
		if err != nil {
			return "", nil, err
		}
		documents = append(documents, document)
	}
	if err := validation.ValidateCatalog(documents); err != nil {
		return "", nil, fmt.Errorf("cross-document validation: %w", err)
	}
	if err := validation.ValidateCodeowners(absoluteRoot, documents, "github-config"); err != nil {
		return "", nil, fmt.Errorf("CODEOWNERS validation: %w", err)
	}
	if err := validateCanonicalWorkflowPins(absoluteRoot, documents); err != nil {
		return "", nil, fmt.Errorf("canonical workflow pin validation: %w", err)
	}
	return absoluteRoot, documents, nil
}

func validateCanonicalWorkflowPins(root string, documents []*validation.Document) error {
	allowedPins := make(map[string]string)
	authorities := make(map[string]map[string]any)
	for _, document := range documents {
		if document.Kind != "ActionsPolicy" {
			continue
		}
		spec, _ := document.Spec.(map[string]any)
		rawActions, _ := spec["allowed_actions"].([]any)
		for _, raw := range rawActions {
			action, _ := raw.(map[string]any)
			source, _ := action["source"].(string)
			commit, _ := action["commit"].(string)
			if source == "" || commit == "" {
				continue
			}
			allowedPins[source] = commit
		}
		for _, raw := range anyList(spec["authority_inventories"]) {
			authority, _ := raw.(map[string]any)
			repository, _ := authority["repository"].(string)
			if repository == "" {
				continue
			}
			if _, duplicate := authorities[repository]; duplicate {
				return fmt.Errorf("duplicate canonical workflow authority %q", repository)
			}
			authorities[repository] = authority
		}
	}
	if len(allowedPins) == 0 {
		return errors.New("ActionsPolicy must declare exact allowed action pins")
	}

	for repositoryName, expectedWorkflows := range canonicalWorkflowInventories {
		if repositoryName == "github-config" {
			continue
		}
		authority, exists := authorities[repositoryName]
		if !exists {
			return fmt.Errorf("canonical workflow authority %q is undeclared", repositoryName)
		}
		actualWorkflows := stringListValue(authority["workflows"])
		sort.Strings(actualWorkflows)
		expected := append([]string(nil), expectedWorkflows...)
		sort.Strings(expected)
		if strings.Join(actualWorkflows, "\x00") != strings.Join(expected, "\x00") {
			return fmt.Errorf("canonical workflow authority %q does not declare the exact workflow inventory", repositoryName)
		}
		activation, _ := authority["activation"].(map[string]any)
		state, _ := activation["state"].(string)
		revision, _ := authority["revision"].(string)
		implementationRevision, hasImplementationRevision := authority["implementation_revision"].(string)
		switch state {
		case "reviewed":
			if !isCommitSHA(revision) {
				return fmt.Errorf("canonical workflow authority %q requires an immutable reviewed revision", repositoryName)
			}
		case "blocked":
			if revision != "" {
				return fmt.Errorf("blocked canonical workflow authority %q must not claim a reviewed revision", repositoryName)
			}
		default:
			return fmt.Errorf("canonical workflow authority %q has an unsupported activation state", repositoryName)
		}
		if repositoryName == ".github" {
			if !isCommitSHA(implementationRevision) || implementationRevision == revision {
				return errors.New("canonical .github authority requires distinct immutable catalog and implementation revisions")
			}
		} else if hasImplementationRevision {
			return fmt.Errorf("canonical workflow authority %q must not declare a reusable-workflow implementation revision", repositoryName)
		}
	}

	repositoryRoots := map[string]string{"github-config": root}
	sharedImplementationRoot := ""
	blockedAuthorities := make([]string, 0)
	authorityRoot := strings.TrimSpace(os.Getenv("MINDCLADE_AUTHORITY_ROOT"))
	requireAuthorities := os.Getenv("MINDCLADE_REQUIRE_AUTHORITY_INVENTORIES") == "1"
	if requireAuthorities && authorityRoot == "" {
		return errors.New("connected canonical workflow pin qualification requires MINDCLADE_AUTHORITY_ROOT")
	}
	if authorityRoot != "" {
		absoluteAuthorityRoot, err := filepath.Abs(authorityRoot)
		if err != nil {
			return fmt.Errorf("resolve canonical workflow authority root: %w", err)
		}
		for repositoryName, authority := range authorities {
			activation, _ := authority["activation"].(map[string]any)
			if activation["state"] != "reviewed" {
				blockedAuthorities = append(blockedAuthorities, repositoryName)
				continue
			}
			repositoryRoot := filepath.Join(absoluteAuthorityRoot, repositoryName)
			revision, _ := authority["revision"].(string)
			head, err := detachedGitHead(repositoryRoot)
			if err != nil {
				return fmt.Errorf("canonical workflow authority %q is unavailable: %w", repositoryName, err)
			}
			if head != revision {
				return fmt.Errorf("canonical workflow authority %q revision %q does not match reviewed revision %q", repositoryName, head, revision)
			}
			repositoryRoots[repositoryName] = repositoryRoot
			if repositoryName == ".github" {
				implementationRevision, _ := authority["implementation_revision"].(string)
				implementationRoot := filepath.Join(absoluteAuthorityRoot, ".github-implementation")
				implementationHead, err := detachedGitHead(implementationRoot)
				if err != nil {
					return fmt.Errorf("canonical .github reusable-workflow implementation is unavailable: %w", err)
				}
				if implementationHead != implementationRevision {
					return fmt.Errorf("canonical .github reusable-workflow implementation revision %q does not match reviewed revision %q", implementationHead, implementationRevision)
				}
				sharedImplementationRoot = implementationRoot
			}
		}
	}

	repositoryNames := make([]string, 0, len(repositoryRoots))
	for name := range repositoryRoots {
		repositoryNames = append(repositoryNames, name)
	}
	sort.Strings(repositoryNames)
	for _, repositoryName := range repositoryNames {
		repositoryRoot := repositoryRoots[repositoryName]
		if repositoryName == "github-config" {
			workflowRoot := filepath.Join(repositoryRoot, ".github", "workflows")
			info, err := os.Stat(workflowRoot)
			if errors.Is(err, os.ErrNotExist) {
				// Catalog-only migration fixtures intentionally omit workflows.
				// The canonical repository inventory test requires this directory
				// in a source checkout, where its pins are validated below.
				continue
			}
			if err != nil {
				return fmt.Errorf("inspect github-config workflows: %w", err)
			}
			if !info.IsDir() {
				return errors.New("github-config/.github/workflows is not a directory")
			}
		}
		for _, workflowName := range canonicalWorkflowInventories[repositoryName] {
			relativePath := filepath.ToSlash(filepath.Join(".github", "workflows", workflowName))
			value, err := decodeYAML(filepath.Join(repositoryRoot, filepath.FromSlash(relativePath)))
			if err != nil {
				return fmt.Errorf("%s/%s: %w", repositoryName, relativePath, err)
			}
			workflow, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("%s/%s: root must be an object", repositoryName, relativePath)
			}
			uses := make([]string, 0)
			collectStringKey(workflow, "uses", &uses)
			sort.Strings(uses)
			for _, reference := range uses {
				if err := validateWorkflowUsePin(reference, allowedPins, authorities[".github"]); err != nil {
					return fmt.Errorf("%s/%s: %w", repositoryName, relativePath, err)
				}
			}
		}
		for _, relativePath := range canonicalWorkflowTemplateInventories[repositoryName] {
			value, err := decodeYAML(filepath.Join(repositoryRoot, filepath.FromSlash(relativePath)))
			if err != nil {
				return fmt.Errorf("%s/%s: %w", repositoryName, relativePath, err)
			}
			workflow, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("%s/%s: root must be an object", repositoryName, relativePath)
			}
			uses := make([]string, 0)
			collectStringKey(workflow, "uses", &uses)
			if len(uses) == 0 {
				return fmt.Errorf("%s/%s: canonical workflow template must call a reviewed reusable workflow", repositoryName, relativePath)
			}
			sort.Strings(uses)
			for _, reference := range uses {
				if err := validateWorkflowUsePin(reference, allowedPins, authorities[".github"]); err != nil {
					return fmt.Errorf("%s/%s: %w", repositoryName, relativePath, err)
				}
			}
		}
	}
	if sharedImplementationRoot != "" {
		for _, workflowName := range canonicalWorkflowInventories[".github"] {
			relativePath := filepath.ToSlash(filepath.Join(".github", "workflows", workflowName))
			value, err := decodeYAML(filepath.Join(sharedImplementationRoot, filepath.FromSlash(relativePath)))
			if err != nil {
				return fmt.Errorf(".github-implementation/%s: %w", relativePath, err)
			}
			workflow, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf(".github-implementation/%s: root must be an object", relativePath)
			}
			uses := make([]string, 0)
			collectStringKey(workflow, "uses", &uses)
			sort.Strings(uses)
			for _, reference := range uses {
				if err := validateWorkflowUsePin(reference, allowedPins, authorities[".github"]); err != nil {
					return fmt.Errorf(".github-implementation/%s: %w", relativePath, err)
				}
			}
		}
	}
	if requireAuthorities && len(blockedAuthorities) > 0 {
		sort.Strings(blockedAuthorities)
		return fmt.Errorf("canonical workflow authorities are blocked and unavailable for connected qualification: %s", strings.Join(blockedAuthorities, ", "))
	}
	return nil
}

func detachedGitHead(repositoryRoot string) (string, error) {
	path := filepath.Join(repositoryRoot, ".git", "HEAD")
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 256 {
		return "", errors.New(".git/HEAD must be a small regular non-symlink file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	head := strings.TrimSpace(string(data))
	if !isCommitSHA(head) {
		return "", errors.New("checkout must use a detached immutable commit")
	}
	return head, nil
}

func anyList(value any) []any {
	items, _ := value.([]any)
	return items
}

func stringListValue(value any) []string {
	result := make([]string, 0)
	for _, raw := range anyList(value) {
		text, _ := raw.(string)
		if text != "" {
			result = append(result, text)
		}
	}
	return result
}

func validateWorkflowUsePin(reference string, allowedPins map[string]string, sharedAuthority map[string]any) error {
	// Repository-local composite actions do not cross the catalog trust
	// boundary. The $/ prefix is the organization workflow repository's
	// validated checkout-relative composite-action convention.
	if strings.HasPrefix(reference, "./") || strings.HasPrefix(reference, "$/") {
		if strings.Contains(reference, "@") || strings.Contains(reference, "..") ||
			(strings.HasPrefix(reference, "$/") && !strings.HasPrefix(reference, "$/.github/actions/")) {
			return fmt.Errorf("local action source %q has an invalid path", reference)
		}
		return nil
	}
	separator := strings.LastIndex(reference, "@")
	if separator <= 0 || separator == len(reference)-1 {
		return fmt.Errorf("external source %q is not pinned to a commit", reference)
	}
	sourcePath := reference[:separator]
	commit := reference[separator+1:]
	if !isCommitSHA(commit) {
		return fmt.Errorf("external source %q is not pinned to a 40-character commit", reference)
	}
	parts := strings.Split(sourcePath, "/")
	if !validActionPathParts(parts) || strings.ContainsAny(sourcePath, "*?[]{} ") {
		return fmt.Errorf("external source %q has an invalid owner/repository path", reference)
	}
	if strings.HasPrefix(sourcePath, "mindclade/.github/.github/workflows/") {
		workflowName := strings.TrimPrefix(sourcePath, "mindclade/.github/.github/workflows/")
		if strings.Contains(workflowName, "/") || workflowName == "" {
			return fmt.Errorf("shared workflow source %q has an invalid canonical path", reference)
		}
		activation, _ := sharedAuthority["activation"].(map[string]any)
		catalogRevision, _ := sharedAuthority["revision"].(string)
		implementationRevision, _ := sharedAuthority["implementation_revision"].(string)
		if activation["state"] != "reviewed" || !isCommitSHA(catalogRevision) || !isCommitSHA(implementationRevision) {
			return errors.New("organization .github workflow authority is not reviewed at immutable catalog and implementation revisions")
		}
		declared := false
		for _, expected := range stringListValue(sharedAuthority["workflows"]) {
			if expected == workflowName {
				declared = true
				break
			}
		}
		if !declared {
			return fmt.Errorf("shared workflow %q is absent from the canonical .github authority inventory", workflowName)
		}
		if commit != implementationRevision {
			return fmt.Errorf("shared workflow %q uses %s, canonical .github implementation authority requires %s", workflowName, commit, implementationRevision)
		}
		return nil
	}
	source := parts[0] + "/" + parts[1]
	expected, exists := allowedPins[source]
	if !exists {
		return fmt.Errorf("external action %q is absent from config/actions-policy.yaml", source)
	}
	if expected != commit {
		return fmt.Errorf("external action %q uses %s, catalog requires %s", source, commit, expected)
	}
	return nil
}

func validActionPathParts(parts []string) bool {
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, character := range part {
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

func isCommitSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validateComponentMetadata(root string) error {
	value, err := decodeYAML(filepath.Join(root, "component.yaml"))
	if err != nil {
		return err
	}
	document, ok := value.(map[string]any)
	if !ok {
		return errors.New("document root must be an object")
	}
	if document["apiVersion"] != "mindclade.io/v1alpha1" || document["kind"] != "Component" {
		return errors.New("apiVersion and kind must identify the Mindclade Component contract")
	}
	metadata, ok := document["metadata"].(map[string]any)
	if !ok || metadata["name"] != "github-config" {
		return errors.New("metadata.name must be github-config")
	}
	spec, ok := document["spec"].(map[string]any)
	if !ok {
		return errors.New("spec must be an object")
	}
	expectedStrings := map[string]string{
		"owner": "developer-platform", "lifecycle": "pre-production",
		"maturity": "pre-production", "repository_class": "governance-source",
	}
	for field, expected := range expectedStrings {
		if spec[field] != expected {
			return fmt.Errorf("spec.%s must be %q", field, expected)
		}
	}
	for _, field := range []string{"trust_tier", "recovery_tier"} {
		if text, fieldOK := spec[field].(string); !fieldOK || strings.TrimSpace(text) == "" {
			return fmt.Errorf("spec.%s must be a non-empty string", field)
		}
	}
	if authority, exists := spec["production_authority"].(bool); !exists || authority {
		return errors.New("spec.production_authority must be false until connected qualification")
	}
	reviewers, ok := spec["security_reviewers"].([]any)
	if !ok || len(reviewers) != 1 || reviewers[0] != "security" {
		return errors.New("spec.security_reviewers must contain only security")
	}
	if dependencies, dependenciesOK := spec["dependencies"].([]any); !dependenciesOK || len(dependencies) == 0 {
		return errors.New("spec.dependencies must be a non-empty list")
	}
	release, ok := spec["release"].(map[string]any)
	if !ok || release["strategy"] != "reviewed-main" || release["artifact"] != "source-commit" || release["immutable"] != true {
		return errors.New("spec.release must bind an immutable reviewed-main source commit")
	}
	activation, ok := spec["activation"].(map[string]any)
	if !ok {
		return errors.New("spec.activation must distinguish source_ready and connected")
	}
	for _, stage := range []string{"source_ready", "connected"} {
		record, ok := activation[stage].(map[string]any)
		description, hasDescription := record["description"].(string)
		if !ok || !hasDescription || strings.TrimSpace(description) == "" {
			return fmt.Errorf("spec.activation.%s.description must be non-empty", stage)
		}
	}
	return nil
}

// AsMap converts a catalog without losing JSON field names.
func (catalog *Catalog) AsMap() map[string]any {
	return map[string]any{
		"api_version":           catalog.APIVersion,
		"activation":            catalog.Activation,
		"organization":          catalog.Organization,
		"actions_policy":        catalog.ActionsPolicy,
		"security_policy":       catalog.SecurityPolicy,
		"oidc_policy":           catalog.OIDCPolicy,
		"members":               catalog.Members,
		"outside_collaborators": catalog.OutsideCollaborators,
		"teams":                 catalog.Teams,
		"repositories":          catalog.Repositories,
		"rulesets":              catalog.Rulesets,
		"environments":          catalog.Environments,
		"integrations":          catalog.Integrations,
		"source_digest":         catalog.SourceDigest,
	}
}

// PolicyInput returns validated raw envelopes in the collection shapes used by
// the Rego packages. Workflow references are parsed from the exact blueprint
// workflow files so source-pinning policy evaluates real repository content.
func PolicyInput(root string) (map[string]any, error) {
	absoluteRoot, documents, err := validatedDocuments(root)
	if err != nil {
		return nil, err
	}
	result := map[string]any{
		"api_version": validation.APIVersion,
		"memberships": []any{}, "teams": []any{}, "repositories": []any{},
		"rulesets": []any{}, "environments": []any{}, "integrations": []any{},
		"tokens": []any{}, "workflow_qualifications": []any{},
	}
	for _, document := range documents {
		switch document.Kind {
		case "Organization":
			result["organization"] = document.Raw
		case "ActionsPolicy":
			result["actions_policy"] = document.Raw
		case "SecurityPolicy":
			result["security_policy"] = document.Raw
		case "OidcPolicy":
			result["oidc_policy"] = document.Raw
		case "Membership":
			result["memberships"] = append(result["memberships"].([]any), document.Raw)
		case "Team":
			result["teams"] = append(result["teams"].([]any), document.Raw)
		case "Repository":
			result["repositories"] = append(result["repositories"].([]any), document.Raw)
		case "Ruleset":
			result["rulesets"] = append(result["rulesets"].([]any), document.Raw)
		case "Environment":
			result["environments"] = append(result["environments"].([]any), document.Raw)
		case "Integration":
			result["integrations"] = append(result["integrations"].([]any), document.Raw)
		}
	}
	// The canonical inventory is the single registration point for a workflow.
	// Deriving the policy input from it keeps source-pinning policy and the Go
	// pin validation over the same set: a workflow cannot be added to one and
	// silently escape the other.
	githubConfigWorkflows := canonicalWorkflowInventories["github-config"]
	workflows := make([]any, 0, len(githubConfigWorkflows))
	for _, name := range githubConfigWorkflows {
		path := filepath.Join(absoluteRoot, ".github", "workflows", name)
		value, err := decodeYAML(path)
		if err != nil {
			return nil, fmt.Errorf(".github/workflows/%s: %w", name, err)
		}
		workflow, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf(".github/workflows/%s: root must be an object", name)
		}
		uses := make([]string, 0)
		collectStringKey(workflow, "uses", &uses)
		events := workflowEvents(workflow["on"])
		sort.Strings(uses)
		sort.Strings(events)
		workflows = append(workflows, map[string]any{
			"name": name, "events": stringsToAny(events), "uses": stringsToAny(uses),
		})
	}
	result["workflows"] = workflows
	return result, nil
}

func loadDocument(root string, definition sourceDefinition) (*validation.Document, error) {
	fullPath := filepath.Join(root, filepath.FromSlash(definition.path))
	value, err := decodeYAML(fullPath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", definition.path, err)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: document root must be an object", definition.path)
	}
	kind, _ := object["kind"].(string)
	if kind != definition.kind {
		return nil, fmt.Errorf("%s: kind must be %q", definition.path, definition.kind)
	}
	metadata, ok := object["metadata"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: metadata must be an object", definition.path)
	}
	id, _ := metadata["id"].(string)
	document := &validation.Document{
		Path: definition.path, Schema: definition.schema, Kind: kind, ID: id,
		Metadata: metadata, Spec: object["spec"], Raw: object,
	}
	if err := validation.ValidateDocument(filepath.Join(root, "schemas", "v1", definition.schema), document); err != nil {
		return nil, err
	}
	return document, nil
}

func validateInventory(root string) error {
	expectedConfig := make(map[string]struct{}, len(sourceDefinitions))
	for _, definition := range sourceDefinitions {
		expectedConfig[filepath.Clean(definition.path)] = struct{}{}
	}
	if err := validateExactTree(root, "config", expectedConfig); err != nil {
		return err
	}
	expectedSchemas := make(map[string]struct{}, len(schemaFiles))
	for _, name := range schemaFiles {
		expectedSchemas[filepath.Join("schemas", "v1", name)] = struct{}{}
	}
	if err := validateExactTree(root, filepath.Join("schemas", "v1"), expectedSchemas); err != nil {
		return err
	}
	expectedGenerated := make(map[string]struct{}, len(generatedPolicyFiles))
	for path := range generatedPolicyFiles {
		expectedGenerated[filepath.Clean(path)] = struct{}{}
	}
	if err := validateExactTree(root, "generated", expectedGenerated); err != nil {
		return err
	}
	_, err := validateGeneratedPolicyArtifacts(root)
	return err
}

func validateGeneratedPolicyArtifacts(root string) (string, error) {
	paths := make([]string, 0, len(generatedPolicyFiles))
	for path := range generatedPolicyFiles {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	contents := make(map[string][]byte, len(paths))
	for _, relative := range paths {
		data, err := readGeneratedPolicyFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			return "", fmt.Errorf("%s: %w", relative, err)
		}
		digest := sha256.Sum256(data)
		actual := hex.EncodeToString(digest[:])
		if actual != generatedPolicyFiles[relative] {
			return "", fmt.Errorf("%s: generated policy digest differs from immutable authority %s", relative, generatedPolicyAuthorityCommit)
		}
		contents[relative] = data
	}
	var lock map[string]any
	if err := json.Unmarshal(contents["generated/nix-bazel-policy.lock.json"], &lock); err != nil {
		return "", fmt.Errorf("generated policy lock is invalid JSON: %w", err)
	}
	authority, _ := lock["authority"].(map[string]any)
	if authority["repository"] != generatedPolicyAuthority || authority["revision"] != generatedPolicyAuthorityCommit ||
		lock["api_version"] != "ci.mindclade.dev/v1" || lock["kind"] != "GeneratedPolicyLock" ||
		lock["contract_digest"] != "sha256:f50150993359d7888ce9a6cffaa71e9f6132abb10f76ebbc826de51835dbcdb9" {
		return "", errors.New("generated policy lock does not bind the exact reviewed authority contract")
	}
	artifacts, _ := lock["artifacts"].(map[string]any)
	for relative, expected := range map[string]string{
		".github/actions/required-workflow-profile/profiles.generated.json": "sha256:88bd5bcc329969ba69120b98afc7d97c4f92064bc6ab3f7e1fc4a19a447d823b",
		"generated/bazelrc.common":                   "sha256:" + generatedPolicyFiles["generated/bazelrc.common"],
		"generated/nix-bazel-policy.nix":             "sha256:" + generatedPolicyFiles["generated/nix-bazel-policy.nix"],
		"generated/toolchain-manifest.defaults.json": "sha256:" + generatedPolicyFiles["generated/toolchain-manifest.defaults.json"],
	} {
		if artifacts[relative] != expected {
			return "", fmt.Errorf("generated policy lock artifact %q differs from its reviewed digest", relative)
		}
	}
	return "sha256:" + generatedPolicyFiles["generated/nix-bazel-policy.lock.json"], nil
}

func readGeneratedPolicyFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxGeneratedPolicyBytes {
		return nil, fmt.Errorf("generated policy must be a regular non-symlink file no larger than %d bytes", maxGeneratedPolicyBytes)
	}
	return os.ReadFile(path)
}

func validateExactTree(root, relativeDirectory string, expected map[string]struct{}) error {
	directory := filepath.Join(root, relativeDirectory)
	found := make(map[string]struct{}, len(expected))
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlinks are forbidden: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.Clean(relative)
		if _, ok := expected[relative]; !ok {
			return fmt.Errorf("unexpected file in authoritative tree: %s", filepath.ToSlash(relative))
		}
		found[relative] = struct{}{}
		return nil
	})
	if err != nil {
		return fmt.Errorf("validate %s inventory: %w", relativeDirectory, err)
	}
	missing := make([]string, 0)
	for path := range expected {
		if _, ok := found[path]; !ok {
			missing = append(missing, filepath.ToSlash(path))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("missing required file(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

func decodeYAML(path string) (any, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, errors.New("YAML must be a regular, non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close() // A read-only descriptor has no buffered state to preserve.
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect YAML: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxYAMLBytes {
		return nil, fmt.Errorf("YAML must be a regular file no larger than %d bytes", maxYAMLBytes)
	}
	decoder := yaml.NewDecoder(io.LimitReader(file, maxYAMLBytes+1))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}
	if len(root.Content) != 1 {
		return nil, errors.New("YAML must contain exactly one document")
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("multiple YAML documents are forbidden")
		}
		return nil, fmt.Errorf("parse trailing YAML: %w", err)
	}
	return nodeValue(root.Content[0], "")
}

func nodeValue(node *yaml.Node, path string) (any, error) {
	if node.Kind == yaml.AliasNode || node.Alias != nil || node.Anchor != "" {
		return nil, fmt.Errorf("YAML aliases and anchors are forbidden at %s", pointerOrRoot(path))
	}
	switch node.Kind {
	case yaml.MappingNode:
		if len(node.Content)%2 != 0 {
			return nil, fmt.Errorf("invalid mapping at %s", pointerOrRoot(path))
		}
		result := make(map[string]any, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			keyNode := node.Content[index]
			if keyNode.Kind != yaml.ScalarNode || keyNode.Tag != "!!str" {
				return nil, fmt.Errorf("mapping key at %s must be a string", pointerOrRoot(path))
			}
			key := keyNode.Value
			if key == "<<" {
				return nil, fmt.Errorf("YAML merge keys are forbidden at %s", pointerOrRoot(path))
			}
			if _, exists := result[key]; exists {
				return nil, fmt.Errorf("duplicate YAML key %q at %s", key, pointerOrRoot(path))
			}
			value, err := nodeValue(node.Content[index+1], path+"/"+escapePointer(key))
			if err != nil {
				return nil, err
			}
			result[key] = value
		}
		return result, nil
	case yaml.SequenceNode:
		result := make([]any, len(node.Content))
		for index, child := range node.Content {
			value, err := nodeValue(child, fmt.Sprintf("%s/%d", path, index))
			if err != nil {
				return nil, err
			}
			result[index] = value
		}
		return result, nil
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!null":
			return nil, nil
		case "!!bool":
			return strconv.ParseBool(strings.ToLower(node.Value))
		case "!!int":
			text := strings.ReplaceAll(node.Value, "_", "")
			if value, err := strconv.ParseInt(text, 0, 64); err == nil {
				return value, nil
			}
			if value, err := strconv.ParseUint(text, 0, 64); err == nil {
				return value, nil
			}
			return nil, fmt.Errorf("integer outside 64-bit range at %s", pointerOrRoot(path))
		case "!!float":
			value, err := strconv.ParseFloat(strings.ReplaceAll(node.Value, "_", ""), 64)
			if err != nil {
				return nil, fmt.Errorf("invalid finite number at %s", pointerOrRoot(path))
			}
			return value, nil
		case "!!str", "!!timestamp":
			return node.Value, nil
		default:
			return nil, fmt.Errorf("unsupported YAML tag %q at %s", node.Tag, pointerOrRoot(path))
		}
	default:
		return nil, fmt.Errorf("unsupported YAML node at %s", pointerOrRoot(path))
	}
}

func extractMembership(spec any, preferred string) []any {
	object, ok := spec.(map[string]any)
	if !ok {
		if list, ok := spec.([]any); ok {
			return list
		}
		return []any{}
	}
	for _, key := range []string{preferred, "organization_members", "members", "collaborators", "outside_collaborators"} {
		if list, ok := object[key].([]any); ok {
			return list
		}
	}
	return []any{}
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

func collectStringKey(value any, target string, result *[]string) {
	switch current := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(current))
		for key := range current {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if key == target {
				if text, ok := current[key].(string); ok {
					*result = append(*result, text)
				}
			}
			collectStringKey(current[key], target, result)
		}
	case []any:
		for _, item := range current {
			collectStringKey(item, target, result)
		}
	}
}

func workflowEvents(value any) []string {
	switch current := value.(type) {
	case string:
		return []string{current}
	case []any:
		result := make([]string, 0, len(current))
		for _, item := range current {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		return result
	case map[string]any:
		result := make([]string, 0, len(current))
		for event := range current {
			result = append(result, event)
		}
		return result
	default:
		return []string{}
	}
}

func stringsToAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}
