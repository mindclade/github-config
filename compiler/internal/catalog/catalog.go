// Package catalog loads the authoritative YAML tree into a deterministic,
// schema-validated catalog consumed by policy and OpenTofu.
package catalog

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/mindclade/github-config/compiler/internal/rendering"
	"github.com/mindclade/github-config/compiler/internal/validation"
	"gopkg.in/yaml.v3"
)

const maxYAMLBytes = 4 << 20

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
	RepositoryGates      map[string]any `json:"repository_gates"`
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
	{"config/teams/ml-systems.yaml", "team.schema.json", "Team", "teams"},
	{"config/teams/platform-operations.yaml", "team.schema.json", "Team", "teams"},
	{"config/teams/product-engineering.yaml", "team.schema.json", "Team", "teams"},
	{"config/teams/release-engineering.yaml", "team.schema.json", "Team", "teams"},
	{"config/teams/security.yaml", "team.schema.json", "Team", "teams"},
	{"config/repositories/dot-github.yaml", "repository.schema.json", "Repository", "repositories"},
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
	{"config/repository-gates/infrastructure-live-authorities.yaml", "repository_gate.schema.json", "RepositoryGate", "repository_gates"},
	{"config/environments/trusted-build.yaml", "environment.schema.json", "Environment", "environments"},
	{"config/environments/release-signing.yaml", "environment.schema.json", "Environment", "environments"},
	{"config/environments/infrastructure-apply.yaml", "environment.schema.json", "Environment", "environments"},
	{"config/environments/production-promotion.yaml", "environment.schema.json", "Environment", "environments"},
	{"config/environments/infrastructure-source-review.yaml", "environment.schema.json", "Environment", "environments"},
	{"config/environments/security-source-review.yaml", "environment.schema.json", "Environment", "environments"},
	{"config/integrations/buildkite.yaml", "integration.schema.json", "Integration", "integrations"},
	{"config/integrations/artifact-signing.yaml", "integration.schema.json", "Integration", "integrations"},
	{"config/integrations/gitops-controller.yaml", "integration.schema.json", "Integration", "integrations"},
}

var schemaFiles = []string{
	"actions_policy.schema.json",
	"environment.schema.json",
	"integration.schema.json",
	"membership.schema.json",
	"oidc_policy.schema.json",
	"organization.schema.json",
	"repository.schema.json",
	"repository_gate.schema.json",
	"ruleset.schema.json",
	"security_policy.schema.json",
	"team.schema.json",
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
		RepositoryGates:      make(map[string]any),
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
		case "repository_gates":
			result.RepositoryGates[document.ID] = document.Spec
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
	baseBytes, err := rendering.CanonicalJSON(result)
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
	return absoluteRoot, documents, nil
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
		"repository_gates":      catalog.RepositoryGates,
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
		"rulesets": []any{}, "repository_gates": []any{}, "environments": []any{}, "integrations": []any{},
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
		case "RepositoryGate":
			result["repository_gates"] = append(result["repository_gates"].([]any), document.Raw)
		case "Environment":
			result["environments"] = append(result["environments"].([]any), document.Raw)
		case "Integration":
			result["integrations"] = append(result["integrations"].([]any), document.Raw)
		}
	}
	workflows := make([]any, 0, 3)
	for _, name := range []string{"drift-detection.yml", "protected-apply.yml", "pull-request.yml"} {
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
	return validateExactTree(root, filepath.Join("schemas", "v1"), expectedSchemas)
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
	defer file.Close()
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
