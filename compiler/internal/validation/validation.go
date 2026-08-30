// Package validation enforces schema, identity, and cross-document invariants.
package validation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mindclade/github-config/compiler/internal/rendering"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

const APIVersion = "github.mindclade.io/v1"

// Document is a validated source document before catalog flattening.
type Document struct {
	Path     string
	Schema   string
	Kind     string
	ID       string
	Metadata map[string]any
	Spec     any
	Raw      map[string]any
}

// ValidateDocument verifies the envelope and its JSON Schema. Secret scanning
// happens before schema error formatting so a credential can never be echoed.
func ValidateDocument(schemaPath string, document *Document) error {
	if secretPath, found := rendering.HasSecretLikeValue(document.Raw); found {
		return fmt.Errorf("%s: inline credential-like value at %s", document.Path, secretPath)
	}
	if version, _ := document.Raw["api_version"].(string); version != APIVersion {
		return fmt.Errorf("%s: api_version must be %q", document.Path, APIVersion)
	}
	if document.Kind == "" {
		return fmt.Errorf("%s: kind must be a non-empty string", document.Path)
	}
	if document.ID == "" {
		return fmt.Errorf("%s: metadata.id must be a non-empty string", document.Path)
	}
	if document.Spec == nil {
		return fmt.Errorf("%s: spec is required", document.Path)
	}
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		return fmt.Errorf("read schema for %s: %w", document.Path, err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	resource := "schema://github-config/" + document.Schema
	if err := compiler.AddResource(resource, bytes.NewReader(schemaBytes)); err != nil {
		return fmt.Errorf("load schema %s: %w", document.Schema, err)
	}
	schema, err := compiler.Compile(resource)
	if err != nil {
		return fmt.Errorf("compile schema %s: %w", document.Schema, err)
	}
	if err := schema.Validate(document.Raw); err != nil {
		return fmt.Errorf("%s does not satisfy %s: %w", document.Path, document.Schema, err)
	}
	return nil
}

// ValidateCatalog enforces invariants that JSON Schema cannot express across
// independently owned documents.
func ValidateCatalog(documents []*Document) error {
	if len(documents) == 0 {
		return errors.New("catalog has no documents")
	}
	teams := make(set)
	repositories := make(set)
	integrations := make(set)
	environments := make(set)
	environmentSpecs := make(map[string]map[string]any)
	organizationMemberLogins := make(set)
	organizationMemberPrincipals := make(map[string]string)
	securityRequirements := make(map[string]bool)
	var outsideCollaboratorPolicy map[string]any
	seenIDs := make(map[string]string)
	for _, document := range documents {
		key := strings.ToLower(document.ID)
		if prior, exists := seenIDs[key]; exists {
			return fmt.Errorf("duplicate metadata.id %q in %s and %s", document.ID, prior, document.Path)
		}
		seenIDs[key] = document.Path
		switch document.Kind {
		case "SecurityPolicy":
			if spec, ok := document.Spec.(map[string]any); ok {
				for _, key := range []string{
					"dependabot_alerts_required", "dependabot_security_updates_required",
					"advanced_security_required", "secret_scanning_required",
					"secret_scanning_push_protection_required",
				} {
					securityRequirements[key] = boolValue(spec[key])
				}
			}
		case "Team":
			teams.add(document.ID)
		case "Repository":
			repositories.add(document.ID)
			if spec, ok := document.Spec.(map[string]any); ok {
				repositories.add(stringValue(spec["name"]))
			}
		case "Integration":
			integrations.add(document.ID)
		case "Environment":
			environments.add(document.ID)
			if spec, ok := document.Spec.(map[string]any); ok {
				name := stringValue(spec["name"])
				environments.add(name)
				environmentSpecs[strings.ToLower(document.ID)] = spec
				environmentSpecs[strings.ToLower(name)] = spec
			}
		case "Membership":
			spec, _ := document.Spec.(map[string]any)
			scope := stringValue(spec["scope"])
			if scope == "outside_collaborators" {
				outsideCollaboratorPolicy = spec
				continue
			}
			if scope != "organization_members" {
				return fmt.Errorf("%s: unsupported membership scope %q", document.Path, scope)
			}
			for _, member := range objectList(spec["organization_members"]) {
				login, _ := member["login"].(string)
				if login == "" {
					return fmt.Errorf("%s: membership login is empty", document.Path)
				}
				if organizationMemberLogins.has(login) {
					return fmt.Errorf("%s: duplicate membership login %q", document.Path, login)
				}
				organizationMemberLogins.add(login)
				principal, _ := member["principal_id"].(string)
				if principal == "" {
					return fmt.Errorf("%s: member %q has no principal_id", document.Path, login)
				}
				if active, exists := member["active"].(bool); exists && !active {
					continue
				}
				organizationMemberPrincipals[strings.ToLower(login)] = principal
			}
		}
	}
	if outsideCollaboratorPolicy != nil {
		maxRank, supported := permissionRank(stringValue(outsideCollaboratorPolicy["max_permission"]))
		if !supported {
			return errors.New("outside collaborator max_permission is unsupported")
		}
		outsideLogins := make(set)
		for _, collaborator := range objectList(outsideCollaboratorPolicy["outside_collaborators"]) {
			login := stringValue(collaborator["login"])
			if outsideLogins.has(login) {
				return fmt.Errorf("duplicate outside collaborator login %q", login)
			}
			outsideLogins.add(login)
			sponsor := stringValue(collaborator["sponsor_login"])
			if strings.EqualFold(login, sponsor) {
				return fmt.Errorf("outside collaborator %q cannot sponsor itself", login)
			}
			if organizationMemberLogins.has(login) {
				return fmt.Errorf("outside collaborator %q must have a login distinct from managed organization members", login)
			}
			sponsorPrincipal := organizationMemberPrincipals[strings.ToLower(sponsor)]
			if sponsorPrincipal == "" {
				return fmt.Errorf("outside collaborator %q sponsor %q is not an active managed organization member", login, sponsor)
			}
			collaboratorPrincipal := stringValue(collaborator["principal_id"])
			if collaboratorPrincipal == "" {
				return fmt.Errorf("outside collaborator %q has no principal_id", login)
			}
			if collaboratorPrincipal == sponsorPrincipal {
				return fmt.Errorf("outside collaborator %q and sponsor %q must have distinct principal_id values", login, sponsor)
			}
			seenRepositories := make(set)
			for _, grant := range objectList(collaborator["repository_permissions"]) {
				repository := stringValue(grant["repository"])
				if !repositories.has(repository) {
					return fmt.Errorf("outside collaborator %q repository %q is not declared", login, repository)
				}
				if seenRepositories.has(repository) {
					return fmt.Errorf("outside collaborator %q has duplicate repository grant %q", login, repository)
				}
				seenRepositories.add(repository)
				rank, ok := permissionRank(stringValue(grant["permission"]))
				if !ok || rank > maxRank {
					return fmt.Errorf("outside collaborator %q grant on %q exceeds max_permission", login, repository)
				}
			}
		}
	}
	repositoryCanonicalNames := make(map[string]string)
	for _, document := range documents {
		if document.Kind != "Repository" {
			continue
		}
		spec, _ := document.Spec.(map[string]any)
		name := stringValue(spec["name"])
		repositoryCanonicalNames[strings.ToLower(document.ID)] = name
		repositoryCanonicalNames[strings.ToLower(name)] = name
	}
	oidcEnvironmentAuthorities := make(map[string]struct{})
	for _, document := range documents {
		if document.Kind != "OidcPolicy" {
			continue
		}
		spec, _ := document.Spec.(map[string]any)
		for _, subject := range objectList(spec["subjects"]) {
			context := specObject(subject, "context")
			if stringValue(context["type"]) != "environment" || !boolValue(subject["require_immutable_workflow_ref"]) {
				continue
			}
			repository := repositoryCanonicalNames[strings.ToLower(stringValue(subject["repository"]))]
			oidcEnvironmentAuthorities[environmentAuthorityKey(
				repository,
				stringValue(subject["workflow"]),
				stringValue(context["value"]),
			)] = struct{}{}
		}
	}
	repositoryAccess := make(map[string]map[string]int)
	for _, document := range documents {
		if document.Kind != "Repository" {
			continue
		}
		spec, _ := document.Spec.(map[string]any)
		name := stringValue(spec["name"])
		grants := make(map[string]int)
		for _, grant := range objectList(spec["team_grants"]) {
			team := stringValue(grant["team"])
			permission := stringValue(grant["permission"])
			rank, ok := permissionRank(permission)
			if !ok || rank > 4 {
				return fmt.Errorf("%s: team %q permission %q exceeds maintain or is unsupported", document.Path, team, permission)
			}
			normalizedTeam := strings.ToLower(team)
			if _, duplicate := grants[normalizedTeam]; duplicate {
				return fmt.Errorf("%s: duplicate team grant for %q", document.Path, team)
			}
			grants[normalizedTeam] = rank
		}
		owner := strings.ToLower(stringValue(specObject(spec, "custom_properties")["owner_team"]))
		if grants[owner] < 4 {
			return fmt.Errorf("%s: repository owner team %q must have maintain access", document.Path, owner)
		}
		repositoryAccess[strings.ToLower(name)] = grants
		repositoryAccess[strings.ToLower(document.ID)] = grants
	}
	for _, document := range documents {
		owner, _ := document.Metadata["owner_team"].(string)
		if owner == "" || !teams.has(owner) {
			return fmt.Errorf("%s: metadata.owner_team %q does not reference a declared team", document.Path, owner)
		}
		spec, _ := document.Spec.(map[string]any)
		switch document.Kind {
		case "ActionsPolicy":
			sources := make(set)
			for _, action := range objectList(spec["allowed_actions"]) {
				source := stringValue(action["source"])
				if sources.has(source) {
					return fmt.Errorf("%s: duplicate allowed action source %q", document.Path, source)
				}
				sources.add(source)
			}
		case "Team":
			for _, member := range objectList(spec["members"]) {
				login, _ := member["login"].(string)
				if !organizationMemberLogins.has(login) {
					return fmt.Errorf("%s: team member %q is not declared in members.yaml", document.Path, login)
				}
			}
		case "Repository":
			customProperties, _ := spec["custom_properties"].(map[string]any)
			if err := requireReference(document.Path, "spec.custom_properties.owner_team", stringValue(customProperties["owner_team"]), teams); err != nil {
				return err
			}
			for _, grant := range objectList(spec["team_grants"]) {
				if err := requireReference(document.Path, "spec.team_grants[].team", stringValue(grant["team"]), teams); err != nil {
					return err
				}
			}
			repositorySecurity := specObject(spec, "security")
			requirementFields := map[string]string{
				"dependabot_alerts_required":               "vulnerability_alerts",
				"dependabot_security_updates_required":     "dependabot_security_updates",
				"advanced_security_required":               "advanced_security",
				"secret_scanning_required":                 "secret_scanning",
				"secret_scanning_push_protection_required": "secret_scanning_push_protection",
			}
			for policyField, repositoryField := range requirementFields {
				if securityRequirements[policyField] && !boolValue(repositorySecurity[repositoryField]) {
					return fmt.Errorf("%s: repository security.%s must be enabled by security policy %s", document.Path, repositoryField, policyField)
				}
			}
		case "Ruleset":
			if err := requireReferences(document.Path, "spec.repositories", stringList(spec["repositories"]), repositories); err != nil {
				return err
			}
			for _, actor := range objectList(spec["bypass_actors"]) {
				actorType := stringValue(actor["actor_type"])
				actorID := stringValue(actor["actor"])
				switch actorType {
				case "team":
					if err := requireReference(document.Path, "spec.bypass_actors[].actor", actorID, teams); err != nil {
						return err
					}
				case "integration":
					if err := requireReference(document.Path, "spec.bypass_actors[].actor", actorID, integrations); err != nil {
						return err
					}
				default:
					return fmt.Errorf("%s: spec.bypass_actors[].actor_type %q is unsupported", document.Path, actorType)
				}
			}
			checkContexts := make(set)
			for _, check := range objectList(specObject(specObject(spec, "rules"), "required_status_checks")["checks"]) {
				context := stringValue(check["context"])
				if checkContexts.has(context) {
					return fmt.Errorf("%s: duplicate required status-check context %q", document.Path, context)
				}
				checkContexts.add(context)
			}
			if err := requireReferences(document.Path, "spec.rules.authorized_creator_integrations", valuesForKey(spec, "authorized_creator_integrations"), integrations); err != nil {
				return err
			}
		case "RepositoryGate":
			if err := requireReference(document.Path, "spec.repository", stringValue(spec["repository"]), repositories); err != nil {
				return err
			}
			if err := requireReferences(document.Path, "spec.required_deployments", stringList(spec["required_deployments"]), environments); err != nil {
				return err
			}
			checkContexts := make(set)
			workflowPaths := make(set)
			for _, check := range objectList(specObject(spec, "required_status_checks")["checks"]) {
				context := stringValue(check["context"])
				if checkContexts.has(context) {
					return fmt.Errorf("%s: duplicate required status-check context %q", document.Path, context)
				}
				checkContexts.add(context)
				workflowPaths.add(stringValue(check["workflow_path"]))
			}
			gateRepository := repositoryCanonicalNames[strings.ToLower(stringValue(spec["repository"]))]
			reviewerTeams := make(set)
			for _, environmentReference := range stringList(spec["required_deployments"]) {
				environment := environmentSpecs[strings.ToLower(environmentReference)]
				assigned := false
				for _, repositoryReference := range stringList(environment["repositories"]) {
					if repositoryCanonicalNames[strings.ToLower(repositoryReference)] == gateRepository {
						assigned = true
						break
					}
				}
				if !assigned {
					return fmt.Errorf("%s: required deployment %q is not assigned to repository %q", document.Path, environmentReference, stringValue(spec["repository"]))
				}
				reviewers := objectList(environment["required_reviewers"])
				if len(reviewers) != 1 || stringValue(reviewers[0]["team"]) == "" {
					return fmt.Errorf("%s: required deployment %q must name exactly one reviewer authority team", document.Path, environmentReference)
				}
				team := stringValue(reviewers[0]["team"])
				if reviewerTeams.has(team) {
					return fmt.Errorf("%s: required deployments must use distinct reviewer authority teams", document.Path)
				}
				reviewerTeams.add(team)
				allowedWorkflows := make(set)
				for _, workflow := range stringList(environment["allowed_workflows"]) {
					allowedWorkflows.add(workflow)
				}
				for workflow := range workflowPaths {
					if !allowedWorkflows.has(workflow) {
						return fmt.Errorf("%s: required deployment %q does not allow authority workflow %q", document.Path, environmentReference, workflow)
					}
				}
			}
		case "Environment":
			if err := requireReferences(document.Path, "spec.repositories", stringList(spec["repositories"]), repositories); err != nil {
				return err
			}
			reviewerTeams := make(set)
			for _, reviewer := range objectList(spec["required_reviewers"]) {
				if team := stringValue(reviewer["team"]); team != "" {
					if reviewerTeams.has(team) {
						return fmt.Errorf("%s: duplicate required reviewer team %q", document.Path, team)
					}
					reviewerTeams.add(team)
					if err := requireReference(document.Path, "spec.required_reviewers[].team", team, teams); err != nil {
						return err
					}
					for _, repository := range stringList(spec["repositories"]) {
						if repositoryAccess[strings.ToLower(repository)][strings.ToLower(team)] < 1 {
							return fmt.Errorf("%s: reviewer team %q does not have repository access to %q", document.Path, team, repository)
						}
					}
				}
			}
			activation := specObject(spec, "activation")
			if stringValue(activation["state"]) == "ready" {
				for _, repositoryReference := range stringList(spec["repositories"]) {
					repository := repositoryCanonicalNames[strings.ToLower(repositoryReference)]
					for _, workflow := range stringList(spec["allowed_workflows"]) {
						authority := environmentAuthorityKey(repository, workflow, stringValue(spec["name"]))
						if _, exists := oidcEnvironmentAuthorities[authority]; !exists {
							return fmt.Errorf(
								"%s: ready environment workflow %q in repository %q has no exact immutable OIDC subject authority",
								document.Path, workflow, repository,
							)
						}
					}
				}
			}
		case "Integration":
			if err := requireReferences(document.Path, "spec.repositories", stringList(spec["repositories"]), repositories); err != nil {
				return err
			}
			permissionNames := make(set)
			for _, permission := range objectList(spec["permissions"]) {
				name := stringValue(permission["name"])
				if permissionNames.has(name) {
					return fmt.Errorf("%s: duplicate integration permission name %q", document.Path, name)
				}
				permissionNames.add(name)
			}
			qualification := specObject(spec, "qualification")
			if stringValue(qualification["state"]) == "qualified" {
				repositoryNames := make([]string, 0, len(stringList(spec["repositories"])))
				for _, reference := range stringList(spec["repositories"]) {
					repositoryNames = append(repositoryNames, repositoryCanonicalNames[strings.ToLower(reference)])
				}
				if _, err := validatedIntegrationAttestation(spec, repositoryNames, time.Now().UTC()); err != nil {
					return fmt.Errorf("%s: %w", document.Path, err)
				}
			}
		case "OidcPolicy":
			useDefault, _ := spec["use_default_subject"].(bool)
			useImmutable, _ := spec["use_immutable_subject"].(bool)
			if useDefault || !useImmutable {
				return fmt.Errorf("%s: OIDC subjects must be customized and immutable", document.Path)
			}
			claims := make(set)
			for _, claim := range stringList(spec["include_claim_keys"]) {
				claims.add(claim)
			}
			for _, claim := range []string{"repo", "context", "workflow_ref", "workflow_sha"} {
				if !claims.has(claim) {
					return fmt.Errorf("%s: OIDC include_claim_keys must contain %q", document.Path, claim)
				}
			}
			for _, repository := range valuesForKey(spec, "repository") {
				if err := requireReference(document.Path, "repository", repository, repositories); err != nil {
					return err
				}
			}
			subjectIDs := make(set)
			subjectAuthorities := make(set)
			for _, subject := range objectList(spec["subjects"]) {
				subjectID := stringValue(subject["id"])
				if subjectIDs.has(subjectID) {
					return fmt.Errorf("%s: duplicate OIDC subject id %q", document.Path, subjectID)
				}
				subjectIDs.add(subjectID)
				context := specObject(subject, "context")
				authorityKey := strings.Join([]string{
					stringValue(subject["repository"]), stringValue(subject["workflow"]),
					stringValue(context["type"]), stringValue(context["value"]), stringValue(subject["audience"]),
				}, "\x00")
				if subjectAuthorities.has(authorityKey) {
					return fmt.Errorf("%s: duplicate effective OIDC subject authority", document.Path)
				}
				subjectAuthorities.add(authorityKey)
				immutable, _ := subject["require_immutable_workflow_ref"].(bool)
				if !immutable {
					return fmt.Errorf("%s: every OIDC subject must require an immutable workflow reference", document.Path)
				}
				if stringValue(context["type"]) == "environment" {
					if err := requireReference(document.Path, "spec.subjects[].context.value", stringValue(context["value"]), environments); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func environmentAuthorityKey(repository, workflow, environment string) string {
	return strings.Join([]string{repository, workflow, environment}, "\x00")
}

// PreflightReport evaluates phase-specific activation gates without changing
// external state. Adopt is read-only discovery. Foundation may establish
// known-missing controls only after the same source-authority, identity, and
// App-inventory safety gates used by enforcement are satisfied. Enforce also
// requires the complete desired managed state to be converged.
func PreflightReport(desired, observed map[string]any, phase string) map[string]any {
	blockers := make([]map[string]any, 0)
	seenBlockers := make(map[string]struct{})
	add := func(code, message string) {
		key := code + "\x00" + message
		if _, exists := seenBlockers[key]; exists {
			return
		}
		seenBlockers[key] = struct{}{}
		blockers = append(blockers, map[string]any{"code": code, "message": message})
	}
	coreComplete := false
	if observed == nil {
		add("OBSERVED_STATE_MISSING", "connected GitHub observation is required")
	} else {
		coreComplete, _ = observed["core_observation_complete"].(bool)
		if _, explicitlyScoped := observed["core_observation_complete"]; !explicitlyScoped {
			coreComplete, _ = observed["observation_complete"].(bool)
		}
		if !coreComplete {
			add("CORE_OBSERVATION_INCOMPLETE", "organization identity and core inventory observation are not complete")
		}
		if phase != "adopt" {
			observationComplete, _ := observed["observation_complete"].(bool)
			if !observationComplete || len(observationErrors(observed)) > 0 {
				add("CAPABILITY_OBSERVATION_INCOMPLETE", "one or more required GitHub capabilities could not be observed")
			}
			if phase == "enforce" && containsUnknown(observed["managed_projection"]) {
				add("OBSERVED_STATE_UNKNOWN", "managed observation contains unsupported or unreadable values")
			}
			if phase == "enforce" {
				matches, known := observed["managed_state_matches_desired"].(bool)
				if !known || !matches {
					add("MANAGED_STATE_NOT_CONVERGED", "complete managed GitHub state does not match the desired catalog projection")
				}
			}
		}
		desiredOrganization, _ := desired["organization"].(map[string]any)
		observedOrganization, _ := observed["organization"].(map[string]any)
		desiredLogin := stringValue(desiredOrganization["organization_login"])
		observedLogin := stringValue(observedOrganization["login"])
		if observedLogin == "" || !strings.EqualFold(desiredLogin, observedLogin) {
			add("ORGANIZATION_IDENTITY_MISMATCH", "observed organization login is missing or does not match the desired organization")
		}
	}
	adoptionMaps, adoptionIssues := adoptionBindings(desired, observed, coreComplete)
	for _, issue := range adoptionIssues {
		add("ADOPTION_IDENTITY_INCOMPLETE", issue)
	}
	oidcIdentity, oidcIdentityIssues, oidcIdentityComplete := observedOIDCIdentity(desired, observed, coreComplete)
	if (phase == "foundation" || phase == "enforce") && !oidcIdentityComplete {
		if len(oidcIdentityIssues) == 0 {
			oidcIdentityIssues = append(oidcIdentityIssues, "complete immutable OIDC organization and repository IDs were not observed")
		}
		for _, issue := range oidcIdentityIssues {
			add("OIDC_IDENTITY_INCOMPLETE", issue)
		}
	}
	if phase == "foundation" || phase == "enforce" {
		observedMembers := observedMemberLogins(observed)
		observedAdmins := observedAdminLogins(observed)
		principals := make(set)
		principalByLogin := make(map[string]string)
		for _, entry := range anyList(desired["members"]) {
			member, _ := entry.(map[string]any)
			login := strings.ToLower(stringValue(member["login"]))
			principal := stringValue(member["principal_id"])
			active, hasActive := member["active"].(bool)
			if login != "" && principal != "" && (!hasActive || active) && observedMembers.has(login) {
				principalByLogin[login] = principal
				if stringValue(member["role"]) == "admin" && observedAdmins.has(login) {
					principals.add(principal)
				}
			}
		}
		minimumAdmins := int64(2)
		activation, _ := desired["activation"].(map[string]any)
		memberActivation, _ := activation["organization-members"].(map[string]any)
		if configured := integerValue(memberActivation["minimum_distinct_admin_principals"]); configured > 0 {
			minimumAdmins = configured
		}
		if int64(len(principals)) < minimumAdmins {
			add("INSUFFICIENT_DISTINCT_HUMANS", fmt.Sprintf("at least %d distinct active organization-admin principals are required", minimumAdmins))
		}
		teams, _ := desired["teams"].(map[string]any)
		teamPrincipals := make(map[string]set, len(teams))
		for id, value := range teams {
			spec, _ := value.(map[string]any)
			teamPrincipals[strings.ToLower(id)] = make(set)
			for _, member := range objectList(spec["members"]) {
				if principal := principalByLogin[strings.ToLower(stringValue(member["login"]))]; principal != "" {
					teamPrincipals[strings.ToLower(id)].add(principal)
				}
			}
		}
		environments, _ := desired["environments"].(map[string]any)
		for id, value := range environments {
			spec, _ := value.(map[string]any)
			minimum := integerValue(specObject(spec, "approval_policy")["minimum_distinct_principals"])
			available := make(set)
			for _, reviewer := range objectList(spec["required_reviewers"]) {
				for principal := range teamPrincipals[strings.ToLower(stringValue(reviewer["team"]))] {
					available.add(principal)
				}
			}
			if int64(len(available)) < minimum {
				add("REVIEWER_QUORUM_UNSATISFIED", fmt.Sprintf("environment %q requires %d distinct principals but reviewer teams provide %d", id, minimum, len(available)))
			}
		}
		repositoryGates, _ := desired["repository_gates"].(map[string]any)
		for gateID, value := range repositoryGates {
			gate, _ := value.(map[string]any)
			authorities := make([]set, 0, len(stringList(gate["required_deployments"])))
			for _, environmentID := range stringList(gate["required_deployments"]) {
				environment, _ := environments[environmentID].(map[string]any)
				principals := make(set)
				for _, reviewer := range objectList(environment["required_reviewers"]) {
					for principal := range teamPrincipals[strings.ToLower(stringValue(reviewer["team"]))] {
						principals.add(principal)
					}
				}
				authorities = append(authorities, principals)
			}
			distinct := true
			for left := 0; left < len(authorities) && distinct; left++ {
				for right := left + 1; right < len(authorities) && distinct; right++ {
					for principal := range authorities[left] {
						if authorities[right].has(principal) {
							distinct = false
							break
						}
					}
				}
			}
			if !distinct {
				add("REVIEW_AUTHORITIES_NOT_DISTINCT", fmt.Sprintf("repository gate %q reviewer authorities share one or more active human principals", gateID))
			}
		}
		validateDesiredAccess(desired, add)
		capabilities, _ := observed["capabilities"].(map[string]any)
		securityPolicy, _ := desired["security_policy"].(map[string]any)
		requiredCapabilities := make(set)
		for _, capability := range stringList(securityPolicy["required_capabilities"]) {
			requiredCapabilities.add(capability)
		}
		requirements := []struct {
			key     string
			code    string
			message string
		}{}
		if requiredCapabilities.has("github-enterprise-cloud") {
			requirements = append(requirements, struct{ key, code, message string }{"enterprise_cloud", "ENTERPRISE_CLOUD_UNCONFIRMED", "GitHub Enterprise Cloud capability is not confirmed"})
		}
		if requiredCapabilities.has("github-advanced-security") || boolValue(securityPolicy["advanced_security_required"]) {
			capabilityKey := "advanced_security"
			if phase == "foundation" {
				capabilityKey = "advanced_security_available"
			}
			requirements = append(requirements, struct{ key, code, message string }{capabilityKey, "GHAS_UNCONFIRMED", "GitHub Advanced Security capability is not confirmed"})
		}
		if environments, _ := desired["environments"].(map[string]any); len(environments) > 0 {
			capabilityKey := "protected_environments"
			message := "complete protected environment reviewer observation is not confirmed"
			if phase == "foundation" {
				capabilityKey = "protected_environments_available"
				message = "protected environment API capability is not confirmed"
			}
			requirements = append(requirements, struct{ key, code, message string }{capabilityKey, "PROTECTED_ENVIRONMENTS_UNCONFIRMED", message})
		}
		for _, requirement := range requirements {
			if enabled, _ := capabilities[requirement.key].(bool); !enabled {
				add(requirement.code, requirement.message)
			}
		}
		desiredOrganization, _ := desired["organization"].(map[string]any)
		observedOrganization, _ := observed["organization"].(map[string]any)
		desiredTwoFactor, _ := desiredOrganization["two_factor_requirement"].(bool)
		observedTwoFactor, observedTwoFactorKnown := observedOrganization["two_factor_requirement_enabled"].(bool)
		if !observedTwoFactorKnown || desiredTwoFactor != observedTwoFactor {
			add("TWO_FACTOR_REQUIREMENT_MISMATCH", "observed two-factor requirement is missing or differs from desired state")
		}
	}
	qualifiedIntegrationActors := make(map[string]any)
	qualifiedStatusCheckActors := make(map[string]any)
	if phase == "foundation" || phase == "enforce" {
		// The organization-installations endpoint does not expose the exact
		// selected-repository scope and the strict catalog intentionally has no
		// bootstrap App disposition document yet. Do not trust an observed JSON
		// boolean as authority; mutation phases remain blocked until a future
		// canonical, TTL-bounded bootstrap attestation contract is implemented.
		add("INSTALLATION_INVENTORY_UNQUALIFIED", "GitHub App installation authority and complete selected-repository dispositions are not bootstrap-qualified")
		activation := desired["activation"]
		if activation == nil {
			activation = desired
		}
		collectActivationBlockers(activation, "/activation", add)
		integrations, _ := desired["integrations"].(map[string]any)
		observedIntegrations, _ := observed["integrations"].(map[string]any)
		for id, desiredValue := range integrations {
			entry, exists := observedIntegrations[id]
			entryMap, _ := entry.(map[string]any)
			desiredIntegration, _ := desiredValue.(map[string]any)
			if !exists || !integrationQualified(id, desiredIntegration, entryMap, observed) {
				add("INTEGRATION_UNQUALIFIED", fmt.Sprintf("integration %q is not ready or does not match its live GitHub App installation", id))
			} else {
				qualifiedIntegrationActors[id] = integerValue(desiredIntegration["actor_id"])
			}
		}
		qualifiedStatusCheckActors = qualifiedStatusCheckIDs(desired, observed, add)
	}
	sort.Slice(blockers, func(i, j int) bool {
		left := blockers[i]["code"].(string) + "\x00" + blockers[i]["message"].(string)
		right := blockers[j]["code"].(string) + "\x00" + blockers[j]["message"].(string)
		return left < right
	})
	eligible := len(blockers) == 0
	status := "blocked"
	if eligible {
		status = "ready"
	}
	result := map[string]any{
		"api_version": APIVersion,
		"kind":        "ActivationPreflight",
		"phase":       phase,
		"status":      status,
		"eligible":    eligible,
		"blockers":    blockers,
	}
	for key, value := range adoptionMaps {
		result[key] = value
	}
	result["observed_oidc_identity"] = oidcIdentity
	if phase == "enforce" {
		result["qualified_integration_actor_ids"] = qualifiedIntegrationActors
		result["qualified_status_check_integration_ids"] = qualifiedStatusCheckActors
	}
	return result
}

func observedOIDCIdentity(desired, observed map[string]any, coreComplete bool) (map[string]any, []string, bool) {
	empty := map[string]any{}
	if !coreComplete || observed == nil {
		return empty, nil, false
	}
	issues := make([]string, 0)
	observedOrganization, _ := observed["organization"].(map[string]any)
	organizationID := integerValue(observedOrganization["id"])
	if organizationID <= 0 {
		issues = append(issues, "observed organization has no positive immutable numeric id")
	}
	desiredRepositories, _ := desired["repositories"].(map[string]any)
	observedRepositories, _ := observed["repositories"].(map[string]any)
	repositoryIDs := make(map[string]any, len(desiredRepositories))
	seenIDs := make(map[int64]string, len(desiredRepositories))
	missing := false
	for key, rawSpec := range desiredRepositories {
		spec, _ := rawSpec.(map[string]any)
		name := stringValue(spec["name"])
		rawRepository, exists := observedRepositories[name]
		if !exists {
			missing = true
			continue
		}
		repository, _ := rawRepository.(map[string]any)
		if stringValue(repository["name"]) != name {
			issues = append(issues, fmt.Sprintf("observed repository %q does not preserve its exact catalog name", key))
			continue
		}
		repositoryID := integerValue(repository["id"])
		if repositoryID <= 0 {
			issues = append(issues, fmt.Sprintf("observed repository %q has no positive immutable numeric id", key))
			continue
		}
		if prior, duplicate := seenIDs[repositoryID]; duplicate {
			issues = append(issues, fmt.Sprintf("observed repositories %q and %q share immutable numeric id %d", prior, key, repositoryID))
			continue
		}
		seenIDs[repositoryID] = key
		repositoryIDs[key] = repositoryID
	}
	sort.Strings(issues)
	complete := organizationID > 0 && !missing && len(issues) == 0 && len(repositoryIDs) == len(desiredRepositories)
	if !complete {
		return empty, issues, false
	}
	return map[string]any{
		"organization_id": organizationID,
		"repository_ids":  repositoryIDs,
	}, nil, true
}

func observationErrors(observed map[string]any) []any {
	if observed == nil {
		return nil
	}
	result := append([]any{}, anyList(observed["errors"])...)
	if len(result) == 0 {
		result = append(result, anyList(observed["capability_errors"])...)
	}
	return result
}

func observedMemberLogins(observed map[string]any) set {
	result := make(set)
	for _, entry := range anyList(observed["members"]) {
		member, _ := entry.(map[string]any)
		if login := stringValue(member["login"]); login != "" {
			result.add(login)
		}
	}
	if managed, _ := observed["managed_projection"].(map[string]any); len(result) == 0 {
		for _, entry := range anyList(managed["members"]) {
			member, _ := entry.(map[string]any)
			if login := stringValue(member["login"]); login != "" {
				result.add(login)
			}
		}
	}
	return result
}

func observedAdminLogins(observed map[string]any) set {
	result := make(set)
	for _, entry := range anyList(observed["organization_admins"]) {
		member, _ := entry.(map[string]any)
		if login := stringValue(member["login"]); login != "" {
			result.add(login)
		}
	}
	for _, source := range []any{observed["members"], specObject(observed, "managed_projection")["members"]} {
		for _, entry := range anyList(source) {
			member, _ := entry.(map[string]any)
			if stringValue(member["role"]) == "admin" {
				result.add(stringValue(member["login"]))
			}
		}
	}
	return result
}

func validateDesiredAccess(desired map[string]any, add func(string, string)) {
	members := make(set)
	for _, entry := range anyList(desired["members"]) {
		member, _ := entry.(map[string]any)
		members.add(stringValue(member["login"]))
	}
	teams, _ := desired["teams"].(map[string]any)
	for id, rawSpec := range teams {
		spec, _ := rawSpec.(map[string]any)
		for _, member := range objectList(spec["members"]) {
			if !members.has(stringValue(member["login"])) {
				add("DESIRED_ACCESS_INVALID", fmt.Sprintf("team %q contains an undeclared organization member", id))
			}
		}
	}
	repositoryAccess := make(map[string]map[string]int)
	repositories, _ := desired["repositories"].(map[string]any)
	for id, rawSpec := range repositories {
		spec, _ := rawSpec.(map[string]any)
		grants := make(map[string]int)
		for _, grant := range objectList(spec["team_grants"]) {
			team := strings.ToLower(stringValue(grant["team"]))
			rank, supported := permissionRank(stringValue(grant["permission"]))
			if !supported || rank > 4 {
				add("DESIRED_ACCESS_INVALID", fmt.Sprintf("repository %q contains an unsupported or administrative team grant", id))
				continue
			}
			if _, duplicate := grants[team]; duplicate {
				add("DESIRED_ACCESS_INVALID", fmt.Sprintf("repository %q contains duplicate grants for team %q", id, team))
			}
			grants[team] = rank
		}
		owner := strings.ToLower(stringValue(specObject(spec, "custom_properties")["owner_team"]))
		if owner == "" || grants[owner] < 4 {
			add("DESIRED_ACCESS_INVALID", fmt.Sprintf("repository %q owner team lacks maintain access", id))
		}
		name := strings.ToLower(stringValue(spec["name"]))
		repositoryAccess[strings.ToLower(id)] = grants
		repositoryAccess[name] = grants
	}
	environments, _ := desired["environments"].(map[string]any)
	for id, rawSpec := range environments {
		spec, _ := rawSpec.(map[string]any)
		for _, reviewer := range objectList(spec["required_reviewers"]) {
			team := strings.ToLower(stringValue(reviewer["team"]))
			for _, repository := range stringList(spec["repositories"]) {
				if repositoryAccess[strings.ToLower(repository)][team] < 1 {
					add("DESIRED_ACCESS_INVALID", fmt.Sprintf("environment %q reviewer team %q lacks pull access to repository %q", id, team, repository))
				}
			}
		}
	}
}

func adoptionBindings(
	desired, observed map[string]any,
	coreComplete bool,
) (map[string]any, []string) {
	maps := make(map[string]any)
	for _, key := range []string{
		"adopted_team_ids", "adopted_repository_names", "adopted_ruleset_ids",
		"adopted_environment_ids", "adopted_environment_policy_ids",
		"adopted_organization_oidc_templates", "adopted_organization_custom_properties",
		"adopted_repository_oidc_templates", "adopted_repository_custom_properties",
		"adopted_memberships", "adopted_team_memberships",
		"adopted_team_repository_grants", "adopted_security_manager_assignments",
		"adopted_dependabot_security_updates", "adopted_outside_collaborator_grants",
	} {
		maps[key] = make(map[string]any)
	}
	teamIDs := maps["adopted_team_ids"].(map[string]any)
	repositoryNames := maps["adopted_repository_names"].(map[string]any)
	rulesetIDs := maps["adopted_ruleset_ids"].(map[string]any)
	environmentIDs := maps["adopted_environment_ids"].(map[string]any)
	environmentPolicyIDs := maps["adopted_environment_policy_ids"].(map[string]any)
	issues := make([]string, 0)
	if !coreComplete || observed == nil {
		return maps, issues
	}
	desiredTeams, _ := desired["teams"].(map[string]any)
	observedTeams, _ := observed["teams"].(map[string]any)
	for id, rawSpec := range desiredTeams {
		spec, _ := rawSpec.(map[string]any)
		name := stringValue(spec["name"])
		rawTeam, exists := observedTeams[name]
		if !exists {
			rawTeam, exists = observedTeams[id]
		}
		if !exists {
			continue
		}
		team, _ := rawTeam.(map[string]any)
		teamID := integerValue(team["id"])
		if teamID <= 0 {
			issues = append(issues, fmt.Sprintf("observed team %q has no positive numeric id", id))
			continue
		}
		teamIDs[id] = teamID
	}
	desiredRepositories, _ := desired["repositories"].(map[string]any)
	observedRepositories, _ := observed["repositories"].(map[string]any)
	for id, rawSpec := range desiredRepositories {
		spec, _ := rawSpec.(map[string]any)
		name := stringValue(spec["name"])
		rawRepository, exists := observedRepositories[name]
		if !exists {
			continue
		}
		repository, _ := rawRepository.(map[string]any)
		if stringValue(repository["name"]) != name {
			issues = append(issues, fmt.Sprintf("observed repository binding for %q does not preserve its exact catalog name", id))
			continue
		}
		repositoryNames[id] = name
	}
	if !hasObservationErrorPrefix(observed, "organization_ruleset") {
		desiredRulesets, _ := desired["rulesets"].(map[string]any)
		observedRulesets, _ := observed["rulesets"].(map[string]any)
		for id, rawSpec := range desiredRulesets {
			spec, _ := rawSpec.(map[string]any)
			name := id
			if configured := stringValue(spec["name"]); configured != "" {
				name = configured
			}
			bindObservedRulesetID(id, name, observedRulesets, rulesetIDs, &issues)
			rules, _ := spec["rules"].(map[string]any)
			if stringValue(spec["target"]) == "tag" && boolValue(rules["creation_restricted"]) {
				bindObservedRulesetID(id+"--creator-gate", name+"-creator-gate", observedRulesets, rulesetIDs, &issues)
			}
		}
	}
	if !hasObservationErrorPrefix(observed, "repository_environments:") {
		bindObservedEnvironments(desired, observed, environmentIDs, environmentPolicyIDs, &issues)
	}
	bindAdditionalAdoptions(desired, observed, maps, teamIDs, repositoryNames, &issues)
	sort.Strings(issues)
	return maps, issues
}

func bindAdditionalAdoptions(
	desired, observed map[string]any,
	maps map[string]any,
	teamIDs, repositoryNames map[string]any,
	issues *[]string,
) {
	organization, _ := desired["organization"].(map[string]any)
	organizationLogin := stringValue(organization["organization_login"])
	desiredOIDC, _ := desired["oidc_policy"].(map[string]any)
	observedOIDC, _ := observed["oidc_policy"].(map[string]any)
	organizationOIDC := maps["adopted_organization_oidc_templates"].(map[string]any)
	if !boolValue(desiredOIDC["use_default_subject"]) && sameSemanticValue(desiredOIDC["include_claim_keys"], observedOIDC["include_claim_keys"]) {
		if sameSemanticValue(desiredOIDC["use_immutable_subject"], observedOIDC["use_immutable_subject"]) {
			organizationOIDC["organization"] = organizationLogin
		} else {
			*issues = append(*issues, "observed organization OIDC template is not proven immutable")
		}
	}

	organizationProperties := maps["adopted_organization_custom_properties"].(map[string]any)
	observedOrganizationProperties := objectList(observed["organization_custom_properties"])
	for _, property := range objectList(organization["custom_properties"]) {
		name := stringValue(property["name"])
		for _, live := range observedOrganizationProperties {
			liveName := stringValue(live["property_name"])
			if liveName == "" {
				liveName = stringValue(live["name"])
			}
			if liveName == name && selectedFieldsEqual(property, live, map[string]string{
				"value_type": "value_type", "required": "required", "allowed_values": "allowed_values",
				"values_editable_by": "values_editable_by",
			}) {
				organizationProperties[name] = name
				break
			}
		}
	}

	admins := observedAdminLogins(observed)
	members := observedMemberLogins(observed)
	adoptedMemberships := maps["adopted_memberships"].(map[string]any)
	for _, member := range anyList(desired["members"]) {
		spec, _ := member.(map[string]any)
		login := stringValue(spec["login"])
		role := stringValue(spec["role"])
		if !members.has(login) || (role == "admin") != admins.has(login) {
			continue
		}
		adoptedMemberships[strings.ToLower(login)] = organizationLogin + ":" + login
	}

	desiredTeams, _ := desired["teams"].(map[string]any)
	observedTeamMembers, _ := observed["team_members"].(map[string]any)
	adoptedTeamMemberships := maps["adopted_team_memberships"].(map[string]any)
	for teamKey, rawTeam := range desiredTeams {
		team, _ := rawTeam.(map[string]any)
		teamName := stringValue(team["name"])
		teamID := integerValue(teamIDs[teamKey])
		if teamID <= 0 {
			continue
		}
		liveMembers := objectList(observedTeamMembers[teamName])
		for _, member := range objectList(team["members"]) {
			login := stringValue(member["login"])
			role := stringValue(member["role"])
			if containsObjectWithFields(liveMembers, map[string]any{"login": login, "role": role}) {
				key := teamKey + ":" + strings.ToLower(login)
				adoptedTeamMemberships[key] = fmt.Sprintf("%d:%s", teamID, login)
			}
		}
	}

	desiredRepositories, _ := desired["repositories"].(map[string]any)
	observedOIDCRepositories, _ := observed["repository_oidc_policies"].(map[string]any)
	observedRepositoryProperties, _ := observed["repository_custom_properties"].(map[string]any)
	observedRepositoryGrants, _ := observed["repository_team_grants"].(map[string]any)
	observedDependabot, _ := observed["repository_dependabot_security_updates"].(map[string]any)
	observedCollaborators, _ := observed["repository_direct_collaborators"].(map[string]any)
	adoptedRepositoryOIDC := maps["adopted_repository_oidc_templates"].(map[string]any)
	adoptedRepositoryProperties := maps["adopted_repository_custom_properties"].(map[string]any)
	adoptedTeamGrants := maps["adopted_team_repository_grants"].(map[string]any)
	adoptedDependabot := maps["adopted_dependabot_security_updates"].(map[string]any)
	adoptedOutsideGrants := maps["adopted_outside_collaborator_grants"].(map[string]any)
	for repositoryKey, rawRepository := range desiredRepositories {
		repository, _ := rawRepository.(map[string]any)
		repositoryName := stringValue(repository["name"])
		if stringValue(repositoryNames[repositoryKey]) != repositoryName {
			continue
		}
		if liveOIDC, ok := observedOIDCRepositories[repositoryName].(map[string]any); ok &&
			liveOIDC["use_default"] == false &&
			sameSemanticValue(desiredOIDC["include_claim_keys"], liveOIDC["include_claim_keys"]) {
			if sameSemanticValue(desiredOIDC["use_immutable_subject"], liveOIDC["use_immutable_subject"]) {
				adoptedRepositoryOIDC[repositoryKey] = repositoryName
			} else {
				*issues = append(*issues, fmt.Sprintf("observed repository %q OIDC template is not proven immutable", repositoryKey))
			}
		}
		for propertyName, desiredValue := range specObject(repository, "custom_properties") {
			if liveValue, found := observedRepositoryPropertyValue(observedRepositoryProperties[repositoryName], propertyName); found && sameSemanticValue(desiredValue, liveValue) {
				key := repositoryKey + ":" + propertyName
				adoptedRepositoryProperties[key] = organizationLogin + ":" + repositoryName + ":" + propertyName
			}
		}
		liveGrants := objectList(observedRepositoryGrants[repositoryName])
		for _, grant := range objectList(repository["team_grants"]) {
			teamKey := stringValue(grant["team"])
			teamID := integerValue(teamIDs[teamKey])
			if teamID <= 0 || !containsTeamGrant(liveGrants, desiredTeams, teamKey, stringValue(grant["permission"])) {
				continue
			}
			key := repositoryKey + ":" + teamKey
			adoptedTeamGrants[key] = fmt.Sprintf("%d:%s", teamID, repositoryName)
		}
		security := specObject(repository, "security")
		if desiredEnabled, exists := security["dependabot_security_updates"].(bool); exists {
			if liveEnabled, known := observedDependabot[repositoryName].(bool); known && liveEnabled == desiredEnabled {
				adoptedDependabot[repositoryKey] = repositoryName
			}
		}
		for _, collaborator := range anyList(desired["outside_collaborators"]) {
			spec, _ := collaborator.(map[string]any)
			login := stringValue(spec["login"])
			for _, grant := range objectList(spec["repository_permissions"]) {
				if repositoryNameForReference(stringValue(grant["repository"]), desiredRepositories) != repositoryName {
					continue
				}
				if containsCollaboratorGrant(objectList(observedCollaborators[repositoryName]), login, stringValue(grant["permission"])) {
					key := strings.ToLower(login) + ":" + repositoryKey
					adoptedOutsideGrants[key] = repositoryName + ":" + login
				}
			}
		}
	}

	bindSecurityManagerAdoption(desired, observed, maps, desiredTeams, issues)
}

func bindSecurityManagerAdoption(
	desired, observed, maps map[string]any,
	desiredTeams map[string]any,
	issues *[]string,
) {
	securityPolicy, _ := desired["security_policy"].(map[string]any)
	teamKey := stringValue(securityPolicy["security_manager_team"])
	teamSpec, _ := desiredTeams[teamKey].(map[string]any)
	teamSlug := stringValue(teamSpec["name"])
	managerTeams := objectList(observed["security_manager_teams"])
	if len(managerTeams) != 1 {
		return
	}
	managerTeam := managerTeams[0]
	if !strings.EqualFold(stringValue(managerTeam["slug"]), teamSlug) &&
		!strings.EqualFold(stringValue(managerTeam["name"]), teamSlug) {
		return
	}
	roles := objectList(specObject(observed, "organization_roles")["roles"])
	roleIDs := make([]int64, 0, 1)
	for _, role := range roles {
		if stringValue(role["name"]) != "security_manager" {
			continue
		}
		roleID := integerValue(role["role_id"])
		if roleID <= 0 {
			roleID = integerValue(role["id"])
		}
		if roleID > 0 {
			roleIDs = append(roleIDs, roleID)
		}
	}
	if len(roleIDs) != 1 {
		*issues = append(*issues, "observed security_manager role does not have one authoritative positive id")
		return
	}
	maps["adopted_security_manager_assignments"].(map[string]any)["security_manager"] = fmt.Sprintf("%d:%s", roleIDs[0], teamSlug)
}

func containsTeamGrant(values []map[string]any, teams map[string]any, teamKey, permission string) bool {
	team, _ := teams[teamKey].(map[string]any)
	teamName := stringValue(team["name"])
	for _, grant := range values {
		liveName := stringValue(grant["slug"])
		if liveName == "" {
			liveName = stringValue(grant["name"])
		}
		livePermission := stringValue(grant["permission"])
		if livePermission == "" {
			livePermission = stringValue(grant["role_name"])
		}
		if strings.EqualFold(liveName, teamName) && livePermission == permission {
			return true
		}
	}
	return false
}

func containsCollaboratorGrant(values []map[string]any, login, permission string) bool {
	for _, collaborator := range values {
		livePermission := stringValue(collaborator["role_name"])
		if livePermission == "" {
			livePermission = stringValue(collaborator["permission"])
		}
		if strings.EqualFold(stringValue(collaborator["login"]), login) && livePermission == permission {
			return true
		}
	}
	return false
}

func observedRepositoryPropertyValue(value any, name string) (any, bool) {
	for _, property := range objectList(value) {
		if stringValue(property["property_name"]) == name {
			liveValue, exists := property["value"]
			return liveValue, exists
		}
	}
	return nil, false
}

func containsObjectWithFields(values []map[string]any, expected map[string]any) bool {
	for _, value := range values {
		matches := true
		for key, expectation := range expected {
			if key == "login" {
				matches = strings.EqualFold(stringValue(value[key]), stringValue(expectation))
			} else {
				matches = sameSemanticValue(value[key], expectation)
			}
			if !matches {
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func selectedFieldsEqual(desired, observed map[string]any, fields map[string]string) bool {
	for desiredKey, observedKey := range fields {
		if !sameSemanticValue(desired[desiredKey], observed[observedKey]) {
			return false
		}
	}
	return true
}

func sameSemanticValue(left, right any) bool {
	leftJSON, leftErr := rendering.CanonicalJSON(normalizeSemanticValue(left))
	rightJSON, rightErr := rendering.CanonicalJSON(normalizeSemanticValue(right))
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func normalizeSemanticValue(value any) any {
	switch current := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(current))
		for key, child := range current {
			result[key] = normalizeSemanticValue(child)
		}
		return result
	case []any:
		result := make([]any, len(current))
		for index, child := range current {
			result[index] = normalizeSemanticValue(child)
		}
		sort.Slice(result, func(i, j int) bool {
			left, _ := rendering.CanonicalJSON(result[i])
			right, _ := rendering.CanonicalJSON(result[j])
			return string(left) < string(right)
		})
		return result
	default:
		return current
	}
}

func bindObservedRulesetID(
	key, name string,
	observedRulesets map[string]any,
	destination map[string]any,
	issues *[]string,
) {
	rawRuleset, exists := observedRulesets[name]
	if !exists {
		return
	}
	ruleset, _ := rawRuleset.(map[string]any)
	rulesetID := integerValue(ruleset["id"])
	if rulesetID <= 0 {
		*issues = append(*issues, fmt.Sprintf("observed ruleset %q has no positive numeric id", name))
		return
	}
	destination[key] = rulesetID
}

func bindObservedEnvironments(
	desired, observed map[string]any,
	environmentIDs, policyIDs map[string]any,
	issues *[]string,
) {
	observedEnvironments, _ := observed["environments"].(map[string]any)
	desiredEnvironments, _ := desired["environments"].(map[string]any)
	desiredRepositories, _ := desired["repositories"].(map[string]any)
	for environmentKey, rawSpec := range desiredEnvironments {
		spec, _ := rawSpec.(map[string]any)
		environmentName := stringValue(spec["name"])
		branchPolicy := specObject(spec, "deployment_branch_policy")
		for _, repositoryReference := range stringList(spec["repositories"]) {
			repositoryName := repositoryNameForReference(repositoryReference, desiredRepositories)
			container, _ := observedEnvironments[repositoryName].(map[string]any)
			var matched map[string]any
			for _, environment := range objectList(container["environments"]) {
				if stringValue(environment["name"]) == environmentName {
					matched = environment
					break
				}
			}
			if matched == nil {
				continue
			}
			if integerValue(matched["id"]) <= 0 {
				*issues = append(*issues, fmt.Sprintf("observed environment %q on repository %q has no positive numeric id", environmentName, repositoryName))
				continue
			}
			assignmentKey := environmentKey + ":" + repositoryReference
			environmentIDs[assignmentKey] = repositoryName + ":" + strings.ReplaceAll(environmentName, ":", "??")
			bindObservedEnvironmentPolicies(
				assignmentKey, repositoryName, environmentName, branchPolicy, matched, policyIDs, issues,
			)
		}
	}
}

func bindObservedEnvironmentPolicies(
	assignmentKey, repositoryName, environmentName string,
	desiredPolicy, observedEnvironment map[string]any,
	destination map[string]any,
	issues *[]string,
) {
	desiredPatterns := map[string][]string{
		"branch": stringList(desiredPolicy["branch_patterns"]),
		"tag":    stringList(desiredPolicy["tag_patterns"]),
	}
	if len(desiredPatterns["branch"])+len(desiredPatterns["tag"]) == 0 {
		return
	}
	policiesValue, exists := observedEnvironment["deployment_branch_policies"]
	if !exists || containsUnknown(policiesValue) {
		*issues = append(*issues, fmt.Sprintf("deployment policies for environment %q on repository %q were not observed", environmentName, repositoryName))
		return
	}
	policies := objectList(policiesValue)
	for policyType, patterns := range desiredPatterns {
		for _, pattern := range patterns {
			matches := make([]map[string]any, 0)
			for _, policy := range policies {
				if stringValue(policy["name"]) == pattern && stringValue(policy["type"]) == policyType {
					matches = append(matches, policy)
				}
			}
			if len(matches) == 0 {
				continue
			}
			if len(matches) != 1 || integerValue(matches[0]["id"]) <= 0 {
				*issues = append(*issues, fmt.Sprintf("deployment policy %q for environment %q is ambiguous or has no positive id", pattern, environmentName))
				continue
			}
			key := assignmentKey + ":" + policyType + ":" + pattern
			destination[key] = fmt.Sprintf("%s:%s:%d", repositoryName, environmentName, integerValue(matches[0]["id"]))
		}
	}
}

func repositoryNameForReference(reference string, repositories map[string]any) string {
	if rawSpec, exists := repositories[reference]; exists {
		spec, _ := rawSpec.(map[string]any)
		if name := stringValue(spec["name"]); name != "" {
			return name
		}
	}
	for _, rawSpec := range repositories {
		spec, _ := rawSpec.(map[string]any)
		if stringValue(spec["name"]) == reference {
			return reference
		}
	}
	return reference
}

func hasObservationErrorPrefix(observed map[string]any, prefix string) bool {
	for _, rawError := range observationErrors(observed) {
		errorEntry, _ := rawError.(map[string]any)
		if strings.HasPrefix(stringValue(errorEntry["section"]), prefix) {
			return true
		}
	}
	return false
}

func qualifiedStatusCheckIDs(
	desired, observed map[string]any,
	add func(string, string),
) map[string]any {
	result := make(map[string]any)
	securityPolicy, _ := desired["security_policy"].(map[string]any)
	activation, _ := securityPolicy["activation"].(map[string]any)
	if stringValue(activation["state"]) != "ready" || len(stringList(activation["blockers"])) != 0 {
		return result
	}
	managed, _ := observed["managed_projection"].(map[string]any)
	observedRulesets, _ := managed["rulesets"].(map[string]any)
	desiredRulesets, _ := desired["rulesets"].(map[string]any)
	for rulesetID, rawSpec := range desiredRulesets {
		spec, _ := rawSpec.(map[string]any)
		rules := specObject(spec, "rules")
		requiredChecks, _ := rules["required_status_checks"].(map[string]any)
		if requiredChecks == nil {
			continue
		}
		observedRuleset, _ := observedRulesets[rulesetID].(map[string]any)
		observedRules := specObject(observedRuleset, "rules")
		observedRequired, _ := observedRules["required_status_checks"].(map[string]any)
		observedChecks := objectList(observedRequired["checks"])
		for _, check := range objectList(requiredChecks["checks"]) {
			issuer := stringValue(check["issuer_type"])
			context := stringValue(check["context"])
			integrationID := integerValue(check["integration_id"])
			if issuer == "" || integrationID <= 0 {
				add("STATUS_CHECK_INTEGRATION_UNQUALIFIED", fmt.Sprintf("ruleset %q check %q lacks a positive reviewed integration id", rulesetID, context))
				continue
			}
			if prior, exists := result[issuer]; exists && integerValue(prior) != integrationID {
				add("STATUS_CHECK_INTEGRATION_UNQUALIFIED", fmt.Sprintf("status-check issuer %q maps to inconsistent integration ids", issuer))
				continue
			}
			matched := false
			for _, observedCheck := range observedChecks {
				if stringValue(observedCheck["context"]) == context && integerValue(observedCheck["integration_id"]) == integrationID {
					matched = true
					break
				}
			}
			if !matched {
				add("STATUS_CHECK_INTEGRATION_UNQUALIFIED", fmt.Sprintf("ruleset %q check %q does not match complete live ruleset evidence", rulesetID, context))
				continue
			}
			result[issuer] = integrationID
		}
	}
	return result
}

type set map[string]struct{}

func (values set) add(value string) { values[strings.ToLower(value)] = struct{}{} }
func (values set) has(value string) bool {
	_, ok := values[strings.ToLower(value)]
	return ok
}

func requireReference(path, field, value string, available set) error {
	if value == "" || !available.has(value) {
		return fmt.Errorf("%s: %s %q is not declared", path, field, value)
	}
	return nil
}

func requireReferences(path, field string, values []string, available set) error {
	for _, value := range values {
		if err := requireReference(path, field, value, available); err != nil {
			return err
		}
	}
	return nil
}

func membershipEntries(spec any) []map[string]any {
	if object, ok := spec.(map[string]any); ok {
		if members, exists := object["organization_members"]; exists {
			return objectList(members)
		}
		if members, exists := object["members"]; exists {
			return objectList(members)
		}
		if collaborators, exists := object["collaborators"]; exists {
			return objectList(collaborators)
		}
	}
	return objectList(spec)
}

func objectList(value any) []map[string]any {
	items := anyList(value)
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if object, ok := item.(map[string]any); ok {
			result = append(result, object)
		}
	}
	return result
}

func anyList(value any) []any {
	if values, ok := value.([]any); ok {
		return values
	}
	return nil
}

func stringList(value any) []string {
	items := anyList(value)
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func boolValue(value any) bool {
	boolean, _ := value.(bool)
	return boolean
}

func specObject(spec map[string]any, key string) map[string]any {
	object, _ := spec[key].(map[string]any)
	return object
}

func permissionRank(permission string) (int, bool) {
	ranks := map[string]int{"pull": 1, "triage": 2, "push": 3, "maintain": 4}
	rank, ok := ranks[permission]
	return rank, ok
}

func integerValue(value any) int64 {
	switch number := value.(type) {
	case int64:
		return number
	case int:
		return int64(number)
	case float64:
		return int64(number)
	case json.Number:
		integer, _ := number.Int64()
		return integer
	}
	return 0
}

func integrationQualified(id string, desired, observed, observedState map[string]any) bool {
	activation, _ := desired["activation"].(map[string]any)
	state, _ := activation["state"].(string)
	if state != "ready" || len(stringList(activation["blockers"])) != 0 {
		return false
	}
	attestation, err := validatedIntegrationAttestation(desired, stringList(desired["repositories"]), time.Now().UTC())
	if err != nil {
		return false
	}
	desiredInstallationID := integerValue(attestation["installation_id"])
	observedInstallationID := integerValue(observed["installation_id"])
	if desiredInstallationID <= 0 || desiredInstallationID != observedInstallationID {
		return false
	}
	desiredActor := integerValue(attestation["app_id"])
	observedActor := integerValue(observed["actor_id"])
	installed, _ := observed["installed"].(bool)
	appSlug, _ := observed["app_slug"].(string)
	suspended := observed["suspended_at"] != nil
	if desiredActor <= 0 || desiredActor != integerValue(desired["actor_id"]) || desiredActor != observedActor || !installed || !strings.EqualFold(appSlug, id) || suspended {
		return false
	}
	desiredSelection := stringValue(attestation["repository_selection"])
	observedSelection := stringValue(observed["repository_selection"])
	if desiredSelection == "" || desiredSelection != stringValue(desired["repository_selection"]) || desiredSelection != observedSelection {
		return false
	}
	repositoryInventoryComplete, _ := observedState["repository_inventory_complete"].(bool)
	observedRepositories, repositoriesKnown := observedState["repositories"].(map[string]any)
	if !repositoryInventoryComplete || !repositoriesKnown {
		return false
	}
	attestedRepositories := objectList(attestation["repositories"])
	for _, repository := range attestedRepositories {
		name := stringValue(repository["name"])
		liveRepository, exists := observedRepositories[name].(map[string]any)
		if !exists || stringValue(liveRepository["name"]) != name ||
			integerValue(repository["id"]) <= 0 || integerValue(repository["id"]) != integerValue(liveRepository["id"]) {
			return false
		}
	}
	desiredPermissions := make(map[string]string)
	for _, permission := range objectList(attestation["permissions"]) {
		desiredPermissions[stringValue(permission["name"])] = stringValue(permission["access"])
	}
	observedPermissions, _ := observed["permissions"].(map[string]any)
	if len(desiredPermissions) != len(observedPermissions) {
		return false
	}
	for name, access := range desiredPermissions {
		if stringValue(observedPermissions[name]) != access {
			return false
		}
	}
	desiredEvents := stringList(attestation["events"])
	observedEvents := stringList(observed["events"])
	sort.Strings(desiredEvents)
	sort.Strings(observedEvents)
	if len(desiredEvents) != len(observedEvents) {
		return false
	}
	for index := range desiredEvents {
		if desiredEvents[index] != observedEvents[index] {
			return false
		}
	}
	return true
}

var integrationSourceSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

const maximumIntegrationAttestationTTL = 7 * 24 * time.Hour

func validatedIntegrationAttestation(desired map[string]any, expectedRepositories []string, now time.Time) (map[string]any, error) {
	qualification := specObject(desired, "qualification")
	if stringValue(qualification["state"]) != "qualified" || stringValue(qualification["authority"]) != "bootstrap" {
		return nil, errors.New("qualified integration requires bootstrap authority")
	}
	attestation := specObject(qualification, "attestation")
	if len(attestation) == 0 || stringValue(attestation["authority"]) != "bootstrap" {
		return nil, errors.New("qualified integration requires a structured bootstrap attestation")
	}
	if !integrationSourceSHAPattern.MatchString(stringValue(attestation["source_sha"])) {
		return nil, errors.New("integration attestation source_sha must be 40 lowercase hexadecimal characters")
	}
	if integerValue(attestation["app_id"]) <= 0 || integerValue(attestation["app_id"]) != integerValue(desired["actor_id"]) {
		return nil, errors.New("integration attestation app_id must equal the catalog actor_id")
	}
	if integerValue(attestation["installation_id"]) <= 0 {
		return nil, errors.New("integration attestation installation_id must be positive")
	}
	if stringValue(attestation["repository_selection"]) != stringValue(desired["repository_selection"]) {
		return nil, errors.New("integration attestation repository_selection does not match the catalog")
	}
	attestedRepositories := objectList(attestation["repositories"])
	if len(attestedRepositories) != len(expectedRepositories) {
		return nil, errors.New("integration attestation repository scope does not match the catalog")
	}
	attestedNames := make([]string, 0, len(attestedRepositories))
	seenNames := make(map[string]struct{}, len(attestedRepositories))
	seenIDs := make(map[int64]struct{}, len(attestedRepositories))
	for _, repository := range attestedRepositories {
		name := stringValue(repository["name"])
		identifier := integerValue(repository["id"])
		if name == "" || identifier <= 0 {
			return nil, errors.New("integration attestation repositories require nonempty names and positive immutable ids")
		}
		if _, duplicate := seenNames[name]; duplicate {
			return nil, fmt.Errorf("integration attestation contains duplicate repository name %q", name)
		}
		if _, duplicate := seenIDs[identifier]; duplicate {
			return nil, fmt.Errorf("integration attestation contains duplicate repository id %d", identifier)
		}
		seenNames[name] = struct{}{}
		seenIDs[identifier] = struct{}{}
		attestedNames = append(attestedNames, name)
	}
	sort.Strings(attestedNames)
	expectedRepositories = append([]string(nil), expectedRepositories...)
	sort.Strings(expectedRepositories)
	if !equalStringLists(attestedNames, expectedRepositories) {
		return nil, errors.New("integration attestation repository names do not exactly match the catalog")
	}
	desiredPermissions, ok := uniquePermissionMap(desired["permissions"])
	if !ok {
		return nil, errors.New("catalog integration permissions are not unique and complete")
	}
	attestedPermissions, ok := uniquePermissionMap(attestation["permissions"])
	if !ok || !equalStringMaps(desiredPermissions, attestedPermissions) {
		return nil, errors.New("integration attestation permissions do not exactly match the catalog")
	}
	desiredEvents, ok := uniqueSortedStrings(desired["events"])
	if !ok {
		return nil, errors.New("catalog integration events are not unique and complete")
	}
	attestedEvents, ok := uniqueSortedStrings(attestation["events"])
	if !ok || !equalStringLists(desiredEvents, attestedEvents) {
		return nil, errors.New("integration attestation events do not exactly match the catalog")
	}
	createdText := stringValue(attestation["created_at"])
	expiresText := stringValue(attestation["expires_at"])
	createdAt, createdErr := time.Parse(time.RFC3339, createdText)
	expiresAt, expiresErr := time.Parse(time.RFC3339, expiresText)
	if createdErr != nil || expiresErr != nil || !strings.HasSuffix(createdText, "Z") || !strings.HasSuffix(expiresText, "Z") {
		return nil, errors.New("integration attestation timestamps must be RFC3339 UTC values ending in Z")
	}
	if !expiresAt.After(createdAt) || expiresAt.Sub(createdAt) > maximumIntegrationAttestationTTL {
		return nil, errors.New("integration attestation validity window must be ordered and no longer than seven days")
	}
	if !expiresAt.After(now) {
		return nil, errors.New("integration attestation is expired")
	}
	canonical, err := canonicalIntegrationAttestation(attestation)
	if err != nil {
		return nil, fmt.Errorf("canonicalize integration attestation: %w", err)
	}
	evidenceDigest := stringValue(qualification["evidence_digest"])
	if !validSHA256Digest(evidenceDigest) || evidenceDigest != rendering.Digest(canonical) {
		return nil, errors.New("integration attestation evidence_digest does not match its canonical content")
	}
	return attestation, nil
}

func canonicalIntegrationAttestation(attestation map[string]any) ([]byte, error) {
	normalized := make(map[string]any, len(attestation))
	for key, value := range attestation {
		normalized[key] = value
	}
	repositories := append([]map[string]any(nil), objectList(attestation["repositories"])...)
	sort.Slice(repositories, func(left, right int) bool {
		return stringValue(repositories[left]["name"]) < stringValue(repositories[right]["name"])
	})
	normalized["repositories"] = mapsToAny(repositories)
	permissions := append([]map[string]any(nil), objectList(attestation["permissions"])...)
	sort.Slice(permissions, func(left, right int) bool {
		return stringValue(permissions[left]["name"]) < stringValue(permissions[right]["name"])
	})
	normalized["permissions"] = mapsToAny(permissions)
	events := stringList(attestation["events"])
	sort.Strings(events)
	normalized["events"] = stringsToAny(events)
	return rendering.CanonicalJSON(normalized)
}

func uniquePermissionMap(value any) (map[string]string, bool) {
	permissions := objectList(value)
	result := make(map[string]string, len(permissions))
	for _, permission := range permissions {
		name := stringValue(permission["name"])
		access := stringValue(permission["access"])
		if name == "" || access == "" {
			return nil, false
		}
		if _, duplicate := result[name]; duplicate {
			return nil, false
		}
		result[name] = access
	}
	return result, len(result) > 0
}

func uniqueSortedStrings(value any) ([]string, bool) {
	values := stringList(value)
	if len(values) == 0 {
		return nil, false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return nil, false
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, false
		}
		seen[value] = struct{}{}
	}
	sort.Strings(values)
	return values, true
}

func equalStringLists(left, right []string) bool {
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

func mapsToAny(values []map[string]any) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
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

func validSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range strings.TrimPrefix(value, "sha256:") {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func collectActivationBlockers(value any, path string, add func(string, string)) {
	switch current := value.(type) {
	case map[string]any:
		if _, hasState := current["state"]; hasState {
			if _, hasBlockers := current["blockers"]; hasBlockers {
				reportActivationBlockers(current, path, add)
				return
			}
		}
		if activation, ok := current["activation"].(map[string]any); ok {
			reportActivationBlockers(activation, path, add)
		}
		keys := make([]string, 0, len(current))
		for key := range current {
			if key != "activation" {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			collectActivationBlockers(current[key], path+"/"+key, add)
		}
	case []any:
		for index, item := range current {
			collectActivationBlockers(item, fmt.Sprintf("%s/%d", path, index), add)
		}
	}
}

func reportActivationBlockers(activation map[string]any, path string, add func(string, string)) {
	state, _ := activation["state"].(string)
	blockers := stringList(activation["blockers"])
	if state != "ready" && len(blockers) == 0 {
		add("DESIRED_ACTIVATION_BLOCKED", fmt.Sprintf("%s: activation state is %q", pointerOrRoot(path), state))
	}
	for _, blocker := range blockers {
		add("DESIRED_ACTIVATION_BLOCKED", fmt.Sprintf("%s: %s", pointerOrRoot(path), blocker))
	}
}

func containsUnknown(value any) bool {
	switch current := value.(type) {
	case map[string]any:
		status, _ := current["status"].(string)
		unknown, _ := current["unknown"].(bool)
		if status == "unknown" || unknown {
			return true
		}
		for _, child := range current {
			if containsUnknown(child) {
				return true
			}
		}
	case []any:
		for _, child := range current {
			if containsUnknown(child) {
				return true
			}
		}
	}
	return false
}

func pointerOrRoot(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func valuesForKey(value any, target string) []string {
	var result []string
	var visit func(any)
	visit = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if key == target {
					if text, ok := typed[key].(string); ok {
						result = append(result, text)
					}
					result = append(result, stringList(typed[key])...)
				}
				visit(typed[key])
			}
		case []any:
			for _, item := range typed {
				visit(item)
			}
		}
	}
	visit(value)
	return result
}
