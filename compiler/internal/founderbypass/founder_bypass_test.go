package founderbypass

import (
	"reflect"
	"testing"

	"github.com/mindclade/github-config/compiler/internal/catalog"
)

func TestPolicyIsDeterministicAndHeadBound(t *testing.T) {
	compiled := &catalog.Catalog{
		SourceDigest: "sha256:catalog",
		Organization: map[string]any{"founder_pull_request_bypass": map[string]any{
			"contract":              "founder-pr-bypass.v1",
			"github_actor_accounts": []any{"mindclade-founder", "robpearc"},
		}},
		Members: []any{
			map[string]any{"login": "robpearc", "principal_id": "founder-primary"},
			map[string]any{"login": "mindclade-founder", "principal_id": "founder-primary"},
		},
		Repositories: map[string]any{
			"second": map[string]any{"name": "zeta"},
			"first":  map[string]any{"name": "alpha"},
		},
	}
	first, err := Policy(compiled)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Policy(compiled)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("founder bypass policy is not deterministic")
	}
	entitlement, _ := first["entitlement"].(map[string]any)
	if entitlement["durable"] != true || entitlement["bypass_mode"] != "pull_request" ||
		entitlement["self_authored_pull_requests"] != true || !reflect.DeepEqual(entitlement["paths"], []any{"**"}) {
		t.Fatalf("unexpected entitlement: %#v", entitlement)
	}
	if !reflect.DeepEqual(entitlement["repositories"], []any{"alpha", "zeta"}) {
		t.Fatalf("repositories are not canonical: %#v", entitlement["repositories"])
	}
	evidence, _ := first["evidence"].(map[string]any)
	if evidence["label"] != "founder-bypass" ||
		evidence["comment_marker"] != "<!-- founder-pr-bypass:v1 -->" ||
		evidence["head_sha_field"] != "head-sha" || evidence["reason_field"] != "reason" ||
		evidence["reason_max_length"] != 500 || evidence["exact_comment_shape_required"] != true ||
		evidence["comment_author_must_map_to_principal"] != "founder-primary" ||
		evidence["new_commit_invalidates_evidence"] != true {
		t.Fatalf("unexpected evidence contract: %#v", evidence)
	}
}

func TestPolicyRejectsUnmappedActor(t *testing.T) {
	compiled := &catalog.Catalog{
		Organization: map[string]any{"founder_pull_request_bypass": map[string]any{
			"contract": "founder-pr-bypass.v1", "github_actor_accounts": []any{"unauthorized"},
		}},
		Members: []any{map[string]any{"login": "unauthorized", "principal_id": "different"}},
	}
	if _, err := Policy(compiled); err == nil {
		t.Fatal("expected unmapped actor to be rejected")
	}
}
