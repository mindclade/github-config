package diff

import (
	"strings"
	"testing"
)

func TestFounderBypassCommentIsExactAndHeadBound(t *testing.T) {
	head := strings.Repeat("a", 40)
	valid := "<!-- founder-pr-bypass:v1 -->\nhead-sha: " + head + "\nreason: Restore governance"
	if !validFounderBypassComment(valid, head) {
		t.Fatal("expected exact current-head comment to be valid")
	}
	for name, value := range map[string]string{
		"stale head":   strings.Replace(valid, head, strings.Repeat("b", 40), 1),
		"empty reason": strings.Replace(valid, "Restore governance", "", 1),
		"extra field":  valid + "\nunbounded: field",
		"embedded sha": "<!-- founder-pr-bypass:v1 -->\nreason: " + head,
	} {
		t.Run(name, func(t *testing.T) {
			if validFounderBypassComment(value, head) {
				t.Fatalf("malformed comment was accepted: %q", value)
			}
		})
	}
}

func TestRepositoryMergeQueueMustMatchTheNoBypassPhysicalContract(t *testing.T) {
	desired := map[string]any{
		"include_refs": []any{"~DEFAULT_BRANCH"},
		"exclude_refs": []any{},
	}
	queue := map[string]any{
		"target": "branch", "enforcement": "active", "bypass_actors": []any{},
		"conditions": map[string]any{"ref_name": map[string]any{
			"include": []any{"~DEFAULT_BRANCH"}, "exclude": []any{},
		}},
		"rules": []any{map[string]any{
			"type": "merge_queue",
			"parameters": map[string]any{
				"check_response_timeout_minutes": 30, "grouping_strategy": "ALLGREEN",
				"max_entries_to_build": 2, "max_entries_to_merge": 1, "merge_method": "SQUASH",
				"min_entries_to_merge": 1, "min_entries_to_merge_wait_minutes": 0,
			},
		}},
	}
	if !repositoryMergeQueueMatches(queue, desired, "active") {
		t.Fatal("expected exact no-bypass merge queue to match")
	}
	queue["bypass_actors"] = []any{map[string]any{"actor_type": "Team", "actor_id": 1}}
	if repositoryMergeQueueMatches(queue, desired, "active") {
		t.Fatal("merge queue with a bypass actor must not match")
	}
	queue["bypass_actors"] = []any{}
	queue["rules"].([]any)[0].(map[string]any)["parameters"].(map[string]any)["max_entries_to_merge"] = 2
	if repositoryMergeQueueMatches(queue, desired, "active") {
		t.Fatal("merge queue with weakened parameters must not match")
	}
}

func TestMetadataInventoryRejectsMissingOrDuplicateIdentifiers(t *testing.T) {
	for name, values := range map[string][]any{
		"missing":        {map[string]any{}},
		"duplicate":      {map[string]any{"name": "TOKEN"}, map[string]any{"name": "TOKEN"}},
		"duplicate case": {map[string]any{"name": "TOKEN"}, map[string]any{"name": "token"}},
	} {
		t.Run(name, func(t *testing.T) {
			inventory := metadataInventory("test", values, int64(len(values)))
			if inventory["status"] != "unknown" {
				t.Fatalf("malformed metadata inventory was accepted: %#v", inventory)
			}
		})
	}
}
