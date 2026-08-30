package github_config.workflow_sources_test

import rego.v1
import data.github_config.workflow_sources

download_artifact_sha := "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"

test_download_artifact_commit_allowed if {
    denials := workflow_sources.deny with input as {
        "actions_policy": {"spec": {
            "github_owned_allowed": false,
            "verified_creator_allowed": false,
            "allowed_actions": [{"source": "actions/download-artifact", "commit": download_artifact_sha}],
        }},
        "workflows": [{
            "name": "Protected apply",
            "events": ["workflow_dispatch"],
            "uses": [sprintf("actions/download-artifact@%s", [download_artifact_sha])],
        }],
    }
    count(denials) == 0
}

test_mutable_action_tag_denied if {
    denials := workflow_sources.deny with input as {
        "actions_policy": {"spec": {
            "github_owned_allowed": false,
            "verified_creator_allowed": false,
            "allowed_actions": [{"source": "actions/checkout", "commit": "3d3c42e5aac5ba805825da76410c181273ba90b1"}],
        }},
        "workflows": [{"name": "Pull request", "events": ["pull_request"], "uses": ["actions/checkout@v7"]}],
    }
    some message in denials
    contains(message, "unapproved source")
}

test_unpinned_reusable_workflow_denied if {
    denials := workflow_sources.deny with input as {
        "actions_policy": {"spec": {"github_owned_allowed": false, "verified_creator_allowed": false, "allowed_actions": []}},
        "workflows": [{
            "name": "Required",
            "events": ["pull_request"],
            "uses": ["mindclade/.github/.github/workflows/reusable-required-check.yml@main"],
        }],
    }
    some message in denials
    contains(message, "unapproved source")
}

test_pull_request_target_denied if {
    denials := workflow_sources.deny with input as {
        "actions_policy": {"spec": {"github_owned_allowed": false, "verified_creator_allowed": false, "allowed_actions": []}},
        "workflows": [{"name": "Unsafe", "events": ["pull_request_target"], "uses": ["./.github/actions/local"]}],
    }
    some message in denials
    contains(message, "pull_request_target")
}
