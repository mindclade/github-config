# Mindclade Full Repository Estate Tree

**Status:** authoritative target architecture

**Source:** Mindclade Monorepo Blueprint v3.4.0, Appendix A3 and Appendix A6
**Evidence boundary:** this is the approved target namespace and activation-stub manifest; it is not evidence that every path is implemented.

This document consolidates the complete product-monorepo tree and the full trees for the organization-wide GitHub policy, GitHub configuration, bootstrap, infrastructure-live, and GitOps repositories. Tree listings are reproduced without ellipses or omitted branches.

## Activation and stub contract

The tree is exhaustive for top-level paths, package/component namespaces, composition roots, public contract files, root metadata, and first-PR activation stubs. It intentionally does not guess every future private implementation file. A trailing directory with no child file is a **namespace declaration**, not a physical empty directory: it is absent until its first domain-specific target is approved. Brace notation is an exact child expansion; a trailing slash after the brace means the listed children are namespace declarations, otherwise each item is a file unless its name is a conventional directory such as `tests`. Ellipses and placeholder path tokens are prohibited in this tree.

When a namespace activates, its first PR uses exactly one applicable stub profile and replaces the profile's domain tokens with the concrete namespace already named in the tree:

| Stub profile | Exact minimum files | Required proof |
|---|---|---|
| governed component | `component.yaml`, `BUILD.bazel`, `README.md` | owner/maturity/dependencies/release metadata validate; at least one real target exists |
| Python library | `pyproject.toml` at release root; package `__init__.py`, `py.typed`, domain-named implementation module, `tests/test_<domain_contract>.py`, `BUILD.bazel`, `component.yaml`, `README.md` | import, type, unit, dependency-law, wheel test |
| Rust crate | `Cargo.toml`, `src/lib.rs`, domain-named module, `tests/<domain>_contract.rs`, `BUILD.bazel`, `component.yaml`, `README.md` | cargo/Bazel parity, clippy, unit/conformance, license audit |
| Go package/deployable | domain-named `.go` files, domain-named `_test.go`, `BUILD.bazel`, `component.yaml`, `README.md`; a deployable also has `cmd/<binary>/main.go` | Go/Bazel parity, race/unit/contract tests, composition-root check |
| TypeScript package/application | `package.json`, `src/index.ts` only for a public package barrel, domain-named source, `tests/<domain>.test.ts`, `BUILD.bazel`, `component.yaml`, `README.md` | typecheck, unit/contract, bundle and dependency-law tests |
| Protobuf/event package | domain-named `.proto`, `buf.lock` only at the protocol workspace boundary, `BUILD.bazel`, compatibility baseline, `README.md` | lint, generation drift, breaking-change and cross-language round trip |
| JSON Schema package | domain-named `.schema.json`, positive/negative fixtures, `BUILD.bazel`, compatibility baseline, `README.md` | metaschema, identifier, compatibility and generated-validator tests |
| service/worker image | domain-specific composition root shown in the tree, `component.yaml`, `BUILD.bazel`, `README.md`, contract/failure tests, image target, deployment descriptor reference | clean image build, cancellation/fencing, health, SBOM/provenance and local integration |
| deployment package | `release-package.yaml`, `values.schema.json`, domain-named base/templates, policy fixtures, `BUILD.bazel`, `component.yaml`, `README.md` | deterministic render, schema/policy, upgrade/rollback and digest-pin tests |
| documentation index | domain-named Markdown plus nearest `README.md` index and link-test target | compiled examples, links, ownership and review-date checks |

`<domain_contract>` in the profile is a generator variable, not a repository filename. The generator MUST materialize a concrete name such as `test_artifact_reference.py`; CI rejects literal angle-bracket names, `utils.*`, generic `service.*`, generic `manager.*`, or a generic `api.*` outside an explicitly approved public API boundary. `tools/generators/stub_catalog.yaml` maps every generator profile to these required files; `docs/architecture/repository-path-manifest.yaml` is the machine-readable path/status/owner/wave projection generated from the tree and repository evidence. Both are Wave 0 targets and are drift-checked.


## 1. Product monorepo (`mindclade/`)

```text
mindclade/
├── .buildkite/
│   ├── pipeline.yml
│   ├── pipeline.py
│   ├── hooks/
│   │   ├── environment
│   │   └── pre-command
│   ├── lib/
│   │   ├── affected_targets.py
│   │   ├── annotations.py
│   │   ├── pipeline_model.py
│   │   └── trusted_context.py
│   ├── steps/
│   │   ├── presubmit.py
│   │   ├── gpu.py
│   │   ├── nightly.py
│   │   ├── release.py
│   │   └── security.py
│   └── README.md
├── .github/
│   ├── actions/
│   │   ├── setup-repository/
│   │   │   ├── action.yml
│   │   │   └── README.md
│   │   └── validate-metadata/
│   │       ├── action.yml
│   │       └── README.md
│   ├── workflows/
│   │   ├── pr-metadata.yml
│   │   ├── buildkite-dispatch.yml
│   │   ├── required-check.yml
│   │   ├── docs.yml
│   │   ├── dependency-review.yml
│   │   ├── codeql.yml
│   │   ├── scorecard.yml
│   │   └── mirror-verification.yml
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug.yml
│   │   ├── architecture-change.yml
│   │   ├── scientific-correctness.yml
│   │   ├── security-control-gap.yml
│   │   └── config.yml
│   ├── CODEOWNERS
│   ├── dependabot.yml
│   ├── labeler.yml
│   └── pull_request_template.md
├── .devcontainer/
│   ├── devcontainer.json
│   ├── Containerfile
│   └── README.md
├── .vscode/
│   ├── extensions.json
│   ├── settings.json
│   └── tasks.json
├── MODULE.bazel
├── BUILD.bazel
├── .bazelrc
├── .bazelversion
├── flake.nix
├── flake.lock
├── pyproject.toml
├── uv.lock
├── .python-version
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── go.mod
├── go.sum
├── package.json
├── pnpm-workspace.yaml
├── pnpm-lock.yaml
├── buf.yaml
├── buf.gen.yaml
├── justfile
├── .editorconfig
├── .gitattributes
├── .gitignore
├── .pre-commit-config.yaml
├── .markdownlint-cli2.yaml
├── .yamllint.yaml
├── component.yaml
├── AGENTS.md
├── ARCHITECTURE.md
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── LICENSE
├── NOTICE
├── README.md
│
├── protocols/
│   ├── proto/
│   │   └── mindclade/
│   │       ├── common/v1/{identifiers.proto,resource_reference.proto,command_context.proto,event_envelope.proto,error_detail.proto,pagination.proto}
│   │       ├── artifact/v1/{artifact_reference.proto,evidence_reference.proto,artifact_commands.proto}
│   │       ├── job/v1/{operation.proto,job.proto,run.proto,attempt.proto,lease_fencing.proto,job_commands.proto}
│   │       ├── dataset/v1/{dataset.proto,dataset_release.proto,dataset_commands.proto}
│   │       ├── experiment/v1/{experiment.proto,study.proto,trial.proto}
│   │       ├── model/v1/{model.proto,model_release.proto,model_commands.proto}
│   │       ├── training/v1/{training_run.proto,training_progress.proto,checkpoint.proto,training_commands.proto}
│   │       ├── inference/v1/{inference_request.proto,inference_result.proto,inference_stream.proto}
│   │       ├── evaluation/v1/{evaluation_run.proto,evaluation_result.proto,promotion_decision.proto}
│   │       ├── agent/v1/{agent_definition.proto,agent_run.proto,agent_step.proto,tool_receipt.proto}
│   │       ├── workflow/v1/{workflow_definition.proto,workflow_run.proto,approval.proto}
│   │       ├── policy/v1/{policy_reference.proto,authorization_decision.proto,use_policy.proto}
│   │       └── admin/v1/{tenant.proto,project.proto,audit_query.proto}
│   ├── events/
│   │   └── mindclade/
│   │       ├── artifact/v1/{artifact_committed.proto,artifact_quarantined.proto}
│   │       ├── job/v1/{job_requested.proto,attempt_leased.proto,attempt_completed.proto}
│   │       ├── model/v1/{model_registered.proto,model_promoted.proto,model_revoked.proto}
│   │       ├── training/v1/{training_started.proto,progress_committed.proto,checkpoint_committed.proto,training_completed.proto}
│   │       ├── agent/v1/{agent_step_dispatched.proto,tool_receipt_committed.proto,agent_run_completed.proto}
│   │       ├── workflow/v1/{workflow_transitioned.proto,approval_recorded.proto}
│   │       └── audit/v1/{audit_event.proto,security_event.proto}
│   ├── schemas/
│   │   ├── artifact_manifest/{artifact_manifest.schema.json,positive.json,negative_missing_digest.json}
│   │   ├── evidence_manifest/{evidence_manifest.schema.json,positive.json,negative_subject_mismatch.json}
│   │   ├── release_manifest/{release_manifest.schema.json,positive.json,negative_mutable_reference.json}
│   │   ├── configuration/{configuration.schema.json,positive.json,negative_secret_value.json}
│   │   ├── biological_representation/{biological_representation.schema.json,positive.json,negative_entity_graph.json}
│   │   ├── feature_spec/{feature_spec.schema.json,positive.json,negative_projection_semantics.json}
│   │   ├── feature_derivation_record/{feature_derivation_record.schema.json,positive.json,negative_semantic_key.json}
│   │   ├── dataset_manifest/{dataset_manifest.schema.json,positive.json,negative_lineage.json}
│   │   ├── dataset_mixture/{dataset_mixture.schema.json,positive.json,negative_mutable_component.json}
│   │   ├── feature_manifest/{feature_manifest.schema.json,positive.json,negative_schema_digest.json}
│   │   ├── training_dataset_manifest/{training_dataset_manifest.schema.json,positive.json,negative_split_overlap.json}
│   │   ├── curriculum_manifest/{curriculum_manifest.schema.json,positive.json,negative_stage_transition.json}
│   │   ├── batch_receipt/{batch_receipt.schema.json,positive.json,negative_progress_range.json}
│   │   ├── checkpoint_manifest/{checkpoint_manifest.schema.json,positive.json,negative_logical_state.json}
│   │   ├── evaluation_snapshot/{evaluation_snapshot.schema.json,positive.json,negative_subject.json}
│   │   ├── model_manifest/{model_manifest.schema.json,positive.json,negative_checkpoint.json}
│   │   ├── logical_state_schema/{logical_state.schema.json,positive.json,negative_state_key.json}
│   │   ├── training_recipe/{training_recipe.schema.json,positive.json,negative_unresolved_value.json}
│   │   ├── training_phase_graph/{training_phase_graph.schema.json,positive.json,negative_cycle.json}
│   │   ├── training_run_manifest/{training_run_manifest.schema.json,positive.json,negative_plan_digest.json}
│   │   ├── hardware_topology_manifest/{hardware_topology_manifest.schema.json,positive.json,negative_capability.json}
│   │   ├── executable_plan/{executable_plan.schema.json,positive.json,negative_unqualified_topology.json}
│   │   ├── provider_manifest/{provider_manifest.schema.json,positive.json,negative_qualification.json}
│   │   ├── compiled_region_manifest/{compiled_region_manifest.schema.json,positive.json,negative_cache_key.json}
│   │   ├── step_capsule/{step_capsule.schema.json,positive.json,negative_lineage.json}
│   │   ├── study_manifest/{study_manifest.schema.json,positive.json,negative_trial_policy.json}
│   │   ├── scaling_study/{scaling_study.schema.json,positive.json,negative_heldout_leakage.json}
│   │   ├── scientific_qualification_profile/{scientific_qualification_profile.schema.json,positive.json,negative_unbounded_claim.json}
│   │   ├── capability_claim/{capability_claim.schema.json,positive.json,negative_evidence_envelope.json}
│   │   ├── adaptive_compute_policy/{adaptive_compute_policy.schema.json,positive.json,negative_unbounded_budget.json}
│   │   ├── agent_definition/{agent_definition.schema.json,positive.json,negative_capability.json}
│   │   ├── tool_contract/{tool_contract.schema.json,positive.json,negative_permission.json}
│   │   ├── agent_policy/{agent_policy.schema.json,positive.json,negative_budget.json}
│   │   ├── workflow_definition/{workflow_definition.schema.json,positive.json,negative_cycle.json}
│   │   ├── agent_run_manifest/{agent_run_manifest.schema.json,positive.json,negative_policy_digest.json}
│   │   ├── development_kit_assembly/{development_kit_assembly.schema.json,positive.json,negative_authority.json}
│   │   └── kernel_qualification/{kernel_qualification.schema.json,positive.json,negative_parity.json}
│   ├── openapi/{external-api.yaml,generation.yaml,compatibility-policy.yaml}
│   ├── generated/
│   │   ├── go/
│   │   ├── python/
│   │   ├── rust/
│   │   └── typescript/
│   ├── compatibility/
│   │   ├── baselines/{protobuf.lock.json,json-schema.lock.json,openapi.lock.json}
│   │   └── tests/{test_protobuf_compatibility.py,test_schema_compatibility.py,test_openapi_compatibility.py}
│   ├── BUILD.bazel
│   └── README.md
│
├── libs/
│   ├── python/
│   │   ├── artifacts/{__init__.py,artifact_reference.py,digest.py,py.typed,BUILD.bazel}
│   │   ├── config/{__init__.py,resolution.py,redaction.py,py.typed,BUILD.bazel}
│   │   ├── contracts/{__init__.py,error_mapping.py,deadline.py,cancellation.py,py.typed,BUILD.bazel}
│   │   ├── identifiers/{__init__.py,resource_id.py,resource_reference.py,py.typed,BUILD.bazel}
│   │   ├── observability/{__init__.py,logging.py,tracing.py,metrics.py,py.typed,BUILD.bazel}
│   │   ├── retry/{__init__.py,retry_policy.py,backoff.py,py.typed,BUILD.bazel}
│   │   ├── serialization/{__init__.py,canonical_json.py,protobuf_io.py,py.typed,BUILD.bazel}
│   │   ├── testing/{__init__.py,clock.py,fixtures.py,contract_cases.py,py.typed,BUILD.bazel}
│   │   ├── time/{__init__.py,clock.py,deadline.py,py.typed,BUILD.bazel}
│   │   ├── dependency_policy_test.py
│   │   ├── BUILD.bazel
│   │   ├── component.yaml
│   │   └── README.md
│   ├── rust/
│   │   ├── artifact/{Cargo.toml,src/lib.rs,src/digest.rs,src/reference.rs,BUILD.bazel}
│   │   ├── bytes/{Cargo.toml,src/lib.rs,src/chunk.rs,src/integrity.rs,BUILD.bazel}
│   │   ├── config/{Cargo.toml,src/lib.rs,src/resolution.rs,src/redaction.rs,BUILD.bazel}
│   │   ├── errors/{Cargo.toml,src/lib.rs,src/taxonomy.rs,BUILD.bazel}
│   │   ├── identifiers/{Cargo.toml,src/lib.rs,src/resource_id.rs,BUILD.bazel}
│   │   ├── observability/{Cargo.toml,src/lib.rs,src/tracing.rs,src/metrics.rs,BUILD.bazel}
│   │   ├── retry/{Cargo.toml,src/lib.rs,src/policy.rs,src/backoff.rs,BUILD.bazel}
│   │   ├── storage/{Cargo.toml,src/lib.rs,src/object_store.rs,src/resumable.rs,BUILD.bazel}
│   │   ├── testing/{Cargo.toml,src/lib.rs,src/fixtures.rs,src/faults.rs,BUILD.bazel}
│   │   ├── component.yaml
│   │   └── README.md
│   ├── go/
│   │   ├── audit/{event.go,writer.go,writer_test.go,BUILD.bazel}
│   │   ├── auth/{principal.go,authorizer.go,delegation.go,authorizer_test.go,BUILD.bazel}
│   │   ├── blobstore/{store.go,object.go,capabilities.go,requirements.go,selection.go,conditional_write.go,BUILD.bazel}
│   │   ├── blobstore/filesystem/{filesystem_store.go,filesystem_component.go,filesystem_factory.go,filesystem_store_test.go,conformance_test.go,BUILD.bazel}
│   │   ├── blobstore/gcs/{gcs_store.go,gcs_component.go,gcs_factory.go,gcs_store_test.go,conformance_test.go,BUILD.bazel}
│   │   ├── blobstoretest/{conformance.go,fixtures.go,conformance_test.go,BUILD.bazel}
│   │   ├── clock/{clock.go,fake_clock.go,clock_test.go,BUILD.bazel}
│   │   ├── component/{identity.go,descriptor.go,failure_policy.go,lifecycle.go,health_snapshot.go,graph.go,runtime.go,binding.go,provider_selection.go,assembly_receipt.go,events.go,errors.go,graph_test.go,runtime_test.go,concurrency_test.go,failure_policy_test.go,provider_selection_test.go,assembly_receipt_test.go,BUILD.bazel}
│   │   ├── componenttest/{harness.go,recording_component.go,manual_health.go,barrier.go,fault_injection.go,leak_check.go,harness_test.go,BUILD.bazel}
│   │   ├── config/{source.go,snapshot.go,decode.go,validation.go,redaction.go,resolution_test.go,BUILD.bazel}
│   │   ├── connectx/{interceptors.go,errors.go,deadlines.go,BUILD.bazel}
│   │   ├── controller/{reconciler.go,result.go,backoff.go,reconciler_test.go,BUILD.bazel}
│   │   ├── eventtransport/{envelope.go,publisher.go,consumer.go,acknowledgement.go,capabilities.go,requirements.go,selection.go,BUILD.bazel}
│   │   ├── eventtransport/inmemory/{inmemory_transport.go,inmemory_component.go,inmemory_factory.go,inmemory_transport_test.go,conformance_test.go,BUILD.bazel}
│   │   ├── eventtransport/pubsub/{pubsub_transport.go,pubsub_component.go,pubsub_factory.go,pubsub_transport_test.go,conformance_test.go,BUILD.bazel}
│   │   ├── eventtransporttest/{conformance.go,fixtures.go,conformance_test.go,BUILD.bazel}
│   │   ├── faults/{classification.go,retryability.go,BUILD.bazel}
│   │   ├── grpcx/{interceptors.go,errors.go,deadlines.go,BUILD.bazel}
│   │   ├── identifiers/{resource_id.go,resource_reference.go,BUILD.bazel}
│   │   ├── kubernetes/{client.go,conditions.go,owner_references.go,BUILD.bazel}
│   │   ├── middleware/{request_context.go,recovery.go,telemetry.go,BUILD.bazel}
│   │   ├── observability/{metrics.go,tracing.go,logging.go,BUILD.bazel}
│   │   ├── secrets/{reference.go,resolver.go,version.go,capabilities.go,requirements.go,selection.go,BUILD.bazel}
│   │   ├── secrets/environment/{environment_resolver.go,environment_component.go,environment_factory.go,environment_resolver_test.go,conformance_test.go,BUILD.bazel}
│   │   ├── secrets/secretmanager/{secretmanager_resolver.go,secretmanager_component.go,secretmanager_factory.go,secretmanager_resolver_test.go,conformance_test.go,BUILD.bazel}
│   │   ├── secretstest/{conformance.go,fixtures.go,conformance_test.go,BUILD.bazel}
│   │   ├── servicekit/{application.go,http_probes.go,signal_handling.go,shutdown_policy.go,application_test.go,BUILD.bazel}
│   │   ├── storage/{transaction.go,outbox.go,leases.go,BUILD.bazel}
│   │   ├── testing/{database.go,queue.go,faults.go,BUILD.bazel}
│   │   ├── component.yaml
│   │   └── README.md
│   ├── typescript/
│   │   ├── config/{package.json,src/index.ts,src/resolution.ts,tests/resolution.test.ts,BUILD.bazel}
│   │   ├── design_system/{package.json,src/index.ts,src/tokens.ts,tests/accessibility.test.ts,BUILD.bazel}
│   │   ├── observability/{package.json,src/index.ts,src/tracing.ts,tests/tracing.test.ts,BUILD.bazel}
│   │   ├── testing/{package.json,src/index.ts,src/fixtures.ts,BUILD.bazel}
│   │   ├── web/{package.json,src/index.ts,src/errors.ts,src/pagination.ts,BUILD.bazel}
│   │   ├── component.yaml
│   │   └── README.md
│   ├── BUILD.bazel
│   └── README.md
│
├── bio/
│   ├── schemas/
│   │   ├── atom/{atom.schema.json,atom_conformance.json}
│   │   ├── residue/{residue.schema.json,residue_conformance.json}
│   │   ├── chain/{chain.schema.json,chain_conformance.json}
│   │   ├── assembly/{assembly.schema.json,assembly_conformance.json}
│   │   ├── sequence/{sequence.schema.json,sequence_conformance.json}
│   │   ├── entity_graph/{entity_graph.schema.json,entity_graph_conformance.json}
│   │   └── feature/{feature.schema.json,feature_conformance.json}
│   ├── entities/
│   │   ├── rust/{Cargo.toml,src/lib.rs,src/atom.rs,src/residue.rs,src/chain.rs,src/assembly.rs,BUILD.bazel}
│   │   ├── python/{__init__.py,atom.py,residue.py,chain.py,assembly.py,py.typed,BUILD.bazel}
│   │   ├── conformance/{entity_cases.json,test_cross_language_entities.py}
│   │   └── README.md
│   ├── representation/
│   │   ├── python/{__init__.py,entity_graph.py,representation_manifest.py,schema_migration.py,py.typed,BUILD.bazel}
│   │   ├── rust/{Cargo.toml,src/lib.rs,src/entity_graph.rs,src/representation_manifest.rs,src/schema_migration.rs,BUILD.bazel}
│   │   ├── conformance/{representation_cases.json,test_representation_parity.py,test_schema_migration.py}
│   │   └── README.md
│   ├── projections/
│   │   ├── python/{__init__.py,projection_contract.py,token_projection.py,tensor_projection.py,py.typed,BUILD.bazel}
│   │   ├── rust/{Cargo.toml,src/lib.rs,src/projection_contract.rs,src/tensor_projection.rs,BUILD.bazel}
│   │   ├── conformance/{projection_cases.json,test_projection_parity.py}
│   │   └── README.md
│   ├── formats/
│   │   ├── rust/
│   │   │   ├── fasta/{parser.rs,writer.rs,validation.rs}
│   │   │   ├── a3m/{parser.rs,writer.rs,validation.rs}
│   │   │   ├── stockholm/{parser.rs,writer.rs,validation.rs}
│   │   │   ├── mmcif/{lexer.rs,parser.rs,writer.rs,validation.rs}
│   │   │   ├── pdb/{parser.rs,writer.rs,validation.rs}
│   │   │   ├── ccd/{parser.rs,components.rs,validation.rs}
│   │   │   ├── sdf/{parser.rs,writer.rs,validation.rs}
│   │   │   ├── Cargo.toml
│   │   │   └── BUILD.bazel
│   │   ├── python/{__init__.py,bindings.py,reference_parser.py,py.typed,BUILD.bazel}
│   │   ├── fixtures/{valid,malformed,adversarial}/
│   │   └── conformance/{format_cases.yaml,test_parser_parity.py}
│   ├── chemistry/
│   │   ├── python/{elements.py,bonds.py,components.py,stereochemistry.py}
│   │   └── tests/{test_elements.py,test_bonds.py,test_stereochemistry.py}
│   ├── sequences/
│   │   ├── python/{alphabet.py,canonicalization.py,identity.py}
│   │   └── tests/{test_canonicalization.py,test_identity.py}
│   ├── structures/
│   │   ├── python/{coordinates.py,frames.py,assemblies.py,validation.py}
│   │   └── tests/{test_frames.py,test_assemblies.py,test_validation.py}
│   ├── alignments/
│   │   ├── python/{alignment.py,identity.py,clustering.py}
│   │   ├── rust/{Cargo.toml,src/lib.rs,src/identity.rs,src/clustering.rs}
│   │   └── tests/{test_identity_parity.py,test_clustering.py}
│   ├── featurization/
│   │   ├── python/{feature_contract.py,feature_spec.py,feature_derivation.py,sequence_features.py,pair_features.py,structure_features.py}
│   │   ├── rust/{Cargo.toml,src/lib.rs,src/feature_spec.rs,src/derivation_key.rs,src/sequence.rs,src/pair.rs,src/structure.rs}
│   │   ├── schemas/{feature_set.schema.json,tensor_layout.schema.json}
│   │   ├── parity/{feature_cases.json,derivation_cases.json,test_feature_parity.py,test_derivation_key_parity.py}
│   │   └── tests/{test_feature_spec.py,test_feature_derivation.py,test_sequence_features.py,test_pair_features.py,test_structure_features.py}
│   ├── bindings/
│   │   ├── python/{__init__.py,formats.py,features.py,py.typed}
│   │   └── abi/{abi_manifest.json,compatibility_test.py}
│   ├── BUILD.bazel
│   ├── component.yaml
│   └── README.md
│
├── data/
│   ├── contracts/
│   │   ├── source.py
│   │   ├── snapshot.py
│   │   ├── lineage.py
│   │   ├── dataset_mixture.py
│   │   ├── validation.py
│   │   └── BUILD.bazel
│   ├── connectors/
│   │   ├── contracts/{connector.py,source_cursor.py,fetch_result.py}
│   │   ├── pdb/{connector.py,release_index.py,license_policy.py}
│   │   ├── uniprot/{connector.py,release_index.py,license_policy.py}
│   │   ├── rnacentral/{connector.py,release_index.py,license_policy.py}
│   │   ├── ccd/{connector.py,release_index.py,license_policy.py}
│   │   └── tests/{test_connector_contract.py,test_cursor_resume.py,test_license_policy.py}
│   ├── ingestion/
│   │   ├── fetch/{request.py,streaming_fetch.py,source_auth.py}
│   │   ├── resume/{cursor_store.py,partial_object.py,resume_policy.py}
│   │   ├── manifests/{raw_snapshot.py,fetch_receipt.py}
│   │   ├── rate_limits/{source_budget.py,adaptive_limiter.py}
│   │   ├── integrity/{source_digest.py,object_verification.py,quarantine.py}
│   │   └── tests/{test_resume.py,test_rate_limit.py,test_integrity_failure.py}
│   ├── normalization/{normalization_plan.py,canonical_record.py,normalization_receipt.py}
│   ├── curation/{curation_policy.py,filter_reason.py,curated_record.py}
│   ├── validation/
│   │   ├── schema/{schema_validator.py,validation_report.py}
│   │   ├── biological/{structure_validator.py,sequence_validator.py}
│   │   ├── policy/{source_policy.py,data_class_policy.py}
│   │   └── quality/{quality_score.py,quality_gate.py}
│   ├── deduplication/{record_key.py,cluster_deduplicator.py,deduplication_receipt.py}
│   ├── leakage/{sequence_identity.py,split_isolation.py,leakage_report.py}
│   ├── splits/{split_contract.py,deterministic_split.py,split_receipt.py}
│   ├── mixtures/{mixture_manifest.py,mixture_validation.py,mixture_resolution.py}
│   ├── sampling/{sample_key.py,deterministic_sampler.py,sampling_receipt.py,receipt_validation.py}
│   ├── featurization/{feature_plan.py,derivation_key.py,derivation_record.py,cache_policy.py,feature_sharding.py,feature_receipt.py}
│   ├── catalog/{dataset_catalog.py,alias_policy.py,publication.py}
│   ├── storage/{raw_object_store.py,shard_store.py,atomic_publication.py}
│   ├── fixtures/{pdb_snapshot_index.json,synthetic_records.json,malformed_records.json}
│   ├── tools/{snapshot_source.py,publish_dataset.py,verify_lineage.py,verify_mixture.py,verify_feature_derivation.py}
│   ├── tests/{test_mixture_validation.py,test_sampling_replay.py,test_feature_derivation_key.py,test_feature_cache_policy.py}
│   ├── BUILD.bazel
│   ├── component.yaml
│   └── README.md
│
├── kernels/
│   ├── api/
│   │   ├── operation.py
│   │   ├── signature.py
│   │   ├── capability.py
│   │   └── result.py
│   ├── common/
│   │   ├── layouts/{layout.py,strides.py,validation.py}
│   │   ├── numerics/{tolerances.py,error_metrics.py,accumulation.py}
│   │   └── tensor_contracts/{shape.py,dtype.py,device.py}
│   ├── registry/{kernel_registry.py,provider_record.py,registration_policy.py}
│   ├── dispatch/{dispatch_key.py,capability_match.py,fallback.py}
│   ├── attention/
│   │   ├── reference.py
│   │   ├── dispatch.py
│   │   ├── spec.py
│   │   ├── tests/
│   │   └── benchmarks/
│   ├── pairformer/
│   │   ├── triangle_attention/{reference.py,spec.py,dispatch.py}
│   │   ├── triangle_multiplication/{reference.py,spec.py,dispatch.py}
│   │   ├── outer_product_mean/{reference.py,spec.py,dispatch.py}
│   │   ├── transition/{reference.py,spec.py,dispatch.py}
│   │   ├── tests/
│   │   └── benchmarks/
│   ├── diffusion/{reference.py,spec.py,dispatch.py,test_reference.py,benchmark.py}
│   ├── normalization/{reference.py,spec.py,dispatch.py,test_reference.py,benchmark.py}
│   ├── qualification/
│   │   ├── correctness/{forward_parity.py,backward_parity.py}
│   │   ├── gradients/{gradient_check.py,gradient_tolerance.py}
│   │   ├── determinism/{determinism_test.py,replay_test.py}
│   │   ├── performance/{benchmark_policy.py,regression_gate.py}
│   │   ├── hardware/{hardware_envelope.py,qualification_matrix.py}
│   │   └── reports/{qualification_report.py,report_schema.json}
│   ├── benchmarks/{benchmark_runner.py,benchmark_cases.yaml}
│   ├── tests/{test_registry.py,test_dispatch_fallback.py,test_reference_contract.py}
│   ├── BUILD.bazel
│   ├── component.yaml
│   └── README.md
│
├── runtime/
│   ├── distributed/
│   │   ├── mesh/{mesh_contract.py,device_mesh.py,placements.py}
│   │   ├── collectives/{collective_contract.py,nccl_backend.py,collective_timeout.py}
│   │   ├── topology/{topology_manifest.py,topology_validation.py}
│   │   ├── rendezvous/{rendezvous_contract.py,static_rendezvous.py}
│   │   └── health/{rank_health.py,collective_watchdog.py}
│   ├── dispatch/{execution_target.py,target_selection.py}
│   ├── memory/{memory_budget.py,tensor_lifetime.py,oom_policy.py}
│   ├── precision/{dtype_policy.py,operation_policy.py,numerical_guard.py}
│   ├── compilation/{compile_contract.py,compile_key.py,cache_policy.py}
│   ├── rng/{rng_contract.py,seed_derivation.py,state_capture.py}
│   ├── extensions/
│   │   ├── rust/{Cargo.toml,src/lib.rs,src/abi.rs,BUILD.bazel}
│   │   └── python/{__init__.py,bindings.py,abi_check.py}
│   ├── diagnostics/{runtime_snapshot.py,memory_snapshot.py,distributed_trace.py}
│   ├── testing/{fake_mesh.py,fault_injection.py,numerical_assertions.py}
│   ├── BUILD.bazel
│   ├── component.yaml
│   └── README.md
│
├── models/
│   ├── api/
│   │   ├── model.py
│   │   ├── batch.py
│   │   ├── outputs.py
│   │   ├── capabilities.py
│   │   └── serialization.py
│   ├── common/
│   │   ├── configuration/{model_config.py,config_validation.py,config_digest.py}
│   │   ├── initialization/{parameter_init.py,init_policy.py}
│   │   ├── masking/{sequence_mask.py,pair_mask.py,coordinate_mask.py}
│   │   ├── embeddings/{sequence_embedding.py,pair_embedding.py,time_embedding.py}
│   │   └── losses/{loss_contract.py,loss_reduction.py,masked_losses.py}
│   ├── components/
│   │   ├── sequence/{sequence_encoder.py,sequence_transition.py}
│   │   ├── pairformer/{pairformer_block.py,triangle_attention.py,triangle_multiplication.py,outer_product_mean.py}
│   │   ├── diffusion/{noise_schedule.py,coordinate_denoiser.py,diffusion_objective.py}
│   │   ├── confidence/{confidence_head.py,calibration_head.py}
│   │   ├── geometry/{rigid_frames.py,coordinate_updates.py,distogram.py}
│   │   └── heads/{structure_head.py,coordinate_diffusion_head.py}
│   ├── families/
│   │   └── clade/
│   │       ├── README.md
│   │       └── cladefold/
│   │           ├── configuration/{cladefold_q0.py,configuration.schema.json}
│   │           ├── architecture/{cladefold.py,pairformer_stack.py,structure_head.py,diffusion_head.py}
│   │           ├── capabilities/{capability_manifest.py,input_contract.py,output_contract.py}
│   │           ├── checkpoints/{state_mapping.py,checkpoint_migration.py}
│   │           ├── conversion/{bundle_export.py,bundle_import.py}
│   │           ├── inference/{inference_pipeline.py,default_sampling.py}
│   │           ├── qualification/{sqp001.yaml,numerical_gates.py,inference_parity.py}
│   │           ├── tests/{test_shapes.py,test_overfit_128.py,test_checkpoint_resume.py,test_inference_parity.py}
│   │           ├── BUILD.bazel
│   │           ├── component.yaml
│   │           └── README.md
│   ├── registry/{model_definition_registry.py,capability_index.py,alias_policy.py}
│   ├── packaging/{model_bundle.py,bundle_manifest.py,capability_claim_refs.py,bundle_signing.py}
│   ├── qualification/{scientific_profile.py,profile_binding.py,claim_compatibility.py}
│   ├── conversion/{state_mapping.py,conversion_receipt.py}
│   ├── tests/{test_model_contract.py,test_bundle_roundtrip.py,test_registry_aliases.py}
│   ├── BUILD.bazel
│   ├── component.yaml
│   └── README.md
│
├── training/
│   ├── api/
│   │   ├── task.py
│   │   ├── objective.py
│   │   ├── loss.py
│   │   ├── phase.py
│   │   ├── program.py
│   │   ├── state.py
│   │   ├── optimization.py
│   │   ├── parallelism.py
│   │   ├── precision.py
│   │   ├── checkpoint.py
│   │   ├── callbacks.py
│   │   ├── reproducibility.py
│   │   └── events.py
│   ├── core/
│   │   ├── trainer/
│   │   │   ├── trainer.py
│   │   │   ├── lifecycle.py
│   │   │   ├── step.py
│   │   │   ├── phase_graph.py
│   │   │   ├── progress_commit.py
│   │   │   └── fault_policy.py
│   │   ├── state/
│   │   │   ├── identity.py
│   │   │   ├── schema.py
│   │   │   ├── registry.py
│   │   │   ├── epochs.py
│   │   │   └── serialization.py
│   │   ├── optimization/
│   │   │   ├── update_graph.py
│   │   │   ├── parameter_groups.py
│   │   │   ├── reductions.py
│   │   │   ├── clipping.py
│   │   │   ├── schedules.py
│   │   │   ├── ema.py
│   │   │   └── health.py
│   │   ├── data/
│   │   │   ├── manifest.py
│   │   │   ├── mixture.py
│   │   │   ├── progress.py
│   │   │   ├── receipt.py
│   │   │   ├── deterministic.py
│   │   │   ├── sharding.py
│   │   │   ├── batching.py
│   │   │   ├── packing.py
│   │   │   ├── buckets.py
│   │   │   ├── work_units.py
│   │   │   └── prefetch.py
│   │   └── callbacks/
│   │       ├── bus.py
│   │       ├── actions.py
│   │       ├── ordering.py
│   │       └── delivery.py
│   ├── execution/
│   │   ├── ir/
│   │   │   ├── topology.py
│   │   │   ├── mesh.py
│   │   │   ├── placements.py
│   │   │   ├── passes.py
│   │   │   ├── pipeline.py
│   │   │   ├── collectives.py
│   │   │   ├── compiled_regions.py
│   │   │   └── executable.py
│   │   ├── planning/
│   │   │   ├── analysis.py
│   │   │   ├── constraints.py
│   │   │   ├── partition.py
│   │   │   ├── cost_model.py
│   │   │   ├── memory_model.py
│   │   │   └── planner.py
│   │   ├── passes/
│   │   │   ├── replacement.py
│   │   │   ├── tensor_parallel.py
│   │   │   ├── expert_parallel.py
│   │   │   ├── pipeline_partition.py
│   │   │   ├── activation_policy.py
│   │   │   ├── fsdp.py
│   │   │   ├── precision.py
│   │   │   ├── optimizer_state.py
│   │   │   ├── compile_regions.py
│   │   │   └── cuda_graphs.py
│   │   ├── schedules/
│   │   │   ├── registry.py
│   │   │   ├── eager.py
│   │   │   ├── gpipe.py
│   │   │   ├── one_f_one_b.py
│   │   │   ├── interleaved.py
│   │   │   └── zero_bubble.py
│   │   ├── native/
│   │   │   ├── engine.py
│   │   │   ├── program.py
│   │   │   ├── bootstrap.py
│   │   │   ├── materialize.py
│   │   │   ├── device_mesh.py
│   │   │   ├── distributed.py
│   │   │   ├── compilation.py
│   │   │   └── teardown.py
│   │   └── single_process/
│   │       ├── engine.py
│   │       └── program.py
│   ├── providers/
│   │   ├── capability_registry.py
│   │   ├── capability_contract.py
│   │   ├── compatibility_policy.py
│   │   └── pytorch/{native_engine.py,fsdp2_adapter.py,dtensor_adapter.py,dcp_adapter.py,nccl_adapter.py}
│   ├── precision/
│   │   ├── policy.py
│   │   ├── native_amp.py
│   │   ├── scaling.py
│   │   ├── quantization_state.py
│   │   ├── recipes.py
│   │   └── qualification.py
│   ├── checkpointing/
│   │   ├── checkpoint_contract.py
│   │   ├── checkpoint_coordinator.py
│   │   ├── logical_state_schema.py
│   │   ├── epochs.py
│   │   ├── snapshot.py
│   │   ├── tiers.py
│   │   ├── manifest.py
│   │   ├── metadata.py
│   │   ├── dcp.py
│   │   ├── save_planner.py
│   │   ├── load_planner.py
│   │   ├── async_save.py
│   │   ├── backpressure.py
│   │   ├── inflight.py
│   │   ├── request_coalescing.py
│   │   ├── staging_budget.py
│   │   ├── atomic_commit.py
│   │   ├── resume.py
│   │   ├── reshard.py
│   │   ├── partial_load.py
│   │   ├── integrity.py
│   │   ├── migration.py
│   │   ├── conversion.py
│   │   ├── retention.py
│   │   ├── format.py
│   │   ├── serialization.py
│   │   ├── lineage.py
│   │   └── tests/
│   ├── tasks/
│   │   ├── pretraining/{task.py,objective.py,batch_contract.py}
│   │   ├── supervised/{task.py,structure_objective.py,batch_contract.py}
│   │   ├── contrastive/{task.py,contrastive_objective.py,batch_contract.py}
│   │   ├── diffusion/{task.py,coordinate_objective.py,batch_contract.py}
│   │   ├── flow/{task.py,flow_objective.py,batch_contract.py}
│   │   ├── multitask/{task.py,loss_composition.py,batch_contract.py}
│   │   └── distillation/{task.py,teacher_contract.py,batch_contract.py}
│   ├── evaluation/
│   │   ├── scheduling.py
│   │   ├── snapshot.py
│   │   ├── leases.py
│   │   └── state.py
│   ├── telemetry/
│   │   ├── events.py
│   │   ├── metrics.py
│   │   ├── reductions.py
│   │   ├── structured_log.py
│   │   ├── tracing.py
│   │   ├── profiler.py
│   │   ├── memory.py
│   │   ├── flight_recorder.py
│   │   ├── step_capsule.py
│   │   └── shadow_qualification.py
│   ├── resilience/
│   │   ├── recovery.py
│   │   ├── preemption.py
│   │   └── failure_injection.py
│   ├── studies/                     # scientific HPO; separate from systems tuning
│   │   ├── definition.py
│   │   ├── trial.py
│   │   ├── scaling_study.py
│   │   ├── scaling_fit.py
│   │   ├── scaling_decision.py
│   │   └── promotion.py
│   ├── curricula/{curriculum_manifest.py,stage_transition.py,curriculum_progress.py}
│   ├── qualification/
│   │   ├── contracts/{qualification_profile.py,scientific_profile.py,evidence_contract.py}
│   │   ├── numerics/{forward_parity.py,loss_parity.py,tolerance_policy.py}
│   │   ├── gradients/{gradient_parity.py,finite_difference.py}
│   │   ├── updates/{optimizer_update_parity.py,step_progress.py}
│   │   ├── distributed/{rank_parity.py,sharding_parity.py,collective_failure.py}
│   │   ├── checkpointing/{roundtrip.py,reshard.py,partial_load.py}
│   │   ├── recovery/{resume_parity.py,preemption.py,stale_attempt.py}
│   │   ├── providers/{provider_conformance.py,provider_rollback.py}
│   │   ├── performance/{throughput_budget.py,memory_budget.py,regression_gate.py}
│   │   └── long_horizon/{drift_detection.py,stability_gate.py}
│   ├── recipes/
│   │   ├── schema.py
│   │   ├── registry.py
│   │   ├── resolution.py
│   │   ├── smoke/{cpu_contract.yaml,single_gpu.yaml}
│   │   ├── pretraining/{sequence.yaml,structure.yaml}
│   │   ├── finetuning/{supervised_structure.yaml,diffusion_structure.yaml}
│   │   └── qualification/{sqp001_cladefold_q0.yaml,overfit_128.yaml,resume_parity.yaml}
│   ├── cli/
│   │   ├── main.py
│   │   ├── plan.py
│   │   ├── study.py
│   │   ├── run.py
│   │   ├── resume.py
│   │   ├── qualify.py
│   │   ├── inspect.py
│   │   └── convert_checkpoint.py
│   ├── tests/{test_task_contract.py,test_phase_graph.py,test_curriculum_transition.py,test_mixture_sampling_receipt.py,test_scaling_study.py,test_progress_commit.py,test_checkpoint_roundtrip.py,test_resume_parity.py}
│   ├── BUILD.bazel
│   ├── component.yaml
│   └── README.md
│
├── evaluation/
│   ├── contracts/{suite_contract.py,metric_contract.py,evidence_contract.py,scaling_study_contract.py,capability_claim_contract.py}
│   ├── harness/{suite_loader.py,evaluation_runner.py,result_aggregation.py,evidence_writer.py}
│   ├── metrics/{geometry_metrics.py,confidence_metrics.py,calibration_metrics.py,statistical_tests.py}
│   ├── suites/
│   │   ├── sequence/{suite.yaml,sequence_evaluator.py}
│   │   ├── structure/{suite.yaml,structure_evaluator.py}
│   │   ├── complexes/{suite.yaml,complex_evaluator.py}
│   │   ├── design/{suite.yaml,design_evaluator.py}
│   │   ├── confidence/{suite.yaml,confidence_evaluator.py}
│   │   ├── robustness/{suite.yaml,robustness_evaluator.py}
│   │   └── safety/{suite.yaml,safety_evaluator.py}
│   ├── datasets/{snapshot_resolver.py,leakage_verification.py}
│   ├── scaling/{study_loader.py,heldout_partition.py,fit_estimation.py,uncertainty.py,decision_gate.py}
│   ├── claims/{claim_builder.py,claim_validation.py,claim_decision.py,claim_revocation.py}
│   ├── regression/{baseline_registry.py,comparison.py,promotion_gates.py}
│   ├── reports/{evaluation_report.py,model_card_projection.py}
│   ├── fixtures/sqp001/{expected_metrics.json,tiny_predictions.json}
│   ├── tests/{test_suite_contract.py,test_metric_aggregation.py,test_scaling_heldout.py,test_capability_claim_envelope.py,test_claim_expiry_revocation.py,test_regression_gates.py}
│   ├── BUILD.bazel
│   ├── component.yaml
│   └── README.md
│
├── inference/
│   ├── contracts/{request_contract.py,result_contract.py,stream_contract.py,execution_mode_contract.py,adaptive_compute_contract.py}
│   ├── pipeline/{preprocessing.py,feature_resolution.py,model_execution.py,postprocessing.py}
│   ├── batching/{batch_key.py,dynamic_batcher.py,batch_limits.py}
│   ├── sampling/{sampler_contract.py,deterministic_sampler.py,diffusion_sampler.py}
│   ├── execution_modes/{mode_selection.py,mode_qualification.py,fallback_decision.py}
│   ├── adaptive_compute/{compute_policy.py,budget_accounting.py,stopping_rule.py,candidate_receipt.py,resume_frontier.py}
│   ├── compilation/{compile_key.py,compiled_variant_cache.py,fallback_policy.py}
│   ├── postprocessing/{coordinate_projection.py,structure_validation.py}
│   ├── confidence/{confidence_estimation.py,calibration.py}
│   ├── ranking/{candidate_ranker.py,ranking_evidence.py}
│   ├── artifacts/{result_manifest.py,stream_writer.py,artifact_commit.py}
│   ├── diagnostics/{execution_trace.py,numerical_diagnostics.py}
│   ├── tests/{test_request_contract.py,test_execution_mode_selection.py,test_mode_fallback.py,test_adaptive_budget.py,test_adaptive_resume.py,test_inference_parity.py,test_artifact_commit.py}
│   ├── BUILD.bazel
│   ├── component.yaml
│   └── README.md
│
├── agents/
│   ├── contracts/
│   │   ├── agent.py
│   │   ├── context.py
│   │   ├── decision.py
│   │   ├── tool.py
│   │   ├── policy.py
│   │   ├── workflow.py
│   │   └── state.py
│   ├── tools/
│   │   ├── registry/{tool_registry.py,capability_resolution.py}
│   │   ├── adapters/{data_adapter.py,inference_adapter.py,evaluation_adapter.py}
│   │   ├── schemas/{input_validation.py,output_validation.py}
│   │   ├── permissions/{delegated_capability.py,scope_intersection.py}
│   │   ├── receipts/{tool_receipt.py,receipt_verification.py}
│   │   ├── qualification/{tool_conformance.py,sandbox_conformance.py}
│   │   └── tests/{test_tool_registry.py,test_permission_scope.py,test_receipts.py}
│   ├── policies/
│   │   ├── authorization/{decision.py,capability_policy.py}
│   │   ├── biological_safety/{use_policy.py,screening_gate.py}
│   │   ├── budgets/{resource_budget.py,budget_reservation.py}
│   │   ├── approvals/{approval_contract.py,approval_gate.py}
│   │   └── tests/{test_authorization.py,test_safety_gate.py,test_budget_enforcement.py}
│   ├── workflows/
│   │   ├── graph/{workflow_graph.py,graph_validation.py}
│   │   ├── planning/{workflow_planner.py,plan_freeze.py}
│   │   ├── execution/{step_dispatch.py,step_reconciliation.py}
│   │   ├── compensation/{compensation_policy.py,compensation_runner.py}
│   │   └── tests/{test_workflow_graph.py,test_compensation.py}
│   ├── state/
│   │   ├── events/{agent_events.py,event_reducer.py}
│   │   ├── snapshots/{agent_snapshot.py,snapshot_migration.py}
│   │   ├── memory_refs/{memory_reference.py,retention_policy.py}
│   │   └── lineage/{decision_lineage.py,tool_lineage.py}
│   ├── biological/
│   │   ├── discovery/{candidate_discovery.py,discovery_policy.py}
│   │   ├── design/{design_request.py,design_constraints.py}
│   │   ├── analysis/{analysis_plan.py,evidence_synthesis.py}
│   │   └── qualification/{biological_agent_suite.py,adversarial_cases.py}
│   ├── runtime/
│   │   ├── coordinator.py
│   │   ├── executor.py
│   │   ├── approvals.py
│   │   ├── budgets.py
│   │   └── replay.py
│   ├── evaluation/{simulation.py,adversarial.py,regression.py}
│   ├── fixtures/{tool_receipts.json,workflow_cases.json}
│   ├── tests/{test_replay.py,test_approval_gates.py,test_sandbox_escape.py}
│   ├── BUILD.bazel
│   ├── component.yaml
│   └── README.md
│
├── services/
│   ├── control_plane/
│   │   ├── cmd/control-plane/{main.go,wire.go}
│   │   ├── internal/
│   │   │   ├── artifacts/{artifact_commands.go,artifact_repository.go,artifact_reconciler.go}
│   │   │   ├── datasets/{dataset_commands.go,dataset_repository.go,dataset_reconciler.go}
│   │   │   ├── experiments/{experiment_commands.go,experiment_repository.go}
│   │   │   ├── jobs/{job_commands.go,job_repository.go,job_reconciler.go,lease_fencing.go}
│   │   │   ├── agents/{agent_commands.go,agent_repository.go,agent_reconciler.go}
│   │   │   ├── workflows/{workflow_commands.go,workflow_repository.go,workflow_reconciler.go}
│   │   │   ├── models/{model_commands.go,model_repository.go,promotion_policy.go}
│   │   │   ├── policies/{authorization.go,policy_repository.go,decision_audit.go}
│   │   │   ├── projects/{project_commands.go,project_repository.go}
│   │   │   ├── tenants/{tenant_commands.go,tenant_repository.go,tenant_isolation.go}
│   │   │   ├── users/{user_projection.go,principal_mapping.go}
│   │   │   └── platform/
│   │   │       ├── database/{transactions.go,migration_guard.go,health.go}
│   │   │       ├── idempotency/{command_keys.go,idempotency_store.go}
│   │   │       ├── outbox/{outbox_store.go,dispatcher.go,delivery_fencing.go}
│   │   │       ├── queue/{transport.go,delivery.go,dead_letter.go}
│   │   │       ├── storage/{artifact_catalog.go,object_store.go}
│   │   │       └── telemetry/{metrics.go,tracing.go,audit_events.go}
│   │   ├── migrations/{000001_kernel.up.sql,000001_kernel.down.sql,migration_policy.yaml}
│   │   ├── tests/{transaction_outbox_test.go,idempotency_test.go,lease_fencing_test.go,tenant_isolation_test.go}
│   │   ├── BUILD.bazel
│   │   ├── component.yaml
│   │   └── README.md
│   ├── runtime_gateway/
│   │   ├── cmd/runtime-gateway/{main.go,wire.go}
│   │   ├── internal/
│   │   │   ├── admission/{request_admission.go,quota_check.go}
│   │   │   ├── authorization/{request_authorization.go,delegation.go}
│   │   │   ├── routing/{model_route.go,worker_route.go}
│   │   │   ├── streaming/{stream_session.go,backpressure.go}
│   │   │   ├── limits/{deadline.go,body_limit.go,rate_limit.go}
│   │   │   └── telemetry/{request_metrics.go,tracing.go,audit.go}
│   │   ├── tests/{authorization_test.go,admission_test.go,stream_backpressure_test.go}
│   │   ├── BUILD.bazel
│   │   ├── component.yaml
│   │   └── README.md
│   ├── artifact_proxy/
│   │   ├── src/{main.rs,authorization.rs,transfer.rs,integrity.rs,limits.rs,telemetry.rs}
│   │   ├── tests/{authorization.rs,resumable_transfer.rs,integrity_failure.rs}
│   │   ├── Cargo.toml
│   │   ├── Cargo.lock
│   │   ├── BUILD.bazel
│   │   ├── component.yaml
│   │   └── README.md
│   ├── BUILD.bazel
│   └── README.md
│
├── workers/
│   ├── ingestion_worker/
│   │   ├── rust/src/{main.rs,attempt.rs,source_fetch.rs,artifact_commit.rs,cancellation.rs,telemetry.rs}
│   │   ├── tests/{redelivery.rs,stale_lease.rs,partial_fetch.rs}
│   │   ├── Cargo.toml
│   │   ├── BUILD.bazel
│   │   ├── component.yaml
│   │   └── README.md
│   ├── feature_worker/
│   │   ├── rust/src/{main.rs,attempt.rs,feature_shards.rs,artifact_commit.rs,cancellation.rs}
│   │   ├── python/{feature_contract.py,parity_adapter.py}
│   │   ├── tests/{feature_parity.py,redelivery.py,stale_lease.py}
│   │   ├── Cargo.toml
│   │   ├── BUILD.bazel
│   │   ├── component.yaml
│   │   └── README.md
│   ├── training_worker/
│   │   ├── python/
│   │   │   ├── main.py
│   │   │   ├── bootstrap.py
│   │   │   ├── job.py
│   │   │   ├── execution.py
│   │   │   ├── cancellation.py
│   │   │   ├── heartbeat.py
│   │   │   ├── artifacts.py
│   │   │   └── telemetry.py
│   │   ├── tests/{test_redelivery.py,test_stale_lease.py,test_checkpoint_cancel.py}
│   │   ├── BUILD.bazel
│   │   ├── component.yaml
│   │   └── README.md
│   ├── evaluation_worker/
│   │   ├── python/{main.py,attempt.py,evaluation_execution.py,cancellation.py,artifacts.py,telemetry.py}
│   │   ├── tests/{test_redelivery.py,test_evidence_commit.py,test_cancellation.py}
│   │   ├── BUILD.bazel
│   │   ├── component.yaml
│   │   └── README.md
│   ├── inference_worker/
│   │   ├── python/{main.py,attempt.py,model_loading.py,batch_execution.py,streaming.py,cancellation.py,artifacts.py,telemetry.py}
│   │   ├── tests/{test_batching.py,test_stream_backpressure.py,test_artifact_commit.py}
│   │   ├── BUILD.bazel
│   │   ├── component.yaml
│   │   └── README.md
│   ├── agent_worker/
│   │   ├── python/{main.py,attempt.py,workflow_execution.py,sandbox.py,cancellation.py,receipts.py,telemetry.py}
│   │   ├── tests/{test_tool_fencing.py,test_budget_cancel.py,test_sandbox_policy.py}
│   │   ├── BUILD.bazel
│   │   ├── component.yaml
│   │   └── README.md
│   ├── BUILD.bazel
│   └── README.md
│
├── sdk/
│   ├── python/
│   │   ├── src/mindclade/{__init__.py,client.py,operations.py,artifacts.py,models.py,datasets.py,inference.py,errors.py,py.typed}
│   │   ├── tests/{test_client_contract.py,test_operation_polling.py,test_artifact_transfer.py}
│   │   ├── pyproject.toml
│   │   ├── BUILD.bazel
│   │   ├── component.yaml
│   │   └── README.md
│   ├── typescript/
│   │   ├── src/{index.ts,client.ts,operations.ts,artifacts.ts,models.ts,datasets.ts,inference.ts,errors.ts}
│   │   ├── tests/{client-contract.test.ts,operation-polling.test.ts,artifact-transfer.test.ts}
│   │   ├── package.json
│   │   ├── BUILD.bazel
│   │   ├── component.yaml
│   │   └── README.md
│   ├── conformance/{public_api_cases.yaml,error_cases.yaml,pagination_cases.yaml}
│   ├── examples/{submit_operation.py,stream_inference.ts,download_artifact.py}
│   ├── BUILD.bazel
│   └── README.md
│
├── kits/
│   ├── mcdk/{environment_assembly.go,environment_validation.go,README.md}
│   ├── mddk/{dataset_assembly.py,dataset_validation.py,README.md}
│   ├── mmdk/{model_assembly.py,model_validation.py,README.md}
│   ├── mtdk/{training_assembly.py,training_validation.py,README.md}
│   ├── medk/{evaluation_assembly.py,evaluation_validation.py,README.md}
│   ├── madk/{agent_assembly.py,agent_simulation.py,README.md}
│   ├── assembly/{assembly_manifest.py,assembly_signing.py}
│   ├── conformance/{kit_contract_cases.yaml,clean_project_test.py}
│   ├── cli/{main.py,validation_commands.py,generation_commands.py}
│   ├── BUILD.bazel
│   ├── component.yaml
│   └── README.md
│
├── apps/
│   ├── console/
│   │   ├── app/{layout.tsx,page.tsx,error.tsx,not-found.tsx}
│   │   ├── components/{operation-status.tsx,artifact-link.tsx,evidence-badge.tsx}
│   │   ├── features/{datasets,models,training,evaluation,inference,agents,operations}/
│   │   ├── tests/{authorization.test.ts,operation-flow.test.ts,accessibility.test.ts}
│   │   ├── package.json
│   │   ├── BUILD.bazel
│   │   ├── component.yaml
│   │   └── README.md
│   ├── admin/
│   │   ├── app/{layout.tsx,page.tsx,error.tsx}
│   │   ├── features/{tenants,policies,audit,incidents}/
│   │   ├── tests/{authorization.test.ts,audit-view.test.ts}
│   │   ├── package.json
│   │   ├── BUILD.bazel
│   │   ├── component.yaml
│   │   └── README.md
│   ├── docs/
│   │   ├── app/{layout.tsx,page.tsx}
│   │   ├── content/{sdk,contracts,operations,runbooks}/
│   │   ├── tests/{link-integrity.test.ts,code-samples.test.ts}
│   │   ├── package.json
│   │   ├── BUILD.bazel
│   │   ├── component.yaml
│   │   └── README.md
│   ├── BUILD.bazel
│   └── README.md
│
├── deploy/
│   ├── crds/
│   │   ├── workload-profile/{workload-profile-crd.yaml,conversion-policy.yaml}
│   │   └── README.md
│   ├── components/
│   │   ├── control_plane/{release-package.yaml,values.schema.json,base.yaml,service-monitor.yaml}
│   │   ├── runtime_gateway/{release-package.yaml,values.schema.json,base.yaml,service-monitor.yaml}
│   │   ├── artifact_proxy/{release-package.yaml,values.schema.json,base.yaml,service-monitor.yaml}
│   │   └── workers/{release-package.yaml,values.schema.json,worker-templates.yaml,network-policies.yaml}
│   ├── local/{compose.yaml,local-values.yaml,fake-identity.yaml,README.md}
│   ├── integration/{kustomization.yaml,integration-values.yaml,synthetic-data-policy.yaml,README.md}
│   ├── policies/{signed_images.rego,workload_identity.rego,tenant_network.rego,resource_limits.rego}
│   ├── tests/{test_deterministic_render.py,test_policy_denials.py,test_upgrade_rollback.py}
│   ├── BUILD.bazel
│   ├── component.yaml
│   └── README.md
│
├── research/
│   ├── notebooks/{README.md,notebook_policy.py}
│   ├── prototypes/{README.md,prototype_manifest.schema.json}
│   ├── ablations/{README.md,ablation_manifest.schema.json}
│   ├── studies/{README.md,study_manifest.schema.json}
│   ├── papers/{README.md,reproduction_manifest.schema.json}
│   ├── fixtures/{synthetic_sequences.fasta,synthetic_structure.cif}
│   ├── README.md
│   └── POLICY.md
│
├── tests/
│   ├── conformance/{contract_matrix.yaml,test_generated_clients.py,test_artifact_manifests.py,test_biological_representation.py,test_feature_derivation.py,test_capability_claims.py}
│   ├── integration/{local_stack_test.py,control_worker_test.py,artifact_commit_test.py}
│   ├── end_to_end/{scientific_slice_test.py,platform_slice_test.py,joined_lifecycle_test.py}
│   ├── distributed/{single_node_fsdp_test.py,multi_rank_checkpoint_test.py,collective_failure_test.py}
│   ├── failure_injection/{outbox_crash_test.py,worker_redelivery_test.py,storage_failure_test.py}
│   ├── performance/{budget.yaml,data_path_benchmark.py,inference_benchmark.py,adaptive_compute_benchmark.py}
│   ├── security/{tenant_isolation_test.py,artifact_authorization_test.py,sandbox_escape_test.py}
│   ├── BUILD.bazel
│   └── README.md
│
├── tools/
│   ├── bazel/
│   │   ├── rules/{component_rule.bzl,contract_rule.bzl,release_rule.bzl}
│   │   ├── macros/{python_component.bzl,rust_component.bzl,go_component.bzl,typescript_component.bzl}
│   │   ├── aspects/{dependency_graph.bzl,component_metadata.bzl,generated_files.bzl}
│   │   └── transitions/{cpu_profile.bzl,gpu_profile.bzl}
│   ├── ci/{affected_targets.py,pipeline_plan.py,required_check.py,evidence_bundle.py}
│   ├── codegen/{generate_protocols.py,generate_schemas.py,verify_generated_drift.py,toolchain.lock.json}
│   ├── dev/{bootstrap.py,doctor.py,environment_profile.py,diagnostic_bundle.py}
│   ├── repo/{build_repository_drift_report.py,dependency_policy.py,owner_policy.py,path_policy.py}
│   ├── release/{build_release_manifest.py,verify_release.py,promote_release.py,revoke_release.py}
│   ├── qualification/{resolve_policy.py,scientific_profile.py,capability_claim.py,collect_evidence.py,verify_evidence.py,hardware_envelope.py}
│   ├── migration/{plan_path_move.py,verify_compatibility.py,remove_shim.py}
│   ├── generators/
│   │   ├── stub_catalog.yaml
│   │   ├── generate_component.py
│   │   ├── templates/{python_library,rust_crate,go_package,typescript_package,deployable,contract,documentation}/
│   │   └── tests/{test_stub_catalog.py,test_generated_component.py}
│   ├── licenses/{allowlist.yaml,exceptions.yaml,scan_licenses.py,generate_notices.py}
│   ├── BUILD.bazel
│   └── README.md
│
├── docs/
│   ├── architecture/{repository-path-manifest.yaml,repository-drift-baseline.md,dependency-law.md,trust-boundaries.md,capability-intake-register.yaml,scientific-capability-ladder.md}
│   ├── adr/{0001-repository-identity.md,0002-dependency-direction.md,0003-artifact-identity.md,0004-contract-authority.md,0005-biological-identity.md,0006-durable-work.md,0007-training-state.md,index.yaml}
│   ├── domains/{bio.md,data.md,models.md,training.md,evaluation.md,inference.md,scientific-qualification.md,agents.md,control-plane.md}
│   ├── standards/{coding.md,contracts.md,testing.md,observability.md,security.md,releases.md}
│   ├── developer/{bootstrap.md,build.md,test.md,code-generation.md,debugging.md,contributing.md}
│   ├── security/{threat-model.md,data-classification.md,identity.md,supply-chain.md,incident-policy.md}
│   ├── runbooks/{control-plane.md,workers.md,artifacts.md,training.md,inference.md,agents.md}
│   ├── operations/{slos.md,capacity.md,cost-attribution.md,disaster-recovery.md}
│   ├── model_cards/{README.md,model-card.schema.json}
│   ├── dataset_cards/{README.md,dataset-card.schema.json}
│   ├── BUILD.bazel
│   └── README.md
│
├── examples/
│   ├── sdk/{submit_operation.py,follow_operation.ts,download_artifact.py}
│   ├── data_connector/{connector.py,connector_contract_test.py,README.md}
│   ├── model_extension/{model_definition.py,model_package.yaml,README.md}
│   ├── training_smoke/{recipe.yaml,run_local.py,README.md}
│   ├── inference/{request.json,run_local.py,README.md}
│   └── agent_workflow/{agent.yaml,workflow.yaml,simulate.py,README.md}
│
└── third_party/
    ├── patches/{README.md,patches.lock.json}
    ├── licenses/{README.md,license_inventory.json}
    ├── notices/{NOTICE.generated.txt}
    ├── source_mirrors/{README.md,sources.lock.json}
    ├── BUILD.bazel
    └── README.md
```

## 2. Organization `.github` repository

```text
.github/
├── .github/
│   ├── actions/
│   │   ├── validate-trusted-context/
│   │   │   ├── action.yml
│   │   │   └── README.md
│   │   ├── verify-pinned-actions/
│   │   │   ├── action.yml
│   │   │   └── README.md
│   │   └── publish-ci-evidence/
│   │       ├── action.yml
│   │       └── README.md
│   ├── workflows/
│   │   ├── reusable-buildkite-dispatch.yml
│   │   ├── reusable-required-check.yml
│   │   ├── reusable-metadata-validation.yml
│   │   ├── reusable-documentation-check.yml
│   │   ├── reusable-dependency-review.yml
│   │   ├── reusable-codeql.yml
│   │   ├── reusable-scorecard.yml
│   │   └── self-test.yml
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug.yml
│   │   ├── security-control-gap.yml
│   │   ├── architecture-change.yml
│   │   ├── scientific-correctness.yml
│   │   └── config.yml
│   ├── CODEOWNERS
│   ├── dependabot.yml
│   └── pull_request_template.md
├── profile/
│   └── README.md
├── workflow-templates/
│   ├── buildkite-bridge.yml
│   ├── buildkite-bridge.properties.json
│   ├── repository-metadata.yml
│   └── repository-metadata.properties.json
├── schemas/
│   ├── trusted_context.schema.json
│   └── ci_evidence.schema.json
├── policy/
│   ├── action_pinning.rego
│   ├── workflow_permissions.rego
│   ├── reusable_workflow_interface.rego
│   └── tests/
│       ├── action_pinning_test.rego
│       ├── workflow_permissions_test.rego
│       └── reusable_workflow_interface_test.rego
├── tests/
│   ├── fixtures/
│   │   ├── trusted_pull_request.json
│   │   ├── untrusted_pull_request.json
│   │   └── protected_release.json
│   ├── test_reusable_workflow_contract.py
│   ├── test_declared_permissions.py
│   └── test_action_digest_pinning.py
├── tools/
│   ├── validate_reusable_workflows.py
│   └── emit_ci_evidence.py
├── BUILD.bazel
├── MODULE.bazel
├── component.yaml
├── justfile
├── .editorconfig
├── .gitignore
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── GOVERNANCE.md
├── LICENSE
├── README.md
├── SECURITY.md
└── SUPPORT.md
```

## 3. `github-config` repository

```text
github-config/
├── .github/
│   ├── workflows/
│   │   ├── pull-request.yml
│   │   ├── drift-detection.yml
│   │   └── protected-apply.yml
│   ├── CODEOWNERS
│   ├── dependabot.yml
│   └── pull_request_template.md
├── config/
│   ├── organization.yaml
│   ├── actions-policy.yaml
│   ├── security-policy.yaml
│   ├── oidc-policy.yaml
│   ├── members.yaml
│   ├── outside-collaborators.yaml
│   ├── teams/
│   │   ├── architecture.yaml
│   │   ├── biological-safety.yaml
│   │   ├── computational-biology.yaml
│   │   ├── data-platform.yaml
│   │   ├── developer-platform.yaml
│   │   ├── ml-systems.yaml
│   │   ├── platform-operations.yaml
│   │   ├── product-engineering.yaml
│   │   ├── release-engineering.yaml
│   │   └── security.yaml
│   ├── repositories/
│   │   ├── dot-github.yaml
│   │   ├── github-config.yaml
│   │   ├── bootstrap.yaml
│   │   ├── infrastructure-live.yaml
│   │   ├── gitops.yaml
│   │   └── mindclade.yaml
│   ├── rulesets/
│   │   ├── application-source.yaml
│   │   ├── governance-source.yaml
│   │   ├── infrastructure-source.yaml
│   │   ├── deployment-source.yaml
│   │   └── release-tags.yaml
│   ├── environments/
│   │   ├── trusted-build.yaml
│   │   ├── release-signing.yaml
│   │   ├── infrastructure-apply.yaml
│   │   └── production-promotion.yaml
│   └── integrations/
│       ├── buildkite.yaml
│       ├── artifact-signing.yaml
│       └── gitops-controller.yaml
├── schemas/v1/
│   ├── organization.schema.json
│   ├── actions_policy.schema.json
│   ├── security_policy.schema.json
│   ├── oidc_policy.schema.json
│   ├── membership.schema.json
│   ├── team.schema.json
│   ├── repository.schema.json
│   ├── ruleset.schema.json
│   ├── environment.schema.json
│   └── integration.schema.json
├── compiler/
│   ├── cmd/github-configctl/main.go
│   ├── internal/catalog/catalog.go
│   ├── internal/validation/validation.go
│   ├── internal/rendering/rendering.go
│   ├── internal/diff/github_diff.go
│   ├── internal/evidence/plan_evidence.go
│   ├── go.mod
│   ├── go.sum
│   └── BUILD.bazel
├── opentofu/
│   ├── modules/
│   │   ├── organization-settings/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── repository-governance/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── team-access/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── ruleset/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   └── repository-environment/
│   │       ├── main.tf
│   │       ├── variables.tf
│   │       └── outputs.tf
│   └── live/organization/
│       ├── backend.tf
│       ├── versions.tf
│       ├── providers.tf
│       ├── main.tf
│       ├── imports.tf
│       └── outputs.tf
├── policy/
│   ├── least_privilege.rego
│   ├── protected_rulesets.rego
│   ├── workflow_sources.rego
│   ├── oidc_subjects.rego
│   ├── environment_approvals.rego
│   └── tests/
│       ├── least_privilege_test.rego
│       ├── protected_rulesets_test.rego
│       ├── workflow_sources_test.rego
│       ├── oidc_subjects_test.rego
│       └── environment_approvals_test.rego
├── tests/
│   ├── contract/
│   │   ├── test_catalog_schema.py
│   │   └── test_compiler_determinism.py
│   ├── plan/
│   │   ├── test_ruleset_plan.py
│   │   └── test_permission_reduction.py
│   ├── drift/
│   │   └── test_observed_state_diff.py
│   └── recovery/
│       └── test_last_known_good_restore.py
├── runbooks/
│   ├── unauthorized-settings-change.md
│   ├── oidc-policy-lockout.md
│   ├── compromised-github-app.md
│   └── governance-state-restore.md
├── BUILD.bazel
├── MODULE.bazel
├── component.yaml
├── justfile
├── .editorconfig
├── .gitignore
├── LICENSE
├── README.md
└── SECURITY.md
```

## 4. `bootstrap` repository

```text
bootstrap/
├── .github/
│   ├── workflows/
│   │   ├── pull-request.yml
│   │   ├── recovery-verification.yml
│   │   └── protected-apply.yml
│   ├── CODEOWNERS
│   ├── dependabot.yml
│   └── pull_request_template.md
├── manifests/
│   ├── trust-anchors.yaml
│   ├── state-backends.yaml
│   ├── identity-federation.yaml
│   ├── signing-roots.yaml
│   ├── audit-roots.yaml
│   ├── break-glass-roles.yaml
│   └── recovery-policy.yaml
├── schemas/v1/
│   ├── trust_anchor.schema.json
│   ├── state_backend.schema.json
│   ├── federation.schema.json
│   ├── signing_root.schema.json
│   ├── audit_root.schema.json
│   ├── break_glass.schema.json
│   └── recovery_policy.schema.json
├── opentofu/
│   ├── modules/
│   │   ├── state-backend/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── audit-root/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── workforce-identity/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── github-federation/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── buildkite-federation/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── gitops-federation/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── signing-root/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── break-glass/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   └── recovery-exports/
│   │       ├── main.tf
│   │       ├── variables.tf
│   │       └── outputs.tf
│   └── live/
│       ├── root-trust/
│       │   ├── backend.tf
│       │   ├── versions.tf
│       │   ├── providers.tf
│       │   ├── main.tf
│       │   └── outputs.tf
│       └── recovery-plane/
│           ├── backend.tf
│           ├── versions.tf
│           ├── providers.tf
│           ├── main.tf
│           └── outputs.tf
├── policy/
│   ├── root_separation.rego
│   ├── federation_claims.rego
│   ├── key_administration.rego
│   ├── state_protection.rego
│   ├── break_glass.rego
│   └── tests/
│       ├── root_separation_test.rego
│       ├── federation_claims_test.rego
│       ├── key_administration_test.rego
│       ├── state_protection_test.rego
│       └── break_glass_test.rego
├── recovery/
│   ├── restore-manifest.yaml
│   ├── independent-contact-procedure.md
│   ├── offline-evidence-procedure.md
│   └── quarterly-drill-procedure.md
├── tests/
│   ├── contract/test_manifest_schemas.py
│   ├── plan/test_minimum_privilege.py
│   ├── failure/test_partial_bootstrap_apply.py
│   └── recovery/test_isolated_restore.py
├── tooling/
│   ├── cmd/bootstrapctl/main.go
│   ├── internal/manifest/manifest.go
│   ├── internal/plan/plan.go
│   ├── internal/evidence/evidence.go
│   ├── internal/recovery/recovery.go
│   ├── go.mod
│   ├── go.sum
│   └── BUILD.bazel
├── runbooks/
│   ├── state-backend-unavailable.md
│   ├── root-identity-compromise.md
│   ├── signing-root-recovery.md
│   └── break-glass-activation.md
├── BUILD.bazel
├── MODULE.bazel
├── component.yaml
├── justfile
├── .editorconfig
├── .gitignore
├── LICENSE
├── README.md
└── SECURITY.md
```

## 5. `infrastructure-live` repository

```text
infrastructure-live/
├── .github/
│   ├── workflows/
│   │   ├── pull-request.yml
│   │   ├── drift-detection.yml
│   │   ├── protected-apply.yml
│   │   └── disaster-recovery.yml
│   ├── CODEOWNERS
│   ├── dependabot.yml
│   └── pull_request_template.md
├── catalog/
│   ├── environments.yaml
│   ├── regions.yaml
│   ├── project-classes.yaml
│   ├── data-classes.yaml
│   ├── resource-profiles.yaml
│   ├── accelerator-profiles.yaml
│   └── service-capabilities.yaml
├── schemas/v1/
│   ├── environment.schema.json
│   ├── region.schema.json
│   ├── project_class.schema.json
│   ├── data_class.schema.json
│   ├── resource_profile.schema.json
│   ├── accelerator_profile.schema.json
│   ├── service_capability.schema.json
│   └── infrastructure_export.schema.json
├── opentofu/
│   ├── modules/gcp/
│   │   ├── project-factory/{main.tf,variables.tf,outputs.tf}
│   │   ├── shared-vpc/{main.tf,variables.tf,outputs.tf}
│   │   ├── private-dns/{main.tf,variables.tf,outputs.tf}
│   │   ├── controlled-egress/{main.tf,variables.tf,outputs.tf}
│   │   ├── artifact-registry/{main.tf,variables.tf,outputs.tf}
│   │   ├── artifact-bucket/{main.tf,variables.tf,outputs.tf}
│   │   ├── cloud-sql-postgres/{main.tf,variables.tf,outputs.tf}
│   │   ├── pubsub-transport/{main.tf,variables.tf,outputs.tf}
│   │   ├── secret-bindings/{main.tf,variables.tf,outputs.tf}
│   │   ├── delegated-kms/{main.tf,variables.tf,outputs.tf}
│   │   ├── gke-regional-cluster/{main.tf,variables.tf,outputs.tf}
│   │   ├── gke-node-pool/{main.tf,variables.tf,outputs.tf}
│   │   ├── workload-identity/{main.tf,variables.tf,outputs.tf}
│   │   ├── observability-backend/{main.tf,variables.tf,outputs.tf}
│   │   ├── buildkite-agents/{main.tf,variables.tf,outputs.tf}
│   │   └── argocd-management/{main.tf,variables.tf,outputs.tf}
│   ├── stacks/
│   │   ├── foundation/{main.tf,variables.tf,outputs.tf}
│   │   ├── network/{main.tf,variables.tf,outputs.tf}
│   │   ├── artifacts/{main.tf,variables.tf,outputs.tf}
│   │   ├── data-services/{main.tf,variables.tf,outputs.tf}
│   │   ├── clusters/{main.tf,variables.tf,outputs.tf}
│   │   ├── ci-execution/{main.tf,variables.tf,outputs.tf}
│   │   └── observability/{main.tf,variables.tf,outputs.tf}
│   └── live/
│       ├── development/
│       │   ├── foundation/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   ├── network/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   ├── artifacts/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   ├── data-services/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   ├── clusters/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   ├── ci-execution/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   └── observability/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       ├── staging/
│       │   ├── foundation/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   ├── network/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   ├── artifacts/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   ├── data-services/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   ├── clusters/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   ├── ci-execution/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   └── observability/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       ├── production/
│       │   ├── foundation/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   ├── network/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   ├── artifacts/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   ├── data-services/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   ├── clusters/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   ├── ci-execution/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       │   └── observability/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│       └── restricted/
│           ├── foundation/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│           ├── network/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│           ├── artifacts/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│           ├── data-services/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│           ├── clusters/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│           ├── ci-execution/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
│           └── observability/{backend.tf,versions.tf,providers.tf,main.tf,environment.auto.tfvars.json,outputs.tf}
├── policy/
│   ├── organization_constraints.rego
│   ├── network_boundaries.rego
│   ├── workload_identity.rego
│   ├── encryption_and_retention.rego
│   ├── database_recovery.rego
│   ├── gke_security.rego
│   ├── accelerator_isolation.rego
│   ├── cost_guardrails.rego
│   └── tests/
│       ├── organization_constraints_test.rego
│       ├── network_boundaries_test.rego
│       ├── workload_identity_test.rego
│       ├── encryption_and_retention_test.rego
│       ├── database_recovery_test.rego
│       ├── gke_security_test.rego
│       ├── accelerator_isolation_test.rego
│       └── cost_guardrails_test.rego
├── tests/
│   ├── contract/test_environment_plan.py
│   ├── plan/test_development_plan.py
│   ├── plan/test_staging_plan.py
│   ├── plan/test_production_plan.py
│   ├── security/test_cross_environment_denial.py
│   ├── failure/test_partial_apply_reconciliation.py
│   ├── drift/test_cloud_drift_classification.py
│   ├── recovery/test_database_restore.py
│   ├── recovery/test_artifact_restore.py
│   └── capacity/test_accelerator_profile.py
├── tooling/
│   ├── cmd/infractl/main.go
│   ├── internal/catalog/catalog.go
│   ├── internal/plan/plan.go
│   ├── internal/policy/policy.go
│   ├── internal/drift/drift.go
│   ├── internal/exports/exports.go
│   ├── go.mod
│   ├── go.sum
│   └── BUILD.bazel
├── runbooks/
│   ├── infrastructure-apply-failure.md
│   ├── cloud-drift.md
│   ├── network-isolation-failure.md
│   ├── cluster-control-plane-failure.md
│   ├── database-failover-and-restore.md
│   ├── artifact-storage-recovery.md
│   └── regional-recovery.md
├── BUILD.bazel
├── MODULE.bazel
├── component.yaml
├── justfile
├── .editorconfig
├── .gitignore
├── LICENSE
├── README.md
└── SECURITY.md
```

## 6. `gitops` repository

```text
gitops/
├── .github/
│   ├── workflows/
│   │   ├── pull-request.yml
│   │   ├── promotion.yml
│   │   ├── drift-detection.yml
│   │   └── rollback-verification.yml
│   ├── CODEOWNERS
│   ├── dependabot.yml
│   └── pull_request_template.md
├── controllers/
│   ├── argocd/
│   │   ├── namespace.yaml
│   │   ├── repository-credentials-reference.yaml
│   │   ├── notifications.yaml
│   │   ├── resource-customizations.yaml
│   │   └── kustomization.yaml
│   └── applicationsets/
│       ├── platform-components.yaml
│       ├── control-plane-services.yaml
│       ├── execution-workers.yaml
│       └── environment-root.yaml
├── projects/
│   ├── platform.appproject.yaml
│   ├── services.appproject.yaml
│   ├── workers.appproject.yaml
│   └── restricted.appproject.yaml
├── platform/
│   ├── kueue/{release.yaml,values.yaml,kustomization.yaml}
│   ├── jobset/{release.yaml,values.yaml,kustomization.yaml}
│   ├── otel-collector/{release.yaml,values.yaml,kustomization.yaml}
│   ├── external-secrets/{release.yaml,values.yaml,kustomization.yaml}
│   ├── policy-controller/{release.yaml,values.yaml,kustomization.yaml}
│   ├── gpu-operator/{release.yaml,values.yaml,kustomization.yaml}
│   └── ingress/{release.yaml,values.yaml,kustomization.yaml}
├── environments/
│   ├── development/
│   │   ├── cluster-set.yaml
│   │   ├── infrastructure-exports.yaml
│   │   ├── platform-releases.yaml
│   │   ├── service-releases.yaml
│   │   ├── worker-releases.yaml
│   │   ├── policy-bindings.yaml
│   │   ├── secret-references.yaml
│   │   └── kustomization.yaml
│   ├── staging/
│   │   ├── cluster-set.yaml
│   │   ├── infrastructure-exports.yaml
│   │   ├── platform-releases.yaml
│   │   ├── service-releases.yaml
│   │   ├── worker-releases.yaml
│   │   ├── policy-bindings.yaml
│   │   ├── secret-references.yaml
│   │   └── kustomization.yaml
│   ├── production/
│   │   ├── cluster-set.yaml
│   │   ├── infrastructure-exports.yaml
│   │   ├── platform-releases.yaml
│   │   ├── service-releases.yaml
│   │   ├── worker-releases.yaml
│   │   ├── policy-bindings.yaml
│   │   ├── secret-references.yaml
│   │   └── kustomization.yaml
│   └── restricted/
│       ├── cluster-set.yaml
│       ├── infrastructure-exports.yaml
│       ├── platform-releases.yaml
│       ├── service-releases.yaml
│       ├── worker-releases.yaml
│       ├── policy-bindings.yaml
│       ├── secret-references.yaml
│       └── kustomization.yaml
├── schemas/v1/
│   ├── cluster_set.schema.json
│   ├── infrastructure_exports.schema.json
│   ├── platform_releases.schema.json
│   ├── workload_releases.schema.json
│   ├── policy_bindings.schema.json
│   ├── secret_references.schema.json
│   └── promotion_receipt.schema.json
├── policy/
│   ├── signed_release.rego
│   ├── immutable_digest.rego
│   ├── approved_environment.rego
│   ├── destination_allowlist.rego
│   ├── secret_reference.rego
│   ├── rollout_safety.rego
│   └── tests/
│       ├── signed_release_test.rego
│       ├── immutable_digest_test.rego
│       ├── approved_environment_test.rego
│       ├── destination_allowlist_test.rego
│       ├── secret_reference_test.rego
│       └── rollout_safety_test.rego
├── tests/
│   ├── render/test_development_render.py
│   ├── render/test_staging_render.py
│   ├── render/test_production_render.py
│   ├── render/test_restricted_render.py
│   ├── promotion/test_evidence_chain.py
│   ├── promotion/test_schema_compatibility.py
│   ├── failure/test_partial_sync.py
│   ├── rollback/test_previous_digest.py
│   └── drift/test_live_object_diff.py
├── tooling/
│   ├── cmd/promotectl/main.go
│   ├── internal/release/verification.go
│   ├── internal/rendering/rendering.go
│   ├── internal/policy/policy.go
│   ├── internal/promotion/promotion.go
│   ├── internal/rollback/rollback.go
│   ├── internal/evidence/receipt.go
│   ├── go.mod
│   ├── go.sum
│   └── BUILD.bazel
├── runbooks/
│   ├── argocd-unavailable.md
│   ├── failed-synchronization.md
│   ├── deployment-drift.md
│   ├── compromised-release.md
│   ├── emergency-rollback.md
│   └── cluster-rebootstrap.md
├── BUILD.bazel
├── MODULE.bazel
├── component.yaml
├── justfile
├── .editorconfig
├── .gitignore
├── LICENSE
├── README.md
└── SECURITY.md
```

## Authority notes

- `mindclade/` owns product source, contracts, build metadata, release packages, repository-local CI, developer tooling, and architectural documentation.
- Organization `.github` owns reusable workflow implementations, policy workflow entry points, issue forms, community health, and governance automation.
- `github-config/` owns declarative GitHub organization and repository settings reconciled by an authenticated bot.
- `bootstrap/` owns one-time and rare identity, state-backend, key, workload-identity, and break-glass foundations.
- `infrastructure-live/` owns environment-specific infrastructure composition, reviewed plans, and applied infrastructure state references.
- `gitops/` owns desired cluster application state and promotion-by-digest; it does not build artifacts.
- Namespace declarations do not authorize empty directories. A path activates only with a named owner, applicable stub profile, real build target, tests, and implementation-wave approval.
