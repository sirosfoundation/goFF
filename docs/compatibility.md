# pyFF Compatibility Matrix

This document tracks pyFF pipeline feature compatibility in `goFF`.

## Status Legend
- `supported`: behavior implemented and parity-tested
- `partial`: implemented with documented differences
- `planned`: not implemented yet but explicitly targeted
- `not-supported`: intentionally not implemented

## Pipeline Actions
| Action | Status | Notes |
| --- | --- | --- |
| `load` | partial | Named source loading, pyFF-style list arguments, and source-backed metadata loading from `files` and `urls` are implemented; loaded entity IDs are validated, deduplicated, and sorted deterministically; source options `verify`, `cleanup`, `timeout`, and `retries` are supported; deprecated aliases `local`, `remote`, and `_fetch` map to `load` |
| `select` | partial | Explicit entity ID filtering is implemented; pyFF-style selector expressions (`!//md:EntityDescriptor[...]`) are supported with repository-scoped XPath (`source!xpath`, including `as` aliases) and selector intersections (`selector+selector`); options `as` (synthetic alias for later `load.source`) and `dedup` are supported; pyFF-like `match` query behavior is partially supported for case-insensitive text tokens and IP hint network matching; predicates are supported for `role`/`roles`, `entity_category`/`entity_categories`, and `registration_authority` (with `match: any|all` for role/category lists) for metadata loaded from files/urls |
| `filter` | supported | Implemented as current-working-set constrained selection with fixture coverage (`filter-current-only.yaml`) |
| `pick` | supported | Implemented as repository-scoped selection with fixture coverage (`pick-repository.yaml`) |
| `first` | supported | Supported for single-entity XML publish behavior with fixture coverage (`first-single-entity.yaml`) |
| `sort` | supported | Deterministic default sorting and `sort order_by <xpath>` are supported with fixture-backed parity coverage (including XPath value sorting and tie handling) |
| `break` / `end` | supported | Supported as pipeline flow-stop actions |
| `info` / `dump` / `print` | partial | Basic entity listing output is supported |
| `publish` | partial | Writes selected entities to output file; supports nested output paths, inline action syntax (`publish <path>`, `publish as <path>`, `publish output as <path>`, `publish output as resource <path>`), mapping alias syntax (`publish: {as: ...}`), mapping resource alias (`publish: {resource: ...}`), and constrained side-effects via `hash_link` (sha256sum-style digest sidecar + link pointer when store is enabled) and `update_store` (hashed store copy) |
| `stats` | partial | Basic selected-entity count output is implemented |
| `sign` | partial | Enveloped XML signature using `vc/pkg/pki` is implemented for XML publish output (file key/cert and PKCS#11-backed key loading); non-XML publish outputs now fail fast when signing is configured |
| `verify` | partial | XML signature verification against a configured certificate is implemented for XML publish output; non-XML publish outputs now fail fast when verification is configured |
| `finalize` | supported | Aggregate XML metadata attributes (`Name`, `cacheDuration`, `validUntil`) are applied with fixture-backed output parity |
| `setattr` | partial | Initial enrichment support for current entities: `entity_category`/`entity_categories`, `registration_authority`, `role`/`roles`, and fallback text-token additions, with structured prefix tokens for explicit `select.match` queries (`<name>:<value>`, `role:<value>`, `entity_category:<value>`, `registration_authority:<value>`) |
| `reginfo` | partial | Initial update-scope registration enrichment for current entities (`authority` / `registration_authority`) with structured policy tokens (`policy`, `policies`, plus `policy:<value>` query-friendly prefixes) |
| `pubinfo` | partial | Initial update-scope publication metadata enrichment via text-token additions (`publisher`, `value`, `values`, `url`, `urls`, `lang`) for current entities, including structured query-friendly prefixes (`publisher:<value>`, `value:<value>`, `url:<value>`, `lang:<value>`) |

goFF pipelines are update-task pipelines. Native step lists are supported, and pyFF-style `when update`/`when x` wrapper branches are also accepted and flattened into the executable update step sequence.

Request-only primitives (for request pipeline branches) are intentionally de-prioritized in the pipeline engine because goFF serves MDQ requests using standalone handlers.

## Hard 100% Compatibility Challenges
- `xslt`: pyFF relies on lxml XSLT behavior and bundled stylesheets; exact output parity depends on XSLT engine differences and namespace/whitespace handling.
- `publish` directory/hash-link/store-updates: pyFF supports rich output routing semantics (`output as resource`, directory writes, symlink/hash link management, update_store side effects) that require a repository-backed publishing model.
- `fork`/`pipe` flow control (`merge`, `parsecopy`, `break`, nested branch state): exact execution parity requires full pyFF request/state machine semantics.
- `emit` and request-oriented content negotiation pipelines: goFF intentionally separates request handling from update pipelines.
- `load` advanced resource options (`via`, threaded fetch policy callbacks): full pyFF callback-graph parity still requires a pyFF-equivalent resource manager.
- Certificate/report pipes (`certreport`, `signcerts`) and transformation helpers (`discojson*`, `reginfo`, `pubinfo`, `setattr`, `nodecountry`) need full XML tree mutation/reporting parity and equivalent extension handling.

Migration compatibility:
- Top-level pyFF wrappers `when update` and `when x` are accepted for update-scope migration and flattened during parsing.
- Non-update wrapper branches such as `when request` and `when accept ...` are intentionally skipped by the update executor parser path.

## Modes
| Capability | Status | Notes |
| --- | --- | --- |
| Batch mode pipeline execution | partial | Parser and executor implemented for initial action subset; exit code contract is now explicit: `2` invalid usage/input, `3` pipeline parse failure, `4` pipeline execution failure |
| MDQ server backed by pipeline-built repository | partial | Startup load + periodic refresh loop implemented via pipeline execution |
| MDQ XML/JSON content negotiation | partial | `/entities/{id}` supports `Accept` negotiation plus `.xml`/`.json` extension behavior |
| Health/readiness and operational counters | partial | `/healthz` and `/readyz` are available; `/metrics` returns request counters plus server/refresh metrics |
| pyFF-equivalent server-mode pipeline response handling | not-supported | Explicit simplification from specs |

## CLI Exit Code Contract
- `0`: success
- `1`: unclassified runtime error
- `2`: invalid usage or missing/invalid required input
- `3`: pipeline parse/load failure
- `4`: pipeline execution failure
- `5`: server runtime failure (startup/listen/shutdown path)

## Test Evidence
- `tests/fixtures/pipelines/filter-current-only.yaml` validates `filter` operates on current working set.
- `tests/fixtures/pipelines/pick-repository.yaml` validates `pick` can select from repository scope.
- `tests/fixtures/pipelines/first-single-entity.yaml` validates `first` + `publish` emits single `EntityDescriptor` XML.
- `tests/fixtures/pipelines/select-dedup-false-alias.yaml` validates selector edge behavior for `dedup: false` (duplicate retention) with repository-scoped selector members.
- `tests/fixtures/pipelines/select-alias-reload.yaml` validates `select as` synthetic source alias can be reloaded by later `load.source`.
- `internal/app/app_test.go:TestRunBatchSignVerifyFinalizeDeterministicOutput` validates byte-identical output across two batch runs for combined `sort` + `finalize` + `sign` + `verify` + `publish`.
- `internal/app/server_test.go:TestRunServerServesHealthz` validates `/healthz`, `/readyz`, and `/metrics` availability and payload sections.
- `internal/mdq/server_test.go:TestReadyz` and `internal/mdq/server_test.go:TestMetrics` validate readiness transitions and request counter payload generation.
- `internal/pipeline/metadata_load_test.go:TestLoadSourceDataVerifyFailsForUnsignedSource` and `internal/pipeline/metadata_load_test.go:TestLoadSourceDataVerifyPassesForSignedSource` validate `sources[].verify` signature verification behavior for load-time source ingestion.
- `internal/pipeline/metadata_load_test.go:TestLoadSourceDataURLRetriesEventuallySucceeds` validates source URL retry policy (`retries`) for transient upstream failures.
- `internal/pipeline/metadata_load_test.go:TestLoadSourceDataCleanupSkipsBrokenFile` validates source cleanup behavior (`cleanup: true`) by skipping broken source files while still ingesting valid sources.
- `internal/pipeline/parser_test.go:TestParseFileSupportsWhenUpdateWrapper` and `internal/pipeline/parser_test.go:TestParseFileSkipsNonUpdateWhenBranches` validate pyFF `when` wrapper parsing behavior for update scope.
- `internal/pipeline/engine_test.go:TestExecuteLoadViaIntersectsWithViaSource` validates `load.via` source intersection behavior.
- `internal/app/app_test.go:TestRunBatchWhenWrapperFixtures` plus fixtures `tests/fixtures/pipelines/when-update-batch.yaml` and `tests/fixtures/pipelines/when-x-batch.yaml` validate end-to-end batch execution of `when update` and `when x` wrappers (with request/accept branches ignored).
- `internal/pipeline/parser_test.go:TestParseFilePublishInlineOutput` and `internal/pipeline/parser_test.go:TestParseFilePublishAsActionOption` validate inline publish syntax parsing.
- `internal/pipeline/engine_test.go:TestExecutePublishCreatesNestedDirectories` validates nested output-path publishing.
- `internal/pipeline/parser_test.go:TestParseFilePublishMappingAs` and `internal/pipeline/engine_test.go:TestExecutePublishMappingAsWritesOutput` validate mapping-style publish alias syntax (`as`) and output resolution.
- `internal/app/app_test.go:TestRunBatchPublishPathFixtures` plus fixtures `tests/fixtures/pipelines/publish-inline-batch.yaml`, `tests/fixtures/pipelines/publish-mapping-as-batch.yaml`, and `tests/fixtures/pipelines/publish-mapping-resource.yaml` validate end-to-end batch publish path semantics for inline shorthand and mapping `as`/`resource` forms.
- `internal/pipeline/parser_test.go:TestParseFilePublishOutputAsResourceAction` and `internal/pipeline/engine_test.go:TestExecutePublishResourceWritesOutput` validate constrained `publish output as resource` compatibility parsing/execution.
- `internal/pipeline/parser_test.go:TestParseFilePublishMappingResource` validates mapping-form publish resource parsing (`publish: {resource: ...}`).
- `internal/pipeline/engine_test.go:TestExecutePublishHashLinkWritesDigestFile`, `internal/pipeline/engine_test.go:TestExecutePublishUpdateStoreWritesHashedCopy`, and `internal/app/app_test.go:TestRunBatchPublishHashAndStoreSideEffects` validate constrained publish side-effect semantics (`hash_link`, `update_store`, `store_dir`).
- `internal/pipeline/engine_test.go:TestExecutePublishHashAndStoreWritesLinkPointer` validates link-pointer topology output (`<output>.link`) when both `hash_link` and `update_store` are enabled.
- `internal/app/app_test.go:TestRunBatchSortAndFinalizeFixtures` plus fixtures `tests/fixtures/pipelines/sort-default-batch.yaml`, `tests/fixtures/pipelines/sort-xpath-batch.yaml`, and `tests/fixtures/pipelines/finalize-xml.yaml` validate end-to-end batch parity for sort/finalize outputs.
- `tests/fixtures/pipelines/setattr-category.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`setattr category enriches current entities`) validate initial `setattr` enrichment behavior.
- `tests/fixtures/pipelines/setattr-structured-match.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`setattr structured prefix match`) validate structured `setattr` prefix token matching semantics.
- `tests/fixtures/pipelines/reginfo-authority.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`reginfo authority enriches current entities`) validate initial `reginfo` enrichment behavior.
- `tests/fixtures/pipelines/reginfo-structured-match.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`reginfo structured policy prefix match`) validate structured `reginfo` policy token matching semantics.
- `tests/fixtures/pipelines/pubinfo-match.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`pubinfo publisher enriches current entities`) validate initial `pubinfo` enrichment behavior.
- `tests/fixtures/pipelines/pubinfo-structured-match.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`pubinfo structured publisher prefix match`) validate structured `pubinfo` token matching semantics.
- `tests/fixtures/pipelines/pubinfo-url-lang-match.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`pubinfo url and lang structured match`) validate structured `pubinfo` URL/lang token matching semantics.
- `tests/fixtures/pipelines/pubinfo-values-structured-match.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`pubinfo values structured match`) validate structured `pubinfo` `values` token matching semantics (`value:<value>` prefixes).
- `internal/pipeline/engine_test.go:TestExecuteSignWithNonXMLPublishFails` and `internal/pipeline/engine_test.go:TestExecuteVerifyWithNonXMLPublishFails` validate explicit sign/verify guardrails for non-XML publish outputs.
- `internal/pipeline/parser_test.go:TestParseFilePublishOutputAsAction` and `internal/app/app_test.go:TestRunBatchPublishPathFixtures` (`publish output as writes nested output`) validate inline `publish output as <path>` parsing and end-to-end execution parity.

## Sprint A Tracking
- [x] Define and implement strict CLI exit code contract for batch/server paths
- [x] Expand selector parity coverage for additional pyFF edge-case expressions
- [x] Add fixture/golden tests for `filter`/`pick`/`first` partial behavior paths
- [x] Close deterministic output deltas for `publish`/`finalize`/`sign`/`verify`

## Sprint C Tracking
- [x] Add Sprint C plan section in implementation plan with triaged-pipe source of truth (`docs/pyff-pipe-triage.md`)
- [x] Implement first `load` advanced option subset: source signature verification via `sources[].verify`
- [x] Implement prioritized `load` advanced option subset (`verify`, `via`, `cleanup`, and fetch policy subset via `timeout`/`retries`)
- [ ] Close remaining P0 `partial` pipes toward `supported` with fixture-backed parity evidence (`publish`, `sign`, `verify`)
- [x] Start P1 transformation/enrichment track (`setattr`, `reginfo`, `pubinfo`) with parity fixtures
