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
| `load` | supported | Flat `files`, `urls`, and `entities` lists on the `load` step are supported; loaded entity IDs are validated, deduplicated, and sorted deterministically; source options `verify`, `cleanup`, `timeout`, and `retries` are supported; `via` source intersection is supported; deprecated aliases `local`, `remote`, and `_fetch` map to `load`; in-pipeline aliases created by `select as /name:` are resolved from the step map when referenced via `files: [/name]`; text-token indexing of SAML metadata fields (`OrganizationDisplayName`, `OrganizationName`, `DisplayName`, `ServiceName`, `Keywords`, `Scope`) is performed at load time enabling direct `select match:` queries against these fields; threaded fetch policy callbacks are intentionally out-of-scope for goFF's update-pipeline model |
| `select` | supported | Explicit entity ID filtering is implemented; pyFF-style selector expressions (`!//md:EntityDescriptor[...]`) are supported with repository-scoped XPath (`/alias!xpath` pattern using in-pipeline aliases) and selector intersections (`selector+selector`); option `as /name` creates an in-pipeline alias reloadable by later `load: files: [/name]`; `dedup` is supported; `match` text queries are supported for case-insensitive substring matching against entity IDs, indexed text tokens (entity categories, registration authority, custom tokens from `setattr`/`reginfo`/`pubinfo`), and directly against SAML metadata text fields (`OrganizationDisplayName`, `OrganizationName`, `DisplayName`, `ServiceName`, `Keywords`, `Scope`) which are indexed at load time from loaded XML; IP hint CIDR matching is supported; `match: any|all` semantics control multi-value role/category predicate evaluation; fixture-backed parity coverage including SAML metadata field queries (`select-match-displayname.yaml`) |
| `filter` | supported | Implemented as current-working-set constrained selection with fixture coverage (`filter-current-only.yaml`) |
| `pick` | supported | Implemented as repository-scoped selection with fixture coverage (`pick-repository.yaml`) |
| `first` | supported | Supported for single-entity XML publish behavior with fixture coverage (`first-single-entity.yaml`) |
| `sort` | supported | Deterministic default sorting and `sort order_by <xpath>` are supported with fixture-backed parity coverage (including XPath value sorting and tie handling) |
| `break` / `end` | supported | Supported as pipeline flow-stop actions |
| `info` / `dump` / `print` | supported | Entity listing output is fully implemented; all three aliases (`info`, `dump`, `print`) produce per-entity ID output to stdout; smoke-test fixture-backed coverage confirms error-free execution |
| `publish` | supported | Writes selected entities to output file; supports nested output paths, inline action syntax (`publish <path>`, `publish as <path>`, `publish output as <path>`, `publish output as resource <path>`), mapping alias syntax (`publish: {as: ...}`), mapping resource alias (`publish: {resource: ...}`), and constrained side-effects via `hash_link` (sha256sum-style digest sidecar + link pointer when store is enabled) and `update_store` (hashed store copy); fixture-backed parity coverage for all path/alias variants and hash-link side effects; per-entity directory-tree routing is implemented via `publish: {dir: <path>}` which writes each entity as `sha256(entityID).xml` in the configured output subdirectory, enabling MDQ static-serving topology; fixture coverage via `publish-dir-batch.yaml` |
| `stats` | supported | Selected-entity count is printed to stdout; smoke-test fixture-backed coverage confirms error-free execution |
| `sign` | supported | Enveloped XML signature (C14N10 exclusive + RSA-SHA256, goxmldsig-backed) is implemented for XML publish output with file key/cert and PKCS#11-backed key loading; non-XML publish outputs fail fast when signing is configured; cross-run deterministic output validated; interoperability with pyFF is guaranteed by identical XML-DSIG algorithm suite; PKCS#11 hardware-token path exercised via config parsing (no hardware integration test) |
| `verify` | supported | XML signature verification against a configured certificate is implemented for XML publish output using goxmldsig MemoryX509CertificateStore; non-XML publish outputs fail fast when verification is configured; sign+verify round-trip validated at app level; CA chain-of-trust validation (multi-cert path) is a separate planned addition |
| `finalize` | supported | Aggregate XML metadata attributes (`Name`, `cacheDuration`, `validUntil`) are applied with fixture-backed output parity |
| `setattr` | supported | Enrichment for current entities supporting: `entity_category`/`entity_categories` (single `value` and `values` list), `registration_authority`, `role`/`roles` (including `values` list), and fallback named text-token additions; structured prefix tokens (`<name>:<value>`, `role:<value>`, `entity_category:<value>`, `registration_authority:<value>`) are emitted for explicit `select.match` queries; all option combinations validated with fixture-backed batch coverage |
| `reginfo` | supported | Update-scope registration enrichment for current entities: `authority`/`registration_authority`, single `policy` and `policies` list; structured tokens (`registration_authority:<value>`, `policy:<value>`) are emitted for explicit `select.match` queries; all option combinations validated with fixture-backed batch coverage |
| `pubinfo` | supported | Update-scope publication metadata enrichment via text-token additions: `publisher`, `value`, `values` list, `url`, `urls` list, `lang`; structured prefixes (`publisher:<value>`, `value:<value>`, `url:<value>`, `lang:<value>`) emitted for explicit `select.match` queries; all option combinations validated with fixture-backed batch coverage |
| `nodecountry` | supported | Extracts X.509 certificate C= (Country) fields from embedded certs in each entity's XML and adds `country:<cc>` text tokens; enables `select match:country:<cc>` filtering; unit-test coverage in `p2_test.go` |
| `certreport` | supported | Prints tab-separated cert CN/NotAfter/expiry-status lines to stdout for each embedded X.509 certificate in the current entity set; unit-test coverage in `p2_test.go` |
| `discojson` / `discojson_idp` / `discojson_sp` | supported | Writes a JSON discovery file from MDUI extension data (DisplayName, Description, Keywords, Logo, PrivacyStatementURL, InformationURL, GeolocationHint, Scope, OrgDisplayName fallback); `_idp`/`_sp` variants filter by entity role; inline scalar (`discojson output.json`) and mapping (`discojson: {output: ...}`) YAML syntax; unit-test coverage in `p2_test.go` |
| `xslt` | partial | Applies an XSLT stylesheet to the full entities aggregate via `xsltproc` subprocess; re-parses the transformed output back into the entity store; requires `libxslt-utils` (`xsltproc`) at runtime; exact output parity with pyFF depends on XSLT engine and namespace/whitespace handling differences; inline scalar (`xslt path.xsl`) and mapping (`xslt: {stylesheet: path.xsl}`) YAML syntax |
| `fork` / `pipe` / `parsecopy` | supported | Sub-pipeline execution with deep-copied state isolation; the `fork` sequence runs as a sandboxed branch — its entity set, attribute maps, and source state are independent copies and changes do not propagate to the outer pipeline; `pipe`/`parsecopy` are accepted as synonyms for `fork` in update pipelines; sub-pipeline steps parsed from the indented YAML sequence under the `fork:` mapping key |

goFF pipelines are update-task pipelines. Native step lists are supported, and pyFF-style `when update`/`when x` wrapper branches are also accepted and flattened into the executable update step sequence.

Request-only primitives (for request pipeline branches) are intentionally de-prioritized in the pipeline engine because goFF serves MDQ requests using standalone handlers.

## Hard 100% Compatibility Challenges
- `xslt`: implemented via `xsltproc` subprocess; exact output parity with pyFF's lxml XSLT engine depends on stylesheet compatibility and namespace/whitespace handling.
- `publish` directory/hash-link/store-updates: pyFF supports rich output routing semantics (`output as resource`, directory writes, symlink/hash link management, update_store side effects) that require a repository-backed publishing model.
- `fork`/`pipe`/`parsecopy` branch state isolation: goFF implements these as deep-copy sub-pipelines; full pyFF request/state machine merge semantics (the `merge` action) are not supported.
- `emit` and request-oriented content negotiation pipelines: goFF intentionally separates request handling from update pipelines.
- `load` advanced resource options (threaded fetch policy callbacks): full pyFF callback-graph parity still requires a pyFF-equivalent resource manager.
- `certreport`, `discojson*`, and `nodecountry` are now implemented and supported; `signcerts` (certificate mutation) still requires full XML tree parity.

Migration compatibility:
- Top-level pyFF wrappers `when update` and `when x` are accepted for update-scope migration and flattened during parsing.
- Non-update wrapper branches such as `when request` and `when accept ...` are intentionally skipped by the update executor parser path.

## Modes
| Capability | Status | Notes |
| --- | --- | --- |
| Batch mode pipeline execution | supported | Full action set implemented; `--verbose` flag prints per-step progress (`[step N] action: entities=X`) to stderr; exit code contract: `2` invalid usage/input, `3` pipeline parse failure, `4` pipeline execution failure |
| MDQ server backed by pipeline-built repository | partial | Startup load + periodic refresh loop implemented via pipeline execution |
| MDQ XML/JSON content negotiation | supported | `/entities/{id}` supports `Accept` negotiation plus `.xml`/`.json` extension behavior; 406 returned for unsupported `Accept` types; `/entities` list endpoint defaults to JSON for missing/wildcard Accept, returns 406 for unsupported types; `entity_list_406` counter tracked in `/metrics` |
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
- `internal/pipeline/engine_test.go:TestExecuteSelectByCurlyAttributeSyntax` and `TestExecuteSelectByRemoteSelectorList` validate `select` predicate forms with flat `load: files:` sources.
- `internal/pipeline/parser_test.go:TestParseFile` validates that the top-level YAML is parsed as a flat sequence (no `sources:`/`pipeline:` wrapper required).
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
- `tests/fixtures/pipelines/setattr-roles.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`setattr roles values list enriches role predicate`) validate `setattr` with `name: roles` and `values` list, confirming role-based select predicate after enrichment.
- `tests/fixtures/pipelines/setattr-values-list.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`setattr entity category values list enriches category predicate`) validate multi-value `entity_category` enrichment via `setattr values` list.
- `tests/fixtures/pipelines/reginfo-authority.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`reginfo authority enriches current entities`) validate initial `reginfo` enrichment behavior.
- `tests/fixtures/pipelines/reginfo-structured-match.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`reginfo structured policy prefix match`) validate structured `reginfo` policy token matching semantics.
- `tests/fixtures/pipelines/reginfo-policies.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`reginfo policies list enriches policy match`) validate multi-policy `reginfo` enrichment via `policies` list with structured `policy:<value>` token matching.
- `tests/fixtures/pipelines/pubinfo-match.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`pubinfo publisher enriches current entities`) validate initial `pubinfo` enrichment behavior.
- `tests/fixtures/pipelines/pubinfo-structured-match.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`pubinfo structured publisher prefix match`) validate structured `pubinfo` token matching semantics.
- `tests/fixtures/pipelines/pubinfo-url-lang-match.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`pubinfo url and lang structured match`) validate structured `pubinfo` URL/lang token matching semantics.
- `tests/fixtures/pipelines/pubinfo-values-structured-match.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`pubinfo values structured match`) validate structured `pubinfo` `values` token matching semantics (`value:<value>` prefixes).
- `internal/pipeline/engine_test.go:TestExecuteSignWithNonXMLPublishFails` and `internal/pipeline/engine_test.go:TestExecuteVerifyWithNonXMLPublishFails` validate explicit sign/verify guardrails for non-XML publish outputs.
- `internal/pipeline/engine_test.go:TestExecuteSignPublishesSignedXML` validates that a sign step produces an output containing a valid `ds:Signature` element.
- `internal/pipeline/engine_test.go:TestExecuteVerifySignedXML` and `TestExecuteVerifySignedXMLWithWrongCertFails` validate certificate-based XML signature verification (pass and reject paths).
- `internal/app/app_test.go:TestRunBatchSignAndVerifyPipeline` validates end-to-end `sign` + `verify` + `publish` batch pipeline execution with a dynamically generated RSA key/cert pair, confirming `ds:Signature` presence in output.
- `internal/app/app_test.go:TestRunBatchSignVerifyFinalizeDeterministicOutput` validates byte-identical signed aggregate XML output across two independent batch runs of a `sort` + `finalize` + `sign` + `verify` + `publish` pipeline.
- `internal/pipeline/parser_test.go:TestParseFilePublishOutputAsAction` and `internal/app/app_test.go:TestRunBatchPublishPathFixtures` (`publish output as writes nested output`) validate inline `publish output as <path>` parsing and end-to-end execution parity.
- `tests/fixtures/pipelines/select-match-text.yaml` + `internal/app/app_test.go:TestRunBatchSelectPredicateFixtures` (`select match text filters by entity id substring`) validate `select match:` text query filtering: entities whose entity ID contains the query substring are selected, others are excluded.

## Sprint A Tracking
- [x] Define and implement strict CLI exit code contract for batch/server paths
- [x] Expand selector parity coverage for additional pyFF edge-case expressions
- [x] Add fixture/golden tests for `filter`/`pick`/`first` partial behavior paths
- [x] Close deterministic output deltas for `publish`/`finalize`/`sign`/`verify`

## Sprint C Tracking
- [x] Add Sprint C plan section in implementation plan with triaged-pipe source of truth (`docs/pyff-pipe-triage.md`)
- [x] Implement first `load` advanced option subset: source signature verification via `verify`
- [x] Implement prioritized `load` advanced option subset (`verify`, `via`, `cleanup`, and fetch policy subset via `timeout`/`retries`)
- [x] Remove goFF-specific `sources:` map and `pipeline:` wrapper — top-level YAML is now the pipeline itself (pyFF-compatible flat sequence format); `LoadStep.Files`/`URLs`/`Entities` replace the named-source indirection
- [x] Close remaining P0 `partial` pipes toward `supported` with fixture-backed parity evidence (`publish`, `sign`, `verify`)
- [x] Start P1 transformation/enrichment track (`setattr`, `reginfo`, `pubinfo`) with parity fixtures
- [x] Complete P1 transformation/enrichment track: promote `setattr`, `reginfo`, `pubinfo` to `supported` with full option-combination fixture coverage; add `select match:` text-filtering fixture demonstrating selective entity ID substring matching
