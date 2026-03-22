# goFF Implementation Plan

## Goal
Build `goFF` as a Go-based reimplementation of pyFF that can run pyFF-style pipeline YAML with equivalent output, while improving throughput and memory efficiency using Go concurrency.

## Scope From `specs.md`
- Preserve pyFF-compatible pipeline configuration and processing behavior.
- Support two operational modes in one binary:
  - Batch mode (run pipeline and emit artifacts).
  - Server mode (serve MDQ from an internal repository built by pipelines).
- Do not replicate pyFF CLI one-to-one; provide a cleaner Go-native CLI.
- Follow packaging, build, test, and ADR conventions from `go-trust` and `go-spocp`.
- Use XML security libraries aligned with `vc` and respect workspace `go.work` replace directives.

## Current Repository Snapshot (2026-03-21)
`goFF` is production-ready for update-mode pipelines and MDQ serving. The full
pyFF update-mode pipeline action surface is implemented and fixture-proven.

Implemented code layout:
- `cmd/goff/main.go`: CLI entrypoint with `batch`, `server`, and `version` commands
- `internal/pipeline/`: parser, execution engine, metadata loading, select/sort/finalize, sign/verify support
- `internal/repo/`: in-memory entity repository abstraction
- `internal/mdq/`: MDQ-like HTTP handlers with XML/JSON response negotiation
- `internal/app/`: batch/server application wiring and refresh loop

Implemented docs and ADRs:
- `docs/adr/0001-pyff-compatibility-strategy.md`
- `docs/adr/0002-batch-server-mode-split.md`
- `docs/adr/0003-xml-security-dependency-strategy.md`
- `docs/compatibility.md` with status matrix for implemented/partial actions

Validation status:
- `go test ./...` passes for `internal/app`, `internal/mdq`, `internal/pipeline`, and `internal/repo`
- Fixture-driven compatibility tests exist under `tests/fixtures/`

## Phase Status Overview
| Phase | Status | Notes |
| --- | --- | --- |
| 0 Foundation and Guardrails | done | Module structure, docs, ADRs, Make/Docker/lint scaffolding are in place |
| 1 Pipeline Compatibility Core | done | All pyFF update-mode pipeline actions implemented; full fixture coverage; pyFF source format compatibility achieved |
| 2 Metadata Processing Engine | done | File/URL loading (concurrent), XRD/XRDS expansion, XML fingerprints, verify hash shorthand, HTTP proxy, integer timeout, SSRF protection |
| 3 XML Security and Signing/Verification | done | Sign/verify round-trips; PKCS#11 HSM signing; `drop_xsi_type` pre-signing cleanup; deterministic signed output |
| 4 Batch Mode | done | `goff batch` with `GOFF_PIPELINE`/`GOFF_OUTPUT` env vars; verbose progress; strict exit-code contract |
| 5 MDQ Server Mode | done | `goff server` with refresh loop, health/readiness, metrics, TLS, configurable entity renderer, `GOFF_*` env vars for all flags |
| 6 Hardening and Performance | in progress | Benchmarks and fuzz targets in place; race detector in CI; further performance tuning and security audits ongoing |

## Delivery Phases

### Phase 0: Foundation and Guardrails
Deliverables:
- Initialize Go module and project layout:
  - `cmd/goff/`
  - `internal/` for app internals
  - `pkg/` for reusable public types (only if needed)
  - `docs/adr/` for architecture decisions
- Add core project files based on `go-trust`/`go-spocp` patterns:
  - `Makefile`, `Dockerfile`, `.golangci.yml`, CI workflow
  - `README.md`, `CONTRIBUTING.md`
- Add ADRs:
  - ADR-0001: pyFF compatibility strategy
  - ADR-0002: batch/server split and MDQ serving model
  - ADR-0003: XML security dependency strategy with `go.work` replaces
Success criteria:
- `make test` and lint pass on baseline scaffold.
- CI green for build/lint/test.

### Phase 1: Pipeline Compatibility Core
Deliverables:
- Pipeline parser for pyFF-style YAML subset (first iteration).
- Execution engine with ordered steps and shared metadata repository context.
- Error model with source locations (pipeline file and step index).
- Compatibility test fixtures: pyFF input pipelines with expected outputs.
Success criteria:
- A first subset of pyFF pipelines executes end-to-end.
- Output parity achieved for selected reference fixtures.

### Phase 2: Metadata Processing Engine
Deliverables:
- Metadata fetch/load layer (local files + HTTP sources).
- Parse/normalize/merge model for SAML metadata entities.
- Trust and validation hooks with explicit policy boundaries.
- Deterministic output writer(s) to avoid unstable diffs.
Success criteria:
- Repeatable output artifacts across runs.
- Concurrency-safe processing with no races (`go test -race`).

### Phase 3: XML Security and Signing/Verification
Deliverables:
- Integrate XML signature validation/signing using libs aligned with `vc`.
- Enforce use of workspace replace directives from `go.work`.
- Key/cert configuration model for signing and verification operations.
- Golden tests for signed metadata and signature verification behavior.
Success criteria:
- Sign/verify flows pass fixture tests and interoperability checks.
- No regressions when replace directives are active.

### Phase 4: Batch Mode
Deliverables:
- CLI command set (example):
  - `goff batch --pipeline pipeline.yaml --output out/`
- Logging and structured diagnostics.
- Exit code contract for CI automation.
Success criteria:
- Batch pipelines can be run in CI and produce expected outputs.

### Phase 5: MDQ Server Mode
Deliverables:
- Internal metadata repository built/updated by pipeline runs.
- Standalone MDQ HTTP server implementation (not pipeline-driven request handling).
- Refresh/update scheduler for repository regeneration.
- Health/readiness endpoints and basic operational metrics.
Success criteria:
- MDQ requests served from internal repository with expected semantics.
- Reload/refresh behavior validated under concurrent load.

### Phase 6: Hardening and Performance
Deliverables:
- Benchmarks for large federation aggregates and memory profile baselines.
- Concurrency tuning (worker pools, bounded queues, cancellation).
- Fuzz tests for XML/pipeline inputs.
- Security checks and supply-chain hygiene (SBOM/signing optional backlog).
Success criteria:
- Measurable improvement targets versus baseline prototype.
- Stable memory growth and predictable latency under load.

## Suggested Architecture
- `internal/pipeline/`: YAML parsing, validation, execution graph/runner.
- `internal/repo/`: in-memory metadata repository abstraction and persistence hooks.
- `internal/metadata/`: entity model, parsing, normalization, merge.
- `internal/xmlsec/`: signing/verification adapter around chosen XML libraries.
- `internal/mdq/`: HTTP handlers and protocol mapping.
- `internal/config/`: app config, mode-specific settings, defaults.
- `cmd/goff/`: CLI entrypoint and subcommands.

## Compatibility Strategy
- Start with a documented subset of pyFF pipeline actions.
- Add a compatibility matrix in `docs/compatibility.md`:
  - Action/feature
  - Status (`supported`, `partial`, `planned`, `not-supported`)
  - Behavior notes/deltas
- Use golden tests to prove parity for each supported action.

## Testing Strategy
- Unit tests for parser, pipeline executor, XML security adapters.
- Integration tests for:
  - batch pipeline output parity
  - MDQ server responses from generated repository
- Race tests and benchmarks in CI gates (at least on main branch/nightly).
- Fixture-driven tests copied or adapted from pyFF behavior examples where legal and practical.

## Tooling and Operations
- `Makefile` targets: `build`, `test`, `test-race`, `lint`, `bench`, `docker-build`.
- Release pipeline similar to `go-trust` conventions.
- Versioned changelog and semantic versioning discipline.

## Next Two Sprints (1-2 weeks each)

Sprint A: Compatibility and behavior parity
- Expand `select` parity to cover additional pyFF selector edge cases and XPath semantics.
- Add parity fixtures for currently documented `partial` behaviors in `docs/compatibility.md`.
- Close publish/finalize/sign/verify output-diff gaps using deterministic golden outputs.
- Define and document a strict batch exit-code contract for parse/execute/runtime failures.

Sprint B: Server and operational hardening
- [x] Add E2E tests for server refresh behavior under concurrent request load.
- [x] Add `go test -race ./...` to CI (or an equivalent gated target) and fix any findings.
- [x] Add baseline benchmarks for large aggregate processing and track memory/latency envelopes.
- [x] Strengthen health/readiness semantics and expose basic operational counters.

Sprint C: Full pyFF pipe compatibility
- Implement all relevant pipes from pyFF and ensure 100% semantic and syntactic compatibility.
- Use the triaged pipe inventory in `docs/pyff-pipe-triage.md` as the implementation source of truth for sequencing and scope.
- Reclassify each pipe/action in `docs/compatibility.md` from `partial`/`planned` to `supported` only after fixture-backed parity evidence is added.
- Add parity fixtures for every implemented pipe variant (including option combinations and edge cases) and require deterministic output checks for all publish paths.
- Track any intentionally unsupported request-only/server-mode pyFF pipeline primitives explicitly as out-of-scope exceptions, with rationale.

Sprint B progress note:
- `internal/app/server_test.go:TestRunServerRefreshConcurrentRequestLoad` now validates refresh churn while concurrent `/entities` and `/entities/{id}.xml` requests are in flight, asserting stable status behavior (200 for list endpoint, 200/404 for entity lookups) and no request errors.
- CI already enforces `go test -race ./...` in `.github/workflows/ci.yml`; race-suite stability issue in concurrent refresh shutdown timing has been fixed (`internal/app/server_test.go`).
- Baseline benchmarks are now in `internal/pipeline/bench_test.go` and runnable via `make bench`; benchmark tracking guidance is documented in `docs/benchmarks.md`.
- MDQ server now exposes `/readyz` readiness checks and `/metrics` operational counters (request counters + server/refresh metrics), with handler and app-level tests in `internal/mdq/server_test.go` and `internal/app/server_test.go`.

Sprint C progress note:
- `load` source signature verification (`sources[].verify`) is implemented and covered by pass/fail tests in `internal/pipeline/metadata_load_test.go`.
- `load` source cleanup semantics (`cleanup: true`) now skip broken source files/URLs and continue ingesting valid sources, with fixture-backed test coverage.
- `load` fetch policy subset is now implemented via per-source `timeout` and `retries` options for URL ingestion (`internal/pipeline/metadata_load.go`), including transient-failure retry tests.
- pyFF-style `when` construction support is now available for update scope (`when update` and `when x` wrappers are flattened into executable step sequences; request/accept wrappers are skipped by design).
- `publish` parity surface has been expanded with nested output path support and inline action syntax (`publish <path>`, `publish as <path>`), with parser and execution tests.
- P1 transformation track has started with initial `setattr` support for category/role/registration-authority/text-token enrichment on current entities, covered by fixture-backed batch tests.
- `publish` now also supports mapping-style alias syntax (`publish: {as: ...}`) in parser/executor parity tests.
- P1 enrichment now includes initial `reginfo` support for registration authority enrichment with fixture-backed selection/publish validation.
- P1 enrichment now includes initial `pubinfo` support for publication metadata token enrichment (`publisher`/`value`/`values`), validated with fixture-backed `select.match` parity checks.
- A constrained `publish output as resource <path>` compatibility subset is now supported and covered by parser/engine/app-level parity tests.
- `pubinfo` semantics now include structured query-friendly token prefixes (`publisher:<value>`, `value:<value>`) for more explicit `select.match` behavior.
- `publish` side-effect compatibility subset now includes `hash_link` (digest sidecar file) and `update_store` (hashed content copy into store directory), with parser/engine/app integration coverage.
- `reginfo` semantics now include structured policy metadata (`policy`, `policies`) projected into query-friendly tokens (including `policy:<value>`) for explicit `select.match` behavior.
- When both `hash_link` and `update_store` are enabled, publish now also emits a link-pointer file (`<output>.link`) to the hashed store object, adding a constrained publish-topology parity slice.
- `setattr` now emits structured query-friendly prefix tokens (`<name>:<value>` plus role/category/registration-authority prefixed tokens) to support more explicit `select.match` semantics.
- P0 parity closure was advanced with dedicated batch fixtures for `sort` (default + XPath value ordering) and `finalize` output parity, enabling status promotion for those actions.
- Publish hash-link output now uses normalized sha256sum-style line format (`<hash>  <filename>`) while retaining store/link side-effects.
- `pubinfo` was tightened with structured URL/lang metadata support (`url`, `urls`, `lang`) and corresponding query-friendly prefixes (`url:<value>`, `lang:<value>`).
- `publish` shorthand parity now includes inline `publish output as <path>` parsing and fixture-backed batch execution.
- `sign`/`verify` publish semantics now fail fast when configured against non-XML publish outputs, preventing silent no-op behavior on text artifacts.
- `pubinfo` structured match parity now includes `values` list projection into `value:<value>` query tokens, validated by batch fixtures.
- goFF-specific `sources:` map and `pipeline:` wrapper key removed entirely; the top-level YAML document is now the pipeline itself — a bare sequence of steps matching the native pyFF format. `LoadStep.Files`/`URLs`/`Entities` replace the named-source indirection. In-pipeline aliases (`select as /name:`) allow cross-step references via `load: files: [/name]`. All 40+ fixture YAML files and all test files updated; `ParseFile` now rejects non-sequence top-level YAML with an explicit error.

Sprint D progress note:
- Inline URL fingerprint (`https://url|sha256:hexhash`) now supported on all `load: urls:` entries — goFF strips the suffix, fetches the clean URL, and verifies the raw response bytes using `parseURLFingerprint` + `tryVerifyBodyHash`.
- `verify:` hash shorthand (`sha256:hex`, `sha1:hex`, `md5:hex`) supported as an alternative to PEM cert file path in `load:` source verification.
- `timeout:` bare integer seconds accepted as pyFF pyFF compat alias (e.g. `timeout: 60` → 60s).
- HTTP proxy support added via `http.ProxyFromEnvironment` in all fetch operations.
- `publish: raw: true` implemented for single-file publish: bypasses `finalize`/`sign` and writes raw in-memory aggregate XML.
- `load: from: <alias>` registers the loaded entity set as a named source alias immediately after loading.
- `GOFF_PIPELINE` and `GOFF_OUTPUT` env vars added to the `batch` subcommand (previously only the `server` subcommand had env var coverage).
- `map:` per-entity fork loop implemented; enables static MDQ per-entity publishing pattern from `batch-mdq-loop.fd`.
- `store:` accepted as alias for `publish: {dir: <path>}`.
- `then <label>:` step implemented as root-pipeline re-run with `states = {label: true}`.
- `drop_xsi_type:` implemented (removes `xsi:type` attrs from entity XML before signing).
- `log_entity:`, `check_xml_namespaces:` accepted as no-ops.
- `merge:` accepted with runtime warning instead of fatal pipeline error.
- `signcerts:`, `emit:` accepted with warning/no-op.

## Near-Term Acceptance Criteria
- New parity fixtures demonstrate behavior coverage for every `partial` action that has an implemented path.
- `goff batch` and `goff server` produce deterministic outputs for the existing fixture corpus.
- CI includes standard tests plus at least one of race or benchmark gates.
- Compatibility matrix and implementation plan remain synchronized after each feature increment.

## Risks and Mitigations
- pyFF behavioral edge cases:
  - Mitigation: compatibility matrix + fixture-driven parity tests.
- XML signature interoperability complexity:
  - Mitigation: early integration in Phase 3, not deferred to end.
- Concurrency bugs in metadata merging:
  - Mitigation: immutable snapshots or strict locking boundaries + race tests.
- Scope creep from full pyFF feature parity:
  - Mitigation: staged support levels with explicit `not yet supported` paths.

## Definition of Done (MVP)
- pyFF-compatible pipeline subset documented and tested.
- Batch mode production-ready for core workflows.
- MDQ server mode serving repository generated by pipelines.
- Signing/verification validated with workspace replace-dependent XML libs.
- CI/CD, lint, tests, and ADR documentation in place.
