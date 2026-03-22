# pyFF Pipe Inventory and Triage

Date: 2026-03-11
Scope: update-task pipeline compatibility for `goFF`

## Triage Method
- Priority:
  - `P0`: migration blocker for common update pipelines
  - `P1`: high-value parity, but not usually first blocker
  - `P2`: useful parity/reporting feature
  - `P3`: intentionally de-prioritized or design-divergent
- Complexity:
  - `S`: small (local parser/engine changes, low blast radius)
  - `M`: medium (multi-file behavior and fixture work)
  - `L`: large (cross-cutting semantics, state model changes)
  - `XL`: very large (architectural or major parity challenge)

## Inventory: Implemented Pipe Surface in goFF

| Pipe / Action | goFF Status | Complexity to reach strong parity | Priority | Notes |
| --- | --- | --- | --- | --- |
| `load` (incl. `local`/`remote`/`fetch`/`_fetch`) | supported | — | P0 | Flat `files`/`urls`/`entities` on load step; `verify`, `via`, `cleanup`, `timeout`, `retries` all implemented; SAML metadata text fields indexed at load time for `select match:` queries; inline URL fingerprints (`url|sha256:hex`); `verify:` hash shorthand (`sha256:hex`, `sha1:hex`); `timeout:` integer seconds; HTTP proxy via `http.ProxyFromEnvironment`; `from: <alias>` registers loaded set as named source alias; threaded fetch policy callbacks intentionally out-of-scope for update-pipeline model |
| `select` | supported | — | P0 | Supports selectors/predicates/intersections/aliases; `match` text queries proven against entity IDs, indexed tokens, and SAML metadata text fields (`OrganizationDisplayName`, `OrganizationName`, `DisplayName`, `ServiceName`, `Keywords`, `Scope`); fixture-backed coverage including `select-match-displayname.yaml` |
| `filter` | supported | — | P1 | Fixture-backed parity via `filter-current-only.yaml` |
| `pick` | supported | — | P1 | Fixture-backed parity via `pick-repository.yaml` |
| `sort` | supported | — | P0 | Deterministic default + XPath value ordering with fixture-backed parity |
| `finalize` | supported | — | P0 | Aggregate XML attributes with fixture-backed output parity |
| `sign` | supported | — | P0 | Enveloped XML signature (C14N10 exclusive + RSA-SHA256) with file key/cert and PKCS#11 path; sign+verify round-trip batch-tested; deterministic across runs |
| `verify` | supported | — | P0 | Certificate-based XML signature verification with goxmldsig MemoryX509CertificateStore; batch-tested; CA chain validation is a separate planned addition |
| `publish` | supported | — | P0 | Output file writing, nested paths, inline/mapping syntax, hash_link, update_store all implemented with fixture-backed parity; per-entity directory routing implemented via `publish: {dir: <path>}` (writes `sha256(entityID).xml` per entity, fixture-backed via `publish-dir-batch.yaml`) |
| `stats` | supported | — | P2 | Selected-entity count printed to stdout; smoke-test fixture-backed coverage |
| `info` / `dump` / `print` | supported | — | P2 | Per-entity ID listing output to stdout; all three aliases work identically; smoke-test fixture-backed coverage |
| `break` / `end` | supported | — | P2 | Flow-stop behavior with test coverage |
| `first` | supported | — | P2 | Fixture-backed parity via `first-single-entity.yaml` |
| `setattr` | supported | — | P1 | Category/role/reg-authority/text-token enrichment with values list; structured prefix tokens for `select.match`; all option combinations fixture-backed |
| `reginfo` | supported | — | P1 | Authority/policy enrichment with structured tokens and policies list; all option combinations fixture-backed |
| `pubinfo` | supported | — | P1 | Publisher/value/url/lang enrichment with structured tokens, values/urls lists; all option combinations fixture-backed |

## Inventory: Known Missing or Intentionally Divergent pyFF Pipes

| Pipe / Area | goFF Status | Complexity | Priority | Triage Rationale |
| --- | --- | --- | --- | --- |
| `publish` per-entity directory routing | supported | — | P0 | `publish: {dir: <path>}` writes each entity as `sha256(entityID).xml`; fixture-backed via `publish-dir-batch.yaml` |
| `publish: raw: true` | supported | — | P0 | Bypasses `finalize`/`sign`; writes in-memory aggregate directly |
| `store` | supported | — | P0 | Alias for `publish: {dir: <path>}`; mapping, scalar, and list forms all supported |
| `xslt` | partial | XL | P1 | Implemented via `xsltproc` subprocess; re-parses transformed output; requires `libxslt-utils` at runtime; exact output parity with pyFF's lxml engine varies by stylesheet |
| `map` | supported | — | P1 | Per-entity fork loop; sub-pipeline runs once per entity with single-entity snapshot; enables static MDQ per-entity publishing pattern |
| `then <label>` | supported | — | P1 | Root pipeline re-run with `states = {label: true}` and current entity set; in-pipeline equivalent of `load … via <label>` |
| `drop_xsi_type` | supported | — | P1 | Removes `xsi:type` attributes from entity XML before signing; no-op when none present |
| `nodecountry` | supported | — | P2 | Extracts C= from embedded X.509 certs and adds `country:<cc>` text tokens; fixture-backed coverage |
| `certreport` | supported | — | P2 | Prints cert CN/expiry/status to stdout per entity; fixture-backed coverage |
| `signcerts` | not-supported (intentional) | M/L | P3 | Certificate-signing workflow; accepted with warning at runtime |
| `discojson` / `discojson_idp` / `discojson_sp` | supported | — | P2 | Writes MDUI-enriched JSON discovery file; role-filter variants; inline scalar and mapping YAML syntax; fixture-backed coverage |
| `log_entity` | supported | — | P2 | Accepted as no-op; per-entity diagnostic inside `map:` loops |
| `check_xml_namespaces` | supported | — | P2 | Accepted as no-op; XML namespace correctness validated implicitly at parse time |
| `fork` / `pipe` / `parsecopy` flow semantics | supported | — | P3 | Deep-copy sub-pipeline isolation implemented; `merge` action graceful warning; outer pipeline state is unaffected by fork branch |
| `merge` | partial | — | P3 | Accepted with runtime warning; `fork` result propagation intentionally not supported |
| `emit` and request-pipeline response shaping | not-supported (intentional) | XL | P3 | Explicitly de-prioritized by goFF design (standalone MDQ handlers) |

## Recommended Implementation Queue

1. `P0` remaining gap (done):
   - [x] `select` match-query parity: text-token, entity-ID substring, and SAML metadata field matching all fixture-proven
   - [x] `publish` per-entity directory routing: `publish: {dir: <path>}` implemented with fixture coverage
   - [x] `load` SAML text field indexing at load time: confirmed supported and documented
   - [x] `publish: raw: true`: bypasses finalize/sign for direct aggregate output
   - [x] `store:` alias for `publish: {dir: <path>}`
2. `P1` transformation/enrichment hardening (done):
   - [x] `setattr`, `reginfo`, `pubinfo` promoted to `supported` with full option-combination fixture coverage
   - [x] `xslt` implemented as partial via `xsltproc` subprocess; inline scalar and mapping YAML syntax supported
   - [x] `map:` per-entity fork loop implemented; enables static MDQ per-entity publishing patterns
   - [x] `then <label>:` root-pipeline re-run step implemented
   - [x] `drop_xsi_type:` implemented
3. `P2` reporting/export helpers (done):
   - [x] `stats`, `info`/`dump`/`print` promoted to `supported` with smoke-test fixture coverage
   - [x] `certreport`, `discojson*`, `nodecountry` promoted to `supported` with fixture-backed unit test coverage
   - [x] `log_entity:`, `check_xml_namespaces:` accepted as no-ops
4. `P3` design-divergent state-machine features (done):
   - [x] `fork`/`pipe`/`parsecopy` implemented as deep-copy sub-pipelines
   - [x] `merge` accepted with runtime warning (not fatal)
   - [x] `emit`, `signcerts` accepted with warning/no-op

## Immediate Backlog Candidates (Sprint-ready)
- `signcerts` full implementation (certificate mutation on embedded X.509 certs).
- Fixture-backed tests for `fork` state isolation.
- Fixture-backed tests for `xslt` with a known-good stylesheet.
- Verify cert CA chain-of-trust multi-cert path validation (`verify: certs:` list already accepted).
