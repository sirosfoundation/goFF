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
| `load` (incl. `local`/`remote`/`fetch`/`_fetch`) | partial | S | P0 | Flat `files`/`urls`/`entities` on load step; `verify`, `via`, `cleanup`, `timeout`, `retries` all implemented; threaded fetch policy callbacks not implemented |
| `select` | partial | M | P0 | Supports selectors/predicates/intersections/aliases; needs broader edge-case and match-query parity |
| `filter` | supported | — | P1 | Fixture-backed parity via `filter-current-only.yaml` |
| `pick` | supported | — | P1 | Fixture-backed parity via `pick-repository.yaml` |
| `sort` | supported | — | P0 | Deterministic default + XPath value ordering with fixture-backed parity |
| `finalize` | supported | — | P0 | Aggregate XML attributes with fixture-backed output parity |
| `sign` | partial | L | P0 | XML signing works (file key/cert + PKCS#11 path); interoperability breadth pending |
| `verify` | partial | M/L | P0 | Certificate-based XML verify exists; broader trust/path behavior pending |
| `publish` | partial | M | P0 | Output file writing, nested paths, inline/mapping syntax, hash_link, update_store all implemented; advanced directory-routing semantics pending |
| `stats` | partial | S | P2 | Basic count output exists |
| `info` / `dump` / `print` | partial | S/M | P2 | Basic listing output exists; output parity formatting may differ |
| `break` / `end` | supported | — | P2 | Flow-stop behavior with test coverage |
| `first` | supported | — | P2 | Fixture-backed parity via `first-single-entity.yaml` |
| `setattr` | partial | S | P1 | Category/role/reg-authority/text-token enrichment; structured prefix tokens for `select.match`; fixture-backed |
| `reginfo` | partial | S | P1 | Authority/policy enrichment with structured tokens; fixture-backed |
| `pubinfo` | partial | S | P1 | Publisher/value/url/lang enrichment with structured tokens; fixture-backed |

## Inventory: Known Missing or Intentionally Divergent pyFF Pipes

| Pipe / Area | goFF Status | Complexity | Priority | Triage Rationale |
| --- | --- | --- | --- | --- |
| `publish` advanced directory routing (symlink management, arbitary output trees) | planned | L | P0 | Environments using pyFF's full directory-publish topology not yet covered |
| `xslt` | planned | XL | P1 | High parity value but substantial engine/whitespace/namespace risk |
| `nodecountry` | planned | M | P2 | Useful enrichment, lower immediate migration pressure |
| `certreport` | planned | M/L | P2 | Reporting-focused; less blocking than core processing |
| `signcerts` | planned | M/L | P2 | Reporting/inspection helper, not a first-pass blocker |
| `discojson*` family | planned | L | P2 | Useful export helpers; lower priority than core update-path parity |
| `fork` / `pipe` / `merge` / `parsecopy` flow semantics | planned | XL | P3 | Large state-machine parity surface; not first milestone for update compatibility |
| `emit` and request-pipeline response shaping | not-supported (intentional) | XL | P3 | Explicitly de-prioritized by goFF design (standalone MDQ handlers) |

## Recommended Implementation Queue

1. `P0` close remaining gaps:
   - `sign` and `verify` interoperability breadth
   - `select` edge-case and `match` query parity
   - `publish` advanced directory-routing semantics
2. `P1` transformation/enrichment hardening:
   - Expand `setattr`, `reginfo`, `pubinfo` toward `supported` (more option combinations and edge-case fixtures)
   - Evaluate `xslt` scope (full parity vs. constrained subset)
3. `P2` reporting/export helpers:
   - `certreport`, `signcerts`, `discojson*`, `nodecountry`, output-format parity for `info`/`dump`/`print`
4. `P3` design-divergent state-machine features:
   - `fork`/`pipe` family and request-pipeline primitives (`emit`)

## Immediate Backlog Candidates (Sprint-ready)
- Add explicit fixture suites for `filter`, `pick`, and `first` so their current behavior is proven.
- Expand `select` parity fixture matrix for edge-case selector expression combinations.
- Add deterministic golden checks for `publish` + `finalize` + `sign/verify` combinations.
- Specify a minimal supported subset for `load` advanced options and implement that subset first.
