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
| `load` (incl. `local`/`remote`/`fetch`/`_fetch`) | partial | M | P0 | Core source/file/url loading exists; advanced resource policy/options still missing |
| `select` | partial | M | P0 | Supports selectors/predicates/intersections; needs more edge-case parity |
| `filter` | partial | M | P1 | Implemented via select-style behavior; parity surface needs explicit fixture coverage |
| `pick` | partial | M | P1 | Implemented as select-style narrowing; parity semantics need tightening |
| `sort` | partial | M | P0 | Deterministic ordering exists; full pyFF xpath/order behavior not complete |
| `finalize` | partial | M | P0 | Aggregate attributes supported; broader parity and diff-hardening required |
| `sign` | partial | L | P0 | XML signing works (file key/cert + PKCS#11 path); interoperability breadth pending |
| `verify` | partial | M/L | P0 | Certificate-based XML verify exists; broader trust/path behavior pending |
| `publish` | partial | L | P0 | Output file writing works; advanced publish routing/store semantics missing |
| `stats` | partial | S | P2 | Basic count output exists |
| `info` / `dump` / `print` | partial | S/M | P2 | Basic listing output exists; output parity formatting may differ |
| `break` / `end` | partial | S | P2 | Flow-stop behavior exists |
| `first` | partial | S/M | P2 | Implemented flow helper; needs explicit parity fixture coverage |

## Inventory: Known Missing or Intentionally Divergent pyFF Pipes

| Pipe / Area | goFF Status | Complexity | Priority | Triage Rationale |
| --- | --- | --- | --- | --- |
| `load` advanced options (`verify`, `via`, `cleanup`, fetch policy) | planned | L | P0 | Common migration blocker for production feed ingestion pipelines |
| `publish` advanced semantics (resource routing, directory/hash-link/store updates) | planned | XL | P0 | Critical for environments relying on pyFF publish topology and side effects |
| `xslt` | planned | XL | P1 | High parity value but substantial engine/whitespace/namespace risk |
| `setattr` | planned | L | P1 | Important transformation primitive in update pipelines |
| `reginfo` | planned | M/L | P1 | Common metadata enrichment use case |
| `pubinfo` | planned | M/L | P1 | Common metadata enrichment use case |
| `nodecountry` | planned | M | P2 | Useful enrichment, lower immediate migration pressure |
| `certreport` | planned | M/L | P2 | Reporting-focused; less blocking than core processing |
| `signcerts` | planned | M/L | P2 | Reporting/inspection helper, not a first-pass blocker |
| `discojson*` family | planned | L | P2 | Useful export helpers; lower priority than core update-path parity |
| `fork` / `pipe` / `merge` / `parsecopy` flow semantics | planned | XL | P3 | Large state-machine parity surface; not first milestone for update compatibility |
| `emit` and request-pipeline response shaping | not-supported (intentional) | XL | P3 | Explicitly de-prioritized by goFF design (standalone MDQ handlers) |

## Recommended Implementation Queue

1. `P0` close gaps in existing implemented surface:
   - `select`, `sort`, `publish`, `finalize`, `sign`, `verify` parity fixtures and deterministic output hardening
   - `load` advanced options needed for migration-critical ingestion flows
2. `P1` transformation/enrichment track:
   - `setattr`, `reginfo`, `pubinfo`
   - evaluate `xslt` scope (full parity vs. constrained subset)
3. `P2` reporting/export helpers:
   - `certreport`, `signcerts`, `discojson*`, `nodecountry`, output-format parity for `info`/`dump`/`print`
4. `P3` design-divergent state-machine features:
   - `fork`/`pipe` family and request-pipeline primitives (`emit`)

## Immediate Backlog Candidates (Sprint-ready)
- Add explicit fixture suites for `filter`, `pick`, and `first` so their current behavior is proven.
- Expand `select` parity fixture matrix for edge-case selector expression combinations.
- Add deterministic golden checks for `publish` + `finalize` + `sign/verify` combinations.
- Specify a minimal supported subset for `load` advanced options and implement that subset first.
