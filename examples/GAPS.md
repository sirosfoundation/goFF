# pyFF → goFF Gap Analysis

This document analyses every pyFF `examples/*.fd` pipeline and records which ones
could not be fully translated, and why.  Closed gaps are marked ✅ with the
implementing commit reference.

---

## Coverage summary

| pyFF file | goFF example | Coverage |
|---|---|---|
| `uk.fd` | `basic-load-publish.yaml` | ✅ full |
| `expiration.fd` | `certreport.yaml` | ✅ full |
| `edugain.fd`, `load.fd` | `multiple-federations.yaml` | ✅ full |
| `edugain-idps.fd` | `select-idps.yaml` | ✅ full (per-URL verify via SourceEntry) |
| `filter-idps.fd` | `select-idps.yaml` | ✅ full (per-URL verify via SourceEntry) |
| `dj.fd`, `edugain-json.fd` | `discojson.yaml` | ✅ full |
| `edugain-discojson_sp.yaml` | `discojson-roles.yaml` | ✅ full |
| `edugain-fork.fd` | `fork-idp-sp.yaml` | ✅ full |
| `renater.fd`, `safire-fed.fd` | `sign-publish.yaml` | ✅ full (per-URL verify via SourceEntry) |
| `p11.fd` | `sign-pkcs11.yaml` | ✅ full (per-URL verify via SourceEntry) |
| `kirei2.fd` | `xslt-sign-publish.yaml` | ✅ full |
| `ukmulti.fd` | `finalize-aggregate.yaml` | ✅ full |
| `test.fd`, `edugain-copy.fd` | `sub-federation-aliases.yaml` | ✅ full (setattr with selector, inline source aliases) |
| `edugain-mdq.fd`, `batch-mdq-loop.fd` | `mdq-server-pipeline.yaml` | ⚠️ partial — `map:`, `log_entity:` omitted; `urlencode_filenames`/`ext` now supported |
| `big.fd` | `xrd-links.yaml` | ✅ full (XRD input now supported) |
| `mdx.fd` | — | ⚠️ partial — `fork and merge` replaced by `setattr: selector:`; XRD/alias now supported |
| `eidas.fd` | — | ✅ full — inline source aliases and custom when-branches now fully supported |
| `edugain-fork-and-filter.fd` | — | ✅ full (`check_xml_namespaces` and inline source aliases now supported) |
| `ndn.fd` | — | ✅ full (XRD input now supported) |
| `out-edugain.fd` | — | ✅ full (directory loading from prior publish:dir output now supported) |
| `pp.fd` | — | ❌ `signcerts` action intentionally unsupported |
| `new-renater.fd` | — | ⚠️ when update is covered by sign-publish.yaml; URLs contain typos in original |

---

## Gap catalogue

### GAP-1 · `fork and merge` → ✅ CLOSED via `setattr: selector:`

**Implemented in:** this release

goFF now supports a `selector:` sub-option on `setattr` and `reginfo` steps.
When set, attribute enrichment is applied only to entities matching the selector
expression (which may be an XPath predicate, source alias, or any standard goFF
selector string).  This replaces the pyFF `fork and merge` pattern for the most
common use-case:

```yaml
# pyFF
- fork and merge:
   - select: "!//md:EntityDescriptor[md:Extensions[mdrpi:RegistrationInfo[...]]]"
   - setattr:
       http://pyff.io/collection: swamid-2.0

# goFF equivalent
- setattr:
    name: collection
    value: swamid-2.0
    selector: "!//md:EntityDescriptor[md:Extensions[mdrpi:RegistrationInfo[...]]]"
```

The `selector:` field accepts the same syntax as `select: selector:` — source
aliases, XPath predicates, and `source!//xpath` intersection expressions.

---

### GAP-2 · Per-URL inline verification → ✅ CLOSED via `SourceEntry`

**Implemented in:** this release

`LoadStep` now accepts structured source entries with per-source `verify` certs:

```yaml
# goFF — per-source cert verification via SourceEntry mapping
- load:
    sources:
      - url: https://mds.swamid.se/md/swamid-2.0.xml
        verify: /path/to/swamid-cert.pem
      - url: https://metadata.safire.ac.za/safire-edugain.xml
        verify: /path/to/safire-cert.pem
```

Both file and URL sources are supported.  The `verify:` field takes a path to a
PEM certificate file (same as the top-level `load: verify:` field).

Note: pyFF's colon-separated SHA-1/SHA-256 fingerprint inline notation
(`URL A6:78:5A:...`) is not supported — use a PEM cert file instead.

---

### GAP-3 · Per-source inline `as` alias → ✅ CLOSED via `SourceEntry` and inline syntax

**Implemented in:** this release

`LoadStep` now supports two ways to create per-source aliases:

**Inline scalar syntax** (mirrors pyFF):
```yaml
- load:
  - /path/to/swamid-2.0.xml as kaka
  - /path/to/swamid-2.0.xml as kaka cleanup
  - https://example.org/fed.xml as /my-source
```

**Mapping syntax** (more explicit):
```yaml
- load:
  - file: /path/to/swamid-2.0.xml
    as: kaka
    cleanup: true
  - url: https://example.org/fed.xml
    as: /my-source
    verify: cert.pem
```

Aliases created by `load` are registered in the source map immediately after the
source is loaded, so they can be referenced in subsequent `setattr: selector:`,
`select:`, and `filter:` expressions.

---

### GAP-4 · XRD/XRDS input format → ✅ CLOSED

**Implemented in:** this release

`load:` now transparently handles XRD/XRDS discovery documents.  When a loaded
file or URL contains an XRD/XRDS document (root element `<XRDS>` or `<XRD>` in
namespace `http://docs.oasis-open.org/ns/xri/xrd-1.0`), goFF extracts all
`<Link rel="urn:oasis:names:tc:SAML:2.0:metadata" href="..."/>` URLs and loads
each one as SAML metadata.

```yaml
# goFF — XRD file now supported directly
- load:
  - examples/big.xrd
  - examples/ndn-links.xrd
```

---

### GAP-5 · `map:` — per-entity fork loop

**Status:** Won't implement (low priority)

pyFF's `map:` step iterates over each entity in the current working set individually,
running a sub-pipeline for each one. This is primarily used for per-entity signing
and per-entity file writing in MDQ pipelines.

goFF's `publish: {dir:}` covers the most common use-case (writing per-entity XML
files to a directory for static MDQ serving).

---

### GAP-6 · `log_entity:` action not supported

**Status:** Won't implement (depends on GAP-5 `map:`)

goFF's `info` and `dump` actions cover aggregate-level listing.

---

### GAP-7 · `check_xml_namespaces` action → ✅ CLOSED (no-op)

**Implemented in:** this release

`check_xml_namespaces` is now accepted as a valid pipeline action.  It is treated
as a no-op: goFF validates XML namespace correctness implicitly when loading
metadata (the XML parser rejects malformed namespace declarations).

---

### GAP-8 · `signcerts` action not supported

**Status:** Intentionally unsupported

pyFF's `signcerts` adds X.509 certificate signing infrastructure to embedded
certificates in entity XML.  It is explicitly rejected by goFF's parser as
unsupported.

---

### GAP-9 · pyFF on-disk store as cross-pipeline source → ✅ CLOSED via directory loading

**Implemented in:** this release

`load:` now supports loading from directories.  When a path points to a directory,
goFF scans and loads every `*.xml` file within it.  This enables round-tripping
data through `publish: {dir:}` output:

```yaml
# Pipeline A: publish per-entity XML files
- publish:
    dir: /tmp/edugain

# Pipeline B (run later): reload from the published directory
- load:
  - /tmp/edugain
```

---

### GAP-10 · `publish:` options `urlencode_filenames`, `raw`, `ext` → ✅ PARTIALLY CLOSED

**Implemented in:** this release

Two of the three options are now implemented:

- **`urlencode_filenames: true`** — writes MDQ-compatible URL-encoded filenames
  (`%7Bsha256%7DHEXHASH`) instead of plain hex filenames.

- **`ext: <suffix>`** — overrides the default `.xml` extension for files written
  to the `dir:` target.

- **`raw: true`** — accepted in the YAML (no parse error) but currently a no-op;
  `publish: {dir:}` always writes raw entity XML (one `EntityDescriptor` per file).

Example (MDQ-compatible per-entity files):
```yaml
- publish:
    dir: entities
    urlencode_filenames: true
    hash_link: true
```

---

### GAP-11 · `when <custom-name>:` pre-processing branches

**Status:** ✅ Closed

Named branches (`when normalize:`, `when edugain:`, etc.) are now extracted by
`ParseFile` into `File.Branches` during a pre-pass over the YAML.  They can then
be referenced by `via branchname` on individual load sources (see GAP-12).

---

### GAP-12 · `load: via:` branch invocation

**Status:** ✅ Closed

Inline source tokens of the form `url via branchname` (or mapping field
`via: branchname`) now trigger per-source branch execution: after the source is
fetched, the named preprocessing branch is run on its entities before they are
merged into the pipeline.  An unknown branch name is a hard error.

---

## Not applicable to goFF (by design)

The following pyFF constructs appear in nearly all `.fd` files but are
**intentionally outside goFF's scope** because goFF handles request routing via its
built-in MDQ HTTP server, not the pipeline:

| pyFF construct | Reason omitted |
|---|---|
| `when request:` | Request handling is the MDQ server's job |
| `when accept <mimetype>:` | Content negotiation is built into the MDQ handler |
| `when path <url>:` | URL routing is built into the MDQ handler |
| `emit <mimetype>` | Response emission is handled by the MDQ handler |
| `fork and merge` (request-side) | Request-side sub-pipeline; not applicable |
| `first` (request-side) | In a request context, equivalent to single-entity lookup in the MDQ server |


This document analyses every pyFF `examples/*.fd` pipeline and records which ones
could not be fully translated, and why.  It is intended to track feature gaps and
inform the goFF roadmap.

---

## Coverage summary

| pyFF file | goFF example | Coverage |
|---|---|---|
| `uk.fd` | `basic-load-publish.yaml` | ✅ full |
| `expiration.fd` | `certreport.yaml` | ✅ full |
| `edugain.fd`, `load.fd` | `multiple-federations.yaml` | ✅ full |
| `edugain-idps.fd` | `select-idps.yaml` | ⚠️ partial — per-URL cert omitted |
| `filter-idps.fd` | `select-idps.yaml` | ⚠️ partial — per-URL cert omitted, xslt not shown |
| `dj.fd`, `edugain-json.fd` | `discojson.yaml` | ✅ full |
| `edugain-discojson_sp.yaml` | `discojson-roles.yaml` | ✅ full |
| `edugain-fork.fd` | `fork-idp-sp.yaml` | ✅ full |
| `renater.fd`, `safire-fed.fd` | `sign-publish.yaml` | ⚠️ partial — per-URL cert omitted |
| `p11.fd` | `sign-pkcs11.yaml` | ⚠️ partial — per-URL cert omitted |
| `kirei2.fd` | `xslt-sign-publish.yaml` | ✅ full |
| `ukmulti.fd` | `finalize-aggregate.yaml` | ✅ full |
| `test.fd`, `edugain-copy.fd` | `sub-federation-aliases.yaml` | ⚠️ partial — `fork and merge` omitted |
| `edugain-mdq.fd`, `batch-mdq-loop.fd` | `mdq-server-pipeline.yaml` | ⚠️ partial — `map:`, `log_entity:`, per-entity publish options omitted |
| `big.fd` | — | ❌ XRD input format not supported |
| `mdx.fd` | — | ❌ `fork and merge`, collection attributes, XRD via |
| `eidas.fd` | — | ✅ full — per-source inline options and custom when-branches now fully supported |
| `edugain-fork-and-filter.fd` | — | ❌ per-source inline options, `check_xml_namespaces` |
| `ndn.fd` | — | ❌ when update portion coverable; XRD input |
| `out-edugain.fd` | — | ❌ loading from a pyFF on-disk store (not an alias) |
| `pp.fd` | — | ❌ `signcerts` action |
| `new-renater.fd` | — | ⚠️ when update is covered by sign-publish.yaml; URLs contain typos in original |

---

## Gap catalogue

### GAP-1 · `fork and merge` not supported

**Affects:** `mdx.fd`, `test.fd`, `edugain-copy.fd`, `edugain-fork-and-filter.fd`

pyFF's `fork and merge` runs a sub-pipeline on a sandboxed copy of the entity set
and then **merges the result back** into the outer working set.  goFF's `fork` is
intentionally sandboxed: side effects (attribute enrichment, entity additions) in a
fork do not propagate to the caller.

The canonical use-case in pyFF is to compute derived attributes on a sub-population
and add them back — e.g. classify entities into collections, then use those
collections as further selection criteria:

```yaml
# pyFF
- fork and merge:
   - select: "!//md:EntityDescriptor[md:Extensions[mdrpi:RegistrationInfo[...]]]"
   - setattr:
       http://pyff.io/collection: swamid-2.0
```

In goFF, `reginfo`, `setattr`, and `pubinfo` already enrich the outer working set
directly (no merge needed), but they only work on the **current** working set, not
a sub-population selected by an XPath predicate.  There is no mechanism to:

1. select a subset of the current entities,
2. add attributes to only those entities, and
3. have those attributes visible to subsequent steps.

**Workaround:** Use `select` + `setattr` in sequence (enriches all currently
selected entities, not just a predicate-filtered sub-population), then `load` the
alias back.  This only covers the case where the entire current set should receive
the attribute.

**Roadmap:** Implement `filter` (already partially supported) as a scoped setattr
driver, or support a `setattr: selector:` sub-option.

---

### GAP-2 · Per-URL inline verification fingerprint not supported

**Affects:** `filter-idps.fd`, `safire-fed.fd`, `p11.fd`, `edugain-idps.fd`

pyFF allows a SHA-1 fingerprint (or SHA-256 colon-separated hex) to be placed
inline after each source URL in the `load:` list:

```yaml
# pyFF
- load:
   - https://mds.swamid.se/md/swamid-2.0.xml A6:78:5A:37:C9:C9:0C:...
   - https://metadata.safire.ac.za/safire-edugain.xml BB:89:BA:97:...
```

goFF's `LoadStep` accepts a single `verify: path/to/cert.pem` for the whole load
step (XML signature verification against a PEM cert file).  There is no support
for per-URL fingerprint pinning.

**Workaround:** Use separate `load:` steps with individual `verify:` cert files
for each source that requires pinning.  This requires splitting each source into
its own load step.

**Roadmap:** Add a `Source` sub-type to `LoadStep` that accepts per-URL fingerprint
or cert-file verification alongside the URL, mirroring pyFF's inline format.

---

### GAP-3 · Per-source inline options (`as`, `cleanup`, keyword flags)

**Affects:** `edugain-fork-and-filter.fd`, `eidas.fd`, `edugain-copy.fd`, `mdx.fd`

pyFF supports a rich inline syntax on each source entry in the `load:` list:

```yaml
# pyFF
- load:
   - /path/to/swamid-2.0 as kaka cleanup clean
   - https://qa.md.eidas.swedenconnect.se/... cleanup eidas validate True
   - examples/links.xrd as links via normalize
```

This embeds `as` (alias), `cleanup` (pre-processing branch to run), and custom
keyword flags directly on the source line.  goFF:

- Does not accept per-entry `as` inside a sources list (aliases are created via
  `select as /name` on a separate step).
- Does not support `cleanup` as a per-source processing branch reference.
- Does not evaluate named non-update branches (`when normalize:`, `when eidas:`,
  etc.) — only `when update`, `when x`, `when true`, `when always` are included.

**Workaround:** Split into multiple `load:` + `select as /alias:` step pairs.
Per-source cleanup transformations must be inline `xslt:` steps after loading.

---

### GAP-4 · XRD format input not supported

**Affects:** `big.fd`, `ndn.fd`, `mdx.fd` (links.xrd, big.xrd, ndn-links.xrd)

pyFF can load XRD/XRDS discovery documents as federation indexes — the XRD file
lists source URLs with optional verification data, and pyFF resolves and loads each
referenced feed.

goFF's `load:` only accepts SAML metadata XML (either `EntitiesDescriptor` or
`EntityDescriptor` root elements).  XRD files are not parsed.

**Workaround:** Inline all source URLs directly in the `load: urls:` list.

**Roadmap:** Add XRD/XRDS parser support in the `load:` step; the main addition
required is an HTTP fetch + XRD XML parse to expand sources before the normal load
path.

---

### GAP-5 · `map:` — per-entity fork loop

**Affects:** `batch-mdq-loop.fd`

pyFF's `map:` step iterates over each entity in the current working set individually,
running a sub-pipeline for each one:

```yaml
# pyFF
- map:
   - log_entity:
   - fork:
      - then sign:
      - publish:
          output: /tmp/mdq/entities
          hash_link: true
          urlencode_filenames: true
```

This enables per-entity processing pipelines such as signing and writing each
entity XML to its own file.  goFF has no equivalent; `publish: {dir: ...}` writes
all entities to a directory but does not support per-entity sub-pipelines.

**Workaround:** Use `publish: {dir: ..., hash_link: true}` for the common case of
writing per-entity files.  Per-entity signing is not currently supported; the
workaround is to sign at the aggregate level.

**Roadmap:** Low priority for the current MDQ server model; `publish: {dir:}` with
`hash_link` covers the most important use-case.

---

### GAP-6 · `log_entity:` action not supported

**Affects:** `batch-mdq-loop.fd`

pyFF's `log_entity:` prints diagnostic information about the current entity inside
a `map:` loop.  Not applicable without `map:` support (GAP-5), and goFF's `info` /
`dump` actions cover aggregate-level listing.

---

### GAP-7 · `check_xml_namespaces` action not supported

**Affects:** `edugain-fork-and-filter.fd`, `eidas.fd`, `edugain-copy.fd`

pyFF's `check_xml_namespaces` validates that XML namespace declarations in loaded
metadata are well-formed and consistent.  goFF does not have an equivalent action;
namespace validation happens implicitly during XML parse at load time.

---

### GAP-8 · `signcerts` action not supported

**Affects:** `pp.fd`

pyFF's `signcerts` adds X.509 certificate signing infrastructure to embedded
certificates in entity XML (used for certificate renewal workflows).  It is
explicitly rejected by goFF's parser as unsupported.

---

### GAP-9 · pyFF on-disk store as cross-pipeline source

**Affects:** `out-edugain.fd`

`out-edugain.fd` loads entities from `/tmp/edugain` — a pyFF store directory
written by a prior `store: {directory: /tmp/edugain}` step in `edugain-idps.fd`.
This relies on pyFF's persistent content-addressable store format (one XML file per
entity, named by SHA-256).

goFF does not have a pyFF-compatible store directory; `publish: {dir:}` writes
`sha256(entityID).xml` files in a similar layout, but there is no `load:` path that
reads back from such a directory.  In-pipeline aliases (`select as /name`) only
persist for the duration of one pipeline run.

**Workaround:** Combine both pipelines into one, using `select as /alias:` to
pass data between what pyFF split into separate processes.

---

### GAP-10 · `publish:` options `urlencode_filenames`, `raw`, `ext`

**Affects:** `batch-mdq-loop.fd`

pyFF's `publish:` step supports additional options not present in goFF:
- `urlencode_filenames: true` — percent-encode entity IDs when used as filenames.
- `raw: true` — write the JSON body without XML wrapping when used after discojson.
- `ext: .json` — override the output file extension.

These were used in the MDQ batch loop to write per-entity discovery JSON files
alongside XML files.  goFF's `PublishStep` struct has no equivalent fields.

---

### GAP-11 · `when <custom-name>:` pre-processing branches

**Affects:** `edugain-copy.fd`, `eidas.fd`, `test.fd`, `mdx.fd`
**Status:** ✅ Closed

Named branches (`when normalize:`, `when edugain:`, `when eidas:`, `when swamid:`,
`when sign:`) are now extracted by `ParseFile` into `File.Branches` during a
pre-pass over the YAML.  The main `when update:` (or unconditional) pipeline is
built as before; named branches are stored separately and invoked via the `via`
notation (see GAP-12).

---

### GAP-12 · `load: via:` branch invocation

**Affects:** `mdx.fd`, `edugain-copy.fd`
**Status:** ✅ Closed

pyFF's `via` notation — `url via branchname` — is now fully supported.  After a
source entry is fetched, the named preprocessing branch is run on its entity set
before the result is merged into the pipeline.  The inline token form
(`url via branchname`) and the mapping form (`via: branchname`) are both parsed.
An unknown branch name is a hard error.

---

## Not applicable to goFF (by design)

The following pyFF constructs appear in nearly all `.fd` files but are
**intentionally outside goFF's scope** because goFF handles request routing via its
built-in MDQ HTTP server, not the pipeline:

| pyFF construct | Reason omitted |
|---|---|
| `when request:` | Request handling is the MDQ server's job |
| `when accept <mimetype>:` | Content negotiation is built into the MDQ handler |
| `when path <url>:` | URL routing is built into the MDQ handler |
| `emit <mimetype>` | Response emission is handled by the MDQ handler |
| `fork and merge` (request-side) | Request-side sub-pipeline; not applicable |
| `first` (request-side) | In a request context, equivalent to single-entity lookup in the MDQ server |
