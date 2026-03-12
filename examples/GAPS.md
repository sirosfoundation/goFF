# pyFF → goFF Gap Analysis

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
| `eidas.fd` | — | ❌ per-source inline options, custom when-branches |
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

pyFF uses named when-branches as named entry points for multi-mode pipelines:
`when normalize:`, `when edugain:`, `when eidas:`, `when swamid:`, `when sign:`.
A separate pyFF invocation is run with `--target=branchname` to trigger the
appropriate branch.

goFF evaluates only `when update`, `when x`, `when true`, `when always` branches.
All other branch names are skipped.  This is intentional — goFF does not implement
pyFF's multi-target invocation model.

**Impact:** Any pre-processing logic (XSLT cleanup, XML normalisation) embedded in
those branches is silently skipped.  Users must inline the XSLT/cleanup steps
directly in the `when update:` section.

---

### GAP-12 · `load: via:` only supports in-pipeline aliases, not branch names

**Affects:** `mdx.fd`, `edugain-copy.fd`

pyFF's `via` notation — `url via branchname` — means "fetch this source and run it
through the `when branchname:` processing branch before ingesting".  In goFF, `via`
is implemented as an **intersection** filter: only entities whose IDs also appear in
the referenced alias are admitted.  The branch-invocation semantics are not
supported.

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
