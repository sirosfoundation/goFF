# pyFF → goFF Gap Analysis

This document analyses every pyFF `examples/*.fd` pipeline and records which ones
could not be fully translated, and why.  Two dimensions are tracked:

- **Functionality coverage**: Can all the semantic behaviour of the pyFF pipeline
  be expressed in a goFF pipeline?  Governs the ✅ / ⚠️ / ❌ indicator in the table.
- **Syntax compatibility**: Would a direct transliteration of the pyFF YAML file be
  accepted by goFF's parser without modification?  Where pyFF syntax differs, the
  relevant GAP entry is referenced.

Closed gaps are marked ✅ with the implementing commit reference.  Items marked
"Won't implement" are out of scope; items marked "Intentionally unsupported" are
deliberately excluded.

The **MDQ request-handling pipeline** (`when request:`, `when accept:`, `when
path:`, and `emit`) is **out of scope** — goFF handles HTTP request routing in its
built-in MDQ server, not the pipeline.  See the final section for details.

---

## Coverage summary

| pyFF file | goFF example | Coverage |
|---|---|---|
| `uk.fd` | `basic-load-publish.yaml` | ✅ full |
| `expiration.fd` | `certreport.yaml` | ✅ full |
| `renater.fd` | `sign-publish.yaml` | ✅ full |
| `safire-fed.fd` | `sign-publish.yaml` | ✅ full — per-URL verify via `SourceEntry`; `store:` → `publish: dir:` (GAP-13) |
| `edugain.fd` | `multiple-federations.yaml` | ✅ full — `store:` → `publish: dir:` (GAP-13) |
| `load.fd` | `multiple-federations.yaml` | ✅ full — `store:` → `publish: dir:` (GAP-13) |
| `edugain-idps.fd` | `select-idps.yaml` | ✅ full — per-URL verify via `SourceEntry`; `store:` → `publish: dir:` (GAP-13) |
| `filter-idps.fd` | `select-idps.yaml` | ✅ full — per-URL verify via `SourceEntry` |
| `dj.fd`, `edugain-json.fd` | `discojson.yaml` | ✅ full |
| `edugain-fork.fd` | `fork-idp-sp.yaml` | ✅ full — `store:` → `publish: dir:` (GAP-13) |
| `kirei2.fd` | `xslt-sign-publish.yaml` | ✅ full — `store:` → `publish: dir:` (GAP-13) |
| `ukmulti.fd` | `finalize-aggregate.yaml` | ✅ full |
| `test.fd`, `edugain-copy.fd` | `sub-federation-aliases.yaml` | ✅ full — `when`/`via` semantics correct; `setattr: selector:` covers `fork and merge` |
| `big.fd` | `xrd-links.yaml` | ✅ full — XRD input + `store:` → `publish: dir:` (GAP-13) |
| `mdx.fd` | — | ⚠️ partial — `fork and merge` replaced by `setattr: selector:` (GAP-1 workaround); XRD/alias supported |
| `eidas.fd` | — | ✅ full — inline source aliases and custom `when`-branches fully supported |
| `edugain-fork-and-filter.fd` | — | ✅ full — `check_xml_namespaces` accepted; inline source aliases supported |
| `ndn.fd` | — | ✅ full — XRD input supported; `when update:` + `via` semantics correct |
| `out-edugain.fd` | — | ✅ full — directory-load from prior `publish: dir:` output |
| `edugain-mdq.fd` | `mdq-server-pipeline.yaml` | ✅ full — request pipeline body is no-op in batch; batch portion works |
| `batch-mdq-loop.fd` | `mdq-server-pipeline.yaml` | ⚠️ partial — `map:` / `log_entity:` omitted (GAP-5/6); all other constructs (`when batch:`, `then <label>:`, `drop_xsi_type:`, `store:`) now supported |
| `new-renater.fd` | — | ⚠️ partial — batch portion covered by `sign-publish.yaml`; source URLs contain typos in original |
| `pp.fd` | — | ❌ `signcerts` intentionally unsupported (GAP-8) |

---

## Gap catalogue

### GAP-1 · `fork and merge` → ✅ CLOSED via `setattr: selector:`

**Implemented in:** commit `eda16f9`

goFF supports a `selector:` sub-option on `setattr`, `reginfo`, and `pubinfo` steps.
When set, attribute enrichment is applied only to entities matching the selector
expression (XPath predicate, source alias, or any standard goFF selector string).

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

Note: pyFF's `fork and merge` YAML key is parsed by goFF as a regular `fork` (the
`and merge` suffix is stripped by `baseActionName`), so it does not cause a parse
error.  goFF's fork is sandbox-only and does not propagate results back; any
pyFF pipeline using `fork and merge` for attribute enrichment should be translated
to `setattr: {selector: ...}` as shown above.

The request-side variant of `fork and merge` (used inside `when request:` bodies
for MDQ sub-pipeline dispatch) is intentionally out of scope.

---

### GAP-2 · Per-URL inline verification → ✅ CLOSED via `SourceEntry`

**Implemented in:** commit `eda16f9`

`LoadStep` accepts structured source entries with per-source `verify` certs:

```yaml
# goFF — per-source cert verification via SourceEntry mapping
- load:
    sources:
      - url: https://mds.swamid.se/md/swamid-2.0.xml
        verify: /path/to/swamid-cert.pem
      - url: https://metadata.safire.ac.za/safire-edugain.xml
        verify: /path/to/safire-cert.pem
```

**Limitation:** pyFF's colon-separated SHA-1/SHA-256 fingerprint inline notation
(`URL A6:78:5A:...` on a single line) is not supported.  goFF requires a PEM cert
file path.  Operators migrating from pyFF need to save the peer certificate to a
file and reference it via `verify:`.

---

### GAP-3 · Per-source inline `as` alias and keyword flags → ✅ CLOSED via `SourceEntry` and inline syntax

**Implemented in:** commit `eda16f9`

`LoadStep` supports two syntaxes for per-source aliases:

**Inline scalar syntax** (mirrors pyFF):
```yaml
- load:
  - /path/to/fed.xml as kaka
  - /path/to/fed.xml as kaka cleanup
  - https://example.org/fed.xml as /my-source
  - examples/links.xrd as links via normalize
```

**Mapping syntax** (more explicit):
```yaml
- load:
  - file: /path/to/fed.xml
    as: kaka
    cleanup: true
  - url: https://example.org/fed.xml
    as: /my-source
    verify: cert.pem
    via: normalize
```

Aliases are registered in the source map immediately after loading, so they are
available to subsequent `select:`, `setattr: selector:`, and `filter:` expressions.

---

### GAP-4 · XRD/XRDS input format → ✅ CLOSED

**Implemented in:** commit `eda16f9`

`load:` transparently handles XRD/XRDS discovery documents.  When a loaded file or
URL contains an XRD/XRDS document (root `<XRDS>` or `<XRD>` in namespace
`http://docs.oasis-open.org/ns/xri/xrd-1.0`), goFF extracts all
`<Link rel="urn:oasis:names:tc:SAML:2.0:metadata" href="..."/>` URLs and loads
each one as SAML metadata.

---

### GAP-5 · `map:` — per-entity fork loop

**Status:** Won't implement

pyFF's `map:` step iterates over each entity in the current working set, running a
sub-pipeline for each entity individually:

```yaml
# pyFF
- map:
   - log_entity:
   - fork:
      - then sign:
      - publish:
          hash_link: true
          urlencode_filenames: true
          update_store: false
```

This is primarily used for per-entity signing and per-entity file emission in MDQ
batch loops.  goFF's `publish: {dir:, hash_link: true}` covers the most important
use-case (writing per-entity files to a directory for static MDQ serving).

Per-entity signing via `map:` is not currently representable in goFF; the
workaround is to sign at the aggregate level before publishing.

---

### GAP-6 · `log_entity:` action not supported

**Status:** Won't implement (depends on GAP-5 `map:`)

Used inside `map:` loops for per-entity diagnostic logging.  goFF's `info` and
`dump` actions cover aggregate-level listing.  Not applicable without `map:`.

---

### GAP-7 · `check_xml_namespaces` action → ✅ CLOSED (no-op)

**Implemented in:** commit `eda16f9`

`check_xml_namespaces` is accepted as a valid pipeline action and treated as a
no-op.  goFF validates XML namespace correctness implicitly during load (the XML
parser rejects malformed namespace declarations).

---

### GAP-8 · `signcerts` action not supported

**Status:** Intentionally unsupported

**Affects:** `pp.fd`

pyFF's `signcerts` adds X.509 certificate signing infrastructure to embedded
certificates in entity XML.  This is a certificate renewal workflow tool with no
equivalent in goFF.  The action is accepted by the parser but a no-op at runtime
(same as `emit` and `merge`).

---

### GAP-9 · pyFF on-disk store as cross-pipeline source → ✅ CLOSED via directory loading

**Implemented in:** commit `eda16f9`

`load:` supports loading from directories: when a path points to a directory, goFF
scans and loads every `*.xml` file within it.  This enables round-tripping through
`publish: {dir:}`:

```yaml
# Pipeline A
- publish:
    dir: /tmp/edugain

# Pipeline B (run later)
- load:
  - /tmp/edugain
```

See also GAP-13 for the `store:` action which pyFF uses to write such directories.

---

### GAP-10 · `publish:` options `urlencode_filenames`, `raw`, `ext` → ✅ PARTIALLY CLOSED

**Implemented in:** commit `eda16f9`

- **`urlencode_filenames: true`** — ✅ implemented; writes MDQ-compatible
  percent-encoded filenames (`%7Bsha256%7DHEXHASH`).
- **`ext: <suffix>`** — ✅ implemented; overrides the default `.xml` extension.
- **`raw: true`** — accepted but currently a no-op; `publish: {dir:}` always
  writes raw entity XML (one `EntityDescriptor` per file).
- **`update_store: false`** — accepted (unknown keys are silently ignored by the
  Go YAML library); no pyFF store concept in goFF so has no effect regardless.

---

### GAP-11 · `when <custom-name>:` pre-processing branches → ✅ CLOSED

**Implemented in:** commit `8468ad9`

`when <name>:` blocks are preserved as `WhenStep` nodes in the pipeline AST.  At
runtime, a `when name:` block fires iff `name` is present in the pipeline's active
state labels, matching pyFF's `req.state.get(condition)` semantics exactly.

Default batch execution sets `states = {update, x, true, always}` so all standard
batch-mode guards fire.  Custom named branches (`when normalize:`, `when edugain:`,
etc.) do not fire unless that label is present in `ExecuteOptions.States`, which
only happens during a `via`-invoked re-run (see GAP-12).

---

### GAP-12 · `load: via:` branch invocation → ✅ CLOSED

**Implemented in:** commit `8468ad9`

`load <url> via foo` re-runs the **full root pipeline** with
`states = {foo: true}` and the freshly-loaded entities as the initial set.  Any
`when foo:` blocks fire; `when update:` blocks do not.

Pipelines should include `break` at the end of `when <name>:` bodies to stop
execution before the `when update:` load step is reached, preventing recursive
re-fetching — the same discipline pyFF requires.

The canonical pattern from `edugain-copy.fd` and `mdx.fd` works correctly:

```yaml
- when normalize:
    - xslt: tidy.xsl
    - break
- when update:
    - load:
      - https://example.org/fed.xml via normalize
    - select
    - publish: ...
```

---

### GAP-13 · `store:` action not recognized by parser → ✅ CLOSED

**Implemented in:** this release

**Affects:** `big.fd`, `edugain.fd`, `edugain-fork.fd`, `edugain-idps.fd`,
`kirei2.fd`, `load.fd`, `safire-fed.fd`

pyFF's `store:` step writes entity XML to a content-addressable on-disk directory
AND registers those entities as a named source in pyFF's in-memory store.  It
appears in many pipelines as a checkpoint step between loading/processing and final
publishing.

```yaml
# pyFF
- store:
    directory: /tmp/edugain
# or scalar form
- store:
   - directory /tmp/big
```

goFF now accepts `store:` and executes it as `publish: {dir: <path>}`.  Three
pyFF forms are all supported:

```yaml
# mapping form (most common)
- store:
    directory: /tmp/edugain

# scalar form (old pyFF)
- store:
   - directory /tmp/edugain

# bare path form
- store: /tmp/edugain
```

The in-memory store concept from pyFF is not needed: goFF uses in-pipeline aliases
(`select as /name:`) for same-run cross-step references and directory loading
(GAP-9 closed) for cross-run persistence.

---

### GAP-14 · `then <label>:` step not recognised by parser → ✅ CLOSED

**Implemented in:** this release

**Affects:** `batch-mdq-loop.fd`

pyFF's `then <label>:` step, used within `fork:` bodies, re-invokes the root
pipeline with `states = {label: true}` and the current entity set.  It is
semantically equivalent to a `via` invocation but as a standalone pipeline step
rather than a per-source load option.

```yaml
# pyFF  — in batch-mdq-loop.fd
- fork:
   - then sign:    # re-run root pipeline with states={sign:true}
   - break
```

goFF now accepts `then <label>:` as a step and implements it as a root-pipeline
re-run with `states = {label: true}` and the current entity set as input — the
in-pipeline equivalent of `load … via <label>`.  The canonical pattern from
`batch-mdq-loop.fd` works correctly:

```yaml
- when sign:
    - drop_xsi_type
    - finalize: …
    - sign: …
- when batch:
    - load: […]
    - select:
    - fork:
       - then sign:    # re-runs root pipeline with {sign:true}
       - publish: …
       - break
```

---

### GAP-15 · `when batch:` not in default execution states → ✅ CLOSED

**Implemented in:** this release

**Affects:** `batch-mdq-loop.fd`

`batch-mdq-loop.fd` uses `when batch:` as its main conditional guard for all batch
processing.  In pyFF, `batch` is a label that operators pass explicitly when
invoking the pipeline in batch mode.

goFF's default batch execution states are `{update, x, true, always}`.  `batch`
is not included, so a `when batch:` block in a migrated pipeline will be silently
skipped.

`"batch": true` is now included in the default batch-mode states alongside
`update`, `x`, `true`, and `always`.  Pipelines using `when batch:` as their
main guard (e.g. `batch-mdq-loop.fd`) now work without modification.

---

### GAP-16 · `drop_xsi_type:` step not recognised by parser → ✅ CLOSED (no-op)

**Implemented in:** this release

**Affects:** `batch-mdq-loop.fd`

pyFF's `drop_xsi_type` pipe removes `xsi:type` attributes from entity XML elements.
It is used as a pre-processing cleanup step before signing in `when sign:` blocks.

```yaml
# pyFF
- when sign:
   - drop_xsi_type:
   - finalize: ...
   - sign: ...
```

`drop_xsi_type` is now accepted by the parser as a no-op, consistent with
how `check_xml_namespaces` (GAP-7) was handled.  goFF's XML parser does not
introduce `xsi:type` attributes, so SAML metadata processed by goFF does not
need this cleanup step.  `log_entity` (per-entity diagnostic logging inside
`map:` loops) is also accepted as a no-op for the same reason.

---

## Not applicable to goFF (by design)

The following pyFF constructs appear in most `.fd` files but are **intentionally
outside goFF's scope** because goFF handles request routing via its built-in MDQ
HTTP server, not the pipeline:

| pyFF construct | Reason omitted |
|---|---|
| `when request:` | Request handling is the MDQ server's responsibility |
| `when accept <mimetype>:` | Content negotiation is built into the MDQ handler |
| `when path <url>:` | URL routing is built into the MDQ handler |
| `emit <mimetype>` | Response emission is handled by the MDQ handler |
| `fork and merge` (request-side) | Request-side sub-pipeline dispatch; not applicable |
| `first` (request-side) | Single-entity lookup in MDQ context; handled by the server |
| `pipe:` (request-side) | Response dispatch sub-pipeline; handled by the server |

All of the above are **parsed without error** by goFF (they are in the accepted
action list or their `when` bodies are), but their bodies are silently skipped
during batch execution.  This means pyFF pipeline files that contain both a batch
section (`when update:`) and a request section (`when request:`) can be loaded and
executed in goFF without any YAML changes — only the batch portion fires.
