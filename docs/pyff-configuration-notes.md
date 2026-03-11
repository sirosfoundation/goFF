# pyFF Configuration Notes For goFF

This document captures pyFF configuration and runtime behaviors that `goFF` should replicate.

## Observed pyFF Pipeline Patterns

References: `IdentityPython/pyFF` docs and examples (`docs/usage/running.rst`, `docs/usage/examples.rst`, `examples/met.mdx`).

### 1. Dual-entry pipelines
Common server-mode structure:

```yaml
- when update:
  - load:
      - https://example.org/metadata.xml
- when request:
  - select
  - pipe:
      - when accept application/samlmetadata+xml application/xml:
          - first
          - finalize:
              cacheDuration: PT5H
              validUntil: P10D
          - sign:
              key: sign.key
              cert: sign.crt
          - emit application/samlmetadata+xml
          - break
      - when accept application/json:
          - discojson
          - emit application/json
          - break
```

Implication for `goFF`:
- Keep pipeline-driven update processing.
- Use standalone request handlers for MDQ responses, but preserve request-time format behavior and output semantics.
- Author native goFF pipelines as update-body pipelines (the contents of `when update`), not full dual-entry pyFF files.

### 2. Content negotiation expectations
pyFF supports:
- `Accept` header negotiation for XML/JSON.
- extension-aware routing (`.xml`, `.json`) under configured policy.

Implication for `goFF`:
- `/entities/{id}` should negotiate XML or JSON.
- `/entities/{id}.xml` and `/entities/{id}.json` should be supported.
- wildcard or missing `Accept` should follow extension/default behavior.

### 3. Refresh/update model
pyFF server mode regularly refreshes loaded metadata via update pipelines.

Implication for `goFF`:
- Server mode should run pipeline on startup.
- A periodic refresh loop should rerun pipelines and atomically replace repository state.
- Failed refresh must not clear the current repository.

## Initial goFF Mapping
Current implementation status:
- Batch pipeline execution: available for initial action subset (`load`, `select`, `publish`).
- Server repository build from pipeline: implemented.
- Server refresh loop: implemented via `--refresh-interval`.
- MDQ entity negotiation: implemented for XML/JSON on `/entities/{id}` plus `.xml/.json` path suffix.

## Near-term Compatibility Targets
- Prioritize pipe primitives used in pyFF `when update` branches for server refresh pipelines.
- Keep request-only pipeline primitives (`emit`, `break`, `discojson`, `when accept`) out of the update executor scope.
- Add fixture corpus modeled from pyFF update examples (`when update`) for parity validation.

## Update-Scope Primitive Priority
1. `load` with pyFF-style list arguments
2. `select` on loaded repository content
3. `publish`
4. update-time transforms and signing primitives (`xslt`, `finalize`, `sign`) in staged follow-up

Note:
- Native goFF step-list pipelines remain supported and preferred for concise configs.
- pyFF-style `when update` and `when x` wrappers are now accepted for migration convenience and flattened into the update execution sequence.
- Request-scope wrappers (`when request`, `when accept ...`) remain out of scope for update execution and are skipped.
