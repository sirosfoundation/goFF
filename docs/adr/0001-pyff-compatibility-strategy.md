# ADR 0001: pyFF Compatibility Strategy

## Status
Accepted

## Context
`goFF` is intended to run pyFF-style pipeline YAML and produce equivalent output while taking advantage of Go's concurrency model.

## Decision
`goFF` will implement pipeline compatibility incrementally through a documented compatibility matrix and fixture-driven parity tests.

## Consequences
- Features are released in compatibility tiers instead of all-at-once parity.
- Every supported pipeline action must have parity tests and explicit behavior notes.
- Known deviations are allowed only if documented in `docs/compatibility.md`.
