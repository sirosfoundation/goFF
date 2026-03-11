# ADR 0003: XML Security Dependency Strategy

## Status
Accepted

## Context
SAML metadata signature generation and verification require stable XML security behavior, and the workspace `go.work` contains required replace directives for local XML security modules.

## Decision
`goFF` will consume XML security packages through the same dependency path used by sibling projects and rely on workspace `go.work` replace directives during development and integration testing.

## Consequences
- `goFF` must be part of the workspace `go.work` set.
- CI must validate signature workflows with expected module versions.
- Any deviation from workspace replace directives requires an ADR update.
