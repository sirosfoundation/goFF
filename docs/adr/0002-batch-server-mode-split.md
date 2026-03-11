# ADR 0002: Batch and Server Mode Split

## Status
Accepted

## Context
pyFF historically uses pipelines in both batch and server use cases. The `goFF` specification explicitly allows simplifying server behavior.

## Decision
`goFF` will provide two modes in one binary:
- `batch`: execute pipelines and write artifacts.
- `server`: build/refresh internal metadata repository from pipelines, then serve MDQ via dedicated handlers.

Server request handling will not be implemented as pipeline actions.

## Consequences
- Runtime request path is simpler and easier to optimize.
- Pipeline logic remains central for repository generation and updates.
- Some pyFF server-mode behaviors may be modeled differently and must be documented.
