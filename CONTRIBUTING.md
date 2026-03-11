# Contributing to goFF

## Development
- Use the Go version declared in `go.mod`.
- Run baseline checks before opening a PR:
  - `make fmt`
  - `make vet`
  - `make test`

## Compatibility Policy
- Changes that affect pyFF behavior must update:
  - `docs/compatibility.md`
  - parity tests and fixtures

## ADR Policy
Architectural changes should include a new ADR in `docs/adr/`.
