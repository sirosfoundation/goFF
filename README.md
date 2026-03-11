# goFF

`goFF` (go Federation Feeder) is a Go reimplementation of pyFF focused on pipeline compatibility and high-performance SAML metadata processing.

## Current Status
This repository is in bootstrap mode. The initial Phase 0 scaffold provides:
- a single `goff` binary entrypoint
- batch/server command stubs
- baseline lint/test/build targets
- ADR and compatibility documentation skeletons

## Quickstart
```bash
make test
make build
./bin/goff version
```

## Predicate Fixture Examples
From the `goFF` repository root, you can run the select-predicate fixtures:

```bash
./bin/goff batch --pipeline tests/fixtures/pipelines/select-by-role-idp.yaml --output /tmp/goff-out
cat /tmp/goff-out/role-idp.txt

./bin/goff batch --pipeline tests/fixtures/pipelines/select-by-roles-all.yaml --output /tmp/goff-out
cat /tmp/goff-out/roles-all.txt

./bin/goff batch --pipeline tests/fixtures/pipelines/select-by-entity-category.yaml --output /tmp/goff-out
cat /tmp/goff-out/category-rs.txt

./bin/goff batch --pipeline tests/fixtures/pipelines/select-by-registration-authority.yaml --output /tmp/goff-out
cat /tmp/goff-out/reg-auth.txt

./bin/goff batch --pipeline tests/fixtures/pipelines/select-by-source-xpath.yaml --output /tmp/goff-out
cat /tmp/goff-out/source-xpath.txt

./bin/goff batch --pipeline tests/fixtures/pipelines/select-by-intersection.yaml --output /tmp/goff-out
cat /tmp/goff-out/intersection.txt
```

Reference metadata and expected outputs:
- `tests/fixtures/metadata/select-predicates.xml`
- `tests/fixtures/expected/role-idp.txt`
- `tests/fixtures/expected/roles-all.txt`
- `tests/fixtures/expected/category-rs.txt`
- `tests/fixtures/expected/reg-auth.txt`
- `tests/fixtures/expected/source-xpath.txt`
- `tests/fixtures/expected/intersection.txt`

## Project Docs
- `docs/specs.md`: source requirements
- `docs/implementation-plan.md`: phased delivery plan
- `docs/compatibility.md`: pyFF feature compatibility matrix
- `docs/pyff-pipe-triage.md`: pyFF pipe inventory triaged by complexity and priority
- `docs/benchmarks.md`: baseline benchmark suite and tracking guidance
- `docs/adr/`: architecture decision records
