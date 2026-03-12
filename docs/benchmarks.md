# goFF Benchmark Baseline

This document tracks baseline benchmark results for core metadata processing paths.

## How to run

From the `goFF` repository root:

```bash
make bench
```

Equivalent direct command:

```bash
go test -run '^$' -bench . -benchmem ./internal/pipeline
```

## Current benchmark suite

- `BenchmarkParseMetadataFromXML_LargeAggregate`
  - Parses a synthetic aggregate with 5000 entities.
- `BenchmarkExecute_LoadSelectSortPublish_LargeAggregate`
  - Runs `load -> select(role=idp) -> sort(@entityID) -> publish` on a synthetic 3000-entity source.
- `BenchmarkBuildEntitiesXML_LargeAggregate`
  - Serialises 5000 entities into an `EntitiesDescriptor` XML aggregate.

## Fuzz tests

Short smoke runs (5 s each) are available via:

```bash
make fuzz
```

Targets: `FuzzParseMetadataFromXML`, `FuzzParseEntityXMLByID`, `FuzzParsePipelineYAML`.

CI runs each fuzz target for 30 seconds on every push.

## Tracking guidance

For each release cycle, capture and compare:
- `ns/op`
- `B/op`
- `allocs/op`

Store snapshots in PR descriptions or release notes so regressions are visible over time.
