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

## Tracking guidance

For each release cycle, capture and compare:
- `ns/op`
- `B/op`
- `allocs/op`

Store snapshots in PR descriptions or release notes so regressions are visible over time.
