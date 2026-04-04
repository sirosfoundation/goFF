# goFF

<div align="center">

[![CI](https://github.com/sirosfoundation/goFF/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/goFF/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/sirosfoundation/goff.svg)](https://pkg.go.dev/github.com/sirosfoundation/goff)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirosfoundation/goff)](https://goreportcard.com/report/github.com/sirosfoundation/goff)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sirosfoundation/goFF)](https://go.dev/)
[![Latest Release](https://img.shields.io/github/v/release/sirosfoundation/goFF?include_prereleases)](https://github.com/sirosfoundation/goFF/releases)
[![Issues](https://img.shields.io/github/issues/sirosfoundation/goFF)](https://github.com/sirosfoundation/goFF/issues)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-orange.svg)](LICENSE)

</div>

`goFF` (go Federation Feeder) is a Go reimplementation of [pyFF](https://github.com/IdentityPython/pyFF) — a SAML metadata processing pipeline engine used extensively by identity federations world-wide.

goFF runs the same pipeline YAML as pyFF and produces equivalent output, while offering:
- **Concurrent URL fetching** out of the box.
- **Drop-in binary replacement** for most pyFF update-mode pipeline configurations.
- **Standalone MDQ HTTP server** backed by pipeline-built repositories with TLS, graceful refresh, and health/metrics endpoints.
- **PKCS#11 / HSM signing** support alongside standard file-based key/cert pairs.

See [examples/GAPS.md](examples/GAPS.md) for a full gap analysis of pyFF → goFF migration and [docs/compatibility.md](docs/compatibility.md) for the complete pipeline action compatibility matrix.

---

## Quickstart

```bash
make build
./bin/goff version
```

### Batch mode

Run a pipeline and write output artifacts to a directory:

```bash
goff batch --pipeline pipeline.yaml --output ./out
# Env var equivalents: GOFF_PIPELINE, GOFF_OUTPUT
```

Minimal `pipeline.yaml`:

```yaml
- load:
    urls:
      - https://mds.swamid.se/md/swamid-2.0.xml
        verify: /path/to/swamid-cert.pem
- select:
    role: idp
- finalize:
    Name: https://metadata.my-fed.org/swamid-idps
    cacheDuration: PT1H
- sign:
    key: sign.key
    cert: sign.crt
- publish: swamid-idps.xml
```

### Server mode

Serve an MDQ endpoint backed by a periodically-refreshed pipeline:

```bash
goff server --pipeline pipeline.yaml --listen :8080
# Full env var list: see goff help server
```

MDQ endpoints:
- `GET /entities` — JSON list of all entity IDs
- `GET /entities/{sha1}HEXHASH` — XML or JSON for a single entity
- `GET /entities/{sha1}HEXHASH.xml` — XML
- `GET /entities/{sha1}HEXHASH.json` — JSON
- `GET /healthz` — liveness probe
- `GET /readyz` — readiness probe (200 after first successful refresh)
- `GET /metrics` — operational counters

---

## CLI Reference

### `goff batch`

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--pipeline` | `GOFF_PIPELINE` | _(required)_ | Path to pipeline YAML |
| `--output` | `GOFF_OUTPUT` | `./out` | Output directory |
| `--verbose` | — | `false` | Print per-step progress to stderr |

### `goff server`

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--pipeline` | `GOFF_PIPELINE` | _(required)_ | Path to pipeline YAML |
| `--listen` | `GOFF_LISTEN` | `:8080` | HTTP listen address |
| `--output` | `GOFF_OUTPUT_DIR` | _(none)_ | Optional pipeline output directory |
| `--refresh-interval` | `GOFF_REFRESH_INTERVAL` | `5m` | Pipeline refresh interval (`0` disables) |
| `--base-url` | `GOFF_BASE_URL` | _(none)_ | Externally-visible base URL |
| `--cache-duration` | `GOFF_CACHE_DURATION` | _(none)_ | ISO 8601 cache duration for XML responses |
| `--valid-until` | `GOFF_VALID_UNTIL` | _(none)_ | RFC 3339 or `+<duration>` validUntil |
| `--tls-cert` | `GOFF_TLS_CERT` | _(none)_ | Path to TLS certificate PEM |
| `--tls-key` | `GOFF_TLS_KEY` | _(none)_ | Path to TLS private key PEM |
| `--shutdown-timeout` | `GOFF_SHUTDOWN_TIMEOUT` | `15s` | Graceful shutdown timeout |
| `--entity-renderer` | `GOFF_ENTITY_RENDERER` | `auto` | JSON entity renderer: `auto`\|`minimal`\|`disco` |

### Logging

| Env var | Values | Default |
|---|---|---|
| `GOFF_LOG_LEVEL` | `debug`\|`info`\|`warn`\|`error` | `info` |
| `GOFF_LOG_FORMAT` | `text`\|`json` | `text` |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `2` | Invalid usage or missing required input |
| `3` | Pipeline parse/load failure |
| `4` | Pipeline execution failure |
| `5` | Server runtime failure |

---

## Pipeline Actions

All pyFF update-mode pipeline actions are supported. See [docs/compatibility.md](docs/compatibility.md) for the full matrix.

Quick reference:

| Category | Actions |
|---|---|
| Load | `load` (files, URLs, XRD/XRDS, inline entity IDs, per-source `verify`/`via`/`as`/`from`) |
| Select / filter | `select`, `filter`, `pick`, `first`, `sort` |
| Enrich | `setattr`, `reginfo`, `pubinfo`, `nodecountry` |
| Transform | `xslt` (via `xsltproc`), `drop_xsi_type` |
| Sign / verify | `sign`, `verify` (RSA-SHA256 enveloped; PKCS#11 supported) |
| Publish | `publish` (single file, directory, hash_link, update_store, raw) |
| Export | `discojson`, `discojson_idp`, `discojson_sp` |
| Report | `certreport`, `stats`, `info`/`dump`/`print` |
| Flow control | `when`, `then`, `fork`/`pipe`/`parsecopy`, `map`, `break`/`end` |
| pyFF compat | `store`, `finalize`, `check_xml_namespaces`, `log_entity`, `signcerts` (no-op), `emit` (no-op), `merge` (warns) |

---

## Examples

The [examples/](examples/) directory contains annotated pipeline YAML files covering common federation patterns:

| File | Description |
|---|---|
| `basic-load-publish.yaml` | Minimal load → publish pipeline |
| `sign-publish.yaml` | Load → sign → publish |
| `finalize-aggregate.yaml` | Finalize with `Name`/`cacheDuration`/`validUntil` |
| `multiple-federations.yaml` | Load from multiple sources, merge, publish |
| `select-idps.yaml` | Role-based filtering |
| `fork-idp-sp.yaml` | Fork to separate IdP/SP output files |
| `discojson.yaml` | Generate discovery JSON |
| `discojson-roles.yaml` | Per-role discovery JSON |
| `xrd-links.yaml` | Load from XRD/XRDS discovery document |
| `xslt-sign-publish.yaml` | XSLT transform → sign → publish |
| `sub-federation-aliases.yaml` | In-pipeline source aliases with `via` preprocessing |
| `mdq-server-pipeline.yaml` | Per-entity MDQ static file publishing |
| `sign-pkcs11.yaml` | PKCS#11 / HSM signing |
| `certreport.yaml` | Certificate expiry report |

pyFF → goFF migration notes: [examples/GAPS.md](examples/GAPS.md)

---

## Development

```bash
make test        # unit + integration tests
make test-race   # race detector
make bench       # benchmarks
make lint        # golangci-lint
make build       # build ./bin/goff
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/adr/](docs/adr/) for architecture decisions.
