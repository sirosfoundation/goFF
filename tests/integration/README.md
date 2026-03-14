# Integration Tests

This directory contains end-to-end integration tests that make live network
requests to real-world SAML federation metadata endpoints.  They are gated
behind the `integration` build tag so they never run in the normal `go test`
invocation.

## Running

```sh
go test -tags integration -timeout 15m ./tests/integration/...
```

The `-timeout 15m` flag is important: downloading and XML-parsing the full
eduGAIN metadata aggregate (≈50 MB) typically takes 1–5 minutes on a
residential connection.

## What the tests do

### `TestEduGAINMDQServer`

1. **Downloads the eduGAIN signing certificate** from
   `https://technical.edugain.org/mds-v2.cer` and validates that it parses as
   a valid X.509 certificate.

2. **Writes a goFF pipeline YAML** that loads the eduGAIN metadata aggregate
   (`https://mds.edugain.org/edugain-v2.xml`) with XML-signature verification
   against the downloaded certificate.

3. **Starts a goFF MDQ HTTP server** and waits up to 10 minutes for the first
   pipeline run to complete (`/readyz`).

4. **MDQ protocol conformance**:
   - `GET /entities` returns `application/json` by default and
     `application/samlmetadata+xml` when requested via `Accept`.

5. **SWAMID presence check**: fetches SWAMID's registered IdP feed
   (`https://mds.swamid.se/md/swamid-idp.xml`), draws a random sample of 10
   entity IDs, and verifies that ≥70% of them are accessible via the goFF MDQ
   `/entities/<entityID>` endpoint.

## Reference endpoints and certificates

| Resource | URL |
|---|---|
| eduGAIN metadata aggregate | `https://mds.edugain.org/edugain-v2.xml` |
| eduGAIN signing certificate | `https://technical.edugain.org/mds-v2.cer` |
| eduGAIN cert SHA-256 | `BD:21:40:48:9A:9B:D7:40:44:DD:68:05:34:F7:78:88:A9:C1:3B:0A:C1:7C:4F:3A:03:6E:0F:EC:6D:89:99:95` |
| SWAMID registered IdP feed | `https://mds.swamid.se/md/swamid-idp.xml` |
| SWAMID signing certificate | `https://mds.swamid.se/md/md-signer2.crt` |
| SWAMID cert SHA-256 | `A6:78:5A:37:C9:C9:0C:25:AD:5F:1F:69:22:EF:76:7B:C9:78:67:67:3A:AF:4F:8B:EA:A1:A7:6D:A3:A8:E5:85` |

Source: [eduGAIN MDS technical page](https://technical.edugain.org/metadata)
and [SWAMID metadata trust page](https://wiki.sunet.se/spaces/SWAMID/pages/17137848/SAML+Metadata+and+Trust).

## Notes

- If eduGAIN rotates their signing key, the test will fail at the pipeline
  `verify:` step.  Update `eduGAINCertURL` in the test if that happens.
- The 70% SWAMID presence threshold is intentionally conservative.  Some
  SWAMID-registered IdPs may be excluded from eduGAIN by policy or may fail
  eduGAIN's validation requirements.  A rate consistently below 70% warrants
  investigation of the goFF pipeline or the SWAMID export policy.
