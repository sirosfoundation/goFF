//go:build integration

// Package integration_test contains end-to-end integration tests that make
// live network requests to real-world SAML federation metadata endpoints.
//
// These tests require network access and may take several minutes to complete
// (the eduGAIN feed is ≈50 MB).  Run them with:
//
//	go test -tags integration -timeout 15m ./tests/integration/...
//
// The tests validate that goFF can:
//   - Fetch and XML-signature-verify the eduGAIN metadata aggregate.
//   - Load it into a running MDQ server.
//   - Serve entity lookups conforming to the MDQ protocol.
//   - Return SWAMID-registered entities that are exported to eduGAIN, and that
//     the entities exposed by eduGAIN are consistent with the SWAMID source:
//   - Public keys in eduGAIN ⊆ public keys in SWAMID (no key injection).
//   - Entity categories in eduGAIN ⊆ entity categories in SWAMID
//     (SWAMID is a superset — it may carry federation-local categories that
//     are not exported to eduGAIN).
//   - mdui:DisplayName and md:OrganizationDisplayName values in eduGAIN
//     must match the corresponding SWAMID values for the same xml:lang tag.
package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/antchfx/xmlquery"
	"github.com/sirosfoundation/goff/internal/app"
)

// ---------------------------------------------------------------------------
// Published endpoints and certificates
// Sources:
//   - https://technical.edugain.org/metadata  (eduGAIN MDS)
//   - https://wiki.sunet.se/spaces/SWAMID/pages/17137848  (SWAMID trust)
// ---------------------------------------------------------------------------

const (
	// eduGAIN metadata aggregate (v2).
	eduGAINMetadataURL = "https://mds.edugain.org/edugain-v2.xml"
	// eduGAIN signing certificate.
	// SHA-256: BD:21:40:48:9A:9B:D7:40:44:DD:68:05:34:F7:78:88:A9:C1:3B:0A:C1:7C:4F:3A:03:6E:0F:EC:6D:89:99:95
	// Generated during GEANT Key Signing Ceremony, Stockholm 2022-03-08.
	eduGAINCertURL = "https://technical.edugain.org/mds-v2.cer"

	// SWAMID registered IdP feed — the entities SWAMID registers and exports
	// to eduGAIN.
	swamidIdpURL = "https://mds.swamid.se/md/swamid-idp.xml"

	// Minimum fraction of sampled SWAMID IdPs that must appear in the goFF
	// MDQ server for the presence sub-test to pass.
	swamidPresenceThreshold = 0.70

	// Number of entity IDs to sample from the SWAMID feed for integrity checks.
	swamidSampleSize = 10

	// Maximum time to wait for the MDQ server to finish its first pipeline run.
	// Downloading and parsing ≈50 MB eduGAIN XML typically takes 1–5 minutes.
	serverReadyTimeout = 10 * time.Minute
)

// ---------------------------------------------------------------------------
// Entity data model
// ---------------------------------------------------------------------------

// entityInfo holds the attributes of a SAML EntityDescriptor that are checked
// for cross-federation consistency.
type entityInfo struct {
	EntityID string

	// UIDisplayNames: xml:lang → mdui:DisplayName text.
	UIDisplayNames map[string]string
	// OrgDisplayNames: xml:lang → md:OrganizationDisplayName text.
	OrgDisplayNames map[string]string

	// EntityCategories: set of entity-category URI values from the
	// http://macedir.org/entity-category saml:Attribute.
	EntityCategories map[string]struct{}

	// CertFingerprints: set of lower-case hex SHA-256(DER) fingerprints for
	// all X.509 certificates found in KeyDescriptor elements.
	CertFingerprints map[string]struct{}
}

// ---------------------------------------------------------------------------
// XML parsing helpers (namespace-prefix agnostic via local-name() XPath)
// ---------------------------------------------------------------------------

// extractEntityInfo builds an entityInfo from an xmlquery EntityDescriptor node.
func extractEntityInfo(ed *xmlquery.Node) *entityInfo {
	info := &entityInfo{
		EntityID:         ed.SelectAttr("entityID"),
		UIDisplayNames:   make(map[string]string),
		OrgDisplayNames:  make(map[string]string),
		EntityCategories: make(map[string]struct{}),
		CertFingerprints: make(map[string]struct{}),
	}

	// mdui:DisplayName — nested under role-descriptor Extensions/UIInfo.
	for _, dn := range xmlquery.Find(ed, ".//*[local-name()='UIInfo']/*[local-name()='DisplayName']") {
		if lang := xmlLang(dn); lang != "" {
			info.UIDisplayNames[lang] = strings.TrimSpace(dn.InnerText())
		}
	}

	// md:OrganizationDisplayName — under the Organization element.
	for _, odn := range xmlquery.Find(ed, ".//*[local-name()='Organization']/*[local-name()='OrganizationDisplayName']") {
		if lang := xmlLang(odn); lang != "" {
			info.OrgDisplayNames[lang] = strings.TrimSpace(odn.InnerText())
		}
	}

	// Entity categories: search EntityAttributes > Attribute[@Name=...] > AttributeValue.
	// The URI is checked in Go rather than embedded in XPath to avoid quoting issues.
	for _, attrEl := range xmlquery.Find(ed, ".//*[local-name()='EntityAttributes']/*[local-name()='Attribute']") {
		if attrEl.SelectAttr("Name") != "http://macedir.org/entity-category" {
			continue
		}
		for _, av := range xmlquery.Find(attrEl, "./*[local-name()='AttributeValue']") {
			val := strings.TrimSpace(av.InnerText())
			if val != "" {
				info.EntityCategories[val] = struct{}{}
			}
		}
	}

	// X.509 certificate fingerprints from all KeyDescriptor trees.
	for _, certEl := range xmlquery.Find(ed, ".//*[local-name()='KeyDescriptor']//*[local-name()='X509Certificate']") {
		raw := stripWS(certEl.InnerText())
		der, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(der)
		info.CertFingerprints[hex.EncodeToString(sum[:])] = struct{}{}
	}

	return info
}

// xmlLang returns the xml:lang value of node n. The xml prefix is predeclared
// in XML so parsers store it as Local="lang"; matching by local name is safe.
func xmlLang(n *xmlquery.Node) string {
	for _, attr := range n.Attr {
		if attr.Name.Local == "lang" {
			return attr.Value
		}
	}
	return ""
}

// stripWS removes all ASCII whitespace from a base64-encoded certificate
// string — some serialisers insert line breaks every 64 or 76 characters.
func stripWS(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		default:
			return r
		}
	}, s)
}

// parseEntitiesFeed parses a SAML EntitiesDescriptor (or EntityDescriptor)
// XML document and returns a map entityID → *entityInfo.
func parseEntitiesFeed(xmlData []byte) (map[string]*entityInfo, error) {
	doc, err := xmlquery.Parse(bytes.NewReader(xmlData))
	if err != nil {
		return nil, fmt.Errorf("parse feed XML: %w", err)
	}
	result := make(map[string]*entityInfo)
	for _, ed := range xmlquery.Find(doc, "//*[local-name()='EntityDescriptor']") {
		info := extractEntityInfo(ed)
		if info.EntityID != "" {
			result[info.EntityID] = info
		}
	}
	return result, nil
}

// parseSingleEntityXML parses a single-entity XML response from an MDQ
// /entities/<id> lookup.
func parseSingleEntityXML(xmlData []byte) (*entityInfo, error) {
	doc, err := xmlquery.Parse(bytes.NewReader(xmlData))
	if err != nil {
		return nil, fmt.Errorf("parse entity XML: %w", err)
	}
	ed := xmlquery.FindOne(doc, "//*[local-name()='EntityDescriptor']")
	if ed == nil {
		return nil, fmt.Errorf("no EntityDescriptor in response")
	}
	info := extractEntityInfo(ed)
	if info.EntityID == "" {
		return nil, fmt.Errorf("EntityDescriptor has no entityID attribute")
	}
	return info, nil
}

// ---------------------------------------------------------------------------
// Cross-federation data integrity comparison
// ---------------------------------------------------------------------------

// compareEntityData validates the eduGAIN version of an entity against the
// SWAMID source-of-truth and returns human-readable violation descriptions.
// An empty slice means all checks passed.
//
// Rules enforced:
//
//  1. All X.509 certs in eduGAIN must also appear in SWAMID — prevents
//     undetected key injection during aggregation.  SWAMID may legitimately
//     have additional certs during a key-rollover period.
//
//  2. All entity categories in eduGAIN must appear in SWAMID.  SWAMID is a
//     superset: it carries federation-local categories not exported to
//     eduGAIN, but eduGAIN must not introduce new ones.
//
//  3. Every mdui:DisplayName in eduGAIN (keyed by xml:lang) must match the
//     same lang/value pair in SWAMID.  eduGAIN may have fewer languages than
//     SWAMID (translations may be dropped), but values that do appear must
//     be identical.
//
//  4. Same rule as (3) for md:OrganizationDisplayName.
func compareEntityData(swamid, edugain *entityInfo) []string {
	var violations []string

	// Rule 1 — public keys.
	for fp := range edugain.CertFingerprints {
		if _, ok := swamid.CertFingerprints[fp]; !ok {
			violations = append(violations, fmt.Sprintf(
				"cert SHA256=%s…%s in eduGAIN not found in SWAMID (unauthorized key?)",
				fp[:8], fp[56:]))
		}
	}
	if len(edugain.CertFingerprints) == 0 {
		violations = append(violations, "eduGAIN entity has no X.509 certificates")
	}

	// Rule 2 — entity categories.
	for cat := range edugain.EntityCategories {
		if _, ok := swamid.EntityCategories[cat]; !ok {
			violations = append(violations, fmt.Sprintf(
				"entity-category %q in eduGAIN not found in SWAMID", cat))
		}
	}

	// Rule 3 — mdui:DisplayName.
	for lang, eduName := range edugain.UIDisplayNames {
		swamidName, ok := swamid.UIDisplayNames[lang]
		if !ok {
			violations = append(violations, fmt.Sprintf(
				"mdui:DisplayName[%q]=%q in eduGAIN missing from SWAMID",
				lang, clip(eduName, 60)))
			continue
		}
		if swamidName != eduName {
			violations = append(violations, fmt.Sprintf(
				"mdui:DisplayName[%q] mismatch — eduGAIN=%q  SWAMID=%q",
				lang, clip(eduName, 60), clip(swamidName, 60)))
		}
	}

	// Rule 4 — md:OrganizationDisplayName.
	for lang, eduName := range edugain.OrgDisplayNames {
		swamidName, ok := swamid.OrgDisplayNames[lang]
		if !ok {
			violations = append(violations, fmt.Sprintf(
				"md:OrganizationDisplayName[%q]=%q in eduGAIN missing from SWAMID",
				lang, clip(eduName, 60)))
			continue
		}
		if swamidName != eduName {
			violations = append(violations, fmt.Sprintf(
				"md:OrganizationDisplayName[%q] mismatch — eduGAIN=%q  SWAMID=%q",
				lang, clip(eduName, 60), clip(swamidName, 60)))
		}
	}

	return violations
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

// fetchURL downloads rawURL with the given timeout and returns the body.
// It returns an error rather than calling t.Fatal so it is safe to call from
// goroutines that are not the test goroutine.
func fetchURL(rawURL string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, rawURL)
	}
	return io.ReadAll(resp.Body)
}

// ensurePEM returns b as a PEM CERTIFICATE block.
// If b already starts with a PEM header it is returned as-is; otherwise it is
// assumed to be DER-encoded and wrapped.
func ensurePEM(b []byte) []byte {
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte("-----BEGIN")) {
		return b
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
}

// waitHTTP polls rawURL until it returns HTTP 200 or the deadline expires.
func waitHTTP(t *testing.T, rawURL string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		resp, err := http.Get(rawURL) //nolint:noctx,gosec
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server at %q did not become ready within %v", rawURL, timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// Main test
// ---------------------------------------------------------------------------

// TestEduGAINMDQServer is the primary end-to-end integration test.
//
// It starts a goFF MDQ server loaded with the full eduGAIN metadata aggregate
// (XML-signature verified), then runs sub-tests for MDQ protocol conformance
// and cross-federation data integrity against the SWAMID source registry.
func TestEduGAINMDQServer(t *testing.T) {
	tmpDir := t.TempDir()

	// -----------------------------------------------------------------------
	// Step 1 — download and validate the eduGAIN signing certificate.
	// -----------------------------------------------------------------------
	t.Log("downloading eduGAIN signing certificate…")
	rawCert, err := fetchURL(eduGAINCertURL, 2*time.Minute)
	if err != nil {
		t.Fatalf("download eduGAIN cert: %v", err)
	}
	pemCert := ensurePEM(rawCert)
	block, _ := pem.Decode(pemCert)
	if block == nil {
		t.Fatal("eduGAIN cert could not be decoded as PEM")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("eduGAIN cert is not valid X.509: %v", err)
	}
	certPath := filepath.Join(tmpDir, "mds-v2.pem")
	if err := os.WriteFile(certPath, pemCert, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	t.Logf("eduGAIN signing certificate saved to %s", certPath)

	// -----------------------------------------------------------------------
	// Step 2 — write the pipeline YAML.
	// -----------------------------------------------------------------------
	pipelinePath := filepath.Join(tmpDir, "edugain.yaml")
	pipelineYAML := fmt.Sprintf(`
- when update:
    - load:
        sources:
          - url: %s
            verify: %s
    - select
`, eduGAINMetadataURL, certPath)
	if err := os.WriteFile(pipelinePath, []byte(pipelineYAML), 0o600); err != nil {
		t.Fatalf("write pipeline: %v", err)
	}

	// -----------------------------------------------------------------------
	// Step 3 — start the goFF MDQ server on a randomly allocated port.
	// -----------------------------------------------------------------------
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- app.RunServer(ctx, app.ServerOptions{
			PipelinePath: pipelinePath,
			ListenAddr:   addr,
			OutputDir:    tmpDir,
		})
	}()

	// -----------------------------------------------------------------------
	// Step 4 — fetch the SWAMID IdP feed concurrently while the server
	// downloads and processes the eduGAIN aggregate.
	// -----------------------------------------------------------------------
	type swamidResult struct {
		feed map[string]*entityInfo
		err  error
	}
	swamidCh := make(chan swamidResult, 1)
	go func() {
		b, err := fetchURL(swamidIdpURL, 2*time.Minute)
		if err != nil {
			swamidCh <- swamidResult{err: fmt.Errorf("download SWAMID feed: %w", err)}
			return
		}
		feed, err := parseEntitiesFeed(b)
		if err != nil {
			swamidCh <- swamidResult{err: fmt.Errorf("parse SWAMID feed: %w", err)}
			return
		}
		swamidCh <- swamidResult{feed: feed}
	}()

	// -----------------------------------------------------------------------
	// Step 5 — wait for healthz (HTTP listener up) then readyz (pipeline done).
	// -----------------------------------------------------------------------
	t.Log("waiting for /healthz…")
	waitHTTP(t, fmt.Sprintf("http://%s/healthz", addr), 30*time.Second)
	t.Log("waiting for /readyz — downloading ≈50 MB eduGAIN feed…")
	waitHTTP(t, fmt.Sprintf("http://%s/readyz", addr), serverReadyTimeout)
	t.Log("MDQ server is ready")

	select {
	case err := <-serverErrCh:
		t.Fatalf("MDQ server exited unexpectedly: %v", err)
	default:
	}

	// Collect the SWAMID parse result.
	swamidRes := <-swamidCh
	if swamidRes.err != nil {
		t.Fatalf("SWAMID feed: %v", swamidRes.err)
	}
	swamidFeed := swamidRes.feed
	t.Logf("SWAMID IdP feed: %d registered identity providers", len(swamidFeed))

	// -----------------------------------------------------------------------
	// Sub-tests
	// -----------------------------------------------------------------------

	t.Run("entities_list_json", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://%s/entities", addr)) //nolint:noctx,gosec
		if err != nil {
			t.Fatalf("GET /entities: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("unexpected Content-Type %q (want application/json)", ct)
		}
	})

	t.Run("entities_list_xml", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet,
			fmt.Sprintf("http://%s/entities", addr), nil)
		req.Header.Set("Accept", "application/samlmetadata+xml")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /entities (XML): %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !bytes.Contains(body, []byte("EntitiesDescriptor")) {
			t.Error("aggregate XML does not contain EntitiesDescriptor")
		}
	})

	t.Run("swamid_presence_and_integrity", func(t *testing.T) {
		testSWAMIDPresenceAndIntegrity(t, addr, swamidFeed)
	})
}

// testSWAMIDPresenceAndIntegrity samples swamidSampleSize entity IDs from the
// SWAMID feed, checks each against the goFF MDQ server, and for those that are
// found verifies key, entity-category, and display-name consistency.
func testSWAMIDPresenceAndIntegrity(t *testing.T, mdqAddr string, swamidFeed map[string]*entityInfo) {
	t.Helper()

	ids := make([]string, 0, len(swamidFeed))
	for id := range swamidFeed {
		ids = append(ids, id)
	}
	rand.Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })
	if len(ids) > swamidSampleSize {
		ids = ids[:swamidSampleSize]
	}
	t.Logf("sampling %d of %d SWAMID IdPs", len(ids), len(swamidFeed))

	found := 0
	for _, entityID := range ids {
		swamidInfo := swamidFeed[entityID]
		entityURL := fmt.Sprintf("http://%s/entities/%s", mdqAddr, url.PathEscape(entityID))

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, entityURL, nil)
		if err != nil {
			t.Errorf("[%s] build MDQ request: %v", entityID, err)
			continue
		}
		req.Header.Set("Accept", "application/samlmetadata+xml")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("[%s] MDQ lookup: %v", entityID, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			t.Logf("  ✗  not in eduGAIN: %s", entityID)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("  ?  HTTP %d for %q", resp.StatusCode, entityID)
			continue
		}
		found++

		// Parse the entity XML returned by the goFF MDQ server (loaded from eduGAIN).
		eduInfo, err := parseSingleEntityXML(body)
		if err != nil {
			t.Errorf("  ✓  found but XML unreadable: %s — %v", entityID, err)
			continue
		}

		// Compare SWAMID (source of truth) vs eduGAIN (derived copy).
		violations := compareEntityData(swamidInfo, eduInfo)
		if len(violations) > 0 {
			t.Errorf("  ✓  found — DATA INTEGRITY FAILURES for %s:", entityID)
			for _, v := range violations {
				t.Errorf("       • %s", v)
			}
		} else {
			t.Logf("  ✓  OK  certs=%d  cats=%d  uiNames=%d  orgNames=%d  — %s",
				len(eduInfo.CertFingerprints),
				len(eduInfo.EntityCategories),
				len(eduInfo.UIDisplayNames),
				len(eduInfo.OrgDisplayNames),
				entityID)
		}
	}

	hitRate := float64(found) / float64(len(ids))
	t.Logf("presence: %d/%d (%.0f%%) SWAMID IdPs found in eduGAIN",
		found, len(ids), 100*hitRate)
	if hitRate < swamidPresenceThreshold {
		t.Errorf("hit rate %.0f%% is below the %.0f%% threshold",
			100*hitRate, 100*swamidPresenceThreshold)
	}
}
