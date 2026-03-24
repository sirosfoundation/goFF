package pipeline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// p2EnrichmentXML is a minimal SAML metadata document with embedded X.509
// certificates and MDUI elements for use in P2 step tests.
var p2EnrichmentXML = func() string {
	b, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "metadata", "p2-enrichment.xml"))
	if err != nil {
		panic("p2-enrichment.xml not found: " + err.Error())
	}
	return string(b)
}()

// TestNodeCountryAddsCountryTokens verifies that runNodeCountry extracts
// C= fields from embedded X.509 certs and adds country:<cc> text tokens.
func TestNodeCountryAddsCountryTokens(t *testing.T) {
	// Split combined XML into per-entity fragments, matching real pipeline behaviour.
	xmlDocs, err := parseEntityXMLByID([]byte(p2EnrichmentXML))
	if err != nil {
		t.Fatalf("parseEntityXMLByID: %v", err)
	}

	entities := []string{
		"https://idp.example.org/idp",
		"https://sp.example.org/sp",
	}
	attrs := map[string]EntityAttributes{
		"https://idp.example.org/idp": {Roles: map[string]struct{}{}, Categories: map[string]struct{}{}, TextTokens: map[string]struct{}{}, IPHints: map[string]struct{}{}},
		"https://sp.example.org/sp":   {Roles: map[string]struct{}{}, Categories: map[string]struct{}{}, TextTokens: map[string]struct{}{}, IPHints: map[string]struct{}{}},
	}

	result := runNodeCountry(entities, attrs, xmlDocs, nil)

	idpAttrs := result["https://idp.example.org/idp"]
	if _, ok := idpAttrs.TextTokens["country:se"]; !ok {
		t.Errorf("expected country:se token for IdP, got tokens: %v", idpAttrs.TextTokens)
	}

	spAttrs := result["https://sp.example.org/sp"]
	if _, ok := spAttrs.TextTokens["country:de"]; !ok {
		t.Errorf("expected country:de token for SP, got tokens: %v", spAttrs.TextTokens)
	}
}

// TestExtractCertsFromEntityXML verifies that extractCertsFromEntityXML can
// parse X.509 certificates from a SAML EntityDescriptor XML string.
func TestExtractCertsFromEntityXML(t *testing.T) {
	// Use just the IdP portion from the combined fixture;
	// extractCertsFromEntityXML scans for X509Certificate elements regardless.
	certs, err := extractCertsFromEntityXML(p2EnrichmentXML, nil)
	if err != nil {
		t.Fatalf("extractCertsFromEntityXML returned error: %v", err)
	}
	if len(certs) < 2 {
		t.Fatalf("expected at least 2 certs, got %d", len(certs))
	}

	countries := map[string]bool{}
	for _, c := range certs {
		for _, cc := range c.Subject.Country {
			countries[strings.ToLower(cc)] = true
		}
	}
	if !countries["se"] {
		t.Errorf("expected SE country in certs, got: %v", countries)
	}
	if !countries["de"] {
		t.Errorf("expected DE country in certs, got: %v", countries)
	}
}

// TestCertReportRunsWithoutError verifies that runCertReport does not panic or
// return an error when called with entities that have embedded X.509 certs.
func TestCertReportRunsWithoutError(t *testing.T) {
	entities := []string{"https://idp.example.org/idp"}
	xmlDocs := map[string]string{
		"https://idp.example.org/idp": p2EnrichmentXML,
	}
	// runCertReport prints to stdout; just verify it doesn't panic.
	runCertReport(entities, xmlDocs, nil)
}

// TestDiscoJSONWritesOutputFile verifies that runDiscoJSON produces a JSON file
// with correct entity entries from SAML metadata with MDUI extensions.
func TestDiscoJSONWritesOutputFile(t *testing.T) {
	outDir := t.TempDir()
	entities := []string{
		"https://idp.example.org/idp",
		"https://sp.example.org/sp",
	}
	attrs := map[string]EntityAttributes{
		"https://idp.example.org/idp": {
			Roles:      map[string]struct{}{"idp": {}},
			Categories: map[string]struct{}{},
			TextTokens: map[string]struct{}{},
			IPHints:    map[string]struct{}{},
		},
		"https://sp.example.org/sp": {
			Roles:      map[string]struct{}{"sp": {}},
			Categories: map[string]struct{}{},
			TextTokens: map[string]struct{}{},
			IPHints:    map[string]struct{}{},
		},
	}
	xmlDocs := map[string]string{
		"https://idp.example.org/idp": p2EnrichmentXML,
		"https://sp.example.org/sp":   p2EnrichmentXML,
	}

	cfg := DiscoJSONStep{Output: "disco.json"}
	if err := runDiscoJSON(cfg, outDir, BuildDiscoEntries(entities, attrs, xmlDocs, "")); err != nil {
		t.Fatalf("runDiscoJSON returned error: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(outDir, "disco.json"))
	if err != nil {
		t.Fatalf("did not find output disco.json: %v", err)
	}

	var entries []DiscoEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("disco.json is not valid JSON: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	byID := map[string]DiscoEntry{}
	for _, e := range entries {
		byID[e.EntityID] = e
	}

	idp, ok := byID["https://idp.example.org/idp"]
	if !ok {
		t.Fatal("missing idp entry")
	}
	if len(idp.DisplayNames) == 0 {
		t.Error("idp entry has no DisplayNames")
	}
	if len(idp.Type) == 0 || idp.Type[0] != "idp" {
		t.Errorf("idp entry type wrong: %v", idp.Type)
	}

	sp, ok := byID["https://sp.example.org/sp"]
	if !ok {
		t.Fatal("missing sp entry")
	}
	if len(sp.DisplayNames) == 0 {
		t.Error("sp entry has no DisplayNames")
	}
	if len(sp.Logos) == 0 {
		t.Error("sp entry has no Logos")
	}
	if len(sp.Geo) == 0 {
		t.Error("sp entry has no Geo hints")
	}
	if len(sp.Type) == 0 || sp.Type[0] != "sp" {
		t.Errorf("sp entry type wrong: %v", sp.Type)
	}
}

// TestDiscoJSONIdpFilter verifies that discojson_idp only includes IdP entities.
func TestDiscoJSONIdpFilter(t *testing.T) {
	outDir := t.TempDir()
	entities := []string{
		"https://idp.example.org/idp",
		"https://sp.example.org/sp",
	}
	attrs := map[string]EntityAttributes{
		"https://idp.example.org/idp": {
			Roles:      map[string]struct{}{"idp": {}},
			Categories: map[string]struct{}{},
			TextTokens: map[string]struct{}{},
			IPHints:    map[string]struct{}{},
		},
		"https://sp.example.org/sp": {
			Roles:      map[string]struct{}{"sp": {}},
			Categories: map[string]struct{}{},
			TextTokens: map[string]struct{}{},
			IPHints:    map[string]struct{}{},
		},
	}
	xmlDocs := map[string]string{
		"https://idp.example.org/idp": p2EnrichmentXML,
		"https://sp.example.org/sp":   p2EnrichmentXML,
	}

	cfg := DiscoJSONStep{Output: "disco-idp.json"}
	if err := runDiscoJSON(cfg, outDir, BuildDiscoEntries(entities, attrs, xmlDocs, "idp")); err != nil {
		t.Fatalf("runDiscoJSON (idp) returned error: %v", err)
	}

	raw, _ := os.ReadFile(filepath.Join(outDir, "disco-idp.json"))
	var entries []DiscoEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("disco-idp.json not valid JSON: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 idp entry, got %d", len(entries))
	}
	if entries[0].EntityID != "https://idp.example.org/idp" {
		t.Errorf("unexpected entityID: %s", entries[0].EntityID)
	}
}
