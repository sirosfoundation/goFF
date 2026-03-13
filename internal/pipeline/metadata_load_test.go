package pipeline

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestEntityAttributesAddIPHintNormalizationAndValidation(t *testing.T) {
	var a EntityAttributes

	a.AddIPHint("192.0.2.10")
	a.AddIPHint("2001:db8::1")
	a.AddIPHint("192.0.2.0/24")
	a.AddIPHint("not-an-ip")
	a.AddIPHint("   ")

	if len(a.IPHints) != 3 {
		t.Fatalf("expected 3 IP hints, got %d (%#v)", len(a.IPHints), a.IPHints)
	}
	if _, ok := a.IPHints["192.0.2.10/32"]; !ok {
		t.Fatalf("expected normalized /32 hint, got %#v", a.IPHints)
	}
	if _, ok := a.IPHints["2001:db8::1/128"]; !ok {
		t.Fatalf("expected normalized /128 hint, got %#v", a.IPHints)
	}
	if _, ok := a.IPHints["192.0.2.0/24"]; !ok {
		t.Fatalf("expected existing CIDR hint, got %#v", a.IPHints)
	}
}

func TestLoadSourceDataURLStatusError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer ts.Close()

	_, err := loadSourceData(Source{ID: "federation", URLs: []string{ts.URL}})
	if err == nil {
		t.Fatal("expected loadSourceData to fail for non-2xx source URL")
	}
	if !strings.Contains(err.Error(), "unexpected status") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseMetadataFromXMLExtractsIPHints(t *testing.T) {
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:IDPSSODescriptor>
      <md:Extensions>
        <mdui:UIInfo>
          <mdui:IPHint>192.0.2.10</mdui:IPHint>
          <mdui:IPHint>2001:db8::1</mdui:IPHint>
          <mdui:IPHint>not-an-ip</mdui:IPHint>
        </mdui:UIInfo>
      </md:Extensions>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`

	attrs, err := parseMetadataFromXML([]byte(xmlBody))
	if err != nil {
		t.Fatalf("parseMetadataFromXML returned error: %v", err)
	}

	a, ok := attrs["https://idp.example.org/idp"]
	if !ok {
		t.Fatalf("expected parsed entity attributes, got %#v", attrs)
	}
	if _, ok := a.IPHints["192.0.2.10/32"]; !ok {
		t.Fatalf("expected normalized IPv4 hint, got %#v", a.IPHints)
	}
	if _, ok := a.IPHints["2001:db8::1/128"]; !ok {
		t.Fatalf("expected normalized IPv6 hint, got %#v", a.IPHints)
	}
	if _, ok := a.IPHints["not-an-ip"]; ok {
		t.Fatalf("did not expect invalid ip hint to be preserved: %#v", a.IPHints)
	}
}

func TestLoadSourceDataVerifyFailsForUnsignedSource(t *testing.T) {
	certFile, _ := writeTestCertAndKey(t)

	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	unsigned := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:IDPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(metadataPath, []byte(unsigned), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	_, err := loadSourceData(Source{ID: "federation", Files: []string{metadataPath}, Verify: certFile})
	if err == nil {
		t.Fatal("expected loadSourceData to fail verification for unsigned xml")
	}
	if !strings.Contains(err.Error(), "verify xml signature") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadSourceDataVerifyPassesForSignedSource(t *testing.T) {
	certFile, keyFile := writeTestCertAndKey(t)

	unsigned := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:IDPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`

	signed, err := signXMLDocument([]byte(unsigned), SignStep{Key: keyFile, Cert: certFile})
	if err != nil {
		t.Fatalf("failed signing metadata fixture: %v", err)
	}

	metadataPath := filepath.Join(t.TempDir(), "metadata-signed.xml")
	if err := os.WriteFile(metadataPath, signed, 0o600); err != nil {
		t.Fatalf("failed writing signed metadata fixture: %v", err)
	}

	data, err := loadSourceData(Source{ID: "federation", Files: []string{metadataPath}, Verify: certFile})
	if err != nil {
		t.Fatalf("loadSourceData returned error: %v", err)
	}
	if len(data.EntityIDs) != 1 || data.EntityIDs[0] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected loaded entities: %#v", data.EntityIDs)
	}
}

func TestLoadSourceDataURLRetriesEventuallySucceeds(t *testing.T) {
	var calls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/retry-ok">
    <md:IDPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`))
	}))
	defer ts.Close()

	data, err := loadSourceData(Source{ID: "retry-source", URLs: []string{ts.URL}, Retries: 1})
	if err != nil {
		t.Fatalf("loadSourceData returned error: %v", err)
	}
	if len(data.EntityIDs) != 1 || data.EntityIDs[0] != "https://idp.example.org/retry-ok" {
		t.Fatalf("unexpected loaded entities: %#v", data.EntityIDs)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected exactly 2 calls with single retry, got %d", got)
	}
}

func TestLoadSourceDataCleanupSkipsBrokenFile(t *testing.T) {
	tmp := t.TempDir()
	broken := filepath.Join(tmp, "broken.xml")
	good := filepath.Join(tmp, "good.xml")

	if err := os.WriteFile(broken, []byte("<not-xml"), 0o600); err != nil {
		t.Fatalf("failed writing broken fixture: %v", err)
	}
	if err := os.WriteFile(good, []byte(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/cleanup-ok">
    <md:IDPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`), 0o600); err != nil {
		t.Fatalf("failed writing good fixture: %v", err)
	}

	data, err := loadSourceData(Source{ID: "cleanup-source", Files: []string{broken, good}, Cleanup: true})
	if err != nil {
		t.Fatalf("loadSourceData returned error: %v", err)
	}
	if len(data.EntityIDs) != 1 || data.EntityIDs[0] != "https://idp.example.org/cleanup-ok" {
		t.Fatalf("unexpected loaded entities: %#v", data.EntityIDs)
	}
}

func TestIsXRDContent(t *testing.T) {
	xrds := `<?xml version="1.0"?>
<XRDS xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">
  <XRD>
    <Link rel="urn:oasis:names:tc:SAML:2.0:metadata" href="https://example.org/fed.xml"/>
  </XRD>
</XRDS>`
	xrd := `<?xml version="1.0"?>
<XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">
  <Link rel="urn:oasis:names:tc:SAML:2.0:metadata" href="https://example.org/fed.xml"/>
</XRD>`
	saml := `<?xml version="1.0"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
</md:EntitiesDescriptor>`

	if !isXRDContent([]byte(xrds)) {
		t.Error("expected XRDS document to be detected as XRD content")
	}
	if !isXRDContent([]byte(xrd)) {
		t.Error("expected XRD document to be detected as XRD content")
	}
	if isXRDContent([]byte(saml)) {
		t.Error("expected SAML document to NOT be detected as XRD content")
	}
}

func TestParseXRDURLs(t *testing.T) {
	xrds := `<?xml version="1.0"?>
<XRDS xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">
  <XRD>
    <Link rel="urn:oasis:names:tc:SAML:2.0:metadata" href="https://example.org/fed-a.xml"/>
  </XRD>
  <XRD>
    <Link rel="http://other.example/other-rel" href="https://example.org/ignored.xml"/>
  </XRD>
  <XRD>
    <Link rel="urn:oasis:names:tc:SAML:2.0:metadata" href="https://example.org/fed-b.xml"/>
  </XRD>
</XRDS>`

	urls, err := parseXRDURLs([]byte(xrds))
	if err != nil {
		t.Fatalf("parseXRDURLs returned error: %v", err)
	}
	if len(urls) != 2 {
		t.Fatalf("expected 2 URLs, got %d: %#v", len(urls), urls)
	}
	if urls[0] != "https://example.org/fed-a.xml" {
		t.Errorf("expected first URL to be fed-a.xml, got %q", urls[0])
	}
	if urls[1] != "https://example.org/fed-b.xml" {
		t.Errorf("expected second URL to be fed-b.xml, got %q", urls[1])
	}
}

func TestLoadSourceDataFromDirectory(t *testing.T) {
	dir := t.TempDir()

	for _, entity := range []struct{ id, file string }{
		{"https://idp.example.org/dir-a", "a.xml"},
		{"https://idp.example.org/dir-b", "b.xml"},
	} {
		body := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="` + entity.id + `">
    <md:IDPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
		if err := os.WriteFile(filepath.Join(dir, entity.file), []byte(body), 0o600); err != nil {
			t.Fatalf("failed writing fixture: %v", err)
		}
	}
	// Also write a non-xml file that should be skipped.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("ignore me"), 0o600); err != nil {
		t.Fatalf("failed writing non-xml fixture: %v", err)
	}

	data, err := loadSourceData(Source{ID: "dir-source", Files: []string{dir}})
	if err != nil {
		t.Fatalf("loadSourceData returned error: %v", err)
	}
	if len(data.EntityIDs) != 2 {
		t.Fatalf("expected 2 entities from directory, got %d: %#v", len(data.EntityIDs), data.EntityIDs)
	}
}

func TestLoadSourceDataXRDFileExpands(t *testing.T) {
	entity := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/xrd-expanded">
    <md:IDPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(entity))
	}))
	defer ts.Close()

	xrdsBody := `<?xml version="1.0"?>
<XRDS xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">
  <XRD>
    <Link rel="urn:oasis:names:tc:SAML:2.0:metadata" href="` + ts.URL + `/fed.xml"/>
  </XRD>
</XRDS>`
	xrdFile := filepath.Join(t.TempDir(), "links.xrd")
	if err := os.WriteFile(xrdFile, []byte(xrdsBody), 0o600); err != nil {
		t.Fatalf("failed writing XRD fixture: %v", err)
	}

	data, err := loadSourceData(Source{ID: "xrd-source", Files: []string{xrdFile}})
	if err != nil {
		t.Fatalf("loadSourceData returned error: %v", err)
	}
	if len(data.EntityIDs) != 1 || data.EntityIDs[0] != "https://idp.example.org/xrd-expanded" {
		t.Fatalf("unexpected loaded entities: %#v", data.EntityIDs)
	}
}
