package pipeline

import (
	"crypto/md5"  //nolint:gosec
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

	_, err := loadSourceData(Source{ID: "federation", URLs: []string{ts.URL}, AllowPrivateAddrs: true})
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

	signed, err := signXMLDocument([]byte(unsigned), SignStep{Key: keyFile, Cert: certFile}, nil)
	if err != nil {
		t.Fatalf("failed signing metadata fixture: %v", err)
	}

	metadataPath := filepath.Join(t.TempDir(), "metadata-signed.xml")
	if err = os.WriteFile(metadataPath, signed, 0o600); err != nil {
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

	data, err := loadSourceData(Source{ID: "retry-source", URLs: []string{ts.URL}, Retries: 1, AllowPrivateAddrs: true})
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

	data, err := loadSourceData(Source{ID: "xrd-source", Files: []string{xrdFile}, AllowPrivateAddrs: true})
	if err != nil {
		t.Fatalf("loadSourceData returned error: %v", err)
	}
	if len(data.EntityIDs) != 1 || data.EntityIDs[0] != "https://idp.example.org/xrd-expanded" {
		t.Fatalf("unexpected loaded entities: %#v", data.EntityIDs)
	}
}

// ---------------------------------------------------------------------------
// Gap #3 – timeout: integer seconds compatibility
// ---------------------------------------------------------------------------

func TestFetchURLTimeoutIntegerSeconds(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/timeout-compat">
    <md:IDPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`))
	}))
	defer ts.Close()

	// Bare integer timeout "30" (seconds) should work without error.
	data, err := loadSourceData(Source{
		ID:                "timeout-src",
		URLs:              []string{ts.URL},
		Timeout:           "30",
		AllowPrivateAddrs: true,
	})
	if err != nil {
		t.Fatalf("loadSourceData returned error with integer timeout: %v", err)
	}
	if len(data.EntityIDs) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(data.EntityIDs))
	}
}

func TestFetchURLTimeoutInvalidStringReturnsError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	_, err := loadSourceData(Source{
		ID:                "timeout-bad",
		URLs:              []string{ts.URL},
		Timeout:           "not-a-duration",
		AllowPrivateAddrs: true,
	})
	if err == nil {
		t.Fatal("expected error for invalid timeout string")
	}
	if !strings.Contains(err.Error(), "invalid source timeout") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Gap #6 – verify: hash shorthand (sha256:, sha1:, md5:)
// ---------------------------------------------------------------------------

func TestTryVerifyBodyHashMatchAndMismatch(t *testing.T) {
	body := []byte("hello metadata")

	sha256hex := fmt.Sprintf("%x", sha256.Sum256(body))
	sha1h := sha1.Sum(body) //nolint:gosec
	sha1hex := hex.EncodeToString(sha1h[:])
	md5h := md5.Sum(body) //nolint:gosec
	md5hex := hex.EncodeToString(md5h[:])

	cases := []struct {
		name    string
		spec    string
		wantOK  bool
		wantErr bool
	}{
		{"sha256 match", "sha256:" + sha256hex, true, false},
		{"sha256 mismatch", "sha256:deadbeef", true, true},
		{"sha1 match", "sha1:" + sha1hex, true, false},
		{"sha1 mismatch", "sha1:deadbeef", true, true},
		{"md5 match", "md5:" + md5hex, true, false},
		{"md5 mismatch", "md5:deadbeef", true, true},
		{"cert path (no colon)", "/path/cert.pem", false, false},
		{"empty string", "", false, false},
		{"unknown alg", "blah:abc123", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err, ok := tryVerifyBodyHash(body, tc.spec)
			if ok != tc.wantOK {
				t.Fatalf("ok: got %v want %v", ok, tc.wantOK)
			}
			if tc.wantErr && err == nil {
				t.Fatal("expected non-nil error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerifySourceIfConfiguredHashShorthand(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>`)

	h := sha256.Sum256(body)
	spec := "sha256:" + fmt.Sprintf("%x", h)

	src := Source{ID: "test", Verify: spec}
	if err := verifySourceIfConfigured(src, body); err != nil {
		t.Fatalf("verifySourceIfConfigured returned unexpected error: %v", err)
	}

	srcBad := Source{ID: "test", Verify: "sha256:deadbeef"}
	if err := verifySourceIfConfigured(srcBad, body); err == nil {
		t.Fatal("expected fingerprint mismatch error")
	}
}

// ---------------------------------------------------------------------------
// Gap #1 – inline |sha256: fingerprint in load URLs
// ---------------------------------------------------------------------------

func TestParseURLFingerprint(t *testing.T) {
	cases := []struct {
		input      string
		wantURL    string
		wantAlg    string
		wantDigest string
	}{
		{
			input:      "https://mds.example.org/fed.xml|sha256:abc123",
			wantURL:    "https://mds.example.org/fed.xml",
			wantAlg:    "sha256",
			wantDigest: "abc123",
		},
		{
			input:      "https://mds.example.org/fed.xml|sha1:DEADBEEF",
			wantURL:    "https://mds.example.org/fed.xml",
			wantAlg:    "sha1",
			wantDigest: "deadbeef",
		},
		{
			input:      "https://mds.example.org/fed.xml",
			wantURL:    "https://mds.example.org/fed.xml",
			wantAlg:    "",
			wantDigest: "",
		},
		{
			// Unknown prefix — should be left as-is.
			input:      "https://example.org/|unknown:abc",
			wantURL:    "https://example.org/|unknown:abc",
			wantAlg:    "",
			wantDigest: "",
		},
		{
			// No colon after pipe — not a fingerprint.
			input:      "https://example.org/|notafingerprint",
			wantURL:    "https://example.org/|notafingerprint",
			wantAlg:    "",
			wantDigest: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			gotURL, gotAlg, gotDigest := parseURLFingerprint(tc.input)
			if gotURL != tc.wantURL {
				t.Errorf("url: got %q want %q", gotURL, tc.wantURL)
			}
			if gotAlg != tc.wantAlg {
				t.Errorf("alg: got %q want %q", gotAlg, tc.wantAlg)
			}
			if gotDigest != tc.wantDigest {
				t.Errorf("digest: got %q want %q", gotDigest, tc.wantDigest)
			}
		})
	}
}

func TestLoadSourceDataInlineURLFingerprintMatch(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/fp-ok">
    <md:IDPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	h := sha256.Sum256(body)
	fingerprintURL := ts.URL + "|sha256:" + fmt.Sprintf("%x", h)

	data, err := loadSourceData(Source{
		ID:                "fp-src",
		URLs:              []string{fingerprintURL},
		AllowPrivateAddrs: true,
	})
	if err != nil {
		t.Fatalf("loadSourceData returned error: %v", err)
	}
	if len(data.EntityIDs) != 1 || data.EntityIDs[0] != "https://idp.example.org/fp-ok" {
		t.Fatalf("unexpected entities: %#v", data.EntityIDs)
	}
}

func TestLoadSourceDataInlineURLFingerprintMismatch(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/fp-bad">
    <md:IDPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	badFingerprintURL := ts.URL + "|sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	_, err := loadSourceData(Source{
		ID:                "fp-bad-src",
		URLs:              []string{badFingerprintURL},
		AllowPrivateAddrs: true,
	})
	if err == nil {
		t.Fatal("expected fingerprint mismatch error")
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}
