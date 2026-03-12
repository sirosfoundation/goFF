package mdq

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirosfoundation/goff/internal/pipeline"
	"github.com/sirosfoundation/goff/internal/repo"
)

func TestReadyz(t *testing.T) {
	var ready atomic.Bool
	ready.Store(false)

	h := NewHandler(repo.New(nil), WithReadiness(func() bool { return ready.Load() }))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when not ready, got %d", rr.Code)
	}

	ready.Store(true)
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 when ready, got %d", rr.Code)
	}
}

func TestMetrics(t *testing.T) {
	h := NewHandler(
		repo.New([]string{"https://idp.example.org/idp"}),
		WithExtraMetrics(func() map[string]any {
			return map[string]any{"server": map[string]any{"ready": true}}
		}),
	)

	// Drive a few requests so metrics have non-zero counters.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/readyz", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/entities", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/entities/"+url.PathEscape("https://idp.example.org/idp"), nil))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("unexpected content type: %q", rr.Header().Get("Content-Type"))
	}

	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json: %v", err)
	}

	requests, ok := payload["requests"].(map[string]any)
	if !ok {
		t.Fatalf("missing requests metrics payload: %#v", payload)
	}
	if requests["total"] == nil {
		t.Fatalf("missing requests.total in metrics payload: %#v", requests)
	}
	if payload["server"] == nil {
		t.Fatalf("missing extra metrics payload: %#v", payload)
	}
}

func TestHealthz(t *testing.T) {
	h := NewHandler(repo.New(nil))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestEntitiesList(t *testing.T) {
	h := NewHandler(repo.New([]string{"https://idp.example.org/idp"}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var body map[string][]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(body["entities"]) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(body["entities"]))
	}
}

func TestEntityLookup(t *testing.T) {
	id := "https://idp.example.org/idp"
	h := NewHandler(repo.New([]string{id}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities/"+url.PathEscape(id), nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestEntityLookupXMLByAcceptHeader(t *testing.T) {
	id := "https://idp.example.org/idp"
	h := NewHandler(repo.New([]string{id}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities/"+url.PathEscape(id), nil)
	req.Header.Set("Accept", "application/samlmetadata+xml")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/samlmetadata+xml") {
		t.Fatalf("unexpected content type: %q", rr.Header().Get("Content-Type"))
	}
	if !strings.Contains(rr.Body.String(), "EntityDescriptor") {
		t.Fatalf("expected xml entity descriptor, got %q", rr.Body.String())
	}
}

func TestEntityLookupJSONByExtension(t *testing.T) {
	id := "https://idp.example.org/idp"
	h := NewHandler(repo.New([]string{id}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities/"+url.PathEscape(id)+".json", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("unexpected content type: %q", rr.Header().Get("Content-Type"))
	}
}

func TestEntityLookupExtensionFallbackWhenAcceptWildcard(t *testing.T) {
	id := "https://idp.example.org/idp"
	h := NewHandler(repo.New([]string{id}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities/"+url.PathEscape(id)+".xml", nil)
	req.Header.Set("Accept", "*/*")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/samlmetadata+xml") {
		t.Fatalf("unexpected content type: %q", rr.Header().Get("Content-Type"))
	}
}

func TestEntityLookupNotAcceptable(t *testing.T) {
	id := "https://idp.example.org/idp"
	h := NewHandler(repo.New([]string{id}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities/"+url.PathEscape(id), nil)
	req.Header.Set("Accept", "text/plain")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotAcceptable {
		t.Fatalf("expected 406, got %d", rr.Code)
	}
}

func TestEntitiesListXMLByAcceptHeader(t *testing.T) {
	id := "https://idp.example.org/idp"
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + id + `"></md:EntityDescriptor>` + "\n"
	h := NewHandler(repo.New([]string{id}, map[string]string{id: xmlBody}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities", nil)
	req.Header.Set("Accept", "application/samlmetadata+xml")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/samlmetadata+xml") {
		t.Fatalf("unexpected content type: %q", rr.Header().Get("Content-Type"))
	}
	if !strings.Contains(rr.Body.String(), "EntitiesDescriptor") {
		t.Fatalf("expected EntitiesDescriptor wrapper, got %q", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), id) {
		t.Fatalf("expected entity ID in response, got %q", rr.Body.String())
	}
}

func TestEntityLookupServesStoredXML(t *testing.T) {
	id := "https://idp.example.org/idp"
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + id + `"><md:IDPSSODescriptor></md:IDPSSODescriptor></md:EntityDescriptor>` + "\n"
	h := NewHandler(repo.New([]string{id}, map[string]string{id: xmlBody}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities/"+url.PathEscape(id)+".xml", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "IDPSSODescriptor") {
		t.Fatalf("expected stored XML body, got %q", rr.Body.String())
	}
}

func TestAggregateXMLHasNameFromBaseURL(t *testing.T) {
	id := "https://idp.example.org/idp"
	h := NewHandler(repo.New([]string{id}), WithBaseURL("https://mdq.example.org"))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities", nil)
	req.Header.Set("Accept", "application/samlmetadata+xml")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `Name="https://mdq.example.org/entities"`) {
		t.Fatalf("expected @Name derived from base URL, got:\n%s", body)
	}
}

func TestAggregateXMLNameFromProxyHeaders(t *testing.T) {
	id := "https://idp.example.org/idp"
	h := NewHandler(repo.New([]string{id}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities", nil)
	req.Header.Set("Accept", "application/samlmetadata+xml")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "mdq.proxy.example.org")
	req.Header.Set("X-Forwarded-Prefix", "/saml")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `Name="https://mdq.proxy.example.org/saml/entities"`) {
		t.Fatalf("expected @Name from proxy headers, got:\n%s", body)
	}
}

func TestAggregateXMLCacheDurationAndValidUntilAttributes(t *testing.T) {
	id := "https://idp.example.org/idp"
	h := NewHandler(repo.New([]string{id}),
		WithAggregateConfig(pipeline.AggregateConfig{
			Name:          "https://example.org/fed",
			CacheDuration: "PT2H",
			ValidUntil:    "P7D",
		}),
	)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities", nil)
	req.Header.Set("Accept", "application/samlmetadata+xml")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `cacheDuration="PT2H"`) {
		t.Errorf("expected cacheDuration attribute, got:\n%s", body)
	}
	if !strings.Contains(body, `validUntil="P7D"`) {
		t.Errorf("expected validUntil attribute, got:\n%s", body)
	}
}

func TestAggregateXMLCacheControlHeaderFromCacheDuration(t *testing.T) {
	id := "https://idp.example.org/idp"
	h := NewHandler(repo.New([]string{id}),
		WithAggregateConfig(pipeline.AggregateConfig{CacheDuration: "PT1H"}),
	)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities", nil)
	req.Header.Set("Accept", "application/samlmetadata+xml")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	cc := rr.Header().Get("Cache-Control")
	if cc != "max-age=3600" {
		t.Fatalf("expected Cache-Control: max-age=3600, got %q", cc)
	}
}

func TestEntityLookupXMLCacheControlFromCacheDuration(t *testing.T) {
	id := "https://idp.example.org/idp"
	h := NewHandler(repo.New([]string{id}),
		WithAggregateConfig(pipeline.AggregateConfig{CacheDuration: "PT30M"}),
	)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities/"+url.PathEscape(id)+".xml", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	cc := rr.Header().Get("Cache-Control")
	if cc != "max-age=1800" {
		t.Fatalf("expected Cache-Control: max-age=1800 on entity lookup, got %q", cc)
	}
}

func TestWithRequestCountersSharesCounters(t *testing.T) {
	var c RequestCounters
	h := NewHandler(repo.New(nil), WithRequestCounters(&c))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if c.RequestsTotal.Load() != 2 {
		t.Fatalf("expected 2 total requests via shared counter, got %d", c.RequestsTotal.Load())
	}
}

func TestCacheHeadersFromRFC3339ValidUntil(t *testing.T) {
	id := "https://idp.example.org/idp"
	// Use a ValidUntil that parses as RFC3339 — far future so max-age is positive.
	future := time.Now().UTC().Add(7 * 24 * time.Hour).Truncate(time.Second)
	validUntilStr := future.Format(time.RFC3339)
	h := NewHandler(repo.New([]string{id}),
		WithAggregateConfig(pipeline.AggregateConfig{ValidUntil: validUntilStr}),
	)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities", nil)
	req.Header.Set("Accept", "application/samlmetadata+xml")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if rr.Header().Get("Expires") == "" {
		t.Fatal("expected Expires header to be set when ValidUntil is an RFC3339 timestamp")
	}
	cc := rr.Header().Get("Cache-Control")
	if !strings.HasPrefix(cc, "max-age=") {
		t.Fatalf("expected Cache-Control max-age from RFC3339 ValidUntil, got %q", cc)
	}
}

func TestEntityLookupBySHA1(t *testing.T) {
	id := "https://idp.example.org/idp"
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + id + `"/>`
	h := NewHandler(repo.New([]string{id}, map[string]string{id: xmlBody}))

	h1 := sha1.Sum([]byte(id)) //nolint:gosec
	sha1Hex := fmt.Sprintf("{sha1}%x", h1[:])

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities/"+url.PathEscape(sha1Hex)+".xml", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for SHA1 lookup, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), id) {
		t.Fatalf("expected entity body to contain entity ID, got:\n%s", rr.Body.String())
	}
}

func TestEntityLookupBySHA1NotFound(t *testing.T) {
	h := NewHandler(repo.New([]string{"https://idp.example.org/idp"}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities/%7Bsha1%7D0000000000000000000000000000000000000000", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown SHA1, got %d", rr.Code)
	}
}

func TestEntityLookupXMLETag(t *testing.T) {
	id := "https://idp.example.org/idp"
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + id + `"/>`
	h := NewHandler(repo.New([]string{id}, map[string]string{id: xmlBody}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities/"+url.PathEscape(id)+".xml", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	etag := rr.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected ETag header on XML entity response")
	}

	// Second request with matching If-None-Match should 304.
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/entities/"+url.PathEscape(id)+".xml", nil)
	req2.Header.Set("If-None-Match", etag)
	h.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusNotModified {
		t.Fatalf("expected 304 when If-None-Match matches ETag, got %d", rr2.Code)
	}
	if rr2.Body.Len() != 0 {
		t.Fatalf("expected empty body on 304, got %d bytes", rr2.Body.Len())
	}
}

func TestEntityLookupXMLETagMismatchReturnsFullBody(t *testing.T) {
	id := "https://idp.example.org/idp"
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + id + `"/>`
	h := NewHandler(repo.New([]string{id}, map[string]string{id: xmlBody}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities/"+url.PathEscape(id)+".xml", nil)
	req.Header.Set("If-None-Match", `"stale-etag"`)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 when If-None-Match does not match, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "EntityDescriptor") {
		t.Fatalf("expected full body on ETag mismatch, got:\n%s", rr.Body.String())
	}
}

