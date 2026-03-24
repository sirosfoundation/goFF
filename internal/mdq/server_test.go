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

func TestEntityLookupJSONWithIndexedDiscoRenderer(t *testing.T) {
	id := "https://idp.example.org/idp"
	entries := []pipeline.DiscoEntry{
		{EntityID: id, Type: []string{"idp"}},
	}
	h := NewHandler(
		repo.New([]string{id}),
		WithEntityRenderer(NewIndexedDiscoRenderer(entries)),
	)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities/"+url.PathEscape(id)+".json", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "application/disco+json" {
		t.Fatalf("expected application/disco+json, got %q", rr.Header().Get("Content-Type"))
	}
	var e pipeline.DiscoEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if e.EntityID != id {
		t.Fatalf("unexpected entityID: %q", e.EntityID)
	}
	if len(e.Type) == 0 || e.Type[0] != "idp" {
		t.Fatalf("expected type=[idp], got %v", e.Type)
	}
}

func TestEntityLookupJSONWithIndexedDiscoRendererMiss(t *testing.T) {
	// Entity in repo but not in disco index: should fall back to {"entityID":"..."}.
	id := "https://sp.example.org/sp"
	h := NewHandler(
		repo.New([]string{id}),
		WithEntityRenderer(NewIndexedDiscoRenderer(nil)),
	)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities/"+url.PathEscape(id)+".json", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	// Content-Type is disco+json even on fallback; caller decides how to handle.
	if rr.Body.Len() == 0 {
		t.Fatal("expected non-empty body")
	}
}

func TestEntityLookupJSONWithFuncRenderer(t *testing.T) {
	id := "https://idp.example.org/idp"
	xmlBody := `<EntityDescriptor/>`
	called := false
	r := NewFuncRenderer("application/vnd.custom+json", func(entityID, body string) ([]byte, error) {
		called = true
		return json.Marshal(map[string]string{"id": entityID, "xml": body})
	})
	h := NewHandler(
		repo.New([]string{id}, map[string]string{id: xmlBody}),
		WithEntityRenderer(r),
	)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/entities/"+url.PathEscape(id)+".json", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !called {
		t.Fatal("FuncRenderer was not called")
	}
	if rr.Header().Get("Content-Type") != "application/vnd.custom+json" {
		t.Fatalf("unexpected Content-Type: %q", rr.Header().Get("Content-Type"))
	}
	var m map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if m["xml"] != xmlBody {
		t.Fatalf("xmlBody not forwarded: %q", m["xml"])
	}
}

func TestEntityLookupJSONWithDynamicRendererFunc(t *testing.T) {
	id := "https://idp.example.org/idp"
	var current EntityRenderer = MinimalRenderer{}
	h := NewHandler(
		repo.New([]string{id}),
		WithEntityRendererFunc(func() EntityRenderer { return current }),
	)

	// First request: MinimalRenderer → {"entityID":"..."}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/entities/"+url.PathEscape(id)+".json", nil))
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("expected application/json from MinimalRenderer, got %q", rr.Header().Get("Content-Type"))
	}

	// Hot-swap to IndexedDiscoRenderer with a pre-built disco entry.
	current = NewIndexedDiscoRenderer([]pipeline.DiscoEntry{{EntityID: id, Type: []string{"idp"}}})

	// Second request: should now use IndexedDiscoRenderer → application/disco+json.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/entities/"+url.PathEscape(id)+".json", nil))
	if rr.Header().Get("Content-Type") != "application/disco+json" {
		t.Fatalf("expected application/disco+json after hot-swap, got %q", rr.Header().Get("Content-Type"))
	}
}

func TestWithAggregateConfigFunc(t *testing.T) {
	var ptr atomic.Pointer[pipeline.AggregateConfig]
	ptr.Store(&pipeline.AggregateConfig{CacheDuration: "PT1H"})

	h := NewHandler(
		repo.New([]string{"https://idp.example.org/idp"}),
		WithAggregateConfigFunc(func() pipeline.AggregateConfig { return *ptr.Load() }),
		WithBaseURL("https://mdq.test"),
	)

	req := httptest.NewRequest(http.MethodGet, "/entities", nil)
	req.Header.Set("Accept", "application/samlmetadata+xml")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `cacheDuration="PT1H"`) {
		t.Errorf("expected cacheDuration=PT1H in aggregate, got: %s", body)
	}

	// Dynamic update: swap config atomically.
	ptr.Store(&pipeline.AggregateConfig{CacheDuration: "PT2H"})
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/entities", nil))
	// JSON list still works after config swap.
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 after config swap, got %d", rr.Code)
	}
}

func TestWithDiscoJSON(t *testing.T) {
	entries := []pipeline.DiscoEntry{
		{EntityID: "https://idp.example.org/idp", Type: []string{"idp"}},
	}
	h := NewHandler(
		repo.New([]string{"https://idp.example.org/idp"}),
		WithDiscoJSON(func() []pipeline.DiscoEntry { return entries }),
	)

	req := httptest.NewRequest(http.MethodGet, "/entities", nil)
	req.Header.Set("Accept", "application/disco+json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "application/disco+json" {
		t.Fatalf("expected application/disco+json, got %q", rr.Header().Get("Content-Type"))
	}

	var got []pipeline.DiscoEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(got) != 1 || got[0].EntityID != entries[0].EntityID {
		t.Errorf("unexpected disco entries: %+v", got)
	}
}

func TestWithDiscoJSONNilEntries(t *testing.T) {
	// When disco func returns nil, server should return empty array, not null.
	h := NewHandler(
		repo.New(nil),
		WithDiscoJSON(func() []pipeline.DiscoEntry { return nil }),
	)
	req := httptest.NewRequest(http.MethodGet, "/entities", nil)
	req.Header.Set("Accept", "application/disco+json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := strings.TrimSpace(rr.Body.String())
	if body != "[]" {
		t.Errorf("expected empty JSON array, got %q", body)
	}
}

func TestMetricsPrometheus(t *testing.T) {
	counters := &RequestCounters{}
	h := NewHandler(
		repo.New([]string{"https://idp.example.org/idp"}),
		WithRequestCounters(counters),
		WithExtraMetrics(func() map[string]any {
			return map[string]any{
				"refresh": map[string]any{
					"entity_count":    42,
					"success_total":   10,
					"failure_total":   2,
					"stale_since_unix": 0,
				},
			}
		}),
	)

	// Drive some requests.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Accept", "text/plain")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "goff_requests_total") {
		t.Error("missing goff_requests_total in prometheus output")
	}
	if !strings.Contains(body, "goff_entity_count 42") {
		t.Error("missing goff_entity_count in prometheus output")
	}
	if !strings.Contains(body, "goff_refresh_success_total 10") {
		t.Error("missing goff_refresh_success_total in prometheus output")
	}
	if !strings.Contains(body, "goff_refresh_failure_total 2") {
		t.Error("missing goff_refresh_failure_total in prometheus output")
	}
	if !strings.Contains(body, "goff_stale_since_unix 0") {
		t.Error("missing goff_stale_since_unix in prometheus output")
	}
}

func TestEntitiesDiscoFallbackWithoutDiscoFunc(t *testing.T) {
	// Without WithDiscoJSON, Accept: disco+json should fall back to entity ID list.
	h := NewHandler(repo.New([]string{"https://idp.example.org/idp"}))
	req := httptest.NewRequest(http.MethodGet, "/entities", nil)
	req.Header.Set("Accept", "application/disco+json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("expected application/json fallback, got %q", rr.Header().Get("Content-Type"))
	}
}

func TestEntitiesListNotAcceptable(t *testing.T) {
	h := NewHandler(repo.New([]string{"https://idp.example.org/idp"}))
	req := httptest.NewRequest(http.MethodGet, "/entities", nil)
	req.Header.Set("Accept", "image/png")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotAcceptable {
		t.Fatalf("expected 406, got %d", rr.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := NewHandler(repo.New(nil))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options")
	}
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options")
	}
	if rr.Header().Get("Content-Security-Policy") == "" {
		t.Error("missing Content-Security-Policy")
	}
}
