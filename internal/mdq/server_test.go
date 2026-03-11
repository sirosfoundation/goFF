package mdq

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

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
