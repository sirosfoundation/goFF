package mdq

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/sirosfoundation/goff/internal/pipeline"
)

func TestMinimalRendererContentType(t *testing.T) {
	var r EntityRenderer = MinimalRenderer{}
	if got := r.ContentType(); got != "application/json" {
		t.Fatalf("expected application/json, got %q", got)
	}
}

func TestMinimalRendererOutput(t *testing.T) {
	r := MinimalRenderer{}
	data, err := r.RenderEntity("https://idp.example.org/idp", "<ignored/>")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if m["entityID"] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected entityID: %q", m["entityID"])
	}
}

func TestIndexedDiscoRendererContentType(t *testing.T) {
	r := NewIndexedDiscoRenderer(nil)
	if got := r.ContentType(); got != "application/disco+json" {
		t.Fatalf("expected application/disco+json, got %q", got)
	}
}

func TestIndexedDiscoRendererHit(t *testing.T) {
	entries := []pipeline.DiscoEntry{
		{EntityID: "https://idp.example.org/idp", Type: []string{"idp"}},
	}
	r := NewIndexedDiscoRenderer(entries)

	data, err := r.RenderEntity("https://idp.example.org/idp", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var e pipeline.DiscoEntry
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if e.EntityID != "https://idp.example.org/idp" {
		t.Fatalf("unexpected entityID: %q", e.EntityID)
	}
	if len(e.Type) == 0 || e.Type[0] != "idp" {
		t.Fatalf("expected type=[idp], got %v", e.Type)
	}
}

func TestIndexedDiscoRendererMiss(t *testing.T) {
	r := NewIndexedDiscoRenderer(nil) // empty index
	data, err := r.RenderEntity("https://unknown.example.org/sp", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should fall back to {"entityID":"..."}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if m["entityID"] != "https://unknown.example.org/sp" {
		t.Fatalf("fallback entityID wrong: %q", m["entityID"])
	}
}

func TestFuncRenderer(t *testing.T) {
	called := false
	r := NewFuncRenderer("application/vnd.custom+json", func(entityID, xmlBody string) ([]byte, error) {
		called = true
		return json.Marshal(map[string]string{"id": entityID, "xml": xmlBody})
	})

	if r.ContentType() != "application/vnd.custom+json" {
		t.Fatalf("unexpected content type: %q", r.ContentType())
	}
	data, err := r.RenderEntity("https://sp.example.org/sp", "<body/>")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("fn was not called")
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if m["id"] != "https://sp.example.org/sp" {
		t.Fatalf("unexpected id: %q", m["id"])
	}
}

func TestFuncRendererPropagatesError(t *testing.T) {
	r := NewFuncRenderer("application/json", func(_, _ string) ([]byte, error) {
		return nil, errors.New("boom")
	})
	_, err := r.RenderEntity("x", "")
	if err == nil || err.Error() != "boom" {
		t.Fatalf("expected error, got %v", err)
	}
}
