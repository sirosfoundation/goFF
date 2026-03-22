package mdq

import (
	"encoding/json"

	"github.com/sirosfoundation/goff/internal/pipeline"
)

// EntityRenderer is the pluggable strategy for serializing a single SAML entity
// to JSON for GET /entities/{id} with Accept: application/json.
//
// All built-in implementations are safe for concurrent use.
type EntityRenderer interface {
	// ContentType returns the value for the Content-Type response header.
	ContentType() string
	// RenderEntity serializes the entity to a JSON byte slice.
	// xmlBody is the stored SAML EntityDescriptor XML; it may be empty if no
	// XML body was published for this entity.
	RenderEntity(entityID, xmlBody string) ([]byte, error)
}

// MinimalRenderer is the default backward-compatible renderer.
// It returns {"entityID":"..."} for every entity.
type MinimalRenderer struct{}

func (MinimalRenderer) ContentType() string { return "application/json" }

func (MinimalRenderer) RenderEntity(entityID, _ string) ([]byte, error) {
	return json.Marshal(map[string]string{"entityID": entityID})
}

// IndexedDiscoRenderer serves pre-built pipeline.DiscoEntry values from an
// in-memory index constructed at pipeline execution time.  Lookup is O(1).
//
// For entities not present in the index (e.g. the discojson step used a role
// filter that excluded them) the renderer falls back to {"entityID":"..."}.
//
// Use NewIndexedDiscoRenderer to construct; zero value is not safe to use.
type IndexedDiscoRenderer struct {
	index map[string]pipeline.DiscoEntry
}

// NewIndexedDiscoRenderer builds an IndexedDiscoRenderer from a slice of
// pipeline.DiscoEntry values.  Pass pipeline.Result.DiscoJSON directly.
func NewIndexedDiscoRenderer(entries []pipeline.DiscoEntry) *IndexedDiscoRenderer {
	idx := make(map[string]pipeline.DiscoEntry, len(entries))
	for _, e := range entries {
		idx[e.EntityID] = e
	}
	return &IndexedDiscoRenderer{index: idx}
}

// ContentType returns "application/disco+json".
func (*IndexedDiscoRenderer) ContentType() string { return "application/disco+json" }

// RenderEntity returns the pre-built DiscoEntry for entityID, or falls back
// to {"entityID":"..."} when the entity is absent from the index.
func (r *IndexedDiscoRenderer) RenderEntity(entityID, _ string) ([]byte, error) {
	if e, ok := r.index[entityID]; ok {
		return json.Marshal(e)
	}
	return json.Marshal(map[string]string{"entityID": entityID})
}

// FuncRenderer wraps an arbitrary function as an EntityRenderer.
// It is intended for embedders who need ad-hoc or test-specific rendering logic.
type FuncRenderer struct {
	contentType string
	fn          func(entityID, xmlBody string) ([]byte, error)
}

// NewFuncRenderer creates a FuncRenderer with the given Content-Type and function.
func NewFuncRenderer(contentType string, fn func(entityID, xmlBody string) ([]byte, error)) *FuncRenderer {
	return &FuncRenderer{contentType: contentType, fn: fn}
}

// ContentType returns the value provided to NewFuncRenderer.
func (r *FuncRenderer) ContentType() string { return r.contentType }

// RenderEntity calls the wrapped function.
func (r *FuncRenderer) RenderEntity(entityID, xmlBody string) ([]byte, error) {
	return r.fn(entityID, xmlBody)
}
