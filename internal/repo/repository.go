package repo

import (
	"slices"
	"sync"
)

// Repository is a concurrency-safe in-memory entity repository.
type Repository struct {
	mu        sync.RWMutex
	entities  map[string]struct{}
	entityXML map[string]string
}

// New creates a repository preloaded with entities.
// An optional XML map (entity ID → XML body) may be supplied as the second argument.
func New(initial []string, xml ...map[string]string) *Repository {
	r := &Repository{
		entities:  make(map[string]struct{}, len(initial)),
		entityXML: make(map[string]string),
	}
	for _, id := range initial {
		r.entities[id] = struct{}{}
	}
	if len(xml) > 0 {
		for id, body := range xml[0] {
			r.entityXML[id] = body
		}
	}
	return r
}

// List returns a snapshot of all entity IDs.
func (r *Repository) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]string, 0, len(r.entities))
	for id := range r.entities {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// Get returns the stored XML body for an entity, if known.
func (r *Repository) Get(entityID string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	body, ok := r.entityXML[entityID]
	return body, ok
}

// Replace atomically swaps the repository content with a new entity set.
// An optional XML map may be supplied as the second argument.
func (r *Repository) Replace(all []string, xml ...map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	next := make(map[string]struct{}, len(all))
	for _, id := range all {
		next[id] = struct{}{}
	}
	r.entities = next

	nextXML := make(map[string]string)
	if len(xml) > 0 {
		for id, body := range xml[0] {
			nextXML[id] = body
		}
	}
	r.entityXML = nextXML
}

// Has returns true if an entity exists.
func (r *Repository) Has(entityID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, ok := r.entities[entityID]
	return ok
}
