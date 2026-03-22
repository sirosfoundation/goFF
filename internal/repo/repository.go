package repo

import (
	"crypto/sha1" //nolint:gosec // SHA1 used only for MDQ URL matching, not security
	"fmt"
	"slices"
	"sync"
)

// Repository is a concurrency-safe in-memory entity repository.
//
// All expensive derived state (sorted entity ID list, SHA-1 index) is
// computed once at Replace/New time, not on every request, so reads are
// O(1) / allocation-free under the read lock.
type Repository struct {
	mu        sync.RWMutex
	entities  map[string]struct{}
	entityXML map[string]string

	// sortedIDs is a pre-computed, sorted snapshot of all entity IDs.
	// It is rebuilt once on every Replace/New call.
	sortedIDs []string

	// sha1Index maps lowercase hex SHA-1 of an entity ID to the entity ID.
	// Rebuilt on every Replace/New call.
	sha1Index map[string]string
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
	r.rebuildDerivedState()
	return r
}

// rebuildDerivedState recomputes sortedIDs and sha1Index from the current
// entities map.  Must be called with the write lock held (or before the
// repository is shared).
func (r *Repository) rebuildDerivedState() {
	sorted := make([]string, 0, len(r.entities))
	for id := range r.entities {
		sorted = append(sorted, id)
	}
	slices.Sort(sorted)
	r.sortedIDs = sorted

	idx := make(map[string]string, len(sorted))
	for _, id := range sorted {
		h := sha1.Sum([]byte(id)) //nolint:gosec
		idx[fmt.Sprintf("%x", h[:])] = id
	}
	r.sha1Index = idx
}

// List returns the pre-sorted snapshot of all entity IDs.
// The returned slice must not be modified by the caller.
func (r *Repository) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// Return a copy so callers cannot corrupt the internal snapshot.
	out := make([]string, len(r.sortedIDs))
	copy(out, r.sortedIDs)
	return out
}

// Get returns the stored XML body for an entity, if known.
func (r *Repository) Get(entityID string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	body, ok := r.entityXML[entityID]
	return body, ok
}

// ResolveSHA1 resolves a lowercase hex SHA-1 of an entity ID (as used in the
// pyFF MDQ {sha1}HEXHASH URL form) to the stored entity ID in O(1) time.
// Returns ("", false) when no matching entity is found.
func (r *Repository) ResolveSHA1(hexHash string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.sha1Index[hexHash]
	return id, ok
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

	r.rebuildDerivedState()
}

// Has returns true if an entity exists.
func (r *Repository) Has(entityID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, ok := r.entities[entityID]
	return ok
}
