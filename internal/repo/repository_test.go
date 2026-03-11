package repo

import "testing"

func TestRepositoryHasAndList(t *testing.T) {
	r := New([]string{"a", "b"})

	if !r.Has("a") {
		t.Fatal("expected entity a to exist")
	}
	if r.Has("x") {
		t.Fatal("did not expect entity x to exist")
	}

	ids := r.List()
	if len(ids) != 2 {
		t.Fatalf("expected 2 ids, got %d", len(ids))
	}
}

func TestRepositoryReplace(t *testing.T) {
	r := New([]string{"a", "b"})
	r.Replace([]string{"c"})

	if r.Has("a") {
		t.Fatal("expected entity a to be removed after replace")
	}
	if !r.Has("c") {
		t.Fatal("expected entity c to exist after replace")
	}
}
