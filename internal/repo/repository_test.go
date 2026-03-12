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

func TestRepositoryGetReturnsStoredXML(t *testing.T) {
	xmlBody := `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.org/idp"/>`
	r := New([]string{"https://idp.example.org/idp"}, map[string]string{
		"https://idp.example.org/idp": xmlBody,
	})

	got, ok := r.Get("https://idp.example.org/idp")
	if !ok {
		t.Fatal("expected Get to return true for known entity with stored XML")
	}
	if got != xmlBody {
		t.Fatalf("Get returned unexpected body:\ngot  %q\nwant %q", got, xmlBody)
	}
}

func TestRepositoryGetReturnsFalseForUnknownEntity(t *testing.T) {
	r := New([]string{"https://idp.example.org/idp"})

	_, ok := r.Get("https://unknown.example.org/sp")
	if ok {
		t.Fatal("expected Get to return false for entity without stored XML")
	}
}

func TestRepositoryReplaceUpdatesXMLMap(t *testing.T) {
	r := New([]string{"a"}, map[string]string{"a": "<a/>"})
	r.Replace([]string{"b"}, map[string]string{"b": "<b/>"})

	if _, ok := r.Get("a"); ok {
		t.Fatal("expected old XML entry to be gone after Replace")
	}
	got, ok := r.Get("b")
	if !ok {
		t.Fatal("expected new entity XML to be present after Replace")
	}
	if got != "<b/>" {
		t.Fatalf("unexpected XML after Replace: %q", got)
	}
}
