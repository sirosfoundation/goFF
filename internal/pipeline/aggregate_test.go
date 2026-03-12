package pipeline

import (
	"strings"
	"testing"
)

func TestParseCacheDurationSeconds(t *testing.T) {
	cases := []struct {
		input string
		want  int
		ok    bool
	}{
		{"PT5H", 18000, true},
		{"PT30M", 1800, true},
		{"PT90S", 90, true},
		{"PT1H30M", 5400, true},
		{"PT2H15M45S", 8145, true},
		{"pt5h", 18000, true}, // case-insensitive
		{"P10D", 0, false},    // days not supported
		{"", 0, false},
		{"garbage", 0, false},
		{"PT", 0, false}, // no values
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, ok := ParseCacheDurationSeconds(tc.input)
			if ok != tc.ok {
				t.Fatalf("ParseCacheDurationSeconds(%q) ok=%v want %v", tc.input, ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Fatalf("ParseCacheDurationSeconds(%q) = %d want %d", tc.input, got, tc.want)
			}
		})
	}
}

func TestResolveValidUntilPassthrough(t *testing.T) {
	cases := []string{"P10D", "2026-06-01T00:00:00Z", "", "some-literal"}
	for _, tc := range cases {
		got := ResolveValidUntil(tc)
		if got != tc {
			t.Fatalf("ResolveValidUntil(%q) = %q want %q", tc, got, tc)
		}
	}
}

func TestResolveValidUntilRelativeDuration(t *testing.T) {
	got := ResolveValidUntil("+48h")
	if got == "" || got == "+48h" {
		t.Fatalf("expected resolved RFC3339 timestamp, got %q", got)
	}
	// Should be a valid RFC3339 string starting with 2026 or later.
	if !strings.Contains(got, "T") || !strings.Contains(got, "Z") {
		t.Fatalf("expected RFC3339 UTC timestamp, got %q", got)
	}
}

func TestResolveValidUntilInvalidDuration(t *testing.T) {
	// Invalid Go duration after "+": returned unchanged.
	got := ResolveValidUntil("+notaduration")
	if got != "+notaduration" {
		t.Fatalf("expected passthrough for invalid duration, got %q", got)
	}
}

func TestBuildEntitiesXMLNoBodies(t *testing.T) {
	ids := []string{"https://idp.example.org/idp", "https://sp.example.org/sp"}
	out := string(BuildEntitiesXML(ids, nil, AggregateConfig{}))

	if !strings.Contains(out, "EntitiesDescriptor") {
		t.Fatal("expected EntitiesDescriptor wrapper")
	}
	for _, id := range ids {
		if !strings.Contains(out, id) {
			t.Fatalf("expected entity ID %q in output", id)
		}
	}
	// No body → stub with no child elements inside EntityDescriptor.
	if strings.Contains(out, "IDPSSODescriptor") {
		t.Fatal("expected no entity body content")
	}
}

func TestBuildEntitiesXMLWithBodies(t *testing.T) {
	id := "https://idp.example.org/idp"
	body := `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + id + `"><md:IDPSSODescriptor/></md:EntityDescriptor>`
	out := string(BuildEntitiesXML([]string{id}, map[string]string{id: body}, AggregateConfig{}))

	if !strings.Contains(out, "EntitiesDescriptor") {
		t.Fatal("expected EntitiesDescriptor wrapper")
	}
	if !strings.Contains(out, "IDPSSODescriptor") {
		t.Fatalf("expected entity body content in output, got:\n%s", out)
	}
}

func TestBuildEntitiesXMLAttributes(t *testing.T) {
	cfg := AggregateConfig{
		Name:          "https://example.org/aggregate",
		CacheDuration: "PT5H",
		ValidUntil:    "P10D",
	}
	out := string(BuildEntitiesXML(nil, nil, cfg))

	if !strings.Contains(out, `Name="https://example.org/aggregate"`) {
		t.Errorf("expected Name attribute, got:\n%s", out)
	}
	if !strings.Contains(out, `cacheDuration="PT5H"`) {
		t.Errorf("expected cacheDuration attribute, got:\n%s", out)
	}
	if !strings.Contains(out, `validUntil="P10D"`) {
		t.Errorf("expected validUntil attribute, got:\n%s", out)
	}
}

func TestBuildEntitiesXMLStripsXMLDeclaration(t *testing.T) {
	id := "https://idp.example.org/idp"
	// Body with XML declaration — should be stripped on embedding.
	body := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + id + `"><md:IDPSSODescriptor/></md:EntityDescriptor>`
	out := string(BuildEntitiesXML([]string{id}, map[string]string{id: body}, AggregateConfig{}))

	// The xml declaration should appear once only (for the outer document).
	count := strings.Count(out, "<?xml")
	if count != 1 {
		t.Fatalf("expected exactly 1 xml declaration, got %d in:\n%s", count, out)
	}
}
