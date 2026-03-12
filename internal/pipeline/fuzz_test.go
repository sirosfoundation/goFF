package pipeline

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseMetadataFromXML exercises the XML metadata parser with arbitrary
// byte input.  The goal is to catch panics and out-of-bounds reads in the
// etree-based parsing path; correctness errors are acceptable.
func FuzzParseMetadataFromXML(f *testing.F) {
	// Seed with real fixture files.
	fixtures := []string{
		filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-a.xml"),
		filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-b.xml"),
		filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-predicates.xml"),
	}
	for _, path := range fixtures {
		if b, err := os.ReadFile(path); err == nil {
			f.Add(b)
		}
	}

	// Minimal valid aggregate seed.
	f.Add([]byte(`<?xml version="1.0" encoding="UTF-8"?><md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><md:EntityDescriptor entityID="https://e.example.org/e"><md:IDPSSODescriptor/></md:EntityDescriptor></md:EntitiesDescriptor>`))
	// Malformed seeds.
	f.Add([]byte(`<`))
	f.Add([]byte(``))
	f.Add([]byte(`not xml at all`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic regardless of input.
		_, _ = parseMetadataFromXML(data)
	})
}

// FuzzParseEntityXMLByID exercises per-entity XML extraction with arbitrary input.
func FuzzParseEntityXMLByID(f *testing.F) {
	fixtures := []string{
		filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-a.xml"),
		filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-b.xml"),
	}
	for _, path := range fixtures {
		if b, err := os.ReadFile(path); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(`<?xml version="1.0"?><md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><md:EntityDescriptor entityID="x"/></md:EntitiesDescriptor>`))
	f.Add([]byte(`<bad`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseEntityXMLByID(data)
	})
}

// FuzzParsePipelineYAML exercises the YAML pipeline parser with arbitrary input.
// It only seeds with valid pipeline fragments; the fuzzer mutates from there.
func FuzzParsePipelineYAML(f *testing.F) {
	f.Add([]byte("- load\n- select\n"))
	f.Add([]byte("- load\n- select\n- publish entities.txt\n"))
	f.Add([]byte("- load\n- discojson /tmp/out.json\n"))
	f.Add([]byte("- load\n- sort @entityID\n"))
	f.Add([]byte("- load\n- setattr:\n    name: entity_category\n    value: https://refeds.org/rs\n"))
	f.Add([]byte(``))
	f.Add([]byte(`not: yaml: at: all`))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "fuzz.yaml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip("cannot write fuzz input")
		}
		// ParseFile must not panic regardless of content.
		_, _ = ParseFile(path)
	})
}
