package pipeline

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func BenchmarkParseMetadataFromXML_LargeAggregate(b *testing.B) {
	xmlBody := benchmarkMetadataXML(5000)
	b.SetBytes(int64(len(xmlBody)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		attrs, err := parseMetadataFromXML([]byte(xmlBody))
		if err != nil {
			b.Fatalf("parseMetadataFromXML failed: %v", err)
		}
		if len(attrs) != 5000 {
			b.Fatalf("unexpected entity count: got %d want %d", len(attrs), 5000)
		}
	}
}

func BenchmarkExecute_LoadSelectSortPublish_LargeAggregate(b *testing.B) {
	tmp := b.TempDir()
	metadataPath := filepath.Join(tmp, "large.xml")
	outputDir := filepath.Join(tmp, "out")

	if err := os.WriteFile(metadataPath, []byte(benchmarkMetadataXML(3000)), 0o600); err != nil {
		b.Fatalf("write metadata fixture: %v", err)
	}

	pipeline := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{metadataPath}}},
			{Action: "select", Select: SelectStep{Role: "idp"}},
			{Action: "sort", Sort: SortStep{OrderBy: "@entityID"}},
			{Action: "publish", Publish: PublishStep{Output: "entities.txt"}},
		},
		BaseDir: tmp,
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		res, err := Execute(pipeline, outputDir)
		if err != nil {
			b.Fatalf("Execute failed: %v", err)
		}
		if len(res.Entities) != 1500 {
			b.Fatalf("unexpected selected entity count: got %d want %d", len(res.Entities), 1500)
		}
	}
}

func benchmarkMetadataXML(entityCount int) string {
	var sb strings.Builder
	sb.Grow(entityCount * 180)
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString("\n")
	sb.WriteString(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">`)
	sb.WriteString("\n")

	for i := 0; i < entityCount; i++ {
		entityID := fmt.Sprintf("https://entity-%05d.example.org/%s", i, roleSuffix(i))
		sb.WriteString(fmt.Sprintf(`  <md:EntityDescriptor entityID="%s">`, entityID))
		sb.WriteString("\n")
		if i%2 == 0 {
			sb.WriteString("    <md:IDPSSODescriptor/>\n")
		} else {
			sb.WriteString("    <md:SPSSODescriptor/>\n")
		}
		sb.WriteString("  </md:EntityDescriptor>\n")
	}

	sb.WriteString(`</md:EntitiesDescriptor>`)
	return sb.String()
}

func roleSuffix(i int) string {
	if i%2 == 0 {
		return "idp"
	}
	return "sp"
}

// BenchmarkBuildEntitiesXML measures aggregate XML serialisation for large repos.
func BenchmarkBuildEntitiesXML_LargeAggregate(b *testing.B) {
	const entityCount = 5000
	xmlBody := benchmarkMetadataXML(entityCount)

	// Build a per-entity XML map to simulate a real publish path.
	attrs, err := parseMetadataFromXML([]byte(xmlBody))
	if err != nil {
		b.Fatalf("parseMetadataFromXML: %v", err)
	}
	ids := make([]string, 0, len(attrs))
	bodies := make(map[string]string, len(attrs))
	for id := range attrs {
		ids = append(ids, id)
		// Minimal per-entity XML body.
		bodies[id] = fmt.Sprintf(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s"/>`, id)
	}

	ac := AggregateConfig{
		Name:          "https://mdq.example.org/entities",
		CacheDuration: "PT1H",
		ValidUntil:    "P7D",
	}

	b.SetBytes(int64(len(xmlBody)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = BuildEntitiesXML(ids, bodies, ac)
	}
}
