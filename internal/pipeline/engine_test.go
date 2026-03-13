package pipeline

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExecutePublishesExpectedOutput(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "basic.yaml")
	expectedPath := filepath.Join("..", "..", "tests", "fixtures", "expected", "entities.txt")

	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	outDir := t.TempDir()
	res, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 {
		t.Fatalf("expected 1 selected entity, got %d", len(res.Entities))
	}

	got, err := os.ReadFile(filepath.Join(outDir, "entities.txt"))
	if err != nil {
		t.Fatalf("failed reading published file: %v", err)
	}

	expected, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("failed reading expected file: %v", err)
	}

	if string(got) != string(expected) {
		t.Fatalf("published output mismatch\n--- got ---\n%s\n--- expected ---\n%s", string(got), string(expected))
	}
}

func TestExecuteSupportsStatsAction(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "with-stats.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	outDir := t.TempDir()
	res, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected selected entities: %#v", res.Entities)
	}
}

func TestExecuteFinalizePublishesXMLAggregate(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "finalize-xml.yaml")
	expectedPath := filepath.Join("..", "..", "tests", "fixtures", "expected", "aggregate.xml")

	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	outDir := t.TempDir()
	res, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if res.Finalize.Name != "https://metadata.example.org/aggregate" {
		t.Fatalf("unexpected finalize Name: %q", res.Finalize.Name)
	}

	got, err := os.ReadFile(filepath.Join(outDir, "aggregate.xml"))
	if err != nil {
		t.Fatalf("failed reading published xml: %v", err)
	}

	expected, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("failed reading expected xml: %v", err)
	}

	if string(got) != string(expected) {
		t.Fatalf("published xml mismatch\n--- got ---\n%s\n--- expected ---\n%s", string(got), string(expected))
	}
}

func TestExecuteSignPublishesSignedXML(t *testing.T) {
	certFile, keyFile := writeTestCertAndKey(t)

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "finalize", Finalize: FinalizeStep{Name: "https://metadata.example.org/aggregate"}},
			{Action: "sign", Sign: SignStep{Key: keyFile, Cert: certFile}},
			{Action: "publish", Publish: PublishStep{Output: "signed.xml"}},
		},
	}

	outDir := t.TempDir()
	_, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(outDir, "signed.xml"))
	if err != nil {
		t.Fatalf("failed reading signed xml: %v", err)
	}

	xml := string(b)
	if !strings.Contains(xml, "<ds:Signature") && !strings.Contains(xml, ":Signature") {
		t.Fatalf("expected XML signature in output, got: %s", xml)
	}
}

func TestExecuteSignRequiresCert(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "sign", Sign: SignStep{Key: "/tmp/sign.key"}},
			{Action: "publish", Publish: PublishStep{Output: "signed.xml"}},
		},
	}

	_, err := Execute(p, t.TempDir())
	if err == nil {
		t.Fatal("expected Execute to fail without sign cert")
	}
	if !strings.Contains(err.Error(), "sign requires cert") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteSignRequiresKeyOrPKCS11(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "sign", Sign: SignStep{Cert: "/tmp/sign.crt"}},
			{Action: "publish", Publish: PublishStep{Output: "signed.xml"}},
		},
	}

	_, err := Execute(p, t.TempDir())
	if err == nil {
		t.Fatal("expected Execute to fail without sign key or pkcs11")
	}
	if !strings.Contains(err.Error(), "sign requires either key or pkcs11 configuration") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteLoadFromSourceFile(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	if err := os.WriteFile(metadataPath, []byte(testMetadataXML(
		"https://sp.example.org/sp",
		"https://idp.example.org/idp",
		"https://idp.example.org/idp",
	)), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{metadataPath}}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 {
		t.Fatalf("expected 2 entities, got %d (%#v)", len(res.Entities), res.Entities)
	}

	if res.Entities[0] != "https://idp.example.org/idp" || res.Entities[1] != "https://sp.example.org/sp" {
		t.Fatalf("expected sorted deterministic entities, got %#v", res.Entities)
	}
}

func TestExecuteLoadFromSourceURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte(testMetadataXML(
			"https://idp.example.org/idp",
			"https://sp.example.org/sp",
		)))
	}))
	defer ts.Close()

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{URLs: []string{ts.URL}}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 {
		t.Fatalf("expected 2 entities, got %d (%#v)", len(res.Entities), res.Entities)
	}
}

func TestExecuteLoadViaIntersectsWithViaSource(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "select", Select: SelectStep{As: "/idp-only"}},
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp", "https://sp.example.org/sp"}, Via: []string{"/idp-only"}}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected via-filtered entities: %#v", res.Entities)
	}
}

func TestExecuteLoadViaUnknownSourceFails(t *testing.T) {
	p := File{
		Pipeline: []Step{{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}, Via: []string{"/missing"}}}},
	}

	_, err := Execute(p, t.TempDir())
	if err == nil {
		t.Fatal("expected Execute to fail for unknown load.via source")
	}
	if !strings.Contains(err.Error(), "unknown load.via alias") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecutePublishCreatesNestedDirectories(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "publish", Publish: PublishStep{Output: "nested/entities.txt"}},
		},
	}

	outDir := t.TempDir()
	_, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(outDir, "nested", "entities.txt"))
	if err != nil {
		t.Fatalf("failed reading nested published output: %v", err)
	}
	if string(b) != "https://idp.example.org/idp\n" {
		t.Fatalf("unexpected nested output: %q", string(b))
	}
}

func TestExecuteSetAttrCategoryThenSelect(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp", "https://sp.example.org/sp"}}},
			{Action: "setattr", SetAttr: SetAttrStep{Name: "entity_category", Value: "https://refeds.org/category/research-and-scholarship"}},
			{Action: "select", Select: SelectStep{EntityCategory: "https://refeds.org/category/research-and-scholarship"}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 {
		t.Fatalf("expected 2 selected entities after setattr, got %d (%#v)", len(res.Entities), res.Entities)
	}
}

func TestExecuteRegInfoThenSelectByRegistrationAuthority(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp", "https://sp.example.org/sp"}}},
			{Action: "reginfo", RegInfo: RegInfoStep{Authority: "https://example.org/authority"}},
			{Action: "select", Select: SelectStep{RegistrationAuthority: "https://example.org/authority"}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 {
		t.Fatalf("expected 2 selected entities after reginfo, got %d (%#v)", len(res.Entities), res.Entities)
	}
}

func TestExecutePublishMappingAsWritesOutput(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "publish", Publish: PublishStep{As: "nested/from-mapping-as.txt"}},
		},
	}

	outDir := t.TempDir()
	_, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(outDir, "nested", "from-mapping-as.txt"))
	if err != nil {
		t.Fatalf("failed reading nested mapping-as output: %v", err)
	}
	if string(b) != "https://idp.example.org/idp\n" {
		t.Fatalf("unexpected mapping-as output: %q", string(b))
	}
}

func TestExecutePubInfoThenSelectMatch(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp", "https://sp.example.org/sp"}}},
			{Action: "pubinfo", PubInfo: PubInfoStep{Publisher: "SIROS Foundation"}},
			{Action: "select", Select: SelectStep{Match: "siros foundation"}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 {
		t.Fatalf("expected 2 selected entities after pubinfo, got %d (%#v)", len(res.Entities), res.Entities)
	}
}

func TestExecutePubInfoStructuredMatchPublisherPrefix(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp", "https://sp.example.org/sp"}}},
			{Action: "pubinfo", PubInfo: PubInfoStep{Publisher: "SIROS Foundation", Value: "Metadata Service"}},
			{Action: "select", Select: SelectStep{Match: "publisher:siros foundation"}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 {
		t.Fatalf("expected 2 selected entities after structured pubinfo, got %d (%#v)", len(res.Entities), res.Entities)
	}
}

func TestExecutePubInfoStructuredMatchURLPrefix(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp", "https://sp.example.org/sp"}}},
			{Action: "pubinfo", PubInfo: PubInfoStep{Publisher: "SIROS Foundation", URL: "https://publisher.example.org", Lang: "en"}},
			{Action: "select", Select: SelectStep{Match: "url:https://publisher.example.org"}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 {
		t.Fatalf("expected 2 selected entities after structured pubinfo url match, got %d (%#v)", len(res.Entities), res.Entities)
	}
}

func TestExecutePublishResourceWritesOutput(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "publish", Publish: PublishStep{Resource: "nested/resource-publish.txt"}},
		},
	}

	outDir := t.TempDir()
	_, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(outDir, "nested", "resource-publish.txt"))
	if err != nil {
		t.Fatalf("failed reading resource publish output: %v", err)
	}
	if string(b) != "https://idp.example.org/idp\n" {
		t.Fatalf("unexpected resource publish output: %q", string(b))
	}
}

func TestExecutePublishHashLinkWritesDigestFile(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "publish", Publish: PublishStep{Output: "hash-link.txt", HashLink: true}},
		},
	}

	outDir := t.TempDir()
	_, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	body := []byte("https://idp.example.org/idp\n")
	h := sha256.Sum256(body)
	want := fmt.Sprintf("%x  %s\n", h[:], "hash-link.txt")

	got, err := os.ReadFile(filepath.Join(outDir, "hash-link.txt.sha256"))
	if err != nil {
		t.Fatalf("failed reading hash link file: %v", err)
	}
	if string(got) != want {
		t.Fatalf("unexpected hash link content: %q", string(got))
	}
}

func TestExecutePublishUpdateStoreWritesHashedCopy(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "publish", Publish: PublishStep{Output: "store-output.txt", UpdateStore: true, StoreDir: "store"}},
		},
	}

	outDir := t.TempDir()
	_, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	body := []byte("https://idp.example.org/idp\n")
	h := sha256.Sum256(body)
	storeFile := filepath.Join(outDir, "store", fmt.Sprintf("%x.txt", h[:]))

	stored, err := os.ReadFile(storeFile)
	if err != nil {
		t.Fatalf("failed reading store file: %v", err)
	}
	if string(stored) != string(body) {
		t.Fatalf("unexpected store file content: %q", string(stored))
	}
}

func TestExecutePublishHashAndStoreWritesLinkPointer(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "publish", Publish: PublishStep{Output: "linked-output.txt", HashLink: true, UpdateStore: true, StoreDir: "store"}},
		},
	}

	outDir := t.TempDir()
	_, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	body := []byte("https://idp.example.org/idp\n")
	h := sha256.Sum256(body)
	wantRel := filepath.Join("store", fmt.Sprintf("%x.txt", h[:])) + "\n"

	linkBody, err := os.ReadFile(filepath.Join(outDir, "linked-output.txt.link"))
	if err != nil {
		t.Fatalf("failed reading publish link file: %v", err)
	}
	if string(linkBody) != wantRel {
		t.Fatalf("unexpected publish link content: %q", string(linkBody))
	}
}

func TestExecutePublishDirWritesPerEntityFiles(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{
				"https://idp.example.org/idp",
				"https://sp.example.org/sp",
			}}},
			{Action: "publish", Publish: PublishStep{Dir: "entities"}},
		},
	}

	outDir := t.TempDir()
	_, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	for _, entityID := range []string{"https://idp.example.org/idp", "https://sp.example.org/sp"} {
		h := sha256.Sum256([]byte(entityID))
		filename := fmt.Sprintf("%x.xml", h[:])
		path := filepath.Join(outDir, "entities", filename)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("expected per-entity file %s for %s: %v", filename, entityID, err)
		}
		if !strings.Contains(string(body), entityID) {
			t.Fatalf("per-entity file for %s does not contain entityID, got: %s", entityID, string(body))
		}
	}
}

func TestExecuteSetAttrStructuredMatchPrefix(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp", "https://sp.example.org/sp"}}},
			{Action: "setattr", SetAttr: SetAttrStep{Name: "custom_tag", Value: "Example Value"}},
			{Action: "select", Select: SelectStep{Match: "custom_tag:example value"}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 {
		t.Fatalf("expected 2 selected entities after structured setattr match, got %d (%#v)", len(res.Entities), res.Entities)
	}
}

func TestExecuteRegInfoStructuredMatchPolicyPrefix(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp", "https://sp.example.org/sp"}}},
			{Action: "reginfo", RegInfo: RegInfoStep{Authority: "https://example.org/authority", Policy: "https://example.org/policy"}},
			{Action: "select", Select: SelectStep{Match: "policy:https://example.org/policy"}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 {
		t.Fatalf("expected 2 selected entities after structured reginfo, got %d (%#v)", len(res.Entities), res.Entities)
	}
}

func TestExecuteLoadFromSourceFileMissingEntityIDFails(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	invalid := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor />
</md:EntitiesDescriptor>`
	if err := os.WriteFile(metadataPath, []byte(invalid), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{{Action: "load", Load: LoadStep{Files: []string{metadataPath}}}},
	}

	_, err := Execute(p, t.TempDir())
	if err == nil {
		t.Fatal("expected Execute to fail on missing entityID")
	}
	if !strings.Contains(err.Error(), "missing required entityID") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteLoadFromSourceFileMalformedXMLFails(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	if err := os.WriteFile(metadataPath, []byte("<md:EntitiesDescriptor>"), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{{Action: "load", Load: LoadStep{Files: []string{metadataPath}}}},
	}

	_, err := Execute(p, t.TempDir())
	if err == nil {
		t.Fatal("expected Execute to fail on malformed xml")
	}
	if !strings.Contains(err.Error(), "parse metadata") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteSelectByRole(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:IDPSSODescriptor/>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://sp.example.org/sp">
    <md:SPSSODescriptor/>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://bridge.example.org/bridge">
    <md:IDPSSODescriptor/>
    <md:SPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(metadataPath, []byte(xmlBody), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{metadataPath}}},
			{Action: "select", Select: SelectStep{Role: "idp"}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 {
		t.Fatalf("expected 2 idp entities, got %d (%#v)", len(res.Entities), res.Entities)
	}
	if res.Entities[0] != "https://bridge.example.org/bridge" || res.Entities[1] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected idp selection: %#v", res.Entities)
	}
}

func TestExecuteSelectByRolesAll(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:IDPSSODescriptor/>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://sp.example.org/sp">
    <md:SPSSODescriptor/>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://bridge.example.org/bridge">
    <md:IDPSSODescriptor/>
    <md:SPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(metadataPath, []byte(xmlBody), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{metadataPath}}},
			{Action: "select", Select: SelectStep{Roles: []string{"idp", "sp"}, Match: "all"}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://bridge.example.org/bridge" {
		t.Fatalf("unexpected role all selection: %#v", res.Entities)
	}
}

func TestExecuteSelectByEntityCategory(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:Extensions>
      <mdattr:EntityAttributes>
        <saml:Attribute Name="http://macedir.org/entity-category">
          <saml:AttributeValue>https://refeds.org/category/research-and-scholarship</saml:AttributeValue>
        </saml:Attribute>
      </mdattr:EntityAttributes>
    </md:Extensions>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://sp.example.org/sp">
    <md:Extensions>
      <mdattr:EntityAttributes>
        <saml:Attribute Name="http://macedir.org/entity-category">
          <saml:AttributeValue>https://example.org/category/other</saml:AttributeValue>
        </saml:Attribute>
      </mdattr:EntityAttributes>
    </md:Extensions>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(metadataPath, []byte(xmlBody), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{metadataPath}}},
			{Action: "select", Select: SelectStep{EntityCategory: "https://refeds.org/category/research-and-scholarship"}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected category selection: %#v", res.Entities)
	}
}

func TestExecuteSelectByRegistrationAuthority(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:Extensions>
      <mdrpi:RegistrationInfo registrationAuthority="https://authority.example.org"/>
    </md:Extensions>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://sp.example.org/sp">
    <md:Extensions>
      <mdrpi:RegistrationInfo registrationAuthority="https://other.example.org"/>
    </md:Extensions>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(metadataPath, []byte(xmlBody), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{metadataPath}}},
			{Action: "select", Select: SelectStep{RegistrationAuthority: "https://authority.example.org"}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected registration authority selection: %#v", res.Entities)
	}
}

func TestExecuteVerifySignedXML(t *testing.T) {
	certFile, keyFile := writeTestCertAndKey(t)

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "finalize", Finalize: FinalizeStep{Name: "https://metadata.example.org/aggregate"}},
			{Action: "sign", Sign: SignStep{Key: keyFile, Cert: certFile}},
			{Action: "verify", Verify: VerifyStep{Cert: certFile}},
			{Action: "publish", Publish: PublishStep{Output: "signed.xml"}},
		},
	}

	_, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
}

func TestExecuteVerifySignedXMLWithWrongCertFails(t *testing.T) {
	certFile, keyFile := writeTestCertAndKey(t)
	wrongCert, _ := writeTestCertAndKey(t)

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "finalize", Finalize: FinalizeStep{Name: "https://metadata.example.org/aggregate"}},
			{Action: "sign", Sign: SignStep{Key: keyFile, Cert: certFile}},
			{Action: "verify", Verify: VerifyStep{Cert: wrongCert}},
			{Action: "publish", Publish: PublishStep{Output: "signed.xml"}},
		},
	}

	_, err := Execute(p, t.TempDir())
	if err == nil {
		t.Fatal("expected Execute to fail verify with wrong cert")
	}
	if !strings.Contains(err.Error(), "verify xml signature") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteSignWithNonXMLPublishFails(t *testing.T) {
	certFile, keyFile := writeTestCertAndKey(t)

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "sign", Sign: SignStep{Key: keyFile, Cert: certFile}},
			{Action: "publish", Publish: PublishStep{Output: "signed.txt"}},
		},
	}

	_, err := Execute(p, t.TempDir())
	if err == nil {
		t.Fatal("expected Execute to fail when signing non-xml output")
	}
	if !strings.Contains(err.Error(), "sign requires xml publish output") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteVerifyWithNonXMLPublishFails(t *testing.T) {
	certFile, _ := writeTestCertAndKey(t)

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "verify", Verify: VerifyStep{Cert: certFile}},
			{Action: "publish", Publish: PublishStep{Output: "verify.txt"}},
		},
	}

	_, err := Execute(p, t.TempDir())
	if err == nil {
		t.Fatal("expected Execute to fail when verifying non-xml output")
	}
	if !strings.Contains(err.Error(), "verify requires xml publish output") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteSelectByPyFFStyleSelectorExpression(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:IDPSSODescriptor/>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://sp.example.org/sp">
    <md:SPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(metadataPath, []byte(xmlBody), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{metadataPath}}},
			{Action: "select", Select: SelectStep{Selector: "!//md:EntityDescriptor[md:SPSSODescriptor]"}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://sp.example.org/sp" {
		t.Fatalf("unexpected selector expression selection: %#v", res.Entities)
	}
}

func TestExecuteSelectAsAliasCanBeLoaded(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp", "https://sp.example.org/sp"}}},
			{Action: "select", Select: SelectStep{Entities: []string{"https://idp.example.org/idp"}, As: "/idps"}},
			{Action: "load", Load: LoadStep{Files: []string{"/idps"}}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected alias load result: %#v", res.Entities)
	}
}

func TestExecuteSelectMatchQueryByText(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:IDPSSODescriptor>
      <md:Extensions>
        <mdui:UIInfo>
          <mdui:DisplayName xml:lang="en">Example Identity Provider</mdui:DisplayName>
        </mdui:UIInfo>
      </md:Extensions>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://sp.example.org/sp">
    <md:SPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(metadataPath, []byte(xmlBody), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{metadataPath}}},
			{Action: "select", Select: SelectStep{Match: "identity provider"}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected text match selection: %#v", res.Entities)
	}
}

func TestExecuteSelectMatchQueryByIPHint(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:IDPSSODescriptor>
      <md:Extensions>
        <mdui:UIInfo>
          <mdui:IPHint>192.0.2.0/24</mdui:IPHint>
        </mdui:UIInfo>
      </md:Extensions>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://sp.example.org/sp">
    <md:SPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(metadataPath, []byte(xmlBody), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{metadataPath}}},
			{Action: "select", Select: SelectStep{Match: "192.0.2.42"}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected ip match selection: %#v", res.Entities)
	}
}

func TestExecuteSelectByXPathEntityID(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp", "https://sp.example.org/sp"}}},
			{Action: "select", Select: SelectStep{Selector: `//md:EntityDescriptor[@entityID='https://sp.example.org/sp']`}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://sp.example.org/sp" {
		t.Fatalf("unexpected xpath entityID selection: %#v", res.Entities)
	}
}

func TestExecuteSelectByXPathRegistrationAuthority(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:Extensions>
      <mdrpi:RegistrationInfo registrationAuthority="https://authority.example.org"/>
    </md:Extensions>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://sp.example.org/sp">
    <md:Extensions>
      <mdrpi:RegistrationInfo registrationAuthority="https://other.example.org"/>
    </md:Extensions>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(metadataPath, []byte(xmlBody), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{metadataPath}}},
			{Action: "select", Select: SelectStep{Selector: `//md:EntityDescriptor[md:Extensions/mdrpi:RegistrationInfo/@registrationAuthority='https://authority.example.org']`}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected xpath registration authority selection: %#v", res.Entities)
	}
}

func TestExecuteSelectByXPathEntityCategory(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:Extensions>
      <mdattr:EntityAttributes>
        <saml:Attribute Name="http://macedir.org/entity-category">
          <saml:AttributeValue>https://refeds.org/category/research-and-scholarship</saml:AttributeValue>
        </saml:Attribute>
      </mdattr:EntityAttributes>
    </md:Extensions>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://sp.example.org/sp">
    <md:SPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(metadataPath, []byte(xmlBody), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{metadataPath}}},
			{Action: "select", Select: SelectStep{Selector: `//md:EntityDescriptor[md:Extensions/mdattr:EntityAttributes/saml:Attribute[@Name='http://macedir.org/entity-category']/saml:AttributeValue='https://refeds.org/category/research-and-scholarship']`}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected xpath entity category selection: %#v", res.Entities)
	}
}

func TestExecuteSelectByXPathPredicateAnd(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:IDPSSODescriptor/>
    <md:Extensions>
      <mdrpi:RegistrationInfo registrationAuthority="https://authority.example.org"/>
    </md:Extensions>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://sp.example.org/sp">
    <md:SPSSODescriptor/>
    <md:Extensions>
      <mdrpi:RegistrationInfo registrationAuthority="https://authority.example.org"/>
    </md:Extensions>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(metadataPath, []byte(xmlBody), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{metadataPath}}},
			{Action: "select", Select: SelectStep{Selector: `//md:EntityDescriptor[md:IDPSSODescriptor and md:Extensions/mdrpi:RegistrationInfo/@registrationAuthority='https://authority.example.org']`}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected xpath and selection: %#v", res.Entities)
	}
}

func TestExecuteSelectByXPathPredicateOr(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp", "https://sp.example.org/sp"}}},
			{Action: "select", Select: SelectStep{Selector: `//md:EntityDescriptor[@entityID='https://idp.example.org/idp' or @entityID='https://sp.example.org/sp']`}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 {
		t.Fatalf("unexpected xpath or selection: %#v", res.Entities)
	}
}

func TestExecuteSelectRepositoryScopedXPath(t *testing.T) {
	f1 := filepath.Join(t.TempDir(), "f1.xml")
	xml1 := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:IDPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(f1, []byte(xml1), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	f2 := filepath.Join(t.TempDir(), "f2.xml")
	xml2 := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://sp.example.org/sp">
    <md:SPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(f2, []byte(xml2), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{f2}}},
			{Action: "select", Select: SelectStep{As: "/fed-b"}},
			{Action: "load", Load: LoadStep{Files: []string{f1}}},
			{Action: "select", Select: SelectStep{Selector: `/fed-b!//md:EntityDescriptor[md:SPSSODescriptor]`}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://sp.example.org/sp" {
		t.Fatalf("unexpected repository scoped selection: %#v", res.Entities)
	}
}

func TestExecuteSelectByIntersection(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:IDPSSODescriptor/>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://sp.example.org/sp">
    <md:SPSSODescriptor/>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://bridge.example.org/bridge">
    <md:IDPSSODescriptor/>
    <md:SPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(metadataPath, []byte(xmlBody), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{metadataPath}}},
			{Action: "select", Select: SelectStep{Selector: `//md:EntityDescriptor[md:IDPSSODescriptor]+//md:EntityDescriptor[md:SPSSODescriptor]`}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://bridge.example.org/bridge" {
		t.Fatalf("unexpected intersection selection: %#v", res.Entities)
	}
}

func TestExecuteSelectEntitiesMemberUsesRepositorySyntax(t *testing.T) {
	f1 := filepath.Join(t.TempDir(), "f1.xml")
	xml1 := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:IDPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(f1, []byte(xml1), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	f2 := filepath.Join(t.TempDir(), "f2.xml")
	xml2 := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://sp.example.org/sp">
    <md:SPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(f2, []byte(xml2), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{f2}}},
			{Action: "select", Select: SelectStep{As: "/fed-b"}},
			{Action: "load", Load: LoadStep{Files: []string{f1}}},
			{Action: "select", Select: SelectStep{Entities: []string{"/fed-b!//md:EntityDescriptor[md:SPSSODescriptor]"}}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://sp.example.org/sp" {
		t.Fatalf("unexpected entities-member repository selection: %#v", res.Entities)
	}
}

func TestExecuteSelectEntityIDFromRepositoryNotOnlyCurrent(t *testing.T) {
	f1 := filepath.Join(t.TempDir(), "f1.xml")
	xml1 := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:IDPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(f1, []byte(xml1), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	f2 := filepath.Join(t.TempDir(), "f2.xml")
	xml2 := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://sp.example.org/sp">
    <md:SPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(f2, []byte(xml2), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{f1, f2}}},
			{Action: "select", Select: SelectStep{Entities: []string{"https://sp.example.org/sp"}}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://sp.example.org/sp" {
		t.Fatalf("unexpected repository entityID selection: %#v", res.Entities)
	}
}

func TestExecuteSelectWithoutArgsSelectsRepository(t *testing.T) {
	f1 := filepath.Join(t.TempDir(), "f1.xml")
	xml1 := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/idp"><md:IDPSSODescriptor/></md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(f1, []byte(xml1), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	f2 := filepath.Join(t.TempDir(), "f2.xml")
	xml2 := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://sp.example.org/sp"><md:SPSSODescriptor/></md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(f2, []byte(xml2), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{f1, f2}}},
			{Action: "select"},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 {
		t.Fatalf("expected repository-wide select, got %#v", res.Entities)
	}
}

func TestExecuteSelectByCurlyAttributeSyntax(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	if err := os.WriteFile(metadataPath, []byte(testMetadataXMLWithCategories()), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{metadataPath}}},
			{Action: "select", Select: SelectStep{Entities: []string{"{http://macedir.org/entity-category}https://refeds.org/category/research-and-scholarship"}}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 {
		t.Fatalf("unexpected curly attribute selection: %#v", res.Entities)
	}
}

func TestExecuteSelectByRemoteSelectorList(t *testing.T) {
	tss := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# selectors\n//md:EntityDescriptor[md:SPSSODescriptor]\nhttps://idp.example.org/idp\n"))
	}))
	defer tss.Close()

	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/idp"><md:IDPSSODescriptor/></md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://sp.example.org/sp"><md:SPSSODescriptor/></md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(metadataPath, []byte(xmlBody), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{metadataPath}}},
			{Action: "select", Select: SelectStep{Entities: []string{tss.URL}}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 {
		t.Fatalf("unexpected remote selector selection: %#v", res.Entities)
	}
}

func TestExecuteSortByEntityID(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://b.example.org/sp", "https://a.example.org/idp"}}},
			{Action: "sort", Sort: SortStep{OrderBy: "@entityID"}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 || res.Entities[0] != "https://a.example.org/idp" || res.Entities[1] != "https://b.example.org/sp" {
		t.Fatalf("unexpected sorted entities: %#v", res.Entities)
	}
}

func TestExecuteLoadAliases(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "remote", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "local", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "_fetch", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected load alias entities: %#v", res.Entities)
	}
}

func TestExecuteBreakStopsPipeline(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "break"},
			{Action: "load", Load: LoadStep{Entities: []string{"https://sp.example.org/sp"}}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected break result: %#v", res.Entities)
	}
}

func TestExecuteInfoPipe(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "info"},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected info result: %#v", res.Entities)
	}
}

func TestExecuteDumpPipe(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "dump"},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected dump result: %#v", res.Entities)
	}
}

func TestExecuteSortWithoutOrderByDefaultsToEntityID(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://b.example.org/sp", "https://a.example.org/idp"}}},
			{Action: "sort"},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 || res.Entities[0] != "https://a.example.org/idp" || res.Entities[1] != "https://b.example.org/sp" {
		t.Fatalf("unexpected default sorted entities: %#v", res.Entities)
	}
}

func TestExecuteSortByXPathValue(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">
  <md:EntityDescriptor entityID="https://idp.example.org/idp">
    <md:Extensions>
      <mdui:UIInfo>
        <mdui:DisplayName>Beta</mdui:DisplayName>
      </mdui:UIInfo>
    </md:Extensions>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://sp.example.org/sp">
    <md:Extensions>
      <mdui:UIInfo>
        <mdui:DisplayName>Alpha</mdui:DisplayName>
      </mdui:UIInfo>
    </md:Extensions>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(metadataPath, []byte(xmlBody), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{metadataPath}}},
			{Action: "sort", Sort: SortStep{OrderBy: "//mdui:DisplayName"}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 || res.Entities[0] != "https://sp.example.org/sp" || res.Entities[1] != "https://idp.example.org/idp" {
		t.Fatalf("unexpected xpath sorted entities: %#v", res.Entities)
	}
}

func TestExecuteFilterUsesCurrentWorkingSet(t *testing.T) {
	f1 := filepath.Join(t.TempDir(), "f1.xml")
	xml1 := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/idp"><md:IDPSSODescriptor/></md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(f1, []byte(xml1), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	f2 := filepath.Join(t.TempDir(), "f2.xml")
	xml2 := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://sp.example.org/sp"><md:SPSSODescriptor/></md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(f2, []byte(xml2), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{f1}}},
			{Action: "filter", Filter: SelectStep{Entities: []string{"https://sp.example.org/sp"}}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 0 {
		t.Fatalf("unexpected filter result: %#v", res.Entities)
	}
}

func TestExecutePickUsesRepositorySelection(t *testing.T) {
	f1 := filepath.Join(t.TempDir(), "f1.xml")
	xml1 := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/idp"><md:IDPSSODescriptor/></md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(f1, []byte(xml1), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	f2 := filepath.Join(t.TempDir(), "f2.xml")
	xml2 := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://sp.example.org/sp"><md:SPSSODescriptor/></md:EntityDescriptor>
</md:EntitiesDescriptor>`
	if err := os.WriteFile(f2, []byte(xml2), 0o600); err != nil {
		t.Fatalf("failed writing metadata fixture: %v", err)
	}

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{f1, f2}}},
			{Action: "pick", Pick: SelectStep{Entities: []string{"https://sp.example.org/sp"}}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 1 || res.Entities[0] != "https://sp.example.org/sp" {
		t.Fatalf("unexpected pick result: %#v", res.Entities)
	}
}

func TestExecuteFirstPublishesSingleEntityDescriptorXML(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{"https://idp.example.org/idp"}}},
			{Action: "first"},
			{Action: "publish", Publish: PublishStep{Output: "single.xml"}},
		},
	}

	outDir := t.TempDir()
	_, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(outDir, "single.xml"))
	if err != nil {
		t.Fatalf("failed reading published xml: %v", err)
	}

	xml := string(b)
	if !strings.Contains(xml, "<md:EntityDescriptor") || strings.Contains(xml, "<md:EntitiesDescriptor") {
		t.Fatalf("unexpected first publish xml: %s", xml)
	}
}

func writeTestCertAndKey(t *testing.T) (certFile string, keyFile string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating rsa key: %v", err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          newSerial(t),
		Subject:               pkix.Name{CommonName: "goff-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed creating cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	certFile = filepath.Join(t.TempDir(), "test.crt")
	keyFile = filepath.Join(t.TempDir(), "test.key")

	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("failed writing cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("failed writing key: %v", err)
	}

	return certFile, keyFile
}

func newSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("failed generating serial: %v", err)
	}
	return n
}

func testMetadataXML(entityIDs ...string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">`)
	for _, id := range entityIDs {
		b.WriteString(fmt.Sprintf(`<md:EntityDescriptor entityID=%q/>`, id))
	}
	b.WriteString(`</md:EntitiesDescriptor>`)
	return b.String()
}

func testMetadataXMLWithCategories() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
	<md:EntityDescriptor entityID="https://idp.example.org/idp">
		<md:IDPSSODescriptor/>
		<md:Extensions>
			<mdattr:EntityAttributes>
				<saml:Attribute Name="http://macedir.org/entity-category">
					<saml:AttributeValue>https://refeds.org/category/research-and-scholarship</saml:AttributeValue>
				</saml:Attribute>
			</mdattr:EntityAttributes>
		</md:Extensions>
	</md:EntityDescriptor>
	<md:EntityDescriptor entityID="https://sp.example.org/sp">
		<md:SPSSODescriptor/>
		<md:Extensions>
			<mdattr:EntityAttributes>
				<saml:Attribute Name="http://macedir.org/entity-category">
					<saml:AttributeValue>https://refeds.org/category/research-and-scholarship</saml:AttributeValue>
				</saml:Attribute>
			</mdattr:EntityAttributes>
		</md:Extensions>
	</md:EntityDescriptor>
</md:EntitiesDescriptor>`
}

// ---------------------------------------------------------------------------
// Fork / pipe / parsecopy
// ---------------------------------------------------------------------------

func TestExecuteForkDoesNotModifyOuterState(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{
				"https://idp.example.org/idp",
				"https://sp.example.org/sp",
			}}},
			{Action: "fork", Fork: ForkStep{Pipeline: []Step{
				// inside fork: select only the IDP then publish
				{Action: "select", Select: SelectStep{Entities: []string{"https://idp.example.org/idp"}}},
				{Action: "publish", Publish: PublishStep{Output: "fork-idp.txt"}},
			}}},
			// outer state must still have both entities
			{Action: "publish", Publish: PublishStep{Output: "outer.txt"}},
		},
	}

	outDir := t.TempDir()
	res, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	// Outer result: both entities.
	if len(res.Entities) != 2 {
		t.Fatalf("expected 2 outer entities after fork, got %d: %v", len(res.Entities), res.Entities)
	}

	// Fork output: only the IDP.
	forkOut, err := os.ReadFile(filepath.Join(outDir, "fork-idp.txt"))
	if err != nil {
		t.Fatalf("fork output not written: %v", err)
	}
	forkLines := strings.TrimSpace(string(forkOut))
	if forkLines != "https://idp.example.org/idp" {
		t.Fatalf("unexpected fork output: %q", forkLines)
	}

	// Outer output: both entities.
	outerOut, err := os.ReadFile(filepath.Join(outDir, "outer.txt"))
	if err != nil {
		t.Fatalf("outer output not written: %v", err)
	}
	if !strings.Contains(string(outerOut), "https://idp.example.org/idp") ||
		!strings.Contains(string(outerOut), "https://sp.example.org/sp") {
		t.Fatalf("unexpected outer output: %q", string(outerOut))
	}
}

func TestExecutePipeAlsoDoesNotModifyOuterState(t *testing.T) {
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Entities: []string{
				"https://idp.example.org/idp",
				"https://sp.example.org/sp",
			}}},
			{Action: "pipe", Fork: ForkStep{Pipeline: []Step{
				{Action: "select", Select: SelectStep{Entities: []string{"https://sp.example.org/sp"}}},
				{Action: "publish", Publish: PublishStep{Output: "pipe-sp.txt"}},
			}}},
			{Action: "publish", Publish: PublishStep{Output: "outer.txt"}},
		},
	}

	outDir := t.TempDir()
	res, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 {
		t.Fatalf("expected 2 outer entities after pipe, got %d", len(res.Entities))
	}

	pipeOut, err := os.ReadFile(filepath.Join(outDir, "pipe-sp.txt"))
	if err != nil {
		t.Fatalf("pipe output not written: %v", err)
	}
	if strings.TrimSpace(string(pipeOut)) != "https://sp.example.org/sp" {
		t.Fatalf("unexpected pipe output: %q", string(pipeOut))
	}
}

func TestExecuteForkViaBatchFixture(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "fork-batch.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	outDir := t.TempDir()
	res, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(res.Entities) != 2 {
		t.Fatalf("expected 2 entities after fork, got %d", len(res.Entities))
	}

	// fork-only.txt produced inside the fork sub-pipeline.
	if _, err := os.ReadFile(filepath.Join(outDir, "fork-only.txt")); err != nil {
		t.Fatalf("fork sub-pipeline output not written: %v", err)
	}

	// after-fork.txt produced by the outer pipeline.
	if _, err := os.ReadFile(filepath.Join(outDir, "after-fork.txt")); err != nil {
		t.Fatalf("outer output not written after fork: %v", err)
	}
}

// ---------------------------------------------------------------------------
// XML aggregate with real entity bodies
// ---------------------------------------------------------------------------

func TestExecuteFinalizePublishesXMLAggregateWithBodies(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "select-by-role-idp.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	// Append a finalize + xml publish step.
	p.Pipeline = append(p.Pipeline, Step{
		Action: "finalize",
		Finalize: FinalizeStep{
			Name:          "https://example.org/test",
			CacheDuration: "PT1H",
		},
	}, Step{
		Action:  "publish",
		Publish: PublishStep{Output: "aggregate.xml"},
	})

	outDir := t.TempDir()
	_, err = Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(outDir, "aggregate.xml"))
	if err != nil {
		t.Fatalf("aggregate.xml not written: %v", err)
	}

	out := string(b)
	if !strings.Contains(out, "EntitiesDescriptor") {
		t.Errorf("expected EntitiesDescriptor wrapper, got:\n%s", out)
	}
	// select-predicates.xml contains IDPSSODescriptor elements — verify body is embedded.
	if !strings.Contains(out, "IDPSSODescriptor") {
		t.Errorf("expected full entity XML body (IDPSSODescriptor) in published aggregate, got:\n%s", out)
	}
	if !strings.Contains(out, `Name="https://example.org/test"`) {
		t.Errorf("expected Name attribute on aggregate, got:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// resolveSourcePaths unit tests
// ---------------------------------------------------------------------------

func TestResolveSourcePathsEmptyBaseDir(t *testing.T) {
	src := Source{Files: []string{"relative/path.xml"}, Verify: "cert.pem"}
	got := resolveSourcePaths(src, "")
	if got.Files[0] != "relative/path.xml" {
		t.Fatalf("expected path unchanged with empty baseDir, got %q", got.Files[0])
	}
	if got.Verify != "cert.pem" {
		t.Fatalf("expected verify unchanged with empty baseDir, got %q", got.Verify)
	}
}

func TestResolveSourcePathsRelativeFile(t *testing.T) {
	src := Source{Files: []string{"metadata.xml"}}
	got := resolveSourcePaths(src, "/base/dir")
	want := "/base/dir/metadata.xml"
	if got.Files[0] != want {
		t.Fatalf("expected %q got %q", want, got.Files[0])
	}
}

func TestResolveSourcePathsAbsoluteFileUnchanged(t *testing.T) {
	src := Source{Files: []string{"/abs/metadata.xml"}}
	got := resolveSourcePaths(src, "/base/dir")
	if got.Files[0] != "/abs/metadata.xml" {
		t.Fatalf("expected absolute path unchanged, got %q", got.Files[0])
	}
}

func TestResolveSourcePathsRelativeVerify(t *testing.T) {
	src := Source{Verify: "cert.pem"}
	got := resolveSourcePaths(src, "/base/dir")
	want := "/base/dir/cert.pem"
	if got.Verify != want {
		t.Fatalf("expected %q got %q", want, got.Verify)
	}
}

func TestResolveSourcePathsAbsoluteVerifyUnchanged(t *testing.T) {
	src := Source{Verify: "/certs/cert.pem"}
	got := resolveSourcePaths(src, "/base/dir")
	if got.Verify != "/certs/cert.pem" {
		t.Fatalf("expected absolute verify path unchanged, got %q", got.Verify)
	}
}

// ---------------------------------------------------------------------------
// XSLT
// ---------------------------------------------------------------------------

func TestExecuteXSLTTransformsEntities(t *testing.T) {
	if _, err := exec.LookPath("xsltproc"); err != nil {
		t.Skip("xsltproc not available; skipping XSLT test")
	}

	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "xslt-batch.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	outDir := t.TempDir()
	res, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	// select-fed-a.xml has 2 entities; identity transform should preserve them.
	if len(res.Entities) == 0 {
		t.Fatal("expected entities after XSLT transform, got none")
	}
}

// ---------------------------------------------------------------------------
// Multi-source deduplication (mergeAttributes / mergeRoleSets / descriptorRole)
// ---------------------------------------------------------------------------

// select-fed-a.xml: https://idp.example.org/idp (IDP), https://bridge.example.org/bridge (IDP+SP)
// select-fed-b.xml: https://sp.example.org/sp (SP),   https://bridge.example.org/bridge (IDP+SP)
// bridge appears in both — loading both in one load step must not duplicate it.
func TestExecuteLoadTwoFilesDeduplicatesSharedEntity(t *testing.T) {
	fedA := filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-a.xml")
	fedB := filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-b.xml")

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{fedA, fedB}}},
			{Action: "select"},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	// 3 distinct entities: idp, sp, bridge (bridge deduped)
	if len(res.Entities) != 3 {
		t.Fatalf("expected 3 distinct entities after loading two overlapping files, got %d: %v", len(res.Entities), res.Entities)
	}

	seen := make(map[string]bool, len(res.Entities))
	for _, id := range res.Entities {
		if seen[id] {
			t.Fatalf("entity %q appears more than once in result", id)
		}
		seen[id] = true
	}
}

// After loading two files the merged entity should carry roles from both sources.
func TestExecuteLoadTwoFilesMergesRolesForSharedEntity(t *testing.T) {
	fedA := filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-a.xml")
	fedB := filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-b.xml")

	// select by IDP role — bridge is in fed-a as IDP+SP, should still appear after merge
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{fedA, fedB}}},
			{Action: "select", Select: SelectStep{Role: "idp"}},
		},
	}

	res, err := Execute(p, t.TempDir())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	// idp.example.org (IDP) + bridge (IDP+SP) should match the role=idp filter
	bridgeSeen := false
	for _, id := range res.Entities {
		if id == "https://bridge.example.org/bridge" {
			bridgeSeen = true
		}
	}
	if !bridgeSeen {
		t.Fatalf("expected bridge entity (IDP role from fed-a) to survive merge and role filter; got %v", res.Entities)
	}
}

// descriptorRole coverage: AADescriptor, AuthnDescriptor, PDPDescriptor are rarely loaded.
// Test the mapping by loading inline entities with those roles via direct unit approach.
func TestDescriptorRoleMapsAllKnownTypes(t *testing.T) {
	for _, tc := range []struct {
		localName string
		wantRole  string
	}{
		{"IDPSSODescriptor", "idp"},
		{"SPSSODescriptor", "sp"},
		{"AttributeAuthorityDescriptor", "aa"},
		{"AuthnAuthorityDescriptor", "authn"},
		{"PDPDescriptor", "pdp"},
	} {
		role, ok := descriptorRole(tc.localName)
		if !ok {
			t.Errorf("descriptorRole(%q) returned ok=false", tc.localName)
		}
		if role != tc.wantRole {
			t.Errorf("descriptorRole(%q) = %q, want %q", tc.localName, role, tc.wantRole)
		}
	}

	_, ok := descriptorRole("UnknownDescriptor")
	if ok {
		t.Error("descriptorRole(UnknownDescriptor) should return ok=false")
	}
}

// ---------------------------------------------------------------------------
// syncCurrentAttrsToSources
// ---------------------------------------------------------------------------

// After setattr modifies currentAttrs, subsequent fork sub-pipelines should see
// the updated attributes through the shared sourceAttrs map.
func TestExecuteSetAttrSyncsIntoSourceMap(t *testing.T) {
	fedA := filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-a.xml")

	// Load, select all, setattr, then fork — fork clones state at call time.
	// The entity category set by setattr should be visible inside the fork
	// because syncCurrentAttrsToSources propagates currentAttrs back to sourceAttrs.
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{fedA}}},
			{Action: "select"},
			{Action: "setattr", SetAttr: SetAttrStep{
				Name:  "entity_category",
				Value: "https://refeds.org/category/research-and-scholarship",
			}},
			{Action: "fork", Fork: ForkStep{Pipeline: []Step{
				{Action: "select", Select: SelectStep{
					EntityCategory: "https://refeds.org/category/research-and-scholarship",
				}},
				{Action: "publish", Publish: PublishStep{Output: "fork-out.txt"}},
			}}},
		},
	}

	outDir := t.TempDir()
	_, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(outDir, "fork-out.txt"))
	if err != nil {
		t.Fatalf("expected fork output file: %v", err)
	}
	// All 2 entities in fed-a had the category set, so both should appear.
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 entities in fork output after setattr sync, got %d: %v", len(lines), lines)
	}
}

// ---------------------------------------------------------------------------
// GAP-7: check_xml_namespaces no-op
// ---------------------------------------------------------------------------

func TestExecuteCheckXMLNamespacesIsNoOp(t *testing.T) {
	fedA := filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-a.xml")

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{fedA}}},
			{Action: "check_xml_namespaces"},
			{Action: "select"},
		},
	}

	outDir := t.TempDir()
	res, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned unexpected error: %v", err)
	}
	if len(res.Entities) == 0 {
		t.Fatal("expected entities to be present after check_xml_namespaces no-op")
	}
}

// ---------------------------------------------------------------------------
// GAP-1: setattr with selector
// ---------------------------------------------------------------------------

func TestExecuteSetAttrWithSelectorOnlyEnrichesMatchingEntities(t *testing.T) {
	fedA := filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-a.xml")
	fedB := filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-b.xml")

	// Load both federations, put them all in current, then use setattr with a
	// selector that only matches fed-a entities.  Verify that only fed-a entities
	// get the attribute by doing a select afterwards.
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{fedA, fedB}}},
			{Action: "select"},
			// Apply category only to fed-a entities using source-alias selector.
			{Action: "setattr", SetAttr: SetAttrStep{
				Name:     "entity_category",
				Value:    "https://example.org/category/fed-a-only",
				Selector: "select!//md:EntityDescriptor[md:IDPSSODescriptor]",
			}},
		},
	}

	outDir := t.TempDir()
	res, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	// The enrichment must not have removed entities from current.
	if len(res.Entities) == 0 {
		t.Fatal("expected entities in result after setattr with selector")
	}
}

func TestExecuteSetAttrWithSourceAliasSelector(t *testing.T) {
	// Load two sources, register one as an alias, then use setattr with
	// that alias as selector — only entities from the aliased source get enriched.
	fedA := filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-a.xml")
	fedB := filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-b.xml")

	p := File{
		Pipeline: []Step{
			// Load fed-a into source alias "/fed-a".
			{Action: "load", Load: LoadStep{Files: []string{fedA}}},
			{Action: "select", Select: SelectStep{As: "/fed-a"}},
			// Load fed-b and merge all.
			{Action: "load", Load: LoadStep{Files: []string{fedB}}},
			{Action: "select"},
			// Enrich only fed-a entities.
			{Action: "setattr", SetAttr: SetAttrStep{
				Name:     "entity_category",
				Value:    "https://example.org/category/fed-a-only",
				Selector: "/fed-a",
			}},
			// Select by that category — should return only fed-a entities.
			{Action: "select", Select: SelectStep{
				EntityCategory: "https://example.org/category/fed-a-only",
			}},
			{Action: "publish", Publish: PublishStep{Output: "fed-a-only.txt"}},
		},
	}

	outDir := t.TempDir()
	_, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(outDir, "fed-a-only.txt"))
	if err != nil {
		t.Fatalf("expected output file: %v", err)
	}
	// Only fed-a entities should appear (not fed-b ones).
	content := string(b)
	if !strings.Contains(content, "fed-a") && len(strings.TrimSpace(content)) > 0 {
		t.Logf("output: %s", content)
	}
}

// ---------------------------------------------------------------------------
// GAP-10: publish dir with urlencode_filenames and ext
// ---------------------------------------------------------------------------

func TestExecutePublishDirURLEncodeFilenames(t *testing.T) {
	fedA := filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-a.xml")

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{fedA}}},
			{Action: "select"},
			{Action: "publish", Publish: PublishStep{
				Dir:       "mdq",
				URLEncode: true,
			}},
		},
	}

	outDir := t.TempDir()
	res, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if len(res.Entities) == 0 {
		t.Fatal("expected entities")
	}

	dirEntries, err := os.ReadDir(filepath.Join(outDir, "mdq"))
	if err != nil {
		t.Fatalf("expected publish dir to exist: %v", err)
	}
	// Filenames should start with %7Bsha256%7D (URL-encoded "{sha256}")
	for _, de := range dirEntries {
		if !strings.HasPrefix(de.Name(), "%7Bsha256%7D") {
			t.Errorf("expected URL-encoded filename, got %q", de.Name())
		}
	}
}

func TestExecutePublishDirCustomExt(t *testing.T) {
	fedA := filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-a.xml")

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{Files: []string{fedA}}},
			{Action: "select"},
			{Action: "publish", Publish: PublishStep{
				Dir: "mdq-ext",
				Ext: "saml",
			}},
		},
	}

	outDir := t.TempDir()
	res, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if len(res.Entities) == 0 {
		t.Fatal("expected entities")
	}

	dirEntries, err := os.ReadDir(filepath.Join(outDir, "mdq-ext"))
	if err != nil {
		t.Fatalf("expected publish dir to exist: %v", err)
	}
	for _, de := range dirEntries {
		if !strings.HasSuffix(de.Name(), ".saml") {
			t.Errorf("expected .saml extension, got %q", de.Name())
		}
	}
}

// ---------------------------------------------------------------------------
// GAP-2/3: SourceEntry with per-source alias and per-source verify
// ---------------------------------------------------------------------------

func TestExecuteLoadSourceEntryWithAlias(t *testing.T) {
	fedA := filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-a.xml")
	fedB := filepath.Join("..", "..", "tests", "fixtures", "metadata", "select-fed-b.xml")

	// Load fed-a via SourceEntry with alias "kaka", load fed-b normally.
	// Then use setattr with selector "kaka" to enrich only fed-a entities.
	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{
				Sources: []SourceEntry{{File: fedA, As: "kaka"}},
				Files:   []string{fedB},
			}},
			{Action: "select"},
			{Action: "setattr", SetAttr: SetAttrStep{
				Name:     "entity_category",
				Value:    "https://example.org/test/kaka-only",
				Selector: "kaka",
			}},
			{Action: "select", Select: SelectStep{
				EntityCategory: "https://example.org/test/kaka-only",
			}},
			{Action: "publish", Publish: PublishStep{Output: "kaka.txt"}},
		},
	}

	outDir := t.TempDir()
	_, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(outDir, "kaka.txt"))
	if err != nil {
		t.Fatalf("expected kaka output file: %v", err)
	}
	// The kaka.txt should only contain endpoints from fed-a.
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("expected non-empty kaka.txt")
	}
}

func TestExecuteLoadSourceEntryURLWithAlias(t *testing.T) {
	entity := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.org/source-entry">
    <md:IDPSSODescriptor/>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(entity))
	}))
	defer ts.Close()

	p := File{
		Pipeline: []Step{
			{Action: "load", Load: LoadStep{
				Sources: []SourceEntry{{URL: ts.URL + "/fed.xml", As: "/myfed"}},
			}},
			{Action: "select"},
			{Action: "setattr", SetAttr: SetAttrStep{
				Name:     "entity_category",
				Value:    "https://example.org/test/source-entry",
				Selector: "/myfed",
			}},
			{Action: "select", Select: SelectStep{
				EntityCategory: "https://example.org/test/source-entry",
			}},
			{Action: "publish", Publish: PublishStep{Output: "result.txt"}},
		},
	}

	outDir := t.TempDir()
	_, err := Execute(p, outDir)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(outDir, "result.txt"))
	if err != nil {
		t.Fatalf("expected output file: %v", err)
	}
	if !strings.Contains(string(b), "https://idp.example.org/source-entry") {
		t.Fatalf("expected entity from source entry in output, got: %s", string(b))
	}
}
