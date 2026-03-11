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
