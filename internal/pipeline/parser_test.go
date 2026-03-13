package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFile(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "basic.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(p.Pipeline) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(p.Pipeline))
	}
}

func TestParseFileSupportsWhenUpdateWrapper(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "pyff-when-update.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if len(p.Pipeline) != 2 {
		t.Fatalf("expected 2 expanded steps, got %d", len(p.Pipeline))
	}
	if p.Pipeline[0].Action != "load" || p.Pipeline[1].Action != "select" {
		t.Fatalf("unexpected expanded actions: %#v", []string{p.Pipeline[0].Action, p.Pipeline[1].Action})
	}
}

func TestParseFileSkipsNonUpdateWhenBranches(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "pyff-when-dual-entry.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if len(p.Pipeline) != 1 {
		t.Fatalf("expected only update branch steps, got %d", len(p.Pipeline))
	}
	if p.Pipeline[0].Action != "load" {
		t.Fatalf("expected update branch load action, got %q", p.Pipeline[0].Action)
	}
}

func TestParseFileSignStep(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "sign-parse.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(p.Pipeline) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(p.Pipeline))
	}

	if p.Pipeline[1].Action != "sign" {
		t.Fatalf("expected second step to be sign, got %q", p.Pipeline[1].Action)
	}
	if p.Pipeline[1].Sign.Key == "" || p.Pipeline[1].Sign.Cert == "" {
		t.Fatal("expected sign step key/cert to be populated")
	}
}

func TestParseFileSignStepPKCS11(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "sign-pkcs11-parse.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(p.Pipeline) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(p.Pipeline))
	}

	s := p.Pipeline[1].Sign
	if s.Cert == "" {
		t.Fatal("expected sign step cert to be populated")
	}
	if s.PKCS11 == nil {
		t.Fatal("expected pkcs11 settings to be populated")
	}
	if s.PKCS11.ModulePath == "" || s.PKCS11.KeyLabel == "" {
		t.Fatalf("unexpected pkcs11 settings: %#v", s.PKCS11)
	}
}

func TestParseFileVerifyStep(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "verify-parse.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if p.Pipeline[1].Action != "verify" {
		t.Fatalf("expected second step to be verify, got %q", p.Pipeline[1].Action)
	}
	if p.Pipeline[1].Verify.Cert == "" {
		t.Fatal("expected verify step cert to be populated")
	}
}

func TestParseFileSelectActionOptions(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "select-options-parse.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if p.Pipeline[1].Action != "select" {
		t.Fatalf("expected second step to be select, got %q", p.Pipeline[1].Action)
	}
	if p.Pipeline[1].Select.As != "/foo" {
		t.Fatalf("expected select.as to be /foo, got %q", p.Pipeline[1].Select.As)
	}
	if p.Pipeline[1].Select.Dedup == nil || *p.Pipeline[1].Select.Dedup {
		t.Fatalf("expected select.dedup false, got %#v", p.Pipeline[1].Select.Dedup)
	}
	if len(p.Pipeline[1].Select.Selectors) != 1 {
		t.Fatalf("expected one select selector, got %#v", p.Pipeline[1].Select.Selectors)
	}
}

func TestParseFileSortActionOptions(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "sort-options-parse.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(p.Pipeline) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(p.Pipeline))
	}
	if p.Pipeline[1].Action != "sort" {
		t.Fatalf("expected second step to be sort, got %q", p.Pipeline[1].Action)
	}
	if p.Pipeline[1].Sort.OrderBy != "@entityID" {
		t.Fatalf("expected sort.order_by @entityID, got %q", p.Pipeline[1].Sort.OrderBy)
	}
}

func TestParseFilePublishInlineOutput(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "publish-inline-parse.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(p.Pipeline) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(p.Pipeline))
	}
	if p.Pipeline[1].Action != "publish" {
		t.Fatalf("expected second step to be publish, got %q", p.Pipeline[1].Action)
	}
	if p.Pipeline[1].Publish.Output != "nested/entities.txt" {
		t.Fatalf("expected publish output nested/entities.txt, got %q", p.Pipeline[1].Publish.Output)
	}
}

func TestParseFilePublishAsActionOption(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "publish-as-parse.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(p.Pipeline) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(p.Pipeline))
	}
	if p.Pipeline[1].Action != "publish" {
		t.Fatalf("expected second step to be publish, got %q", p.Pipeline[1].Action)
	}
	if p.Pipeline[1].Publish.Output != "nested/entities.txt" {
		t.Fatalf("expected publish output nested/entities.txt, got %q", p.Pipeline[1].Publish.Output)
	}
}

func TestParseFileSetAttrStep(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	yaml := "- load\n- setattr:\n    name: entity_category\n    value: https://refeds.org/category/research-and-scholarship\n"
	if err := os.WriteFile(fixture, []byte(yaml), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(p.Pipeline) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(p.Pipeline))
	}
	if p.Pipeline[1].Action != "setattr" {
		t.Fatalf("expected second step to be setattr, got %q", p.Pipeline[1].Action)
	}
	if p.Pipeline[1].SetAttr.Name != "entity_category" {
		t.Fatalf("expected setattr.name entity_category, got %q", p.Pipeline[1].SetAttr.Name)
	}
	if p.Pipeline[1].SetAttr.Value == "" {
		t.Fatal("expected setattr.value to be populated")
	}
}

func TestParseFileRegInfoStep(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	yaml := "- load\n- reginfo:\n    authority: https://example.org/authority\n"
	if err := os.WriteFile(fixture, []byte(yaml), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(p.Pipeline) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(p.Pipeline))
	}
	if p.Pipeline[1].Action != "reginfo" {
		t.Fatalf("expected second step to be reginfo, got %q", p.Pipeline[1].Action)
	}
	if p.Pipeline[1].RegInfo.Authority != "https://example.org/authority" {
		t.Fatalf("expected reginfo.authority to be set, got %q", p.Pipeline[1].RegInfo.Authority)
	}
}

func TestParseFilePublishMappingAs(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "publish-mapping-as.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(p.Pipeline) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(p.Pipeline))
	}
	if p.Pipeline[1].Action != "publish" {
		t.Fatalf("expected second step to be publish, got %q", p.Pipeline[1].Action)
	}
	if p.Pipeline[1].Publish.As != "nested/from-mapping-as.txt" {
		t.Fatalf("expected publish.as nested/from-mapping-as.txt, got %q", p.Pipeline[1].Publish.As)
	}
}

func TestParseFilePubInfoStep(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	yaml := "- load\n- pubinfo:\n    publisher: SIROS Foundation\n"
	if err := os.WriteFile(fixture, []byte(yaml), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(p.Pipeline) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(p.Pipeline))
	}
	if p.Pipeline[1].Action != "pubinfo" {
		t.Fatalf("expected second step to be pubinfo, got %q", p.Pipeline[1].Action)
	}
	if p.Pipeline[1].PubInfo.Publisher != "SIROS Foundation" {
		t.Fatalf("expected pubinfo.publisher to be set, got %q", p.Pipeline[1].PubInfo.Publisher)
	}
}

func TestParseFilePubInfoStructuredFields(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	yaml := "- load\n- pubinfo:\n    publisher: SIROS Foundation\n    url: https://publisher.example.org\n    lang: en\n"
	if err := os.WriteFile(fixture, []byte(yaml), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if p.Pipeline[1].Action != "pubinfo" {
		t.Fatalf("expected second step to be pubinfo, got %q", p.Pipeline[1].Action)
	}
	if p.Pipeline[1].PubInfo.URL != "https://publisher.example.org" {
		t.Fatalf("expected pubinfo.url to be set, got %q", p.Pipeline[1].PubInfo.URL)
	}
	if p.Pipeline[1].PubInfo.Lang != "en" {
		t.Fatalf("expected pubinfo.lang to be set, got %q", p.Pipeline[1].PubInfo.Lang)
	}
}

func TestParseFilePublishOutputAsResourceAction(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "publish-output-as-resource-batch.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(p.Pipeline) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(p.Pipeline))
	}
	if p.Pipeline[1].Action != "publish" {
		t.Fatalf("expected second step to be publish, got %q", p.Pipeline[1].Action)
	}
	if p.Pipeline[1].Publish.Resource != "nested/resource-publish.txt" {
		t.Fatalf("expected publish.resource nested/resource-publish.txt, got %q", p.Pipeline[1].Publish.Resource)
	}
}

func TestParseFilePublishOutputAsAction(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "publish-output-as-batch.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(p.Pipeline) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(p.Pipeline))
	}
	if p.Pipeline[1].Action != "publish" {
		t.Fatalf("expected second step to be publish, got %q", p.Pipeline[1].Action)
	}
	if p.Pipeline[1].Publish.Output != "nested/output-as-publish.txt" {
		t.Fatalf("expected publish.output nested/output-as-publish.txt, got %q", p.Pipeline[1].Publish.Output)
	}
}

func TestParseFilePublishMappingResource(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "publish-mapping-resource.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(p.Pipeline) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(p.Pipeline))
	}
	if p.Pipeline[1].Action != "publish" {
		t.Fatalf("expected second step to be publish, got %q", p.Pipeline[1].Action)
	}
	if p.Pipeline[1].Publish.Resource != "nested/mapping-resource.txt" {
		t.Fatalf("expected publish.resource nested/mapping-resource.txt, got %q", p.Pipeline[1].Publish.Resource)
	}
}

func TestParseFileRegInfoStructuredFields(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	yaml := "- load\n- reginfo:\n    authority: https://example.org/authority\n    policy: https://example.org/policy\n    policies:\n      - https://example.org/policy-2\n"
	if err := os.WriteFile(fixture, []byte(yaml), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if p.Pipeline[1].RegInfo.Policy != "https://example.org/policy" {
		t.Fatalf("expected reginfo.policy to be set, got %q", p.Pipeline[1].RegInfo.Policy)
	}
	if len(p.Pipeline[1].RegInfo.Policies) != 1 || p.Pipeline[1].RegInfo.Policies[0] != "https://example.org/policy-2" {
		t.Fatalf("unexpected reginfo.policies: %#v", p.Pipeline[1].RegInfo.Policies)
	}
}

func TestParseFileLoadAliases(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "load-alias-parse.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(p.Pipeline) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(p.Pipeline))
	}
	want := []string{"remote", "local", "_fetch"}
	for i, w := range want {
		if p.Pipeline[i].Action != w {
			t.Fatalf("expected step %d action %q, got %q", i, w, p.Pipeline[i].Action)
		}
		if p.Pipeline[i].Load.Files[0] != "/federation" {
			t.Fatalf("expected step %d load.files[0] /federation, got %q", i, p.Pipeline[i].Load.Files[0])
		}
	}
}

func TestParseFileLoadVia(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "load-via-parse.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(p.Pipeline) != 1 {
		t.Fatalf("expected 1 step, got %d", len(p.Pipeline))
	}
	if p.Pipeline[0].Action != "load" {
		t.Fatalf("expected first step to be load, got %q", p.Pipeline[0].Action)
	}
	if p.Pipeline[0].Load.Files[0] != "/federation" {
		t.Fatalf("expected load.files[0] /federation, got %q", p.Pipeline[0].Load.Files[0])
	}
	if len(p.Pipeline[0].Load.Via) != 1 || p.Pipeline[0].Load.Via[0] != "/idp-only" {
		t.Fatalf("expected load.via [/idp-only], got %#v", p.Pipeline[0].Load.Via)
	}
}

func TestParseFilterAndPickActions(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "filter-pick-parse.yaml")
	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(p.Pipeline) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(p.Pipeline))
	}
	if p.Pipeline[1].Action != "filter" {
		t.Fatalf("expected second step filter, got %q", p.Pipeline[1].Action)
	}
	if p.Pipeline[1].Filter.As != "/filtered" {
		t.Fatalf("expected filter.as /filtered, got %q", p.Pipeline[1].Filter.As)
	}
	if p.Pipeline[2].Action != "pick" {
		t.Fatalf("expected third step pick, got %q", p.Pipeline[2].Action)
	}
	if len(p.Pipeline[2].Pick.Entities) != 1 {
		t.Fatalf("expected pick entities populated, got %#v", p.Pipeline[2].Pick.Entities)
	}
}

func TestParseFileNativeStepSequence(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	yaml := "- load\n- select\n"
	if err := os.WriteFile(fixture, []byte(yaml), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(p.Pipeline) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(p.Pipeline))
	}
	if p.BaseDir != dir {
		t.Fatalf("expected basedir %q, got %q", dir, p.BaseDir)
	}
}

func TestParseFileRejectsInvalidSelectActionOptions(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	yaml := "- load\n- select as\n"
	if err := os.WriteFile(fixture, []byte(yaml), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	_, err := ParseFile(fixture)
	if err == nil {
		t.Fatal("expected ParseFile error for invalid select options")
	}
	if !strings.Contains(err.Error(), "select option as requires a value") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseFileRejectsInvalidSortActionOptions(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	yaml := "- load\n- sort order_by\n"
	if err := os.WriteFile(fixture, []byte(yaml), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	_, err := ParseFile(fixture)
	if err == nil {
		t.Fatal("expected ParseFile error for invalid sort options")
	}
	if !strings.Contains(err.Error(), "sort option order_by requires a value") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseFileRejectsInvalidSortArgumentKind(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	yaml := "- load\n- sort:\n  - \"@entityID\"\n"
	if err := os.WriteFile(fixture, []byte(yaml), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	_, err := ParseFile(fixture)
	if err == nil {
		t.Fatal("expected ParseFile error for invalid sort argument kind")
	}
	if !strings.Contains(err.Error(), "invalid sort argument kind") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseFileRejectsKnownUnsupportedAction(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	yaml := "- load\n- signcerts\n"
	if err := os.WriteFile(fixture, []byte(yaml), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	_, err := ParseFile(fixture)
	if err == nil {
		t.Fatal("expected ParseFile error for unsupported action signcerts")
	}
	if !strings.Contains(err.Error(), "signcerts") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseFileRejectsUnknownAction(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	yaml := "- load\n- totally_made_up_action\n"
	if err := os.WriteFile(fixture, []byte(yaml), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	_, err := ParseFile(fixture)
	if err == nil {
		t.Fatal("expected ParseFile error for unknown action")
	}
	if !strings.Contains(err.Error(), "totally_made_up_action") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseFileDiscoJSONScalarSyntax(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	content := "- load\n- discojson /tmp/disco.json\n"
	if err := os.WriteFile(fixture, []byte(content), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if len(p.Pipeline) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(p.Pipeline))
	}
	if p.Pipeline[1].Action != "discojson" {
		t.Fatalf("expected discojson action, got %q", p.Pipeline[1].Action)
	}
	if p.Pipeline[1].DiscoJSON.Output != "/tmp/disco.json" {
		t.Fatalf("expected DiscoJSON.Output to be /tmp/disco.json, got %q", p.Pipeline[1].DiscoJSON.Output)
	}
}

func TestParseFileDiscoJSONMappingSyntax(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	content := "- load\n- discojson:\n    output: /tmp/disco.json\n"
	if err := os.WriteFile(fixture, []byte(content), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if p.Pipeline[1].DiscoJSON.Output != "/tmp/disco.json" {
		t.Fatalf("expected DiscoJSON.Output to be /tmp/disco.json, got %q", p.Pipeline[1].DiscoJSON.Output)
	}
}

// TestParseFileSortMappingScalarValue exercises SortStep.UnmarshalYAML scalar branch.
// The YAML form "sort: \"@entityID\"" produces a mapping step where the
// value node is a scalar, which goes through SortStep.UnmarshalYAML.
func TestParseFileSortMappingScalarValue(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	// YAML: the mapping value "@entityID" is a plain scalar node.
	content := "- load\n- sort: \"@entityID\"\n"
	if err := os.WriteFile(fixture, []byte(content), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if len(p.Pipeline) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(p.Pipeline))
	}
	if p.Pipeline[1].Action != "sort" {
		t.Fatalf("expected sort action, got %q", p.Pipeline[1].Action)
	}
	if p.Pipeline[1].Sort.OrderBy != "@entityID" {
		t.Fatalf("expected Sort.OrderBy to be @entityID, got %q", p.Pipeline[1].Sort.OrderBy)
	}
}

// ---------------------------------------------------------------------------
// GAP-7: check_xml_namespaces accepted by parser
// ---------------------------------------------------------------------------

func TestParseCheckXMLNamespacesActionIsAccepted(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	content := "- load\n- check_xml_namespaces\n"
	if err := os.WriteFile(fixture, []byte(content), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if len(p.Pipeline) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(p.Pipeline))
	}
	if p.Pipeline[1].Action != "check_xml_namespaces" {
		t.Fatalf("expected check_xml_namespaces action, got %q", p.Pipeline[1].Action)
	}
}

// ---------------------------------------------------------------------------
// GAP-3: inline "url as alias" syntax in load sequence
// ---------------------------------------------------------------------------

func TestParseLoadInlineAsSyntaxURL(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	content := "- load:\n  - https://example.org/fed.xml as /myfed\n"
	if err := os.WriteFile(fixture, []byte(content), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if len(p.Pipeline) != 1 || p.Pipeline[0].Action != "load" {
		t.Fatalf("expected 1 load step, got %d", len(p.Pipeline))
	}
	load := p.Pipeline[0].Load
	if len(load.Sources) != 1 {
		t.Fatalf("expected 1 source entry, got %d", len(load.Sources))
	}
	if load.Sources[0].URL != "https://example.org/fed.xml" {
		t.Errorf("expected URL fed.xml, got %q", load.Sources[0].URL)
	}
	if load.Sources[0].As != "/myfed" {
		t.Errorf("expected alias /myfed, got %q", load.Sources[0].As)
	}
}

func TestParseLoadInlineAsSyntaxFile(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	content := "- load:\n  - /path/to/swamid.xml as kaka cleanup\n"
	if err := os.WriteFile(fixture, []byte(content), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	load := p.Pipeline[0].Load
	if len(load.Sources) != 1 {
		t.Fatalf("expected 1 source entry, got %d", len(load.Sources))
	}
	if load.Sources[0].File != "/path/to/swamid.xml" {
		t.Errorf("expected file /path/to/swamid.xml, got %q", load.Sources[0].File)
	}
	if load.Sources[0].As != "kaka" {
		t.Errorf("expected alias kaka, got %q", load.Sources[0].As)
	}
	if !load.Sources[0].Cleanup {
		t.Error("expected cleanup to be true")
	}
}

func TestParseLoadMappingSequenceItem(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "pipeline.yaml")
	content := "- load:\n  - url: https://example.org/fed.xml\n    as: /myfed\n    verify: cert.pem\n"
	if err := os.WriteFile(fixture, []byte(content), 0o600); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	p, err := ParseFile(fixture)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	load := p.Pipeline[0].Load
	if len(load.Sources) != 1 {
		t.Fatalf("expected 1 source entry, got %d", len(load.Sources))
	}
	e := load.Sources[0]
	if e.URL != "https://example.org/fed.xml" {
		t.Errorf("expected URL, got %q", e.URL)
	}
	if e.As != "/myfed" {
		t.Errorf("expected alias /myfed, got %q", e.As)
	}
	if e.Verify != "cert.pem" {
		t.Errorf("expected verify cert.pem, got %q", e.Verify)
	}
}
