package pipeline

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// File represents a pipeline YAML file.
type File struct {
	Pipeline []Step `yaml:"pipeline"`
	BaseDir  string `yaml:"-"`
}

// WhenStep represents a conditional guard: execute Body only when Condition is
// present (with optional Values) in the pipeline's active state labels.
// This models pyFF's `when <condition> [values]:` pipe.
type WhenStep struct {
	Condition string   // e.g. "update", "normalize", "accept"
	Values    []string // optional multi-word values, e.g. ["application/json"]
	Body      []Step
}

// Source is a named metadata source used by load steps.
type Source struct {
	ID       string   `yaml:"id"`
	Entities []string `yaml:"entities"`
	Files    []string `yaml:"files"`
	URLs     []string `yaml:"urls"`
	Verify   string   `yaml:"verify"`
	Timeout  string   `yaml:"timeout"`
	Retries  int      `yaml:"retries"`
	Cleanup  bool     `yaml:"cleanup"`
}

// Step is one pipeline operation.
type Step struct {
	Action      string
	Load        LoadStep
	Select      SelectStep
	Filter      SelectStep
	Pick        SelectStep
	SetAttr     SetAttrStep
	RegInfo     RegInfoStep
	PubInfo     PubInfoStep
	Sort        SortStep
	Finalize    FinalizeStep
	Sign        SignStep
	Verify      VerifyStep
	Publish     PublishStep
	Stats       StatsStep
	NodeCountry NodeCountryStep
	CertReport  CertReportStep
	DiscoJSON   DiscoJSONStep
	XSLT        XSLTStep
	Fork        ForkStep
	When        WhenStep
}

// SourceEntry is a single source item within a LoadStep, supporting per-source
// aliases (as), preprocessing branches (via), cert verification (verify), and
// cleanup flags.
type SourceEntry struct {
	URL     string `yaml:"url"`
	File    string `yaml:"file"`
	As      string `yaml:"as"`
	Via     string `yaml:"via"`
	Verify  string `yaml:"verify"`
	Cleanup bool   `yaml:"cleanup"`
}

// LoadStep loads metadata into the pipeline.
// Resources are given directly as files, URLs, or inline entity IDs.
// In-pipeline aliases produced by "select as /name" can be referenced in Files.
// Source entries in Sources support per-source aliases and cert verification.
type LoadStep struct {
	Files    []string      `yaml:"files"`
	URLs     []string      `yaml:"urls"`
	Sources  []SourceEntry `yaml:"sources"`
	Verify   string        `yaml:"verify"`
	Timeout  string        `yaml:"timeout"`
	Retries  int           `yaml:"retries"`
	Cleanup  bool          `yaml:"cleanup"`
	Entities []string      `yaml:"entities"`
	Via      []string      `yaml:"via"`
}

// SelectStep filters current entities to the provided set.
type SelectStep struct {
	Entities              []string `yaml:"entities"`
	Selector              string   `yaml:"selector"`
	Selectors             []string `yaml:"selectors"`
	As                    string   `yaml:"as"`
	Dedup                 *bool    `yaml:"dedup"`
	Role                  string   `yaml:"role"`
	Roles                 []string `yaml:"roles"`
	EntityCategory        string   `yaml:"entity_category"`
	EntityCategories      []string `yaml:"entity_categories"`
	RegistrationAuthority string   `yaml:"registration_authority"`
	Match                 string   `yaml:"match"`
}

// SetAttrStep applies metadata-like attribute enrichments to current entities.
// If Selector is set, enrichment is applied only to entities matching the selector.
type SetAttrStep struct {
	Name     string   `yaml:"name"`
	Value    string   `yaml:"value"`
	Values   []string `yaml:"values"`
	Selector string   `yaml:"selector"`
}

// RegInfoStep applies registration authority metadata to current entities.
// If Selector is set, enrichment is applied only to entities matching the selector.
type RegInfoStep struct {
	Authority             string   `yaml:"authority"`
	RegistrationAuthority string   `yaml:"registration_authority"`
	Policy                string   `yaml:"policy"`
	Policies              []string `yaml:"policies"`
	Selector              string   `yaml:"selector"`
}

// PubInfoStep applies publication-related text metadata to current entities.
type PubInfoStep struct {
	Publisher string   `yaml:"publisher"`
	Value     string   `yaml:"value"`
	Values    []string `yaml:"values"`
	URL       string   `yaml:"url"`
	URLs      []string `yaml:"urls"`
	Lang      string   `yaml:"lang"`
}

// PublishStep writes current entities to an output file.
// URLEncode, Ext, and Raw are supported for directory publishing:
//   - URLEncode: write MDQ-compatible URL-encoded {sha256}HEX filenames
//   - Ext: file extension for directory items (default ".xml")
//   - Raw: accepted for pyFF compatibility; dir publish is always raw
type PublishStep struct {
	Output      string `yaml:"output"`
	As          string `yaml:"as"`
	Resource    string `yaml:"resource"`
	Dir         string `yaml:"dir"`
	HashLink    bool   `yaml:"hash_link"`
	UpdateStore bool   `yaml:"update_store"`
	StoreDir    string `yaml:"store_dir"`
	URLEncode   bool   `yaml:"urlencode_filenames"`
	Ext         string `yaml:"ext"`
	Raw         bool   `yaml:"raw"`
}

// UnmarshalYAML supports:
// - scalar: output file path
// - mapping: structured publish arguments
func (p *PublishStep) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		p.Output = node.Value
		return nil
	case yaml.MappingNode:
		type publishAlias PublishStep
		var x publishAlias
		if err := node.Decode(&x); err != nil {
			return err
		}
		*p = PublishStep(x)
		return nil
	default:
		return fmt.Errorf("invalid publish argument kind: %d", node.Kind)
	}
}

// FinalizeStep carries metadata applied to XML aggregate output.
type FinalizeStep struct {
	Name          string `yaml:"Name"`
	CacheDuration string `yaml:"cacheDuration"`
	ValidUntil    string `yaml:"validUntil"`
}

// SignStep configures XML signing for published XML output.
type SignStep struct {
	Key    string              `yaml:"key"`
	Cert   string              `yaml:"cert"`
	PKCS11 *PKCS11SignSettings `yaml:"pkcs11"`
}

// VerifyStep configures XML signature verification for published XML output.
type VerifyStep struct {
	Cert string `yaml:"cert"`
}

// PKCS11SignSettings mirrors PKCS#11 signer configuration.
type PKCS11SignSettings struct {
	ModulePath string `yaml:"module_path"`
	SlotID     uint   `yaml:"slot_id"`
	PIN        string `yaml:"pin"`
	KeyLabel   string `yaml:"key_label"`
	KeyID      string `yaml:"key_id"`
}

// StatsStep configures stats output behavior.
// Empty configuration uses defaults.
type StatsStep struct{}

// NodeCountryStep enriches entities with country tokens from embedded X.509 certs.
type NodeCountryStep struct{}

// CertReportStep prints certificate validity information for current entities.
type CertReportStep struct{}

// DiscoJSONStep writes current entities as a SAML discovery JSON feed.
type DiscoJSONStep struct {
	Output string `yaml:"output"`
}

// UnmarshalYAML supports scalar "discojson <path>" and mapping forms.
func (d *DiscoJSONStep) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		d.Output = node.Value
		return nil
	case yaml.MappingNode:
		type discoAlias DiscoJSONStep
		var x discoAlias
		if err := node.Decode(&x); err != nil {
			return err
		}
		*d = DiscoJSONStep(x)
		return nil
	default:
		return fmt.Errorf("invalid discojson argument kind: %d", node.Kind)
	}
}

// SortStep configures entity sorting behavior.
type SortStep struct {
	OrderBy string `yaml:"order_by"`
}

// XSLTStep applies an XSLT transformation to the current entity set using xsltproc.
type XSLTStep struct {
	Stylesheet string `yaml:"stylesheet"`
}

// UnmarshalYAML supports:
// - scalar: stylesheet file path ("xslt transform.xsl")
// - mapping: structured arguments ({stylesheet: transform.xsl})
func (x *XSLTStep) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		x.Stylesheet = node.Value
		return nil
	case yaml.MappingNode:
		type xsltAlias XSLTStep
		var a xsltAlias
		if err := node.Decode(&a); err != nil {
			return err
		}
		*x = XSLTStep(a)
		return nil
	default:
		return fmt.Errorf("invalid xslt argument kind: %d", node.Kind)
	}
}

// ForkStep runs a sub-pipeline on a copy of the current state.
// Changes to the working set inside the fork do not affect the outer pipeline.
// Primarily used for side-effect outputs (e.g. publishing a sub-aggregate).
type ForkStep struct {
	Pipeline []Step
}
