package pipeline

import (
	"fmt"
	"strings"

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
	// MaxBytes caps the size of each HTTP response body. Defaults to 100 MiB (104857600) when zero.
	MaxBytes int64 `yaml:"max_bytes"`
	// AllowPrivateAddrs disables the private-IP / cloud-metadata SSRF blocklist for this source.
	// Enable only for intentionally internal or intranet federation endpoints.
	AllowPrivateAddrs bool `yaml:"allow_private_addrs"`
}

// StoreStep writes the current entity set to a content-addressable on-disk
// directory, equivalent to pyFF's `store: directory:` pipe.  goFF executes it
// as a `publish: {dir: Directory}` step.
type StoreStep struct {
	Directory string `yaml:"directory"`
}

// UnmarshalYAML supports three pyFF forms:
//
//	store: directory: /path          (mapping)
//	store: - directory /path         (sequence scalar)
//	store: /path                     (bare scalar)
func (s *StoreStep) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.MappingNode:
		type Alias StoreStep
		var a Alias
		if err := node.Decode(&a); err != nil {
			return err
		}
		*s = StoreStep(a)
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if item.Kind == yaml.ScalarNode {
				parts := strings.Fields(item.Value)
				if len(parts) >= 2 && parts[0] == "directory" {
					s.Directory = strings.Join(parts[1:], " ")
				} else if len(parts) == 1 {
					s.Directory = parts[0]
				}
			}
		}
	case yaml.ScalarNode:
		s.Directory = node.Value
	}
	return nil
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
	Store       StoreStep
	Stats       StatsStep
	NodeCountry NodeCountryStep
	CertReport  CertReportStep
	DiscoJSON   DiscoJSONStep
	XSLT        XSLTStep
	Fork        ForkStep
	When        WhenStep
	Then        string // label for `then <label>:` steps — re-runs root pipeline with {label:true}
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
// From registers the loaded entity set under the given alias name in the source
// map after loading (pyFF compat: makes the loaded data addressable by name).
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
	From     string        `yaml:"from"`
	// AllowPrivateAddrs disables the private-IP SSRF blocklist for all URL
	// sources within this load step. Use for intentionally internal endpoints.
	AllowPrivateAddrs bool `yaml:"allow_private_addrs"`
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
// Either Cert (single PEM file path) or Certs (list of PEM file paths) may be
// set; both are accepted and merged into the verification certificate pool.
// Multiple certificates allow key-rollover pipelines where the signer may use
// either of two valid certs.
type VerifyStep struct {
	Cert  string   `yaml:"cert"`
	Certs []string `yaml:"certs"`
	// CheckExpiry enables NotBefore/NotAfter validation on the verification certificates.
	// Disabled by default to support the common SAML practice of pinning known certs
	// independent of their PKI validity period.
	CheckExpiry bool `yaml:"check_expiry"`
}

// PKCS11SignSettings mirrors PKCS#11 signer configuration.
type PKCS11SignSettings struct {
	ModulePath string `yaml:"module_path"`
	SlotID     uint   `yaml:"slot_id"`
	// PIN is the literal slot user PIN. Prefer PINEnv or PINFile to avoid
	// storing secrets in the pipeline YAML file.
	PIN string `yaml:"pin"`
	// PINEnv names an environment variable whose value is the slot PIN.
	PINEnv string `yaml:"pin_env"`
	// PINFile is the path to a file whose first line contains the slot PIN.
	PINFile  string `yaml:"pin_file"`
	KeyLabel string `yaml:"key_label"`
	KeyID    string `yaml:"key_id"`
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
