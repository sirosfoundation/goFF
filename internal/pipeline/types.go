package pipeline

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// File represents a pipeline YAML file.
type File struct {
	Sources  []Source `yaml:"sources"`
	Pipeline []Step   `yaml:"pipeline"`
	BaseDir  string   `yaml:"-"`
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
	Action   string
	Load     LoadStep
	Select   SelectStep
	Filter   SelectStep
	Pick     SelectStep
	SetAttr  SetAttrStep
	RegInfo  RegInfoStep
	PubInfo  PubInfoStep
	Sort     SortStep
	Finalize FinalizeStep
	Sign     SignStep
	Verify   VerifyStep
	Publish  PublishStep
	Stats    StatsStep
}

// LoadStep selects a source to load from the source map.
type LoadStep struct {
	Source   string   `yaml:"source"`
	Entities []string `yaml:"entities"`
	Via      []string `yaml:"via"`
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
type SetAttrStep struct {
	Name   string   `yaml:"name"`
	Value  string   `yaml:"value"`
	Values []string `yaml:"values"`
}

// RegInfoStep applies registration authority metadata to current entities.
type RegInfoStep struct {
	Authority             string   `yaml:"authority"`
	RegistrationAuthority string   `yaml:"registration_authority"`
	Policy                string   `yaml:"policy"`
	Policies              []string `yaml:"policies"`
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
type PublishStep struct {
	Output      string `yaml:"output"`
	As          string `yaml:"as"`
	Resource    string `yaml:"resource"`
	HashLink    bool   `yaml:"hash_link"`
	UpdateStore bool   `yaml:"update_store"`
	StoreDir    string `yaml:"store_dir"`
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

// SortStep configures entity sorting behavior.
type SortStep struct {
	OrderBy string `yaml:"order_by"`
}
