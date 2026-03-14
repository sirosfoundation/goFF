package pipeline

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseFile loads a pipeline YAML file from disk.
func ParseFile(path string) (File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return File{}, fmt.Errorf("read pipeline: %w", err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return File{}, fmt.Errorf("parse pipeline yaml: %w", err)
	}

	if len(root.Content) == 0 {
		return File{}, fmt.Errorf("pipeline yaml is empty")
	}

	body := root.Content[0]
	if body.Kind != yaml.SequenceNode {
		return File{}, fmt.Errorf("pipeline file must be a YAML sequence of steps")
	}

	steps, err := parsePipelineSequence(body)
	if err != nil {
		return File{}, fmt.Errorf("parse pipeline step list: %w", err)
	}

	if len(steps) == 0 {
		return File{}, fmt.Errorf("pipeline must contain at least one step")
	}

	return File{Pipeline: steps, BaseDir: filepath.Dir(path)}, nil
}

func parsePipelineSequence(seq *yaml.Node) ([]Step, error) {
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("pipeline steps must be a sequence")
	}

	out := make([]Step, 0, len(seq.Content))
	for _, n := range seq.Content {
		expanded, err := expandStepNode(n)
		if err != nil {
			return nil, err
		}
		out = append(out, expanded...)
	}

	return out, nil
}

// expandStepNode turns a single YAML node into one or more Steps.
// when-nodes are preserved as a Step{Action:"when", When:WhenStep{...}};
// all other nodes are decoded normally.
func expandStepNode(node *yaml.Node) ([]Step, error) {
	if isWhenNode(node) {
		cond, body := whenNodeParts(node)
		parts := strings.Fields(strings.ToLower(strings.TrimSpace(cond)))
		if len(parts) == 0 {
			return nil, fmt.Errorf("when node has empty condition")
		}
		if body.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("when %q body must be a step sequence", cond)
		}
		bodySteps, err := parsePipelineSequence(body)
		if err != nil {
			return nil, fmt.Errorf("when %q body: %w", cond, err)
		}
		return []Step{{Action: "when", When: WhenStep{
			Condition: parts[0],
			Values:    parts[1:],
			Body:      bodySteps,
		}}}, nil
	}

	var s Step
	if err := node.Decode(&s); err != nil {
		return nil, err
	}
	return []Step{s}, nil
}

func isWhenNode(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.MappingNode || len(node.Content) != 2 {
		return false
	}
	return strings.EqualFold(baseActionName(node.Content[0].Value), "when")
}

func whenNodeParts(node *yaml.Node) (string, *yaml.Node) {
	raw := strings.TrimSpace(node.Content[0].Value)
	cond := strings.TrimSpace(strings.TrimPrefix(raw, "when"))
	return cond, node.Content[1]
}

// UnmarshalYAML supports two formats:
// - scalar: "load"
// - mapping: {load: {source: federation}}
func (s *Step) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		rawAction := node.Value
		s.Action = baseActionName(rawAction)
		if err := validateAction(rawAction); err != nil {
			return err
		}
		if s.Action == "select" {
			if err := applySelectActionOptions(&s.Select, rawAction); err != nil {
				return err
			}
		}
		if s.Action == "filter" {
			if err := applyFilterActionOptions(&s.Filter, rawAction); err != nil {
				return err
			}
		}
		if s.Action == "sort" {
			if err := applySortActionOptions(&s.Sort, rawAction); err != nil {
				return err
			}
		}
		if s.Action == "publish" {
			if err := applyPublishActionOptions(&s.Publish, rawAction); err != nil {
				return err
			}
		}
		if s.Action == "discojson" || s.Action == "discojson_sp" || s.Action == "discojson_idp" {
			parts := strings.Fields(rawAction)
			if len(parts) >= 2 {
				s.DiscoJSON.Output = strings.Join(parts[1:], " ")
			}
		}
		if s.Action == "xslt" {
			parts := strings.Fields(rawAction)
			if len(parts) >= 2 {
				s.XSLT.Stylesheet = strings.Join(parts[1:], " ")
			}
		}
		if s.Action == "then" {
			parts := strings.Fields(rawAction)
			if len(parts) >= 2 {
				s.Then = strings.Join(parts[1:], " ")
			}
		}
		return nil
	case yaml.MappingNode:
		if len(node.Content) != 2 {
			return fmt.Errorf("step mapping must contain exactly one action")
		}

		actionNode := node.Content[0]
		valueNode := node.Content[1]
		s.Action = baseActionName(actionNode.Value)
		if err := validateAction(actionNode.Value); err != nil {
			return err
		}
		// Decode action payload first, then apply inline action options so values like
		// `filter as /alias:` are not overwritten by mapping decode defaults.
		switch s.Action {
		case "load", "local", "remote", "fetch", "_fetch":
			if err := valueNode.Decode(&s.Load); err != nil {
				return err
			}
		case "setattr":
			if err := valueNode.Decode(&s.SetAttr); err != nil {
				return err
			}
		case "reginfo":
			if err := valueNode.Decode(&s.RegInfo); err != nil {
				return err
			}
		case "pubinfo":
			if err := valueNode.Decode(&s.PubInfo); err != nil {
				return err
			}
		case "select":
			if err := valueNode.Decode(&s.Select); err != nil {
				return err
			}
			if err := applySelectActionOptions(&s.Select, actionNode.Value); err != nil {
				return err
			}
		case "filter":
			if err := valueNode.Decode(&s.Filter); err != nil {
				return err
			}
			if err := applyFilterActionOptions(&s.Filter, actionNode.Value); err != nil {
				return err
			}
		case "pick":
			if err := valueNode.Decode(&s.Pick); err != nil {
				return err
			}
		case "sort":
			if err := valueNode.Decode(&s.Sort); err != nil {
				return err
			}
			if err := applySortActionOptions(&s.Sort, actionNode.Value); err != nil {
				return err
			}
		case "finalize":
			if err := valueNode.Decode(&s.Finalize); err != nil {
				return err
			}
		case "sign":
			if err := valueNode.Decode(&s.Sign); err != nil {
				return err
			}
		case "verify":
			if err := valueNode.Decode(&s.Verify); err != nil {
				return err
			}
		case "publish":
			if err := valueNode.Decode(&s.Publish); err != nil {
				return err
			}
			if err := applyPublishActionOptions(&s.Publish, actionNode.Value); err != nil {
				return err
			}
		case "stats":
			// no payload
		case "nodecountry", "certreport":
			// no payload
		case "discojson", "discojson_sp", "discojson_idp":
			if err := valueNode.Decode(&s.DiscoJSON); err != nil {
				return err
			}
		case "xslt":
			if err := valueNode.Decode(&s.XSLT); err != nil {
				return err
			}
		case "fork", "pipe", "parsecopy":
			if valueNode.Kind != yaml.SequenceNode {
				return fmt.Errorf("fork value must be a sequence of steps")
			}
			subSteps, err := parsePipelineSequence(valueNode)
			if err != nil {
				return fmt.Errorf("parse fork sub-pipeline: %w", err)
			}
			s.Fork.Pipeline = subSteps
		case "store":
			if err := valueNode.Decode(&s.Store); err != nil {
				return err
			}
		case "then":
			// `then <label>:` — label is the second word of the raw action key.
			parts := strings.Fields(actionNode.Value)
			if len(parts) >= 2 {
				s.Then = strings.Join(parts[1:], " ")
			}
		case "map":
			// per-entity loop: parse sub-pipeline but execute as a no-op (see GAP-5).
			if valueNode.Kind == yaml.SequenceNode {
				subSteps, err := parsePipelineSequence(valueNode)
				if err != nil {
					return fmt.Errorf("parse map sub-pipeline: %w", err)
				}
				s.Fork.Pipeline = subSteps
			}
		default:
			// unknown action payload ignored here; validation handles unsupported actions
		}
		return nil
	default:
		return fmt.Errorf("invalid step node kind: %d", node.Kind)
	}
}

func baseActionName(raw string) string {
	parts := strings.Fields(raw)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func applySelectActionOptions(s *SelectStep, rawAction string) error {
	parts := strings.Fields(rawAction)
	if len(parts) <= 1 {
		return nil
	}

	for i := 1; i < len(parts); i++ {
		switch parts[i] {
		case "as":
			if i+1 >= len(parts) {
				return fmt.Errorf("select option as requires a value")
			}
			s.As = parts[i+1]
			i++
		case "dedup":
			if i+1 >= len(parts) {
				return fmt.Errorf("select option dedup requires a value")
			}
			v, err := strconv.ParseBool(parts[i+1])
			if err != nil {
				return fmt.Errorf("invalid select dedup value %q", parts[i+1])
			}
			s.Dedup = &v
			i++
		}
	}

	return nil
}

func applyFilterActionOptions(s *SelectStep, rawAction string) error {
	parts := strings.Fields(rawAction)
	if len(parts) <= 1 {
		return nil
	}

	for i := 1; i < len(parts); i++ {
		if parts[i] == "as" {
			if i+1 >= len(parts) {
				return fmt.Errorf("filter option as requires a value")
			}
			s.As = parts[i+1]
			i++
		}
	}

	return nil
}

func applySortActionOptions(s *SortStep, rawAction string) error {
	parts := strings.Fields(rawAction)
	if len(parts) <= 1 {
		return nil
	}

	for i := 1; i < len(parts); i++ {
		if parts[i] == "order_by" {
			if i+1 >= len(parts) {
				return fmt.Errorf("sort option order_by requires a value")
			}
			s.OrderBy = strings.Join(parts[i+1:], " ")
			break
		}
	}

	return nil
}

func applyPublishActionOptions(s *PublishStep, rawAction string) error {
	parts := strings.Fields(rawAction)
	if len(parts) <= 1 {
		return nil
	}

	// Accept pyFF-like shorthands such as:
	// - publish output as resource <path>
	// - publish output as <path>
	// - publish as resource <path>
	if len(parts) >= 5 && parts[1] == "output" && parts[2] == "as" && parts[3] == "resource" {
		s.Resource = strings.Join(parts[4:], " ")
		return nil
	}
	if len(parts) >= 4 && parts[1] == "output" && parts[2] == "as" {
		s.Output = strings.Join(parts[3:], " ")
		return nil
	}
	if len(parts) >= 4 && parts[1] == "as" && parts[2] == "resource" {
		s.Resource = strings.Join(parts[3:], " ")
		return nil
	}

	if parts[1] == "as" {
		if len(parts) <= 2 {
			return fmt.Errorf("publish option as requires a value")
		}
		s.Output = strings.Join(parts[2:], " ")
		return nil
	}

	// Allow shorthand: "publish output-file.ext"
	s.Output = strings.Join(parts[1:], " ")
	return nil
}

func validateAction(action string) error {
	action = baseActionName(action)
	switch action {
	case "load", "local", "remote", "fetch", "_fetch",
		"select", "filter", "pick",
		"sort", "finalize",
		"sign", "verify",
		"publish",
		"setattr", "reginfo", "pubinfo",
		"stats", "info", "dump", "print",
		"first",
		"nodecountry", "certreport",
		"check_xml_namespaces",
		"discojson", "discojson_sp", "discojson_idp",
		"xslt",
		"fork", "pipe", "parsecopy",
		"break", "end",
		"when",
		// Request-side / no-op actions: accepted in pipeline YAML (e.g. inside
		// `when request:` or `when accept:` bodies) but silently ignored at
		// runtime in batch/update execution.
		"emit", "signcerts", "merge",
		// pyFF compatibility aliases / no-ops:
		"store",          // alias for publish:{dir:} — implements pyFF's store: directory: (GAP-13)
		"then",           // root pipeline re-run with {label:true} state (GAP-14)
		"drop_xsi_type",  // XML cleanup no-op (GAP-16)
		"log_entity",     // per-entity diagnostic no-op inside map: loops (GAP-6)
		"map":            // per-entity loop — no-op; publish:{dir:} covers the common case (GAP-5)
		return nil
	default:
		return fmt.Errorf("unknown pipeline action %q", action)
	}
}

// UnmarshalYAML supports:
// - scalar: URL or file path to load (e.g. "- load http://example.org/fed.xml")
// - sequence: list of URLs/file paths
// - mapping: {files: [...], urls: [...], entities: [...], ...}
func (l *LoadStep) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Value == "" {
			return nil
		}
		if strings.HasPrefix(node.Value, "http://") || strings.HasPrefix(node.Value, "https://") {
			l.URLs = []string{node.Value}
		} else {
			l.Files = []string{node.Value}
		}
		return nil
	case yaml.SequenceNode:
		for _, item := range node.Content {
			switch item.Kind {
			case yaml.MappingNode:
				// Structured source entry: {url: ..., file: ..., as: ..., via: ..., verify: ...}
				var entry SourceEntry
				if err := item.Decode(&entry); err != nil {
					return fmt.Errorf("load sequence mapping item: %w", err)
				}
				l.Sources = append(l.Sources, entry)
			case yaml.ScalarNode:
				entry := parseInlineSourceToken(item.Value)
				if entry.URL != "" || entry.File != "" {
					if entry.As != "" || entry.Via != "" || entry.Cleanup {
						l.Sources = append(l.Sources, entry)
					} else if entry.URL != "" {
						l.URLs = append(l.URLs, entry.URL)
					} else {
						l.Files = append(l.Files, entry.File)
					}
				}
			default:
				return fmt.Errorf("load sequence items must be scalars or mappings")
			}
		}
		return nil
	case yaml.MappingNode:
		type loadAlias LoadStep
		var x loadAlias
		if err := node.Decode(&x); err != nil {
			return err
		}
		*l = LoadStep(x)
		return nil
	default:
		return fmt.Errorf("invalid load argument kind: %d", node.Kind)
	}
}

// parseInlineSourceToken parses a space-separated source token string of the form:
//
//	url_or_path [as alias] [via branch] [cleanup]
//
// Keywords "as", "via", "cleanup", "clean" are case-insensitive.  Unrecognised
// tokens are silently ignored (pyFF has extra flags like "validate True" that
// goFF does not use).
func parseInlineSourceToken(v string) SourceEntry {
	parts := strings.Fields(v)
	if len(parts) == 0 {
		return SourceEntry{}
	}
	entry := SourceEntry{}
	resource := parts[0]
	if strings.HasPrefix(resource, "http://") || strings.HasPrefix(resource, "https://") {
		entry.URL = resource
	} else {
		entry.File = resource
	}
	i := 1
	for i < len(parts) {
		switch strings.ToLower(parts[i]) {
		case "as":
			if i+1 < len(parts) {
				entry.As = parts[i+1]
				i += 2
			} else {
				i++
			}
		case "via":
			if i+1 < len(parts) {
				entry.Via = strings.ToLower(parts[i+1])
				i += 2
			} else {
				i++
			}
		case "cleanup", "clean":
			entry.Cleanup = true
			i++
		default:
			i++ // unknown token (eg. "validate True") — skip
		}
	}
	return entry
}

// UnmarshalYAML supports:
// - scalar: selector expression or entity ID
// - sequence: list of selector expressions
// - mapping: structured select arguments
func (s *SelectStep) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		s.Selector = node.Value
		return nil
	case yaml.SequenceNode:
		return node.Decode(&s.Selectors)
	case yaml.MappingNode:
		type selectAlias SelectStep
		var x selectAlias
		if err := node.Decode(&x); err != nil {
			return err
		}
		*s = SelectStep(x)
		return nil
	default:
		return fmt.Errorf("invalid select argument kind: %d", node.Kind)
	}
}

// UnmarshalYAML supports:
// - scalar: xpath used as order_by
// - mapping: structured sort arguments
func (s *SortStep) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		s.OrderBy = strings.TrimSpace(node.Value)
		return nil
	case yaml.MappingNode:
		type sortAlias SortStep
		var x sortAlias
		if err := node.Decode(&x); err != nil {
			return err
		}
		*s = SortStep(x)
		return nil
	default:
		return fmt.Errorf("invalid sort argument kind: %d", node.Kind)
	}
}
