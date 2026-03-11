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

func expandStepNode(node *yaml.Node) ([]Step, error) {
	if isWhenNode(node) {
		cond, body := whenNodeParts(node)
		if !shouldIncludeWhen(cond) {
			return nil, nil
		}
		if body.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("when %q body must be a step sequence", cond)
		}
		return parsePipelineSequence(body)
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

func shouldIncludeWhen(cond string) bool {
	c := strings.ToLower(strings.TrimSpace(cond))
	switch {
	case c == "", c == "update", c == "x", c == "true", c == "always":
		return true
	case c == "request", strings.HasPrefix(c, "accept "):
		return false
	default:
		// Update executor only includes explicit update-like branches.
		return false
	}
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
		"break", "end":
		return nil
	case "xslt", "nodecountry", "certreport", "signcerts",
		"discojson", "discojson_sp", "discojson_idp",
		"fork", "pipe", "merge", "parsecopy",
		"emit":
		return fmt.Errorf("action %q is known but not supported in goFF update pipelines", action)
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
			if item.Kind != yaml.ScalarNode {
				return fmt.Errorf("load sequence items must be scalars")
			}
			v := item.Value
			if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
				l.URLs = append(l.URLs, v)
			} else {
				l.Files = append(l.Files, v)
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
