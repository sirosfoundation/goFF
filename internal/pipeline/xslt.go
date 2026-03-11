package pipeline

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// runXSLT applies an XSLT stylesheet to the full aggregate XML of the current
// entity set using xsltproc, then re-parses the entities from the transformed
// output.  The calling step replaces current/currentAttrs/currentXML with the
// results.
func runXSLT(cfg XSLTStep, baseDir string, current []string, currentXML map[string]string) ([]string, map[string]EntityAttributes, map[string]string, error) {
	if cfg.Stylesheet == "" {
		return nil, nil, nil, fmt.Errorf("xslt: stylesheet path is required")
	}

	xsltprocPath, err := exec.LookPath("xsltproc")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("xslt: xsltproc not found in PATH (install libxslt-utils): %w", err)
	}

	stylesheet := cfg.Stylesheet
	if !filepath.IsAbs(stylesheet) {
		stylesheet = filepath.Join(baseDir, stylesheet)
	}

	aggregate := BuildEntitiesXML(current, currentXML, AggregateConfig{})

	// xsltproc <stylesheet> - (reads document from stdin)
	cmd := exec.Command(xsltprocPath, stylesheet, "-") //nolint:gosec
	cmd.Stdin = bytes.NewReader(aggregate)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return nil, nil, nil, fmt.Errorf("xslt: xsltproc: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, nil, nil, fmt.Errorf("xslt: xsltproc: %w", err)
	}

	attrs, err := parseMetadataFromXML(out)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("xslt: parse transformed xml: %w", err)
	}

	xmlByID, err := parseEntityXMLByID(out)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("xslt: parse entity xml from transformed output: %w", err)
	}

	ids := make([]string, 0, len(attrs))
	for id := range attrs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	return ids, attrs, xmlByID, nil
}
