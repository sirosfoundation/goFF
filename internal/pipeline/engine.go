package pipeline

import (
	"bytes"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"
)

// Result contains final in-memory entities after execution.
type Result struct {
	Entities  []string
	EntityXML map[string]string
	Attrs     map[string]EntityAttributes
	Finalize  FinalizeStep
	Sign      SignStep
	Verify    VerifyStep
	// DiscoJSON holds the entries built by the most recent discojson/discojson_idp/
	// discojson_sp step.  Nil when no discojson step was executed.  The MDQ server
	// uses this to serve the discovery feed in-memory without reading the on-disk
	// file written by the step.
	DiscoJSON []DiscoEntry
}

// ExecuteOptions controls optional behavior of Execute.
type ExecuteOptions struct {
	// Progress, if non-nil, is called after each step with the step index,
	// action name, and a brief status message.
	Progress func(step int, action, msg string)
	// States is the set of active pipeline labels used to evaluate `when`
	// guards.  Nil defaults to {"update": true}, which is the standard batch
	// execution mode.  Set explicitly when invoking the pipeline in a
	// non-update mode (e.g. via-runs use {viaLabel: true}).
	States map[string]bool
}

// errBreak is a sentinel returned by executeSteps when a `break` or `end` step
// is reached.  It propagates through nested when-body executions so that `break`
// inside a when body stops the outer pipeline, matching pyFF's req.done semantics.
var errBreak = fmt.Errorf("break")

// Execute runs a parsed pipeline file.
func Execute(p File, outputDir string, opts ...ExecuteOptions) (Result, error) {
	var o ExecuteOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	states := o.States
	if len(states) == 0 {
		// Default batch-mode states: update, x, true, always are all treated as
		// unconditionally active in batch execution, matching the historical pyFF
		// convention where any of these labels indicates a batch/update run.
		states = map[string]bool{
			"update": true,
			"batch":  true, // pyFF uses 'batch' as a synonym for 'update' in batch-mode pipelines
			"x":      true,
			"true":   true,
			"always": true,
		}
	}
	res, err := executeSteps(
		p.Pipeline, outputDir, p.BaseDir,
		make(map[string][]string),
		make(map[string]map[string]EntityAttributes),
		make(map[string]map[string]string),
		make([]string, 0),
		make(map[string]EntityAttributes),
		make(map[string]string),
		FinalizeStep{}, SignStep{}, VerifyStep{},
		p.Pipeline, states,
		o,
	)
	if err == errBreak {
		err = nil
	}
	return res, err
}

// executeSteps runs a sequence of pipeline steps starting from the provided
// initial state.  It is called recursively by fork/pipe/parsecopy and when
// bodies to run sub-pipelines.
// rootPipeline is the root File.Pipeline; it is passed unchanged through calls
// so that `via` re-runs can always reference the full pipeline.
// states is the set of active labels used to evaluate `when` guards.
func executeSteps(
	steps []Step, outputDir, baseDir string,
	sourceMap map[string][]string,
	sourceAttrs map[string]map[string]EntityAttributes,
	sourceXML map[string]map[string]string,
	current []string,
	currentAttrs map[string]EntityAttributes,
	currentXML map[string]string,
	finalizeCfg FinalizeStep,
	signCfg SignStep,
	verifyCfg VerifyStep,
	rootPipeline []Step,
	states map[string]bool,
	opts ExecuteOptions,
) (Result, error) {
	publishFirst := false
	var discoJSONCfg []DiscoEntry

	for i, step := range steps {
		switch step.Action {
		case "load", "local", "remote", "fetch", "_fetch":
			loaded, attrs, docs, err := runLoad(step.Load, baseDir, outputDir, sourceMap, sourceAttrs, sourceXML, rootPipeline, states, opts)
			if err != nil {
				return Result{}, fmt.Errorf("step %d load: %w", i, err)
			}
			current = loaded
			currentAttrs = attrs
			currentXML = docs
			publishFirst = false
		case "select":
			current, currentAttrs, currentXML = runSelect(step.Select, current, currentAttrs, currentXML, sourceMap, sourceAttrs, sourceXML)
			if step.Select.As != "" {
				sourceMap[step.Select.As] = append([]string(nil), current...)
				sourceAttrs[step.Select.As] = cloneAttrs(currentAttrs)
				sourceXML[step.Select.As] = cloneEntityXML(currentXML)
			}
			publishFirst = false
		case "filter":
			current, currentAttrs, currentXML = runFilter(step.Filter, current, currentAttrs, currentXML)
			if step.Filter.As != "" {
				sourceMap[step.Filter.As] = append([]string(nil), current...)
				sourceAttrs[step.Filter.As] = cloneAttrs(currentAttrs)
				sourceXML[step.Filter.As] = cloneEntityXML(currentXML)
			}
			publishFirst = false
		case "pick":
			current, currentAttrs, currentXML = runSelect(step.Pick, current, currentAttrs, currentXML, sourceMap, sourceAttrs, sourceXML)
			publishFirst = false
		case "setattr":
			applyTo := current
			if step.SetAttr.Selector != "" {
				applyTo, _ = collectSelectorEntityIDs(current, currentAttrs, currentXML,
					SelectStep{Selector: step.SetAttr.Selector},
					sourceMap, sourceAttrs, sourceXML)
			}
			currentAttrs = runSetAttr(step.SetAttr, applyTo, currentAttrs)
			syncCurrentAttrsToSources(current, currentAttrs, sourceAttrs)
			publishFirst = false
		case "reginfo":
			applyTo := current
			if step.RegInfo.Selector != "" {
				applyTo, _ = collectSelectorEntityIDs(current, currentAttrs, currentXML,
					SelectStep{Selector: step.RegInfo.Selector},
					sourceMap, sourceAttrs, sourceXML)
			}
			currentAttrs = runRegInfo(step.RegInfo, applyTo, currentAttrs)
			syncCurrentAttrsToSources(current, currentAttrs, sourceAttrs)
			publishFirst = false
		case "pubinfo":
			currentAttrs = runPubInfo(step.PubInfo, current, currentAttrs)
			syncCurrentAttrsToSources(current, currentAttrs, sourceAttrs)
			publishFirst = false
		case "first":
			publishFirst = len(current) == 1
		case "sort":
			current = runSort(step.Sort, current, currentXML)
			publishFirst = false
		case "finalize":
			finalizeCfg = step.Finalize
		case "sign":
			signCfg = step.Sign
		case "verify":
			verifyCfg = step.Verify
		case "publish":
			if err := runPublish(step.Publish, outputDir, current, currentXML, finalizeCfg, signCfg, verifyCfg, publishFirst); err != nil {
				return Result{}, fmt.Errorf("step %d publish: %w", i, err)
			}
		case "stats":
			runStats(current)
		case "info":
			runInfo(current)
		case "check_xml_namespaces":
			// Namespace validation is implicit during XML parsing; accepted as a no-op.
		case "dump", "print":
			runDump(current)
		case "nodecountry":
			currentAttrs = runNodeCountry(current, currentAttrs, currentXML)
			syncCurrentAttrsToSources(current, currentAttrs, sourceAttrs)
		case "certreport":
			runCertReport(current, currentXML)
		case "discojson":
			entries := BuildDiscoEntries(current, currentAttrs, currentXML, "")
			discoJSONCfg = entries
			if err := runDiscoJSON(step.DiscoJSON, outputDir, entries); err != nil {
				return Result{}, fmt.Errorf("step %d discojson: %w", i, err)
			}
		case "discojson_idp":
			entries := BuildDiscoEntries(current, currentAttrs, currentXML, "idp")
			discoJSONCfg = entries
			if err := runDiscoJSON(step.DiscoJSON, outputDir, entries); err != nil {
				return Result{}, fmt.Errorf("step %d discojson_idp: %w", i, err)
			}
		case "discojson_sp":
			entries := BuildDiscoEntries(current, currentAttrs, currentXML, "sp")
			discoJSONCfg = entries
			if err := runDiscoJSON(step.DiscoJSON, outputDir, entries); err != nil {
				return Result{}, fmt.Errorf("step %d discojson_sp: %w", i, err)
			}
		case "xslt":
			newIDs, newAttrs, newXML, err := runXSLT(step.XSLT, baseDir, current, currentXML)
			if err != nil {
				return Result{}, fmt.Errorf("step %d xslt: %w", i, err)
			}
			current = newIDs
			currentAttrs = newAttrs
			currentXML = newXML
			syncCurrentAttrsToSources(current, currentAttrs, sourceAttrs)
			publishFirst = false
		case "when":
			// Evaluate the condition against active states, matching pyFF's
			// req.state.get(condition) semantics.
			cond := step.When.Condition
			match := states[cond]
			if match && len(step.When.Values) > 0 {
				// Multi-word condition (e.g. "accept application/json"):
				// require the state value to match one of the specified values.
				// In batch mode these conditions never carry values, so this
				// branch is effectively unreachable in normal operation.
				match = false
				for _, v := range step.When.Values {
					if states[v] || states[cond+":"+v] {
						match = true
						break
					}
				}
			}
			if match {
				// Execute the body inline: pass the same sourceMap/sourceAttrs/
				// sourceXML maps (not clones) so that aliases registered inside
				// the body are visible to subsequent outer steps, matching
				// pyFF's iprocess(req) semantics where req is shared.
				sub, err := executeSteps(
					step.When.Body, outputDir, baseDir,
					sourceMap, sourceAttrs, sourceXML,
					current, currentAttrs, currentXML,
					finalizeCfg, signCfg, verifyCfg,
					rootPipeline, states, opts,
				)
				if err != nil && err != errBreak {
					return Result{}, fmt.Errorf("step %d when %q: %w", i, cond, err)
				}
				current = sub.Entities
				currentAttrs = sub.Attrs
				if currentAttrs == nil {
					currentAttrs = make(map[string]EntityAttributes)
				}
				currentXML = sub.EntityXML
				if currentXML == nil {
					currentXML = make(map[string]string)
				}
				finalizeCfg = sub.Finalize
				signCfg = sub.Sign
				verifyCfg = sub.Verify
				if sub.DiscoJSON != nil {
					discoJSONCfg = sub.DiscoJSON
				}
				publishFirst = false
				if err == errBreak {
					// break inside a when body stops the outer pipeline too,
					// matching pyFF's req.done propagation.
					return Result{
						Entities:  append([]string(nil), current...),
						EntityXML: cloneEntityXML(currentXML),
						Attrs:     cloneAttrs(currentAttrs),
						Finalize:  finalizeCfg,
						Sign:      signCfg,
						Verify:    verifyCfg,
						DiscoJSON: discoJSONCfg,
					}, errBreak
				}
			}
			publishFirst = false
		case "emit":
			// Request-side action: silently ignored in batch execution.
			// In pyFF `emit` writes the current entity set as the HTTP response body.
			// The goFF MDQ server handles content negotiation automatically.
			if opts.Progress != nil {
				opts.Progress(i, "emit", "INFO: emit is a no-op in goFF server mode (content negotiation is built-in)")
			}
		case "signcerts":
			// signcerts is not supported in goFF — it is a certificate-signing
			// workflow tool with no equivalent.  Warn so operators are aware.
			if opts.Progress != nil {
				opts.Progress(i, "signcerts", "WARNING: signcerts is not supported; step skipped")
			}
		case "merge":
			// merge would propagate a fork branch's results back to the outer
			// pipeline state; goFF's fork model does not support this.  Warn.
			if opts.Progress != nil {
				opts.Progress(i, "merge", "WARNING: merge is not supported in goFF; fork results remain isolated")
			}
		case "drop_xsi_type":
			// Remove xsi:type attributes from all entity XML bodies in the
			// current working set.  pyFF uses this before signing to strip
			// annotations that some validators reject.
			for _, entityID := range current {
				xmlBody, ok := currentXML[entityID]
				if !ok || strings.TrimSpace(xmlBody) == "" {
					continue
				}
				cleaned, err := dropXSIType([]byte(xmlBody))
				if err != nil {
					// Non-fatal: log and leave original XML intact.
					continue
				}
				currentXML[entityID] = string(cleaned)
			}
		case "log_entity":
		case "map":
			// pyFF per-entity iteration loop: run the sub-pipeline once per entity
			// in the current working set, each time with a single-entity snapshot.
			// Side effects (e.g. publish, sign) execute per-entity; the outer
			// entity set is unchanged after all iterations complete.
			for _, entityID := range current {
				entityAttrs := make(map[string]EntityAttributes)
				if a, ok := currentAttrs[entityID]; ok {
					entityAttrs[entityID] = a
				}
				entityXML := make(map[string]string)
				if x, ok := currentXML[entityID]; ok {
					entityXML[entityID] = x
				}
				_, err := executeSteps(
					step.Fork.Pipeline, outputDir, baseDir,
					cloneSourceMap(sourceMap),
					cloneSourceAttrsMap(sourceAttrs),
					cloneSourceXMLMap(sourceXML),
					[]string{entityID},
					entityAttrs,
					entityXML,
					finalizeCfg, signCfg, verifyCfg,
					rootPipeline, states,
					opts,
				)
				if err != nil && err != errBreak {
					return Result{}, fmt.Errorf("step %d map entity %q: %w", i, entityID, err)
				}
			}
		case "store":
			// pyFF store: directory: — equivalent to publish:{dir:} (GAP-13).
			if step.Store.Directory != "" {
				pub := PublishStep{Dir: step.Store.Directory}
				if err := runPublish(pub, outputDir, current, currentXML, finalizeCfg, signCfg, verifyCfg, publishFirst); err != nil {
					return Result{}, fmt.Errorf("step %d store: %w", i, err)
				}
			}
		case "then":
			// pyFF `then <label>:` — re-run the root pipeline from the top with
			// states={label:true} and the current entity set as input (GAP-14).
			// This is the in-pipeline equivalent of load's `via` option.
			label := step.Then
			if label != "" {
				thenStates := map[string]bool{label: true}
				sub, err := executeSteps(
					rootPipeline, outputDir, baseDir,
					cloneSourceMap(sourceMap),
					cloneSourceAttrsMap(sourceAttrs),
					cloneSourceXMLMap(sourceXML),
					append([]string(nil), current...),
					cloneAttrs(currentAttrs),
					cloneEntityXML(currentXML),
					finalizeCfg, signCfg, verifyCfg,
					rootPipeline, thenStates, opts,
				)
				if err != nil && err != errBreak {
					return Result{}, fmt.Errorf("step %d then %q: %w", i, label, err)
				}
				current = sub.Entities
				currentAttrs = sub.Attrs
				if currentAttrs == nil {
					currentAttrs = make(map[string]EntityAttributes)
				}
				currentXML = sub.EntityXML
				if currentXML == nil {
					currentXML = make(map[string]string)
				}
				finalizeCfg = sub.Finalize
				signCfg = sub.Sign
				verifyCfg = sub.Verify
				if sub.DiscoJSON != nil {
					discoJSONCfg = sub.DiscoJSON
				}
			}
			publishFirst = false
		case "fork", "pipe", "parsecopy":
			// Run sub-pipeline on a snapshot of current state; outer state is unchanged.
			_, err := executeSteps(
				step.Fork.Pipeline, outputDir, baseDir,
				cloneSourceMap(sourceMap),
				cloneSourceAttrsMap(sourceAttrs),
				cloneSourceXMLMap(sourceXML),
				append([]string(nil), current...),
				cloneAttrs(currentAttrs),
				cloneEntityXML(currentXML),
				finalizeCfg, signCfg, verifyCfg,
				rootPipeline, states,
				opts,
			)
			if err != nil && err != errBreak {
				return Result{}, fmt.Errorf("step %d fork: %w", i, err)
			}
		case "break", "end":
			// Return current state as a successful result via errBreak sentinel.
			// errBreak propagates outward through when-body executions (matching
			// pyFF's req.done flag) and is stripped to nil by Execute.
			return Result{
				Entities:  append([]string(nil), current...),
				EntityXML: cloneEntityXML(currentXML),
				Attrs:     cloneAttrs(currentAttrs),
				Finalize:  finalizeCfg,
				Sign:      signCfg,
				Verify:    verifyCfg,
				DiscoJSON: discoJSONCfg,
			}, errBreak
		default:
			return Result{}, fmt.Errorf("step %d: unsupported action %q", i, step.Action)
		}

		if opts.Progress != nil {
			opts.Progress(i, step.Action, fmt.Sprintf("entities=%d", len(current)))
		}
	}

	return Result{
		Entities:  append([]string(nil), current...),
		EntityXML: cloneEntityXML(currentXML),
		Attrs:     cloneAttrs(currentAttrs),
		Finalize:  finalizeCfg,
		Sign:      signCfg,
		Verify:    verifyCfg,
		DiscoJSON: discoJSONCfg,
	}, nil
}

func runFilter(cfg SelectStep, current []string, currentAttrs map[string]EntityAttributes, currentXML map[string]string) ([]string, map[string]EntityAttributes, map[string]string) {
	localSourceMap := map[string][]string{"_current": append([]string(nil), current...)}
	localSourceAttrs := map[string]map[string]EntityAttributes{"_current": cloneAttrs(currentAttrs)}
	localSourceXML := map[string]map[string]string{"_current": cloneEntityXML(currentXML)}
	return runSelect(cfg, current, currentAttrs, currentXML, localSourceMap, localSourceAttrs, localSourceXML)
}

func runLoad(cfg LoadStep, baseDir string, outputDir string, sourceMap map[string][]string, sourceAttrs map[string]map[string]EntityAttributes, sourceXML map[string]map[string]string, rootPipeline []Step, states map[string]bool, opts ExecuteOptions) ([]string, map[string]EntityAttributes, map[string]string, error) {
	applyVia := func(ids []string, attrs map[string]EntityAttributes, docs map[string]string) ([]string, map[string]EntityAttributes, map[string]string, error) {
		if len(cfg.Via) == 0 {
			return ids, attrs, docs, nil
		}

		allowed := make(map[string]struct{})
		for _, viaAlias := range cfg.Via {
			viaIDs, ok := sourceMap[viaAlias]
			if !ok {
				return nil, nil, nil, fmt.Errorf("unknown load.via alias %q", viaAlias)
			}
			for _, id := range viaIDs {
				allowed[id] = struct{}{}
			}
		}

		filtered := make([]string, 0, len(ids))
		for _, id := range ids {
			if _, ok := allowed[id]; ok {
				filtered = append(filtered, id)
			}
		}

		return filtered, copyForIDs(filtered, attrs), copyXMLForIDs(filtered, docs), nil
	}

	// Inline entity IDs (no real metadata loading needed).
	if len(cfg.Entities) > 0 {
		attrs := make(map[string]EntityAttributes, len(cfg.Entities))
		for _, id := range cfg.Entities {
			a := EntityAttributes{Roles: map[string]struct{}{}, Categories: map[string]struct{}{}, TextTokens: map[string]struct{}{}, IPHints: map[string]struct{}{}}
			a.AddTextToken(id)
			attrs[id] = a
		}
		return applyVia(append([]string(nil), cfg.Entities...), attrs, map[string]string{})
	}

	// Files/URLs/Sources: separate real file paths from in-pipeline alias references.
	if len(cfg.Files) > 0 || len(cfg.URLs) > 0 || len(cfg.Sources) > 0 {
		allIDs := make([]string, 0)
		allAttrs := make(map[string]EntityAttributes)
		allDocs := make(map[string]string)

		merge := func(data sourceData) {
			for _, id := range data.EntityIDs {
				if _, seen := allAttrs[id]; !seen {
					allIDs = append(allIDs, id)
				}
				allAttrs[id] = data.Attributes[id]
				if x, ok := data.EntityXML[id]; ok {
					allDocs[id] = x
				}
			}
		}

		var realFiles []string
		for _, f := range cfg.Files {
			// A path starting with "/" that is found in the alias map is an
			// in-pipeline alias, not a filesystem path.
			if strings.HasPrefix(f, "/") {
				if ids, ok := sourceMap[f]; ok {
					merge(sourceData{
						EntityIDs:  ids,
						Attributes: sourceAttrs[f],
						EntityXML:  sourceXML[f],
					})
					continue
				}
			}
			realFiles = append(realFiles, f)
		}

		if len(realFiles) > 0 || len(cfg.URLs) > 0 {
			src := resolveSourcePaths(Source{
				ID:                "_load",
				Files:             realFiles,
				URLs:              cfg.URLs,
				Verify:            cfg.Verify,
				Timeout:           cfg.Timeout,
				Retries:           cfg.Retries,
				Cleanup:           cfg.Cleanup,
				AllowPrivateAddrs: cfg.AllowPrivateAddrs,
			}, baseDir)
			data, err := loadSourceData(src)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("load: %w", err)
			}
			merge(data)
		}

		// Process SourceEntry items (per-source aliases, per-source verify) (GAP-2, GAP-3).
		for _, entry := range cfg.Sources {
			var entryFiles, entryURLs []string
			if entry.URL != "" {
				entryURLs = []string{entry.URL}
			} else if entry.File != "" {
				entryFiles = []string{entry.File}
			} else {
				continue
			}
			verify := entry.Verify
			if verify == "" {
				verify = cfg.Verify
			}
			cleanup := entry.Cleanup || cfg.Cleanup
			entrySrc := resolveSourcePaths(Source{
				ID:                "_load_entry",
				Files:             entryFiles,
				URLs:              entryURLs,
				Verify:            verify,
				Timeout:           cfg.Timeout,
				Retries:           cfg.Retries,
				Cleanup:           cleanup,
				AllowPrivateAddrs: cfg.AllowPrivateAddrs,
			}, baseDir)
			entryData, err := loadSourceData(entrySrc)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("load source entry: %w", err)
			}

			// Apply via preprocessing if specified (GAP-12 / pyFF semantics):
			// re-run the full root pipeline with state={viaLabel:true} and
			// the freshly-loaded entities as the starting entity set.
			// This matches pyFF's PipelineCallback which re-runs Plumbing.process
			// with state={entry_point:True} and t=parsed-tree.
			if entry.Via != "" {
				viaLabel := strings.ToLower(strings.TrimSpace(entry.Via))
				viaStates := map[string]bool{viaLabel: true}
				viaResult, berr := executeSteps(
					rootPipeline, outputDir, baseDir,
					make(map[string][]string),
					make(map[string]map[string]EntityAttributes),
					make(map[string]map[string]string),
					entryData.EntityIDs,
					entryData.Attributes,
					entryData.EntityXML,
					FinalizeStep{}, SignStep{}, VerifyStep{},
					rootPipeline, viaStates, opts,
				)
				if berr != nil && berr != errBreak {
					return nil, nil, nil, fmt.Errorf("via %q: %w", entry.Via, berr)
				}
				resultAttrs := viaResult.Attrs
				if resultAttrs == nil {
					resultAttrs = make(map[string]EntityAttributes)
				}
				entryData = sourceData{
					EntityIDs:  viaResult.Entities,
					Attributes: resultAttrs,
					EntityXML:  viaResult.EntityXML,
				}
			}

			merge(entryData)
			if entry.As != "" {
				sourceMap[entry.As] = append([]string(nil), entryData.EntityIDs...)
				sourceAttrs[entry.As] = cloneAttrs(entryData.Attributes)
				sourceXML[entry.As] = cloneEntityXML(entryData.EntityXML)
			}
		}

		ids, attrs, docs, err := applyVia(allIDs, allAttrs, allDocs)
		if err != nil {
			return nil, nil, nil, err
		}
		// load: from: <alias> — register the loaded set as a named source alias
		// so it can be referenced by subsequent pipeline steps (pyFF compat).
		if cfg.From != "" {
			sourceMap[cfg.From] = append([]string(nil), ids...)
			sourceAttrs[cfg.From] = cloneAttrs(attrs)
			sourceXML[cfg.From] = cloneEntityXML(docs)
		}
		return ids, attrs, docs, nil
	}

	return nil, nil, nil, fmt.Errorf("load: specify files, urls, sources, or entities")
}

func runSelect(cfg SelectStep, current []string, currentAttrs map[string]EntityAttributes, currentXML map[string]string, sourceMap map[string][]string, sourceAttrs map[string]map[string]EntityAttributes, sourceXML map[string]map[string]string) ([]string, map[string]EntityAttributes, map[string]string) {
	if len(cfg.Entities) == 0 && cfg.Selector == "" && len(cfg.Selectors) == 0 && cfg.Role == "" && len(cfg.Roles) == 0 && cfg.EntityCategory == "" && len(cfg.EntityCategories) == 0 && cfg.RegistrationAuthority == "" && strings.TrimSpace(cfg.Match) == "" {
		allAttrs := mergeRepositoryAttrs(currentAttrs, sourceAttrs)
		allXML := mergeRepositoryXML(currentXML, sourceXML)
		allIDs := repositoryEntityIDs(sourceMap, current)
		if len(allIDs) == 0 {
			return current, currentAttrs, currentXML
		}
		return allIDs, copyForIDs(allIDs, allAttrs), copyXMLForIDs(allIDs, allXML)
	}

	selectedAttrs := make(map[string]EntityAttributes)
	selectedXML := make(map[string]string)

	requiredRoles := collectRequiredRoles(cfg)
	requiredCategories := collectRequiredCategories(cfg)
	selectorIDs, selectorSpecified := collectSelectorEntityIDs(current, currentAttrs, currentXML, cfg, sourceMap, sourceAttrs, sourceXML)
	domainIDs := append([]string(nil), current...)
	if selectorSpecified {
		if len(selectorIDs) == 0 {
			return []string{}, map[string]EntityAttributes{}, map[string]string{}
		}
		domainIDs = append([]string(nil), selectorIDs...)
	}
	regAuthority := normalizeString(cfg.RegistrationAuthority)
	allAttrs := mergeRepositoryAttrs(currentAttrs, sourceAttrs)
	allXML := mergeRepositoryXML(currentXML, sourceXML)

	matchMode := strings.ToLower(strings.TrimSpace(cfg.Match))
	query := ""
	if matchMode != "" && matchMode != "any" && matchMode != "all" {
		query = cfg.Match
		matchMode = "any"
	}
	if matchMode == "" {
		matchMode = "any"
	}

	selected := make([]string, 0, len(domainIDs))
	for _, entityID := range domainIDs {
		attr, ok := allAttrs[entityID]
		if !ok {
			if len(requiredRoles) == 0 && len(requiredCategories) == 0 && regAuthority == "" {
				selected = append(selected, entityID)
				if doc, exists := allXML[entityID]; exists {
					selectedXML[entityID] = doc
				}
			}
			continue
		}

		if !rolesMatch(attr, requiredRoles, matchMode) {
			continue
		}
		if !categoriesMatch(attr, requiredCategories, matchMode) {
			continue
		}
		if regAuthority != "" && normalizeString(attr.RegistrationAuthority) != regAuthority {
			continue
		}
		if query != "" && !matchQuery(attr, entityID, query) {
			continue
		}

		selected = append(selected, entityID)
		selectedAttrs[entityID] = attr
		if doc, ok := allXML[entityID]; ok {
			selectedXML[entityID] = doc
		}
	}

	if cfg.Dedup != nil && !*cfg.Dedup {
		return selected, selectedAttrs, selectedXML
	}
	selected = normalizeEntityIDs(selected)
	selectedAttrs = copyForIDs(selected, selectedAttrs)
	selectedXML = copyXMLForIDs(selected, selectedXML)
	return selected, selectedAttrs, selectedXML
}

func collectSelectorEntityIDs(current []string, currentAttrs map[string]EntityAttributes, currentXML map[string]string, cfg SelectStep, sourceMap map[string][]string, sourceAttrs map[string]map[string]EntityAttributes, sourceXML map[string]map[string]string) ([]string, bool) {
	selectors := make([]string, 0, len(cfg.Entities)+len(cfg.Selectors)+1)
	selectors = append(selectors, cfg.Entities...)
	if cfg.Selector != "" {
		selectors = append(selectors, cfg.Selector)
	}
	selectors = append(selectors, cfg.Selectors...)
	if len(selectors) == 0 {
		return nil, false
	}

	selected := make([]string, 0)
	for _, raw := range selectors {
		sel := strings.TrimSpace(raw)
		if sel == "" {
			continue
		}

		if ids, ok := evaluateSelectorMember(sel, current, currentAttrs, currentXML, sourceMap, sourceAttrs, sourceXML); ok {
			selected = append(selected, ids...)
			continue
		}
		if repositoryHasEntityID(sel, sourceMap, current) {
			selected = append(selected, sel)
		}
	}

	if cfg.Dedup != nil && !*cfg.Dedup {
		return selected, true
	}
	return normalizeEntityIDs(selected), true
}

func evaluateSelectorMember(member string, current []string, currentAttrs map[string]EntityAttributes, currentXML map[string]string, sourceMap map[string][]string, sourceAttrs map[string]map[string]EntityAttributes, sourceXML map[string]map[string]string) ([]string, bool) {
	member = strings.TrimSpace(member)
	if member == "" {
		return nil, false
	}

	parts := splitSelectorIntersection(member)
	if len(parts) > 1 {
		var out []string
		for i, part := range parts {
			ids, ok := evaluateSingleSelector(strings.TrimSpace(part), current, currentAttrs, currentXML, sourceMap, sourceAttrs, sourceXML)
			if !ok {
				return nil, false
			}
			if i == 0 {
				out = normalizeEntityIDs(ids)
				continue
			}
			out = intersectIfNeeded(out, normalizeEntityIDs(ids))
		}
		return out, true
	}

	return evaluateSingleSelector(member, current, currentAttrs, currentXML, sourceMap, sourceAttrs, sourceXML)
}

func evaluateSingleSelector(sel string, current []string, currentAttrs map[string]EntityAttributes, currentXML map[string]string, sourceMap map[string][]string, sourceAttrs map[string]map[string]EntityAttributes, sourceXML map[string]map[string]string) ([]string, bool) {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return nil, false
	}

	if src, xp, ok := splitSourceXPath(sel); ok {
		baseIDs, baseDocs, _ := resolveRepositorySource(src, current, currentAttrs, currentXML, sourceMap, sourceAttrs, sourceXML)
		if len(baseIDs) == 0 {
			return []string{}, true
		}
		return evaluateXPath(xp, baseIDs, baseDocs), true
	}

	if strings.HasPrefix(sel, "//") {
		return evaluateXPath(sel, current, currentXML), true
	}

	if ids, ok := sourceMap[sel]; ok {
		return append([]string(nil), ids...), true
	}

	if ids := evaluateAttributeSelector(sel, current, currentAttrs, sourceMap, sourceAttrs); ids != nil {
		return ids, true
	}

	if strings.Contains(sel, "://") {
		if ids, ok := evaluateSelectorURI(sel, current, currentAttrs, currentXML, sourceMap, sourceAttrs, sourceXML); ok {
			return ids, true
		}
		if repositoryHasEntityID(sel, sourceMap, current) {
			return []string{sel}, true
		}
		return []string{}, true
	}

	return nil, false
}

func splitSelectorIntersection(member string) []string {
	parts := make([]string, 0)
	buf := strings.Builder{}
	inQuote := byte(0)
	for i := 0; i < len(member); i++ {
		c := member[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			buf.WriteByte(c)
			continue
		}
		if c == '\'' || c == '"' {
			inQuote = c
			buf.WriteByte(c)
			continue
		}
		if c == '+' {
			parts = append(parts, buf.String())
			buf.Reset()
			continue
		}
		buf.WriteByte(c)
	}
	parts = append(parts, buf.String())
	return parts
}

func splitSourceXPath(sel string) (string, string, bool) {
	parts := strings.SplitN(sel, "!", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	src := strings.TrimSpace(parts[0])
	xp := strings.TrimSpace(parts[1])
	if xp == "" {
		return "", "", false
	}
	return src, xp, true
}

func resolveRepositorySource(src string, current []string, currentAttrs map[string]EntityAttributes, currentXML map[string]string, sourceMap map[string][]string, sourceAttrs map[string]map[string]EntityAttributes, sourceXML map[string]map[string]string) ([]string, map[string]string, map[string]EntityAttributes) {
	if src == "" {
		return append([]string(nil), current...), cloneEntityXML(currentXML), cloneAttrs(currentAttrs)
	}

	ids, ok := sourceMap[src]
	if !ok {
		return nil, nil, nil
	}
	return append([]string(nil), ids...), cloneEntityXML(sourceXML[src]), cloneAttrs(sourceAttrs[src])
}

// samlNS maps the standard SAML metadata namespace prefixes to their URIs
// for use with antchfx/xpath CompileWithNS.
var samlNS = map[string]string{
	"md":     "urn:oasis:names:tc:SAML:2.0:metadata",
	"saml":   "urn:oasis:names:tc:SAML:2.0:assertion",
	"mdrpi":  "urn:oasis:names:tc:SAML:metadata:rpi",
	"mdattr": "urn:oasis:names:tc:SAML:metadata:attribute",
	"mdui":   "urn:oasis:names:tc:SAML:metadata:ui",
	"ds":     "http://www.w3.org/2000/09/xmldsig#",
}

// samlNSOpen / samlNSClose wrap XML fragments that may lack namespace
// declarations (e.g. per-entity XML extracted from a parent EntitiesDescriptor)
// so that xmlquery can resolve all common SAML namespace prefixes.
const samlNSOpen = `<md:EntitiesDescriptor` +
	` xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"` +
	` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
	` xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi"` +
	` xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"` +
	` xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"` +
	` xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`
const samlNSClose = `</md:EntitiesDescriptor>`

func evaluateXPath(xpathExpr string, baseIDs []string, docs map[string]string) []string {
	var buf strings.Builder
	buf.WriteString(samlNSOpen)
	for _, id := range baseIDs {
		if xmlBody, ok := docs[id]; ok && strings.TrimSpace(xmlBody) != "" {
			buf.WriteString(xmlBody)
		} else {
			fmt.Fprintf(&buf, `<md:EntityDescriptor entityID=%q/>`, id)
		}
	}
	buf.WriteString(samlNSClose)

	expr, err := xpath.CompileWithNS(xpathExpr, samlNS)
	if err != nil {
		return []string{}
	}
	root, err := xmlquery.Parse(strings.NewReader(buf.String()))
	if err != nil {
		return []string{}
	}
	nodes := xmlquery.QuerySelectorAll(root, expr)
	ids := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if id := n.SelectAttr("entityID"); id != "" {
			ids = append(ids, id)
		}
	}
	return normalizeEntityIDs(ids)
}

func evaluateAttributeSelector(sel string, current []string, currentAttrs map[string]EntityAttributes, sourceMap map[string][]string, sourceAttrs map[string]map[string]EntityAttributes) []string {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return nil
	}

	name := ""
	value := ""
	if strings.Contains(sel, "=") {
		parts := strings.SplitN(sel, "=", 2)
		if len(parts) != 2 {
			return nil
		}
		name = normalizeString(parts[0])
		value = strings.TrimSpace(parts[1])
	} else if strings.HasPrefix(sel, "{") {
		end := strings.Index(sel, "}")
		if end <= 1 || end >= len(sel)-1 {
			return nil
		}
		name = normalizeString(sel[1:end])
		value = strings.TrimSpace(sel[end+1:])
	} else {
		return nil
	}

	if name == "" || value == "" {
		return nil
	}

	ids := append([]string(nil), current...)
	attrs := currentAttrs
	if len(ids) == 0 {
		for _, sourceIDs := range sourceMap {
			ids = append(ids, sourceIDs...)
		}
		ids = normalizeEntityIDs(ids)
		attrs = make(map[string]EntityAttributes)
		for _, srcAttrs := range sourceAttrs {
			for id, a := range srcAttrs {
				attrs[id] = a
			}
		}
	}

	out := make([]string, 0)
	for _, id := range ids {
		a, ok := attrs[id]
		if !ok {
			continue
		}

		switch name {
		case "registrationauthority", "{urn:oasis:names:tc:saml:metadata:rpi}registrationauthority":
			if normalizeString(a.RegistrationAuthority) == normalizeString(value) {
				out = append(out, id)
			}
		case "entity-category", "http://macedir.org/entity-category", "{http://macedir.org/entity-category}entity-category":
			if a.HasCategory(value) {
				out = append(out, id)
			}
		}
	}

	return normalizeEntityIDs(out)
}

func evaluateSelectorURI(uri string, current []string, currentAttrs map[string]EntityAttributes, currentXML map[string]string, sourceMap map[string][]string, sourceAttrs map[string]map[string]EntityAttributes, sourceXML map[string]map[string]string) ([]string, bool) {
	// Selector URLs are operator-controlled pipeline configuration, so the
	// private-address SSRF blocklist is bypassed here.
	b, err := fetchURL(Source{AllowPrivateAddrs: true}, uri)
	if err != nil {
		return nil, false
	}

	members := parseSelectorList(string(b))
	if len(members) == 0 {
		return []string{}, true
	}

	out := make([]string, 0)
	for _, member := range members {
		ids, ok := evaluateSelectorMember(member, current, currentAttrs, currentXML, sourceMap, sourceAttrs, sourceXML)
		if !ok {
			out = append(out, member)
			continue
		}
		out = append(out, ids...)
	}

	return normalizeEntityIDs(out), true
}

func parseSelectorList(s string) []string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func repositoryEntityIDs(sourceMap map[string][]string, current []string) []string {
	ids := append([]string(nil), current...)
	for _, srcIDs := range sourceMap {
		ids = append(ids, srcIDs...)
	}
	return normalizeEntityIDs(ids)
}

func repositoryHasEntityID(entityID string, sourceMap map[string][]string, current []string) bool {
	if entityID == "" {
		return false
	}
	if slices.Contains(current, entityID) {
		return true
	}
	for _, ids := range sourceMap {
		if slices.Contains(ids, entityID) {
			return true
		}
	}
	return false
}

func runSort(cfg SortStep, current []string, docs map[string]string) []string {
	if len(current) <= 1 {
		return append([]string(nil), current...)
	}

	if strings.TrimSpace(cfg.OrderBy) == "" {
		out := append([]string(nil), current...)
		slices.Sort(out)
		return out
	}

	type keyed struct {
		id  string
		key string
	}
	items := make([]keyed, 0, len(current))
	for _, id := range current {
		items = append(items, keyed{id: id, key: xpathValueForEntity(cfg.OrderBy, id, docs[id])})
	}

	slices.SortFunc(items, func(a, b keyed) int {
		ak := a.key == ""
		bk := b.key == ""
		if ak != bk {
			if ak {
				return 1
			}
			return -1
		}
		if a.key == b.key {
			if a.id < b.id {
				return -1
			}
			if a.id > b.id {
				return 1
			}
			return 0
		}
		if a.key < b.key {
			return -1
		}
		return 1
	})

	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.id)
	}
	return out
}

func xpathValueForEntity(orderBy string, entityID string, xmlBody string) string {
	if strings.TrimSpace(orderBy) == "" || strings.TrimSpace(xmlBody) == "" {
		return ""
	}
	if strings.TrimSpace(orderBy) == "@entityID" {
		return entityID
	}
	expr, err := xpath.CompileWithNS(orderBy, samlNS)
	if err != nil {
		return ""
	}
	var wrapped strings.Builder
	wrapped.WriteString(samlNSOpen)
	wrapped.WriteString(xmlBody)
	wrapped.WriteString(samlNSClose)
	root, err := xmlquery.Parse(strings.NewReader(wrapped.String()))
	if err != nil {
		return ""
	}
	n := xmlquery.QuerySelector(root, expr)
	if n == nil {
		return ""
	}
	if text := strings.TrimSpace(n.InnerText()); text != "" {
		return text
	}
	return strings.TrimSpace(n.SelectAttr("entityID"))
}

func intersectIfNeeded(primary []string, secondary []string) []string {
	if len(primary) == 0 {
		return secondary
	}
	if len(secondary) == 0 {
		return primary
	}
	out := make([]string, 0)
	for _, v := range primary {
		if slices.Contains(secondary, v) {
			out = append(out, v)
		}
	}
	return out
}

func copyForIDs(ids []string, attrs map[string]EntityAttributes) map[string]EntityAttributes {
	out := make(map[string]EntityAttributes, len(ids))
	for _, id := range ids {
		if a, ok := attrs[id]; ok {
			out[id] = a
		}
	}
	return out
}

func copyXMLForIDs(ids []string, docs map[string]string) map[string]string {
	out := make(map[string]string, len(ids))
	for _, id := range ids {
		if d, ok := docs[id]; ok {
			out[id] = d
		}
	}
	return out
}

func collectRequiredRoles(cfg SelectStep) []string {
	roles := make([]string, 0, len(cfg.Roles)+1)
	if cfg.Role != "" {
		roles = append(roles, normalizeRole(cfg.Role))
	}
	for _, r := range cfg.Roles {
		if nr := normalizeRole(r); nr != "" {
			roles = append(roles, nr)
		}
	}
	return normalizeEntityIDs(roles)
}

func rolesMatch(attr EntityAttributes, required []string, matchMode string) bool {
	if len(required) == 0 {
		return true
	}

	switch matchMode {
	case "all":
		for _, role := range required {
			if !attr.HasRole(role) {
				return false
			}
		}
		return true
	default:
		for _, role := range required {
			if attr.HasRole(role) {
				return true
			}
		}
		return false
	}
}

func collectRequiredCategories(cfg SelectStep) []string {
	cats := make([]string, 0, len(cfg.EntityCategories)+1)
	if c := normalizeString(cfg.EntityCategory); c != "" {
		cats = append(cats, c)
	}
	for _, c := range cfg.EntityCategories {
		if nc := normalizeString(c); nc != "" {
			cats = append(cats, nc)
		}
	}
	return normalizeEntityIDs(cats)
}

func categoriesMatch(attr EntityAttributes, required []string, matchMode string) bool {
	if len(required) == 0 {
		return true
	}

	switch matchMode {
	case "all":
		for _, cat := range required {
			if !attr.HasCategory(cat) {
				return false
			}
		}
		return true
	default:
		for _, cat := range required {
			if attr.HasCategory(cat) {
				return true
			}
		}
		return false
	}
}

func normalizeString(v string) string {
	return strings.TrimSpace(strings.ToLower(v))
}

func runSetAttr(cfg SetAttrStep, current []string, currentAttrs map[string]EntityAttributes) map[string]EntityAttributes {
	name := normalizeString(cfg.Name)
	values := make([]string, 0, len(cfg.Values)+1)
	if strings.TrimSpace(cfg.Value) != "" {
		values = append(values, cfg.Value)
	}
	for _, v := range cfg.Values {
		if strings.TrimSpace(v) != "" {
			values = append(values, v)
		}
	}

	if name == "" || len(values) == 0 {
		return cloneAttrs(currentAttrs)
	}

	updated := cloneAttrs(currentAttrs)
	for _, entityID := range current {
		a := updated[entityID]
		if a.Roles == nil {
			a.Roles = map[string]struct{}{}
		}
		if a.Categories == nil {
			a.Categories = map[string]struct{}{}
		}
		if a.TextTokens == nil {
			a.TextTokens = map[string]struct{}{}
		}
		if a.IPHints == nil {
			a.IPHints = map[string]struct{}{}
		}

		switch name {
		case "entity_category", "entity_categories", "http://macedir.org/entity-category", "{http://macedir.org/entity-category}entity-category":
			for _, v := range values {
				a.AddCategory(v)
				a.AddTextToken("entity_category:" + v)
			}
		case "registration_authority", "registrationauthority", "{urn:oasis:names:tc:saml:metadata:rpi}registrationauthority":
			a.RegistrationAuthority = values[0]
			a.AddTextToken("registration_authority:" + values[0])
		case "role", "roles":
			for _, v := range values {
				a.AddRole(v)
				a.AddTextToken("role:" + v)
			}
		default:
			for _, v := range values {
				a.AddTextToken(v)
				if name != "" {
					a.AddTextToken(name + ":" + v)
				}
			}
		}

		updated[entityID] = a
	}

	return updated
}

func runRegInfo(cfg RegInfoStep, current []string, currentAttrs map[string]EntityAttributes) map[string]EntityAttributes {
	authority := strings.TrimSpace(cfg.Authority)
	if authority == "" {
		authority = strings.TrimSpace(cfg.RegistrationAuthority)
	}

	policyValues := make([]string, 0, len(cfg.Policies)+1)
	if v := strings.TrimSpace(cfg.Policy); v != "" {
		policyValues = append(policyValues, v)
	}
	for _, p := range cfg.Policies {
		if v := strings.TrimSpace(p); v != "" {
			policyValues = append(policyValues, v)
		}
	}

	if authority == "" && len(policyValues) == 0 {
		return cloneAttrs(currentAttrs)
	}

	updated := cloneAttrs(currentAttrs)
	if authority != "" {
		updated = runSetAttr(
			SetAttrStep{Name: "registration_authority", Value: authority},
			current,
			updated,
		)
		updated = runSetAttr(
			SetAttrStep{Name: "reginfo", Values: []string{authority, "registration_authority:" + authority}},
			current,
			updated,
		)
	}

	if len(policyValues) > 0 {
		tokens := make([]string, 0, len(policyValues)*2)
		for _, v := range policyValues {
			tokens = append(tokens, v)
			tokens = append(tokens, "policy:"+v)
		}
		updated = runSetAttr(
			SetAttrStep{Name: "reginfo_policy", Values: tokens},
			current,
			updated,
		)
	}

	return updated
}

func runPubInfo(cfg PubInfoStep, current []string, currentAttrs map[string]EntityAttributes) map[string]EntityAttributes {
	values := make([]string, 0, len(cfg.Values)+len(cfg.URLs)+8)
	if strings.TrimSpace(cfg.Publisher) != "" {
		publisher := strings.TrimSpace(cfg.Publisher)
		values = append(values, publisher)
		values = append(values, "publisher:"+publisher)
	}
	if strings.TrimSpace(cfg.Value) != "" {
		v := strings.TrimSpace(cfg.Value)
		values = append(values, v)
		values = append(values, "value:"+v)
	}
	for _, v := range cfg.Values {
		if strings.TrimSpace(v) != "" {
			vv := strings.TrimSpace(v)
			values = append(values, vv)
			values = append(values, "value:"+vv)
		}
	}
	if strings.TrimSpace(cfg.URL) != "" {
		u := strings.TrimSpace(cfg.URL)
		values = append(values, u)
		values = append(values, "url:"+u)
	}
	for _, u := range cfg.URLs {
		if strings.TrimSpace(u) != "" {
			uu := strings.TrimSpace(u)
			values = append(values, uu)
			values = append(values, "url:"+uu)
		}
	}
	if strings.TrimSpace(cfg.Lang) != "" {
		lang := strings.TrimSpace(cfg.Lang)
		values = append(values, lang)
		values = append(values, "lang:"+lang)
	}

	if len(values) == 0 {
		return cloneAttrs(currentAttrs)
	}

	return runSetAttr(
		SetAttrStep{Name: "pubinfo", Values: values},
		current,
		currentAttrs,
	)
}

func syncCurrentAttrsToSources(current []string, currentAttrs map[string]EntityAttributes, sourceAttrs map[string]map[string]EntityAttributes) {
	for sourceID, attrs := range sourceAttrs {
		updated := cloneAttrs(attrs)
		changed := false
		for _, entityID := range current {
			a, ok := currentAttrs[entityID]
			if !ok {
				continue
			}
			if _, exists := updated[entityID]; exists {
				updated[entityID] = a.Clone()
				changed = true
			}
		}
		if changed {
			sourceAttrs[sourceID] = updated
		}
	}
}

func cloneAttrs(in map[string]EntityAttributes) map[string]EntityAttributes {
	out := make(map[string]EntityAttributes, len(in))
	for id, attr := range in {
		out[id] = attr.Clone()
	}
	return out
}

func cloneEntityXML(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for id, body := range in {
		out[id] = body
	}
	return out
}

func cloneSourceMap(m map[string][]string) map[string][]string {
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func cloneSourceAttrsMap(m map[string]map[string]EntityAttributes) map[string]map[string]EntityAttributes {
	out := make(map[string]map[string]EntityAttributes, len(m))
	for k, v := range m {
		out[k] = cloneAttrs(v)
	}
	return out
}

func cloneSourceXMLMap(m map[string]map[string]string) map[string]map[string]string {
	out := make(map[string]map[string]string, len(m))
	for k, v := range m {
		out[k] = cloneEntityXML(v)
	}
	return out
}

func mergeRepositoryAttrs(current map[string]EntityAttributes, sources map[string]map[string]EntityAttributes) map[string]EntityAttributes {
	out := cloneAttrs(current)
	for _, attrs := range sources {
		for id, attr := range attrs {
			out[id] = attr
		}
	}
	return out
}

func mergeRepositoryXML(current map[string]string, sources map[string]map[string]string) map[string]string {
	out := cloneEntityXML(current)
	for _, docs := range sources {
		for id, doc := range docs {
			out[id] = doc
		}
	}
	return out
}

func resolveSourcePaths(src Source, baseDir string) Source {
	if baseDir == "" {
		return src
	}

	resolved := append([]string(nil), src.Files...)
	for i, p := range resolved {
		if p == "" || filepath.IsAbs(p) {
			continue
		}
		resolved[i] = filepath.Join(baseDir, p)
	}
	src.Files = resolved
	if src.Verify != "" && !filepath.IsAbs(src.Verify) {
		src.Verify = filepath.Join(baseDir, src.Verify)
	}
	return src
}

func runPublish(cfg PublishStep, outputDir string, current []string, currentXML map[string]string, fin FinalizeStep, signCfg SignStep, verifyCfg VerifyStep, first bool) error {
	if cfg.Dir != "" {
		return runPublishDir(cfg, outputDir, current, currentXML)
	}

	outputPath := resolvePublishOutput(cfg)
	if outputPath == "" {
		return fmt.Errorf("publish.output is required")
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	path := filepath.Join(outputDir, outputPath)
	parentDir := filepath.Dir(path)
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		return fmt.Errorf("create publish output directory: %w", err)
	}

	var body []byte
	var err error
	if cfg.Raw {
		// raw: true — bypass finalize/sign and write the aggregate using raw
		// in-memory entity XML.  This preserves the original entity XML bytes
		// (e.g. as fetched from a federation feed) without re-serialisation or
		// crypto annotation, matching pyFF's raw-publish semantics.
		body = BuildEntitiesXML(current, currentXML, AggregateConfig{})
	} else {
		body, err = formatOutput(path, current, currentXML, fin, signCfg, verifyCfg, first)
		if err != nil {
			return err
		}
	}

	if err := os.WriteFile(path, body, 0o644); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}

	if err := runPublishSideEffects(path, outputDir, cfg, body); err != nil {
		return err
	}

	return nil
}

func runPublishSideEffects(path string, outputDir string, cfg PublishStep, body []byte) error {
	hash := sha256.Sum256(body)
	hexHash := fmt.Sprintf("%x", hash[:])
	storedPath := ""

	if cfg.HashLink {
		hashPath := path + ".sha256"
		line := fmt.Sprintf("%s  %s\n", hexHash, filepath.Base(path))
		if err := os.WriteFile(hashPath, []byte(line), 0o644); err != nil {
			return fmt.Errorf("write publish hash link: %w", err)
		}
	}

	if cfg.UpdateStore {
		storeDir := strings.TrimSpace(cfg.StoreDir)
		if storeDir == "" {
			storeDir = filepath.Join(outputDir, ".store")
		} else if !filepath.IsAbs(storeDir) {
			storeDir = filepath.Join(outputDir, storeDir)
		}
		if err := os.MkdirAll(storeDir, 0o755); err != nil {
			return fmt.Errorf("create publish store directory: %w", err)
		}

		ext := filepath.Ext(path)
		storePath := filepath.Join(storeDir, hexHash+ext)
		if err := os.WriteFile(storePath, body, 0o644); err != nil {
			return fmt.Errorf("write publish store file: %w", err)
		}
		storedPath = storePath
	}

	if cfg.HashLink && cfg.UpdateStore && storedPath != "" {
		linkPath := path + ".link"
		rel, err := filepath.Rel(filepath.Dir(path), storedPath)
		if err != nil {
			return fmt.Errorf("compute publish link path: %w", err)
		}
		if err := os.WriteFile(linkPath, []byte(rel+"\n"), 0o644); err != nil {
			return fmt.Errorf("write publish link file: %w", err)
		}
	}

	return nil
}

func resolvePublishOutput(cfg PublishStep) string {
	if strings.TrimSpace(cfg.Output) != "" {
		return cfg.Output
	}
	if strings.TrimSpace(cfg.As) != "" {
		return cfg.As
	}
	if strings.TrimSpace(cfg.Resource) != "" {
		return cfg.Resource
	}
	return ""
}

// runPublishDir writes one XML file per entity into a directory.
// Each file is named by the sha256 hex of the entity ID with a .xml extension,
// matching pyFF directory-publish topology for MDQ static file serving.
// When cfg.URLEncode is true, filenames use the MDQ URL-encoded {sha256}HEX convention.
// cfg.Ext overrides the default ".xml" extension.
// Raw XML from currentXML is used when available; otherwise a stub EntityDescriptor is generated.
func runPublishDir(cfg PublishStep, outputDir string, current []string, currentXML map[string]string) error {
	dir := filepath.Join(outputDir, cfg.Dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create publish dir: %w", err)
	}

	ext := ".xml"
	if strings.TrimSpace(cfg.Ext) != "" {
		ext = cfg.Ext
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
	}

	for _, entityID := range current {
		h := sha256.Sum256([]byte(entityID))
		hexHash := fmt.Sprintf("%x", h[:])

		var filename string
		if cfg.URLEncode {
			filename = url.PathEscape("{sha256}"+hexHash) + ext
		} else {
			filename = hexHash + ext
		}
		path := filepath.Join(dir, filename)

		var body []byte
		if raw, ok := currentXML[entityID]; ok && strings.TrimSpace(raw) != "" {
			body = []byte(raw)
		} else {
			var err error
			body, err = renderEntityXML(entityID)
			if err != nil {
				return fmt.Errorf("render entity xml for %s: %w", entityID, err)
			}
		}

		if err := os.WriteFile(path, body, 0o644); err != nil {
			return fmt.Errorf("write entity file %s: %w", filename, err)
		}
	}

	return nil
}

func formatOutput(path string, current []string, currentXML map[string]string, fin FinalizeStep, signCfg SignStep, verifyCfg VerifyStep, first bool) ([]byte, error) {
	hasSign := signCfg.Key != "" || signCfg.Cert != "" || signCfg.PKCS11 != nil
	hasVerify := verifyCfg.Cert != "" || len(verifyCfg.Certs) > 0

	if strings.HasSuffix(strings.ToLower(path), ".xml") {
		var b []byte
		if first && len(current) == 1 {
			var err error
			b, err = renderEntityXML(current[0])
			if err != nil {
				return nil, err
			}
		} else {
			b = BuildEntitiesXML(current, currentXML, AggregateConfig{
				Name:          fin.Name,
				CacheDuration: fin.CacheDuration,
				ValidUntil:    fin.ValidUntil,
			})
		}

		if hasSign {
			if signCfg.Cert == "" {
				return nil, fmt.Errorf("sign requires cert")
			}
			if signCfg.Key == "" && signCfg.PKCS11 == nil {
				return nil, fmt.Errorf("sign requires either key or pkcs11 configuration")
			}
			var err error
			b, err = signXMLDocument(b, signCfg)
			if err != nil {
				return nil, err
			}
		}

		if hasVerify {
			if err := verifyXMLDocument(b, verifyCfg); err != nil {
				return nil, err
			}
		}

		return b, nil
	}

	if hasSign {
		return nil, fmt.Errorf("sign requires xml publish output")
	}
	if hasVerify {
		return nil, fmt.Errorf("verify requires xml publish output")
	}

	body := strings.Join(current, "\n")
	if body != "" {
		body += "\n"
	}
	return []byte(body), nil
}

func renderEntityXML(entityID string) ([]byte, error) {
	type singleEntity struct {
		XMLName  xml.Name `xml:"md:EntityDescriptor"`
		XMLNSMD  string   `xml:"xmlns:md,attr"`
		EntityID string   `xml:"entityID,attr"`
	}

	doc := singleEntity{XMLNSMD: "urn:oasis:names:tc:SAML:2.0:metadata", EntityID: entityID}
	b, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal xml output: %w", err)
	}

	var out bytes.Buffer
	out.WriteString(xml.Header)
	out.Write(b)
	out.WriteString("\n")
	return out.Bytes(), nil
}

func runStats(current []string) {
	fmt.Println("---")
	fmt.Printf("selected:       %d\n", len(current))
}

func runInfo(current []string) {
	for _, id := range current {
		fmt.Println(id)
	}
}

func runDump(current []string) {
	for _, id := range current {
		fmt.Println(id)
	}
}

func matchQuery(attr EntityAttributes, entityID string, query string) bool {
	q := strings.TrimSpace(strings.ToLower(query))
	if q == "" {
		return true
	}

	if ip := net.ParseIP(q); ip != nil {
		for cidr := range attr.IPHints {
			_, n, err := net.ParseCIDR(cidr)
			if err == nil && n.Contains(ip) {
				return true
			}
		}
	}

	if strings.Contains(strings.ToLower(entityID), q) {
		return true
	}
	for token := range attr.TextTokens {
		if strings.Contains(token, q) {
			return true
		}
	}
	return false
}
