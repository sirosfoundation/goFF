package pipeline

import (
	"bytes"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/beevik/etree"
)

// Result contains final in-memory entities after execution.
type Result struct {
	Entities  []string
	EntityXML map[string]string
	Finalize  FinalizeStep
	Sign      SignStep
	Verify    VerifyStep
}

// Execute runs a parsed pipeline file.
func Execute(p File, outputDir string) (Result, error) {
	sourceMap := make(map[string][]string, len(p.Sources))
	sourceAttrs := make(map[string]map[string]EntityAttributes, len(p.Sources))
	sourceXML := make(map[string]map[string]string, len(p.Sources))
	for _, src := range p.Sources {
		if src.ID == "" {
			return Result{}, fmt.Errorf("source id is required")
		}
		src = resolveSourcePaths(src, p.BaseDir)
		data, err := loadSourceData(src)
		if err != nil {
			return Result{}, fmt.Errorf("load source %q: %w", src.ID, err)
		}
		sourceMap[src.ID] = data.EntityIDs
		sourceAttrs[src.ID] = data.Attributes
		sourceXML[src.ID] = data.EntityXML
	}

	current := make([]string, 0)
	currentAttrs := make(map[string]EntityAttributes)
	currentXML := make(map[string]string)
	publishFirst := false
	finalizeCfg := FinalizeStep{}
	signCfg := SignStep{}
	verifyCfg := VerifyStep{}

	for i, step := range p.Pipeline {
		switch step.Action {
		case "load", "local", "remote", "fetch", "_fetch":
			loaded, attrs, docs, err := runLoad(step.Load, sourceMap, sourceAttrs, sourceXML)
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
			currentAttrs = runSetAttr(step.SetAttr, current, currentAttrs)
			syncCurrentAttrsToSources(current, currentAttrs, sourceAttrs)
			publishFirst = false
		case "reginfo":
			currentAttrs = runRegInfo(step.RegInfo, current, currentAttrs)
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
			if err := runPublish(step.Publish, outputDir, current, finalizeCfg, signCfg, verifyCfg, publishFirst); err != nil {
				return Result{}, fmt.Errorf("step %d publish: %w", i, err)
			}
		case "stats":
			runStats(current)
		case "info":
			runInfo(current)
		case "dump", "print":
			runDump(current)
		case "break", "end":
			return Result{
				Entities:  append([]string(nil), current...),
				EntityXML: cloneEntityXML(currentXML),
				Finalize:  finalizeCfg,
				Sign:      signCfg,
				Verify:    verifyCfg,
			}, nil
		default:
			return Result{}, fmt.Errorf("step %d: unsupported action %q", i, step.Action)
		}
	}

	return Result{
		Entities:  append([]string(nil), current...),
		EntityXML: cloneEntityXML(currentXML),
		Finalize:  finalizeCfg,
		Sign:      signCfg,
		Verify:    verifyCfg,
	}, nil
}

func runFilter(cfg SelectStep, current []string, currentAttrs map[string]EntityAttributes, currentXML map[string]string) ([]string, map[string]EntityAttributes, map[string]string) {
	localSourceMap := map[string][]string{"_current": append([]string(nil), current...)}
	localSourceAttrs := map[string]map[string]EntityAttributes{"_current": cloneAttrs(currentAttrs)}
	localSourceXML := map[string]map[string]string{"_current": cloneEntityXML(currentXML)}
	return runSelect(cfg, current, currentAttrs, currentXML, localSourceMap, localSourceAttrs, localSourceXML)
}

func runLoad(cfg LoadStep, sourceMap map[string][]string, sourceAttrs map[string]map[string]EntityAttributes, sourceXML map[string]map[string]string) ([]string, map[string]EntityAttributes, map[string]string, error) {
	applyVia := func(ids []string, attrs map[string]EntityAttributes, docs map[string]string) ([]string, map[string]EntityAttributes, map[string]string, error) {
		if len(cfg.Via) == 0 {
			return ids, attrs, docs, nil
		}

		allowed := make(map[string]struct{})
		for _, viaSource := range cfg.Via {
			viaIDs, ok := sourceMap[viaSource]
			if !ok {
				return nil, nil, nil, fmt.Errorf("unknown load.via source %q", viaSource)
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

	if len(cfg.Entities) > 0 {
		attrs := make(map[string]EntityAttributes, len(cfg.Entities))
		for _, id := range cfg.Entities {
			a := EntityAttributes{Roles: map[string]struct{}{}, Categories: map[string]struct{}{}, TextTokens: map[string]struct{}{}, IPHints: map[string]struct{}{}}
			a.AddTextToken(id)
			attrs[id] = a
		}
		ids := append([]string(nil), cfg.Entities...)
		return applyVia(ids, attrs, map[string]string{})
	}

	if cfg.Source == "" {
		return nil, nil, nil, fmt.Errorf("load.source or load.entities is required")
	}

	entities, ok := sourceMap[cfg.Source]
	if !ok {
		return nil, nil, nil, fmt.Errorf("unknown source %q", cfg.Source)
	}

	attrs := cloneAttrs(sourceAttrs[cfg.Source])
	docs := cloneEntityXML(sourceXML[cfg.Source])
	ids := append([]string(nil), entities...)
	return applyVia(ids, attrs, docs)
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
		baseIDs, baseDocs, baseAttrs := resolveRepositorySource(src, current, currentAttrs, currentXML, sourceMap, sourceAttrs, sourceXML)
		if len(baseIDs) == 0 {
			return []string{}, true
		}
		return evaluateXPath(xp, baseIDs, baseDocs, baseAttrs), true
	}

	if strings.HasPrefix(sel, "//") {
		return evaluateXPath(sel, current, currentXML, currentAttrs), true
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

func evaluateXPath(xpath string, baseIDs []string, docs map[string]string, attrs map[string]EntityAttributes) []string {
	container := etree.NewElement("md:EntitiesDescriptor")
	container.CreateAttr("xmlns:md", "urn:oasis:names:tc:SAML:2.0:metadata")
	for _, id := range baseIDs {
		xmlBody, ok := docs[id]
		if !ok || strings.TrimSpace(xmlBody) == "" {
			container.CreateElement("md:EntityDescriptor").CreateAttr("entityID", id)
			continue
		}
		doc := etree.NewDocument()
		if err := doc.ReadFromString(xmlBody); err != nil || doc.Root() == nil {
			container.CreateElement("md:EntityDescriptor").CreateAttr("entityID", id)
			continue
		}
		container.AddChild(doc.Root().Copy())
	}

	nodes, ok := safeFindElements(container, xpath)
	if !ok {
		return evaluateXPathFallback(xpath, baseIDs, attrs)
	}
	if len(nodes) == 0 {
		return []string{}
	}

	ids := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if id := entityIDFromNode(n); id != "" {
			ids = append(ids, id)
		}
	}
	return normalizeEntityIDs(ids)
}

func safeFindElements(root *etree.Element, xpath string) (out []*etree.Element, ok bool) {
	defer func() {
		if recover() != nil {
			out = nil
			ok = false
		}
	}()
	out = root.FindElements(xpath)
	return out, true
}

func evaluateXPathFallback(xpath string, baseIDs []string, attrs map[string]EntityAttributes) []string {
	xpath = strings.TrimSpace(xpath)
	if !strings.HasPrefix(xpath, "//md:EntityDescriptor") {
		return []string{}
	}
	predicate := selectorPredicate(xpath)
	if predicate == "" {
		return normalizeEntityIDs(baseIDs)
	}
	out := make([]string, 0)
	for _, eid := range baseIDs {
		if selectorPredicateMatch(predicate, eid, attrs[eid]) {
			out = append(out, eid)
		}
	}
	return normalizeEntityIDs(out)
}

func selectorPredicate(sel string) string {
	start := strings.Index(sel, "[")
	end := strings.LastIndex(sel, "]")
	if start < 0 || end < 0 || end <= start {
		return ""
	}
	return strings.TrimSpace(sel[start+1 : end])
}

func selectorPredicateMatch(predicate string, entityID string, attr EntityAttributes) bool {
	orTerms := splitPredicateTerms(predicate, " or ")
	if len(orTerms) == 0 {
		return false
	}

	for _, orTerm := range orTerms {
		andTerms := splitPredicateTerms(orTerm, " and ")
		if len(andTerms) == 0 {
			continue
		}

		allTrue := true
		for _, atom := range andTerms {
			if !selectorAtomMatch(strings.TrimSpace(atom), entityID, attr) {
				allTrue = false
				break
			}
		}

		if allTrue {
			return true
		}
	}

	return false
}

func splitPredicateTerms(expr string, sep string) []string {
	terms := make([]string, 0)
	for {
		i := strings.Index(strings.ToLower(expr), sep)
		if i < 0 {
			if t := strings.TrimSpace(expr); t != "" {
				terms = append(terms, t)
			}
			break
		}
		if t := strings.TrimSpace(expr[:i]); t != "" {
			terms = append(terms, t)
		}
		expr = expr[i+len(sep):]
	}
	return terms
}

func selectorAtomMatch(atom string, entityID string, attr EntityAttributes) bool {
	atom = strings.TrimSpace(strings.Trim(atom, "()"))
	if atom == "" {
		return false
	}

	switch atom {
	case "md:IDPSSODescriptor":
		return attr.HasRole("idp")
	case "md:SPSSODescriptor":
		return attr.HasRole("sp")
	case "md:AttributeAuthorityDescriptor":
		return attr.HasRole("aa")
	case "md:AuthnAuthorityDescriptor":
		return attr.HasRole("authn")
	case "md:PDPDescriptor":
		return attr.HasRole("pdp")
	}

	if strings.HasPrefix(atom, "@entityID=") {
		if v, ok := quotedValue(atom); ok {
			return entityID == v
		}
	}

	if strings.Contains(atom, "RegistrationInfo/@registrationAuthority=") {
		if v, ok := quotedValue(atom); ok {
			return normalizeString(attr.RegistrationAuthority) == normalizeString(v)
		}
	}

	if strings.Contains(atom, "entity-category") && strings.Contains(atom, "AttributeValue=") {
		if v, ok := quotedValueAfter(atom, "AttributeValue="); ok {
			return attr.HasCategory(v)
		}
	}

	if strings.HasPrefix(strings.ToLower(atom), "contains(") {
		q, ok := quotedValue(atom)
		if !ok {
			return false
		}
		return matchQuery(attr, entityID, q)
	}

	return false
}

func quotedValue(s string) (string, bool) {
	start := strings.IndexAny(s, "'\"")
	if start < 0 {
		return "", false
	}
	quote := s[start]
	end := strings.IndexByte(s[start+1:], quote)
	if end < 0 {
		return "", false
	}
	return s[start+1 : start+1+end], true
}

func quotedValueAfter(s string, marker string) (string, bool) {
	i := strings.Index(s, marker)
	if i < 0 {
		return "", false
	}
	return quotedValue(s[i+len(marker):])
}

func entityIDFromNode(n *etree.Element) string {
	for el := n; el != nil; el = el.Parent() {
		tag := el.Tag
		if tag == "EntityDescriptor" || strings.HasSuffix(tag, ":EntityDescriptor") {
			return strings.TrimSpace(el.SelectAttrValue("entityID", ""))
		}
	}
	return ""
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
	b, err := fetchURL(Source{}, uri)
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
	if strings.TrimSpace(orderBy) == "" {
		return ""
	}
	if strings.TrimSpace(xmlBody) == "" {
		return ""
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlBody); err != nil || doc.Root() == nil {
		return ""
	}

	if strings.TrimSpace(orderBy) == "@entityID" {
		return entityID
	}

	nodes, ok := safeFindElements(doc.Root(), orderBy)
	if !ok || len(nodes) == 0 {
		return ""
	}
	n := nodes[0]
	if n.Text() != "" {
		return strings.TrimSpace(n.Text())
	}
	return strings.TrimSpace(n.SelectAttrValue("entityID", ""))
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

func runPublish(cfg PublishStep, outputDir string, current []string, fin FinalizeStep, signCfg SignStep, verifyCfg VerifyStep, first bool) error {
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

	body, err := formatOutput(path, current, fin, signCfg, verifyCfg, first)
	if err != nil {
		return err
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

func formatOutput(path string, current []string, fin FinalizeStep, signCfg SignStep, verifyCfg VerifyStep, first bool) ([]byte, error) {
	hasSign := signCfg.Key != "" || signCfg.Cert != "" || signCfg.PKCS11 != nil
	hasVerify := verifyCfg.Cert != ""

	if strings.HasSuffix(strings.ToLower(path), ".xml") {
		var b []byte
		var err error
		if first && len(current) == 1 {
			b, err = renderEntityXML(current[0])
		} else {
			b, err = renderEntitiesXML(current, fin)
		}
		if err != nil {
			return nil, err
		}

		if hasSign {
			if signCfg.Cert == "" {
				return nil, fmt.Errorf("sign requires cert")
			}
			if signCfg.Key == "" && signCfg.PKCS11 == nil {
				return nil, fmt.Errorf("sign requires either key or pkcs11 configuration")
			}
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

type entitiesDescriptor struct {
	XMLName       xml.Name           `xml:"md:EntitiesDescriptor"`
	XMLNSMD       string             `xml:"xmlns:md,attr"`
	Name          string             `xml:"Name,attr,omitempty"`
	CacheDuration string             `xml:"cacheDuration,attr,omitempty"`
	ValidUntil    string             `xml:"validUntil,attr,omitempty"`
	Entities      []entityDescriptor `xml:"md:EntityDescriptor"`
}

type entityDescriptor struct {
	EntityID string `xml:"entityID,attr"`
}

func renderEntitiesXML(current []string, fin FinalizeStep) ([]byte, error) {
	doc := entitiesDescriptor{
		XMLNSMD:       "urn:oasis:names:tc:SAML:2.0:metadata",
		Name:          fin.Name,
		CacheDuration: fin.CacheDuration,
		ValidUntil:    fin.ValidUntil,
		Entities:      make([]entityDescriptor, 0, len(current)),
	}

	for _, id := range current {
		doc.Entities = append(doc.Entities, entityDescriptor{EntityID: id})
	}

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
