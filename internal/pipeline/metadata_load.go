package pipeline

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/beevik/etree"
)

type sourceData struct {
	EntityIDs  []string
	Attributes map[string]EntityAttributes
	EntityXML  map[string]string
}

type EntityAttributes struct {
	Roles                 map[string]struct{}
	Categories            map[string]struct{}
	RegistrationAuthority string
	TextTokens            map[string]struct{}
	IPHints               map[string]struct{}
}

func (a EntityAttributes) Clone() EntityAttributes {
	roles := make(map[string]struct{}, len(a.Roles))
	for r := range a.Roles {
		roles[r] = struct{}{}
	}
	categories := make(map[string]struct{}, len(a.Categories))
	for c := range a.Categories {
		categories[c] = struct{}{}
	}
	textTokens := make(map[string]struct{}, len(a.TextTokens))
	for t := range a.TextTokens {
		textTokens[t] = struct{}{}
	}
	ipHints := make(map[string]struct{}, len(a.IPHints))
	for ip := range a.IPHints {
		ipHints[ip] = struct{}{}
	}
	return EntityAttributes{Roles: roles, Categories: categories, RegistrationAuthority: a.RegistrationAuthority, TextTokens: textTokens, IPHints: ipHints}
}

func (a EntityAttributes) HasRole(role string) bool {
	_, ok := a.Roles[normalizeRole(role)]
	return ok
}

func (a *EntityAttributes) AddRole(role string) {
	r := normalizeRole(role)
	if r == "" {
		return
	}
	if a.Roles == nil {
		a.Roles = make(map[string]struct{})
	}
	a.Roles[r] = struct{}{}
}

func (a EntityAttributes) HasCategory(cat string) bool {
	_, ok := a.Categories[normalizeString(cat)]
	return ok
}

func (a *EntityAttributes) AddCategory(cat string) {
	c := normalizeString(cat)
	if c == "" {
		return
	}
	if a.Categories == nil {
		a.Categories = make(map[string]struct{})
	}
	a.Categories[c] = struct{}{}
}

func (a *EntityAttributes) AddTextToken(v string) {
	v = normalizeString(v)
	if v == "" {
		return
	}
	if a.TextTokens == nil {
		a.TextTokens = make(map[string]struct{})
	}
	a.TextTokens[v] = struct{}{}
}

func (a *EntityAttributes) AddIPHint(v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	if _, _, err := net.ParseCIDR(v); err != nil {
		if ip := net.ParseIP(v); ip == nil {
			return
		}
		if strings.Contains(v, ":") {
			v += "/128"
		} else {
			v += "/32"
		}
	}
	if a.IPHints == nil {
		a.IPHints = make(map[string]struct{})
	}
	a.IPHints[v] = struct{}{}
}

func loadSourceData(src Source) (sourceData, error) {
	attributes := make(map[string]EntityAttributes)
	entityXML := make(map[string]string)

	for _, id := range src.Entities {
		if id == "" {
			continue
		}
		attributes[id] = EntityAttributes{Roles: map[string]struct{}{}, Categories: map[string]struct{}{}, TextTokens: map[string]struct{}{}, IPHints: map[string]struct{}{}}
	}

	for _, path := range src.Files {
		b, err := os.ReadFile(path)
		if err != nil {
			if src.Cleanup {
				continue
			}
			return sourceData{}, fmt.Errorf("read source file %q: %w", path, err)
		}
		if err := verifySourceIfConfigured(src, b); err != nil {
			if src.Cleanup {
				continue
			}
			return sourceData{}, fmt.Errorf("verify source file %q: %w", path, err)
		}
		parsed, err := parseMetadataFromXML(b)
		if err != nil {
			if src.Cleanup {
				continue
			}
			return sourceData{}, fmt.Errorf("parse metadata from file %q: %w", path, err)
		}
		xmlByID, err := parseEntityXMLByID(b)
		if err != nil {
			if src.Cleanup {
				continue
			}
			return sourceData{}, fmt.Errorf("parse entity xml from file %q: %w", path, err)
		}
		mergeAttributes(attributes, parsed)
		mergeEntityXML(entityXML, xmlByID)
	}

	for _, u := range src.URLs {
		b, err := fetchURL(src, u)
		if err != nil {
			if src.Cleanup {
				continue
			}
			return sourceData{}, err
		}
		if err := verifySourceIfConfigured(src, b); err != nil {
			if src.Cleanup {
				continue
			}
			return sourceData{}, fmt.Errorf("verify source url %q: %w", u, err)
		}
		parsed, err := parseMetadataFromXML(b)
		if err != nil {
			if src.Cleanup {
				continue
			}
			return sourceData{}, fmt.Errorf("parse metadata from url %q: %w", u, err)
		}
		xmlByID, err := parseEntityXMLByID(b)
		if err != nil {
			if src.Cleanup {
				continue
			}
			return sourceData{}, fmt.Errorf("parse entity xml from url %q: %w", u, err)
		}
		mergeAttributes(attributes, parsed)
		mergeEntityXML(entityXML, xmlByID)
	}

	ids := make([]string, 0, len(attributes))
	for id := range attributes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	return sourceData{EntityIDs: ids, Attributes: attributes, EntityXML: entityXML}, nil
}

func verifySourceIfConfigured(src Source, xmlBody []byte) error {
	if strings.TrimSpace(src.Verify) == "" {
		return nil
	}
	return verifyXMLDocument(xmlBody, VerifyStep{Cert: src.Verify})
}

func parseEntityXMLByID(b []byte) (map[string]string, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(b); err != nil {
		return nil, err
	}
	if doc.Root() == nil {
		return nil, fmt.Errorf("xml document is empty")
	}

	out := make(map[string]string)
	for _, e := range doc.FindElements("//md:EntityDescriptor") {
		id := strings.TrimSpace(e.SelectAttrValue("entityID", ""))
		if id == "" {
			continue
		}
		entityDoc := etree.NewDocument()
		entityDoc.SetRoot(e.Copy())
		body, err := entityDoc.WriteToString()
		if err != nil {
			return nil, err
		}
		out[id] = body
	}

	for _, e := range doc.FindElements("//EntityDescriptor") {
		id := strings.TrimSpace(e.SelectAttrValue("entityID", ""))
		if id == "" {
			continue
		}
		if _, ok := out[id]; ok {
			continue
		}
		entityDoc := etree.NewDocument()
		entityDoc.SetRoot(e.Copy())
		body, err := entityDoc.WriteToString()
		if err != nil {
			return nil, err
		}
		out[id] = body
	}

	return out, nil
}

func mergeEntityXML(dst map[string]string, src map[string]string) {
	for id, body := range src {
		dst[id] = body
	}
}

func fetchURL(src Source, u string) ([]byte, error) {
	timeout := 10 * time.Second
	if strings.TrimSpace(src.Timeout) != "" {
		d, err := time.ParseDuration(src.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid source timeout %q: %w", src.Timeout, err)
		}
		timeout = d
	}

	retries := src.Retries
	if retries < 0 {
		retries = 0
	}

	client := &http.Client{Timeout: timeout}
	attempts := retries + 1
	var lastErr error

	for attempt := 0; attempt < attempts; attempt++ {
		resp, err := client.Get(u)
		if err != nil {
			lastErr = err
			continue
		}

		b, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if closeErr != nil {
			lastErr = closeErr
			continue
		}

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			lastErr = fmt.Errorf("fetch source url %q: unexpected status %d", u, resp.StatusCode)
			continue
		}

		return b, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("fetch source url %q: %w", u, lastErr)
	}
	return nil, fmt.Errorf("fetch source url %q failed", u)
}

func parseMetadataFromXML(b []byte) (map[string]EntityAttributes, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	seenRoot := false
	depth := 0
	inEntity := false
	entityDepth := 0
	currentID := ""
	currentAttr := EntityAttributes{Roles: map[string]struct{}{}, Categories: map[string]struct{}{}, TextTokens: map[string]struct{}{}, IPHints: map[string]struct{}{}}
	attrs := make(map[string]EntityAttributes)
	inEntityAttributes := false
	inAttribute := false
	attributeDepth := 0
	attributeName := ""

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		switch x := tok.(type) {
		case xml.StartElement:
			depth++
			if !seenRoot {
				seenRoot = true
				if x.Name.Local != "EntitiesDescriptor" && x.Name.Local != "EntityDescriptor" {
					return nil, fmt.Errorf("unexpected root element %q", x.Name.Local)
				}
			}

			if x.Name.Local == "EntityDescriptor" {
				id, ok := requiredAttr(x.Attr, "entityID")
				if !ok {
					return nil, fmt.Errorf("EntityDescriptor missing required entityID attribute")
				}
				inEntity = true
				entityDepth = depth
				currentID = id
				currentAttr = EntityAttributes{Roles: map[string]struct{}{}, Categories: map[string]struct{}{}, TextTokens: map[string]struct{}{}, IPHints: map[string]struct{}{}}
				currentAttr.AddTextToken(id)
				continue
			}

			if inEntity {
				if role, ok := descriptorRole(x.Name.Local); ok {
					currentAttr.AddRole(role)
					continue
				}

				if x.Name.Local == "RegistrationInfo" {
					if ra, ok := requiredAttr(x.Attr, "registrationAuthority"); ok {
						currentAttr.RegistrationAuthority = ra
					}
					continue
				}

				if x.Name.Local == "EntityAttributes" {
					inEntityAttributes = true
					continue
				}

				if inEntityAttributes && x.Name.Local == "Attribute" {
					name, _ := requiredAttr(x.Attr, "Name")
					attributeName = normalizeString(name)
					inAttribute = true
					attributeDepth = depth
					continue
				}

				if inEntityAttributes && inAttribute && x.Name.Local == "AttributeValue" && attributeName == "http://macedir.org/entity-category" {
					var value string
					if err := dec.DecodeElement(&value, &x); err != nil {
						return nil, err
					}
					currentAttr.AddCategory(value)
					depth--
					continue
				}

				if textElementName(x.Name.Local) {
					var value string
					if err := dec.DecodeElement(&value, &x); err != nil {
						return nil, err
					}
					currentAttr.AddTextToken(value)
					depth--
					continue
				}

				if x.Name.Local == "IPHint" {
					var value string
					if err := dec.DecodeElement(&value, &x); err != nil {
						return nil, err
					}
					currentAttr.AddIPHint(value)
					depth--
				}
			}
		case xml.EndElement:
			if inAttribute && x.Name.Local == "Attribute" && depth == attributeDepth {
				inAttribute = false
				attributeDepth = 0
				attributeName = ""
			}

			if inEntityAttributes && x.Name.Local == "EntityAttributes" {
				inEntityAttributes = false
			}

			if inEntity && x.Name.Local == "EntityDescriptor" && depth == entityDepth {
				existing, ok := attrs[currentID]
				if ok {
					mergeRoleSets(existing.Roles, currentAttr.Roles)
					mergeRoleSets(existing.Categories, currentAttr.Categories)
					if existing.RegistrationAuthority == "" {
						existing.RegistrationAuthority = currentAttr.RegistrationAuthority
					}
					attrs[currentID] = existing
				} else {
					attrs[currentID] = currentAttr.Clone()
				}
				inEntity = false
				entityDepth = 0
				currentID = ""
				currentAttr = EntityAttributes{Roles: map[string]struct{}{}, Categories: map[string]struct{}{}, TextTokens: map[string]struct{}{}, IPHints: map[string]struct{}{}}
				inEntityAttributes = false
				inAttribute = false
				attributeDepth = 0
				attributeName = ""
			}
			depth--
		}
	}

	if !seenRoot {
		return nil, fmt.Errorf("xml document is empty")
	}

	return attrs, nil
}

func normalizeEntityIDs(in []string) []string {
	unique := make(map[string]struct{}, len(in))
	for _, v := range in {
		if v == "" {
			continue
		}
		unique[v] = struct{}{}
	}

	out := make([]string, 0, len(unique))
	for v := range unique {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func requiredAttr(attrs []xml.Attr, name string) (string, bool) {
	for _, a := range attrs {
		if a.Name.Local == name && strings.TrimSpace(a.Value) != "" {
			return a.Value, true
		}
	}
	return "", false
}

func descriptorRole(local string) (string, bool) {
	switch local {
	case "IDPSSODescriptor":
		return "idp", true
	case "SPSSODescriptor":
		return "sp", true
	case "AttributeAuthorityDescriptor":
		return "aa", true
	case "AuthnAuthorityDescriptor":
		return "authn", true
	case "PDPDescriptor":
		return "pdp", true
	default:
		return "", false
	}
}

func mergeAttributes(dst map[string]EntityAttributes, src map[string]EntityAttributes) {
	for id, attr := range src {
		existing, ok := dst[id]
		if !ok {
			dst[id] = attr.Clone()
			continue
		}
		mergeRoleSets(existing.Roles, attr.Roles)
		mergeRoleSets(existing.Categories, attr.Categories)
		mergeRoleSets(existing.TextTokens, attr.TextTokens)
		mergeRoleSets(existing.IPHints, attr.IPHints)
		if existing.RegistrationAuthority == "" {
			existing.RegistrationAuthority = attr.RegistrationAuthority
		}
		dst[id] = existing
	}
}

func mergeRoleSets(dst map[string]struct{}, src map[string]struct{}) {
	if dst == nil {
		return
	}
	for role := range src {
		dst[role] = struct{}{}
	}
}

func normalizeRole(role string) string {
	return strings.ToLower(strings.TrimSpace(role))
}

func textElementName(local string) bool {
	switch local {
	case "DisplayName", "ServiceName", "OrganizationDisplayName", "OrganizationName", "Keywords", "Scope":
		return true
	default:
		return false
	}
}
