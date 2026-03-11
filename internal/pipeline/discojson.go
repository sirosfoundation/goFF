package pipeline

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const nsMDUI = "urn:oasis:names:tc:SAML:metadata:ui"

// DiscoEntry is a single entity's representation in the SAML discovery JSON feed.
type DiscoEntry struct {
	EntityID             string         `json:"entityID"`
	Type                 []string       `json:"type,omitempty"`
	DisplayNames         []LangValue    `json:"DisplayNames,omitempty"`
	Descriptions         []LangValue    `json:"Descriptions,omitempty"`
	Keywords             []LangKeywords `json:"Keywords,omitempty"`
	Logos                []Logo         `json:"Logos,omitempty"`
	PrivacyStatementURLs []LangValue    `json:"PrivacyStatementURLs,omitempty"`
	InformationURLs      []LangValue    `json:"InformationURLs,omitempty"`
	Domains              []string       `json:"Domains,omitempty"`
	Geo                  []GeoHint      `json:"geo,omitempty"`
}

// LangValue is a language-tagged string value.
type LangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// LangKeywords is a language-tagged list of keyword strings.
type LangKeywords struct {
	Lang  string   `json:"lang"`
	Value []string `json:"value"`
}

// Logo is an MDUI logo entry with URL, dimensions, and optional language tag.
type Logo struct {
	Value  string `json:"value"`
	Width  int    `json:"width,omitempty"`
	Height int    `json:"height,omitempty"`
	Lang   string `json:"lang,omitempty"`
}

// GeoHint is a geographic coordinate pair.
type GeoHint struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// runDiscoJSON renders the current entity set as a discovery JSON feed and
// writes it to cfg.Output inside outputDir.  roleFilter restricts output to
// entities carrying the given role ("idp" or "sp"); empty means all entities.
func runDiscoJSON(cfg DiscoJSONStep, outputDir string, current []string, attrs map[string]EntityAttributes, xmlDocs map[string]string, roleFilter string) error {
	entries := make([]DiscoEntry, 0, len(current))
	for _, entityID := range current {
		a := attrs[entityID]
		if roleFilter != "" {
			if _, ok := a.Roles[roleFilter]; !ok {
				continue
			}
		}
		entry, err := parseDiscoEntry(entityID, xmlDocs[entityID], a)
		if err != nil {
			continue
		}
		entries = append(entries, entry)
	}

	if cfg.Output == "" {
		return nil
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal disco json: %w", err)
	}
	outPath := filepath.Join(outputDir, cfg.Output)
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("create disco json output dir: %w", err)
	}
	return os.WriteFile(outPath, append(data, '\n'), 0o644)
}

// parseDiscoEntry extracts MDUI and organizational metadata from a SAML
// EntityDescriptor XML string and returns a populated DiscoEntry.
func parseDiscoEntry(entityID, xmlBody string, attr EntityAttributes) (DiscoEntry, error) {
	entry := DiscoEntry{EntityID: entityID}

	// Populate type from pre-indexed role attributes.
	if _, ok := attr.Roles["idp"]; ok {
		entry.Type = append(entry.Type, "idp")
	}
	if _, ok := attr.Roles["sp"]; ok {
		entry.Type = append(entry.Type, "sp")
	}

	if strings.TrimSpace(xmlBody) == "" {
		return entry, nil
	}

	dec := xml.NewDecoder(strings.NewReader(xmlBody))
	depth := 0
	inUIInfo := false
	uiInfoDepth := 0
	keywordsMap := map[string][]string{} // lang → []keyword
	// Track whether we've added any DisplayName so we know if we need org fallback.
	hadDisplayName := false

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		switch x := tok.(type) {
		case xml.StartElement:
			depth++
			local := x.Name.Local
			ns := x.Name.Space

			if local == "UIInfo" && ns == nsMDUI {
				inUIInfo = true
				uiInfoDepth = depth
				continue
			}

			if inUIInfo {
				switch local {
				case "DisplayName":
					var val string
					if err := dec.DecodeElement(&val, &x); err == nil && strings.TrimSpace(val) != "" {
						entry.DisplayNames = append(entry.DisplayNames, LangValue{
							Lang:  xmlLang(x.Attr),
							Value: strings.TrimSpace(val),
						})
						hadDisplayName = true
					}
					depth--
					continue
				case "Description":
					var val string
					if err := dec.DecodeElement(&val, &x); err == nil && strings.TrimSpace(val) != "" {
						entry.Descriptions = append(entry.Descriptions, LangValue{
							Lang:  xmlLang(x.Attr),
							Value: strings.TrimSpace(val),
						})
					}
					depth--
					continue
				case "Keywords":
					var val string
					if err := dec.DecodeElement(&val, &x); err == nil {
						lang := xmlLang(x.Attr)
						keywordsMap[lang] = append(keywordsMap[lang], splitKeywords(val)...)
					}
					depth--
					continue
				case "Logo":
					var val string
					if err := dec.DecodeElement(&val, &x); err == nil && strings.TrimSpace(val) != "" {
						logo := Logo{Value: strings.TrimSpace(val), Lang: xmlLang(x.Attr)}
						if w := xmlAttr(x.Attr, "width"); w != "" {
							logo.Width, _ = strconv.Atoi(w)
						}
						if h := xmlAttr(x.Attr, "height"); h != "" {
							logo.Height, _ = strconv.Atoi(h)
						}
						entry.Logos = append(entry.Logos, logo)
					}
					depth--
					continue
				case "PrivacyStatementURL":
					var val string
					if err := dec.DecodeElement(&val, &x); err == nil && strings.TrimSpace(val) != "" {
						entry.PrivacyStatementURLs = append(entry.PrivacyStatementURLs, LangValue{
							Lang:  xmlLang(x.Attr),
							Value: strings.TrimSpace(val),
						})
					}
					depth--
					continue
				case "InformationURL":
					var val string
					if err := dec.DecodeElement(&val, &x); err == nil && strings.TrimSpace(val) != "" {
						entry.InformationURLs = append(entry.InformationURLs, LangValue{
							Lang:  xmlLang(x.Attr),
							Value: strings.TrimSpace(val),
						})
					}
					depth--
					continue
				case "GeolocationHint":
					var val string
					if err := dec.DecodeElement(&val, &x); err == nil {
						if g, ok := parseGeo(strings.TrimSpace(val)); ok {
							entry.Geo = append(entry.Geo, g)
						}
					}
					depth--
					continue
				}
			}

			// Scope elements can appear inside or outside UIInfo.
			if local == "Scope" {
				var val string
				if err := dec.DecodeElement(&val, &x); err == nil {
					scope := strings.TrimSpace(val)
					// Only add non-regex scopes as domain hints.
					if !strings.ContainsAny(scope, "\\*?[](){}^$|") {
						entry.Domains = append(entry.Domains, scope)
					}
				}
				depth--
				continue
			}

			// OrganizationDisplayName as fallback when no mdui:DisplayName present.
			if local == "OrganizationDisplayName" && !hadDisplayName {
				var val string
				if err := dec.DecodeElement(&val, &x); err == nil && strings.TrimSpace(val) != "" {
					entry.DisplayNames = append(entry.DisplayNames, LangValue{
						Lang:  xmlLang(x.Attr),
						Value: strings.TrimSpace(val),
					})
				}
				depth--
				continue
			}

		case xml.EndElement:
			if inUIInfo && depth == uiInfoDepth && x.Name.Local == "UIInfo" {
				inUIInfo = false
			}
			depth--
		}
	}

	// Merge per-language keyword slices.
	for lang, words := range keywordsMap {
		entry.Keywords = append(entry.Keywords, LangKeywords{Lang: lang, Value: words})
	}

	return entry, nil
}

// xmlLang extracts the xml:lang attribute value from an attribute list.
func xmlLang(attrs []xml.Attr) string {
	for _, a := range attrs {
		if a.Name.Local == "lang" {
			return a.Value
		}
	}
	return ""
}

// xmlAttr extracts a plain (non-namespaced) attribute value by local name.
func xmlAttr(attrs []xml.Attr, local string) string {
	for _, a := range attrs {
		if a.Name.Local == local && a.Name.Space == "" {
			return a.Value
		}
	}
	return ""
}

// splitKeywords splits a space/comma/plus-separated keyword string.
func splitKeywords(s string) []string {
	var out []string
	for _, w := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '+' || r == ',' || r == ';'
	}) {
		w = strings.Trim(w, " ")
		if w != "" {
			out = append(out, w)
		}
	}
	return out
}

// parseGeo parses a "geo:LAT,LON" hint string.
func parseGeo(s string) (GeoHint, bool) {
	s = strings.TrimPrefix(s, "geo:")
	parts := strings.SplitN(s, ",", 2)
	if len(parts) != 2 {
		return GeoHint{}, false
	}
	lat, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	lon, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	if err1 != nil || err2 != nil {
		return GeoHint{}, false
	}
	return GeoHint{Lat: lat, Lon: lon}, true
}
