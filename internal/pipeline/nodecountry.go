package pipeline

import (
	"fmt"
	"strings"

	"github.com/sirosfoundation/go-cryptoutil"
)

// runNodeCountry enriches each entity's attributes with a country:<CC> text
// token derived from the Subject.Country fields of X.509 certificates embedded
// in the entity's SAML metadata.
func runNodeCountry(current []string, attrs map[string]EntityAttributes, xmlDocs map[string]string, ext *cryptoutil.Extensions) map[string]EntityAttributes {
	result := make(map[string]EntityAttributes, len(attrs))
	for k, v := range attrs {
		result[k] = v.Clone()
	}

	for _, entityID := range current {
		xmlBody, ok := xmlDocs[entityID]
		if !ok || strings.TrimSpace(xmlBody) == "" {
			continue
		}
		certs, err := extractCertsFromEntityXML(xmlBody, ext)
		if err != nil {
			continue
		}
		seen := map[string]struct{}{}
		a, ok := result[entityID]
		if !ok {
			a = EntityAttributes{
				Roles:      map[string]struct{}{},
				Categories: map[string]struct{}{},
				TextTokens: map[string]struct{}{},
				IPHints:    map[string]struct{}{},
			}
		}
		for _, cert := range certs {
			for _, cc := range cert.Subject.Country {
				token := fmt.Sprintf("country:%s", strings.ToLower(cc))
				if _, dup := seen[token]; !dup {
					seen[token] = struct{}{}
					a.AddTextToken(token)
				}
			}
		}
		result[entityID] = a
	}
	return result
}
