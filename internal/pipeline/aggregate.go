package pipeline

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// AggregateConfig holds optional SAML metadata attributes applied to the root
// md:EntitiesDescriptor and the caching parameters derived from them.
type AggregateConfig struct {
	// Name is the @Name attribute; for MDQ endpoints it is typically the
	// aggregate URL (e.g. "https://mdq.example.org/entities").
	Name string

	// CacheDuration is an ISO 8601 duration string (e.g. "PT48H") set as the
	// @cacheDuration attribute and converted to a Cache-Control max-age header.
	CacheDuration string

	// ValidUntil is either an RFC 3339 timestamp or a "+<duration>" offset
	// from the current time (e.g. "+48h").  Written as @validUntil and used
	// to derive an Expires HTTP header.
	ValidUntil string
}

// ResolveValidUntil returns the @validUntil value to write into XML or send as
// an HTTP Expires header.  If vu starts with "+" it is treated as a duration
// added to the current time; otherwise it is returned unchanged.
func ResolveValidUntil(vu string) string {
	if vu == "" {
		return ""
	}
	if strings.HasPrefix(vu, "+") {
		d, err := time.ParseDuration(vu[1:])
		if err == nil {
			return time.Now().UTC().Add(d).Format(time.RFC3339)
		}
	}
	return vu
}

// ParseCacheDurationSeconds converts a subset of ISO 8601 durations (PT[n]H,
// PT[n]M, PT[n]S, and combinations) to seconds.  Returns 0,false for values
// it cannot parse.
func ParseCacheDurationSeconds(cd string) (int, bool) {
	cd = strings.ToUpper(strings.TrimSpace(cd))
	if !strings.HasPrefix(cd, "PT") {
		return 0, false
	}
	rest := cd[2:]
	secs := 0

	if i := strings.Index(rest, "H"); i >= 0 {
		n := 0
		if _, err := fmt.Sscanf(rest[:i], "%d", &n); err != nil {
			return 0, false
		}
		secs += n * 3600
		rest = rest[i+1:]
	}
	if i := strings.Index(rest, "M"); i >= 0 {
		n := 0
		if _, err := fmt.Sscanf(rest[:i], "%d", &n); err != nil {
			return 0, false
		}
		secs += n * 60
		rest = rest[i+1:]
	}
	if i := strings.Index(rest, "S"); i >= 0 {
		n := 0
		if _, err := fmt.Sscanf(rest[:i], "%d", &n); err != nil {
			return 0, false
		}
		secs += n
	}
	if secs == 0 {
		return 0, false
	}
	return secs, true
}

// BuildEntitiesXML renders a complete md:EntitiesDescriptor document embedding
// the full XML body of each entity ID in ids.  Missing or empty bodies fall
// back to a minimal stub EntityDescriptor.  cfg attributes are written on the
// root element; cfg.ValidUntil is resolved via ResolveValidUntil.
func BuildEntitiesXML(ids []string, bodies map[string]string, cfg AggregateConfig) []byte {
	validUntil := ResolveValidUntil(cfg.ValidUntil)

	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	buf.WriteString(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"`)
	if cfg.Name != "" {
		buf.WriteString(fmt.Sprintf(` Name=%q`, cfg.Name))
	}
	if cfg.CacheDuration != "" {
		buf.WriteString(fmt.Sprintf(` cacheDuration=%q`, cfg.CacheDuration))
	}
	if validUntil != "" {
		buf.WriteString(fmt.Sprintf(` validUntil=%q`, validUntil))
	}
	buf.WriteString(">\n")

	for _, id := range ids {
		body, ok := bodies[id]
		if !ok || strings.TrimSpace(body) == "" {
			buf.WriteString(fmt.Sprintf("  <md:EntityDescriptor entityID=%q></md:EntityDescriptor>\n", id))
			continue
		}
		s := strings.TrimSpace(body)
		// Strip XML declaration so the entity body embeds cleanly.
		if strings.HasPrefix(s, "<?xml") {
			if idx := strings.Index(s, "?>"); idx >= 0 {
				s = strings.TrimSpace(s[idx+2:])
			}
		}
		buf.WriteString(s)
		buf.WriteByte('\n')
	}
	buf.WriteString("</md:EntitiesDescriptor>\n")
	return buf.Bytes()
}
