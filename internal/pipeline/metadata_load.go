package pipeline

import (
	"bytes"
	"crypto/md5"  //nolint:gosec
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
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

	// ingestBytes parses SAML metadata bytes and merges entities into the running maps.
	ingestBytes := func(b []byte) error {
		parsed, err := parseMetadataFromXML(b)
		if err != nil {
			return err
		}
		xmlByID, err := parseEntityXMLByID(b)
		if err != nil {
			return err
		}
		mergeAttributes(attributes, parsed)
		mergeEntityXML(entityXML, xmlByID)
		return nil
	}

	// expandXRDAndLoad fetches each metadata URL extracted from an XRD/XRDS document.
	// All URLs are fetched concurrently; results are ingested in original order.
	expandXRDAndLoad := func(b []byte, origin string) error {
		urls, err := parseXRDURLs(b)
		if err != nil {
			return fmt.Errorf("parse XRD from %q: %w", origin, err)
		}
		type xrdResult struct {
			url  string
			body []byte
			err  error
		}
		results := make([]xrdResult, len(urls))
		var wg sync.WaitGroup
		for i, u := range urls {
			wg.Add(1)
			go func(idx int, rawURL string) {
				defer wg.Done()
				body, fetchErr := fetchURL(src, rawURL)
				results[idx] = xrdResult{url: rawURL, body: body, err: fetchErr}
			}(i, u)
		}
		wg.Wait()
		for _, r := range results {
			if r.err != nil {
				if src.Cleanup {
					continue
				}
				return r.err
			}
			if err := ingestBytes(r.body); err != nil {
				if src.Cleanup {
					continue
				}
				return fmt.Errorf("parse metadata from XRD link %q: %w", r.url, err)
			}
		}
		return nil
	}

	for _, path := range src.Files {
		// Directory: load every *.xml file inside it (GAP-9).
		fi, statErr := os.Stat(path)
		if statErr == nil && fi.IsDir() {
			entries, err := os.ReadDir(path)
			if err != nil {
				if src.Cleanup {
					continue
				}
				return sourceData{}, fmt.Errorf("read source directory %q: %w", path, err)
			}
			for _, de := range entries {
				if de.IsDir() || !strings.HasSuffix(de.Name(), ".xml") {
					continue
				}
				xmlPath := filepath.Join(path, de.Name())
				b, err := os.ReadFile(xmlPath)
				if err != nil {
					if src.Cleanup {
						continue
					}
					return sourceData{}, fmt.Errorf("read source file %q: %w", xmlPath, err)
				}
				if err := ingestBytes(b); err != nil && !src.Cleanup {
					return sourceData{}, fmt.Errorf("parse metadata from file %q: %w", xmlPath, err)
				}
			}
			continue
		}

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
		// XRD/XRDS: treat as a list of metadata URLs (GAP-4).
		if isXRDContent(b) {
			if err := expandXRDAndLoad(b, path); err != nil && !src.Cleanup {
				return sourceData{}, err
			}
			continue
		}
		if err := ingestBytes(b); err != nil {
			if src.Cleanup {
				continue
			}
			return sourceData{}, fmt.Errorf("parse metadata from file %q: %w", path, err)
		}
	}

	// All src.URLs are fetched concurrently; results are processed in original order
	// so that ingestion (parse + merge) stays single-threaded and deterministic.
	// URLs may carry an inline fingerprint suffix (pyFF compat):
	//   https://mds.edugain.org|sha256:abc123…
	// Strip the suffix before fetching and verify the body hash afterwards.
	if len(src.URLs) > 0 {
		type urlResult struct {
			rawURL     string // original URL (may contain "|alg:hash")
			fetchedURL string // URL with fingerprint stripped
			alg        string
			digest     string
			body       []byte
			err        error
		}
		urlResults := make([]urlResult, len(src.URLs))
		var wg sync.WaitGroup
		for i, u := range src.URLs {
			fetchedU, alg, digest := parseURLFingerprint(u)
			wg.Add(1)
			go func(idx int, rawURL, fURL, a, d string) {
				defer wg.Done()
				body, fetchErr := fetchURL(src, fURL)
				urlResults[idx] = urlResult{rawURL: rawURL, fetchedURL: fURL, alg: a, digest: d, body: body, err: fetchErr}
			}(i, u, fetchedU, alg, digest)
		}
		wg.Wait()
		for _, r := range urlResults {
			if r.err != nil {
				if src.Cleanup {
					continue
				}
				return sourceData{}, r.err
			}
			// Verify inline fingerprint when present.
			if r.alg != "" {
				if fpErr, _ := tryVerifyBodyHash(r.body, r.alg+":"+r.digest); fpErr != nil {
					if src.Cleanup {
						continue
					}
					return sourceData{}, fmt.Errorf("fingerprint mismatch for url %q: %w", r.rawURL, fpErr)
				}
			}
			if err := verifySourceIfConfigured(src, r.body); err != nil {
				if src.Cleanup {
					continue
				}
				return sourceData{}, fmt.Errorf("verify source url %q: %w", r.rawURL, err)
			}
			// XRD/XRDS: treat as a list of metadata URLs (GAP-4).
			if isXRDContent(r.body) {
				if err := expandXRDAndLoad(r.body, r.rawURL); err != nil && !src.Cleanup {
					return sourceData{}, err
				}
				continue
			}
			if err := ingestBytes(r.body); err != nil {
				if src.Cleanup {
					continue
				}
				return sourceData{}, fmt.Errorf("parse metadata from url %q: %w", r.rawURL, err)
			}
		}
	}

	ids := make([]string, 0, len(attributes))
	for id := range attributes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	return sourceData{EntityIDs: ids, Attributes: attributes, EntityXML: entityXML}, nil
}

// isXRDContent returns true if b is an XRD or XRDS XML document
// (namespace http://docs.oasis-open.org/ns/xri/xrd-1.0).
func isXRDContent(b []byte) bool {
	dec := xml.NewDecoder(bytes.NewReader(b))
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		if se, ok := tok.(xml.StartElement); ok {
			return (se.Name.Local == "XRDS" || se.Name.Local == "XRD") &&
				se.Name.Space == "http://docs.oasis-open.org/ns/xri/xrd-1.0"
		}
	}
}

// parseXRDURLs extracts metadata URLs from an XRD/XRDS document.
// It returns the href values of all <Link> elements whose rel attribute is
// "urn:oasis:names:tc:SAML:2.0:metadata" (the standard SAML metadata relation).
func parseXRDURLs(b []byte) ([]string, error) {
	const samlMetadataRel = "urn:oasis:names:tc:SAML:2.0:metadata"
	dec := xml.NewDecoder(bytes.NewReader(b))
	var urls []string
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Link" {
			continue
		}
		var rel, href string
		for _, a := range se.Attr {
			switch a.Name.Local {
			case "rel":
				rel = strings.TrimSpace(a.Value)
			case "href":
				href = strings.TrimSpace(a.Value)
			}
		}
		if rel == samlMetadataRel && href != "" {
			urls = append(urls, href)
		}
	}
	return urls, nil
}

func verifySourceIfConfigured(src Source, xmlBody []byte) error {
	spec := strings.TrimSpace(src.Verify)
	if spec == "" {
		return nil
	}
	// sha256:HEXHASH, sha1:HEXHASH, md5:HEXHASH — pyFF hash-fingerprint shorthand.
	if err, ok := tryVerifyBodyHash(xmlBody, spec); ok {
		return err
	}
	return verifyXMLDocument(xmlBody, VerifyStep{Cert: spec}, nil)
}

// parseURLFingerprint splits a pyFF-style "https://url|sha256:hexhash" URL into
// the bare URL, hash algorithm, and expected hex digest.  If the URL does not
// contain a fingerprint suffix (no "|alg:" pattern) all three return values are
// set to the original URL, "", "" respectively so callers can use the URL as-is.
func parseURLFingerprint(rawURL string) (fetchURL, alg, digest string) {
	idx := strings.LastIndex(rawURL, "|")
	if idx == -1 {
		return rawURL, "", ""
	}
	suffix := rawURL[idx+1:]
	colon := strings.Index(suffix, ":")
	if colon <= 0 {
		return rawURL, "", ""
	}
	algPart := strings.ToLower(suffix[:colon])
	switch algPart {
	case "sha256", "sha1", "md5":
		return rawURL[:idx], algPart, strings.ToLower(strings.TrimSpace(suffix[colon+1:]))
	default:
		return rawURL, "", ""
	}
}

// tryVerifyBodyHash checks if spec is a "<alg>:<hexhash>" fingerprint string and,
// if so, hashes body and compares it.  Returns (nil, false) when spec is not a
// recognised hash fingerprint (i.e. it's probably a cert file path).
func tryVerifyBodyHash(body []byte, spec string) (error, bool) {
	idx := strings.Index(spec, ":")
	if idx <= 0 {
		return nil, false
	}
	alg := strings.ToLower(spec[:idx])
	want := strings.ToLower(strings.TrimSpace(spec[idx+1:]))
	var got string
	switch alg {
	case "sha256":
		h := sha256.Sum256(body)
		got = hex.EncodeToString(h[:])
	case "sha1":
		h := sha1.Sum(body) //nolint:gosec
		got = hex.EncodeToString(h[:])
	case "md5":
		h := md5.Sum(body) //nolint:gosec
		got = hex.EncodeToString(h[:])
	default:
		// Unknown prefix — treat as a cert file path.
		return nil, false
	}
	if got != want {
		return fmt.Errorf("body fingerprint mismatch (%s): got %s, want %s", alg, got, want), true
	}
	return nil, true
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

// privateIPNets is the set of IP ranges that a metadata source URL must not
// resolve to unless Source.AllowPrivateAddrs is true.
var privateIPNets = func() []*net.IPNet {
	ranges := []string{
		"127.0.0.0/8",    // loopback
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // link-local / cloud metadata (AWS, GCP, Azure IMDS)
		"100.64.0.0/10",  // shared address space (RFC 6598)
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique-local
		"fe80::/10",      // IPv6 link-local
	}
	nets := make([]*net.IPNet, 0, len(ranges))
	for _, r := range ranges {
		_, n, _ := net.ParseCIDR(r)
		nets = append(nets, n)
	}
	return nets
}()

// validateFetchURL checks that rawURL uses an allowed scheme (http/https) and,
// unless allowPrivate is true, that the target hostname does not resolve to a
// private or reserved address (SSRF mitigation).
func validateFetchURL(rawURL string, allowPrivate bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid source url %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("source url %q: scheme %q not allowed (only http/https)", rawURL, u.Scheme)
	}
	if allowPrivate {
		return nil
	}
	host := u.Hostname()
	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("source url %q: dns lookup failed: %w", rawURL, err)
	}
	for _, addrStr := range addrs {
		ip := net.ParseIP(addrStr)
		if ip == nil {
			continue
		}
		for _, blocked := range privateIPNets {
			if blocked.Contains(ip) {
				return fmt.Errorf("source url %q: resolved address %s is in a private/reserved range "+
					"(set allow_private_addrs: true to override)", rawURL, ip)
			}
		}
	}
	return nil
}

func fetchURL(src Source, u string) ([]byte, error) {
	if err := validateFetchURL(u, src.AllowPrivateAddrs); err != nil {
		return nil, err
	}

	maxBytes := src.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 100 * 1024 * 1024 // 100 MiB default
	}

	timeout := 10 * time.Second
	if s := strings.TrimSpace(src.Timeout); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			timeout = d
		} else if n, intErr := strconv.Atoi(s); intErr == nil {
			// pyFF compat: bare integer means seconds.
			timeout = time.Duration(n) * time.Second
		} else {
			return nil, fmt.Errorf("invalid source timeout %q: %w", s, err)
		}
	}

	retries := src.Retries
	if retries < 0 {
		retries = 0
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
	}
	attempts := retries + 1
	var lastErr error

	for attempt := 0; attempt < attempts; attempt++ {
		resp, err := client.Get(u)
		if err != nil {
			lastErr = err
			continue
		}

		b, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
		closeErr := resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if int64(len(b)) > maxBytes {
			lastErr = fmt.Errorf("fetch source url %q: response exceeds %d byte limit", u, maxBytes)
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
