package pipeline

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"
)

// runCertReport prints certificate validity information from each entity's
// embedded X.509 certificates to stdout.
func runCertReport(current []string, xmlDocs map[string]string) {
	now := time.Now()
	for _, entityID := range current {
		xmlBody, ok := xmlDocs[entityID]
		if !ok || strings.TrimSpace(xmlBody) == "" {
			continue
		}
		certs, err := extractCertsFromEntityXML(xmlBody)
		if err != nil || len(certs) == 0 {
			continue
		}
		for _, cert := range certs {
			days := int(cert.NotAfter.Sub(now).Hours() / 24)
			var status string
			switch {
			case now.After(cert.NotAfter):
				status = "EXPIRED"
			case days < 30:
				status = fmt.Sprintf("expiring in %d days", days)
			default:
				status = "ok"
			}
			fmt.Printf("%s\t%s\t%s\t%s\n",
				entityID,
				cert.Subject.CommonName,
				cert.NotAfter.Format("2006-01-02"),
				status,
			)
		}
	}
}

// extractCertsFromEntityXML parses ds:X509Certificate elements from entity XML
// and returns the decoded x509.Certificate objects.
func extractCertsFromEntityXML(xmlBody string) ([]*x509.Certificate, error) {
	dec := xml.NewDecoder(strings.NewReader(xmlBody))
	var certs []*x509.Certificate

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Return partial results on parse error.
			return certs, nil //nolint:nilerr
		}
		x, ok := tok.(xml.StartElement)
		if !ok || x.Name.Local != "X509Certificate" {
			continue
		}
		var certB64 string
		if err := dec.DecodeElement(&certB64, &x); err != nil {
			continue
		}
		// Strip whitespace before base64 decoding.
		certB64 = strings.ReplaceAll(strings.TrimSpace(certB64), "\n", "")
		certB64 = strings.ReplaceAll(certB64, "\r", "")
		certB64 = strings.ReplaceAll(certB64, " ", "")
		certBytes, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
