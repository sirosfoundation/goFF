package pipeline

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/beevik/etree"

	"github.com/sirosfoundation/go-cryptoutil"
	"github.com/sirosfoundation/go-cryptoutil/pkcs11pool"

	xmldsig "github.com/russellhaering/goxmldsig"
)

// signKeyMaterial holds a loaded signing key and certificate (replaces vcpki.KeyMaterial).
type signKeyMaterial struct {
	PrivateKey crypto.Signer
	Cert       *x509.Certificate
}

func signXMLDocument(xmlData []byte, cfg SignStep, ext *cryptoutil.Extensions) ([]byte, error) {
	km, err := loadKeyMaterialForSign(cfg)
	if err != nil {
		return nil, err
	}

	if km.Cert == nil {
		return nil, fmt.Errorf("no signing certificate available")
	}

	ctx, err := xmldsig.NewSigningContext(km.PrivateKey, [][]byte{km.Cert.Raw})
	if err != nil {
		return nil, fmt.Errorf("create signing context: %w", err)
	}
	ctx.Canonicalizer = xmldsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	doc := etree.NewDocument()
	if err = doc.ReadFromBytes(xmlData); err != nil {
		return nil, fmt.Errorf("parse xml for signing: %w", err)
	}

	if doc.Root() == nil {
		return nil, fmt.Errorf("cannot sign empty xml document")
	}

	signed, err := ctx.SignEnveloped(doc.Root())
	if err != nil {
		return nil, fmt.Errorf("sign xml: %w", err)
	}

	out := etree.NewDocument()
	out.SetRoot(signed)
	return out.WriteToBytes()
}

// resolveHSMPIN returns the PKCS#11 slot PIN, resolving it in priority order:
//  1. PINFile — first line of the named file
//  2. PINEnv  — value of the named environment variable
//  3. PIN     — literal value in the config (least preferred)
func resolveHSMPIN(cfg *PKCS11SignSettings) (string, error) {
	if cfg.PINFile != "" {
		b, err := os.ReadFile(cfg.PINFile)
		if err != nil {
			return "", fmt.Errorf("pkcs11 pin_file %q: %w", cfg.PINFile, err)
		}
		line := strings.SplitN(strings.TrimRight(string(b), "\r\n"), "\n", 2)[0]
		return strings.TrimSpace(line), nil
	}
	if cfg.PINEnv != "" {
		v := os.Getenv(cfg.PINEnv)
		if v == "" {
			return "", fmt.Errorf("pkcs11 pin_env %q is not set or empty", cfg.PINEnv)
		}
		return v, nil
	}
	return cfg.PIN, nil
}

func loadKeyMaterialForSign(cfg SignStep) (*signKeyMaterial, error) {
	var signer crypto.Signer

	if cfg.PKCS11 != nil {
		pin, err := resolveHSMPIN(cfg.PKCS11)
		if err != nil {
			return nil, err
		}

		sel := pkcs11pool.KeyByLabel(cfg.PKCS11.KeyLabel)
		if cfg.PKCS11.KeyID != "" {
			sel = pkcs11pool.KeyByID([]byte(cfg.PKCS11.KeyID))
		}

		pool, err := pkcs11pool.New(pkcs11pool.Config{
			ModulePath: cfg.PKCS11.ModulePath,
			SlotID:     cfg.PKCS11.SlotID,
			PIN:        pin,
		})
		if err != nil {
			return nil, fmt.Errorf("pkcs11 pool: %w", err)
		}
		// Note: pool is not closed here because the signer holds a reference.
		// The signer is used for the lifetime of the signing operation.

		s, err := pkcs11pool.NewSigner(pool, sel)
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("pkcs11 signer: %w", err)
		}
		signer = s
	}

	// Load file-based key if no HSM signer or as fallback.
	if signer == nil && cfg.Key != "" {
		keyPEM, err := os.ReadFile(cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("read private key: %w", err)
		}
		block, _ := pem.Decode(keyPEM)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM private key")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			// Try EC-specific format.
			key2, err2 := x509.ParseECPrivateKey(block.Bytes)
			if err2 != nil {
				// Try RSA PKCS#1 format.
				key3, err3 := x509.ParsePKCS1PrivateKey(block.Bytes)
				if err3 != nil {
					return nil, fmt.Errorf("parse private key: %w", err)
				}
				key = key3
			} else {
				key = key2
			}
		}
		s, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("private key does not implement crypto.Signer")
		}
		signer = s
	}

	if signer == nil {
		return nil, fmt.Errorf("no signing key configured (set key or pkcs11)")
	}

	// Load certificate.
	var cert *x509.Certificate
	if cfg.Cert != "" {
		certPEM, err := os.ReadFile(cfg.Cert)
		if err != nil {
			return nil, fmt.Errorf("read certificate: %w", err)
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM certificate")
		}
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
	}

	return &signKeyMaterial{PrivateKey: signer, Cert: cert}, nil
}

// verifyXMLDocument verifies an enveloped XML signature against the certificates
// configured in cfg.  Both cfg.Cert (single path) and cfg.Certs (list of paths)
// are accepted; all listed certs are added to the trust store so key-rollover
// pipelines can verify signatures from either cert.
func verifyXMLDocument(xmlData []byte, cfg VerifyStep, ext *cryptoutil.Extensions) error {
	certs, err := loadVerifyCerts(cfg, ext)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return fmt.Errorf("verify requires at least one certificate")
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return fmt.Errorf("parse xml for verification: %w", err)
	}
	if doc.Root() == nil {
		return fmt.Errorf("cannot verify empty xml document")
	}

	if cfg.CheckExpiry {
		now := time.Now()
		for _, cert := range certs {
			if now.Before(cert.NotBefore) {
				return fmt.Errorf("verify cert %q not yet valid (NotBefore: %s)",
					cert.Subject, cert.NotBefore.Format(time.RFC3339))
			}
			if now.After(cert.NotAfter) {
				return fmt.Errorf("verify cert %q has expired (NotAfter: %s)",
					cert.Subject, cert.NotAfter.Format(time.RFC3339))
			}
		}
	}

	ctx := xmldsig.NewDefaultValidationContext(&xmldsig.MemoryX509CertificateStore{
		Roots: certs,
	})
	ctx.CryptoExtensions = ext

	if _, err := ctx.Validate(doc.Root()); err != nil {
		return fmt.Errorf("verify xml signature: %w", err)
	}

	return nil
}

// loadVerifyCerts loads all certificates referenced by cfg.Cert and cfg.Certs.
func loadVerifyCerts(cfg VerifyStep, ext *cryptoutil.Extensions) ([]*x509.Certificate, error) {
	paths := make([]string, 0, 1+len(cfg.Certs))
	if strings.TrimSpace(cfg.Cert) != "" {
		paths = append(paths, cfg.Cert)
	}
	for _, p := range cfg.Certs {
		if strings.TrimSpace(p) != "" {
			paths = append(paths, p)
		}
	}
	certs := make([]*x509.Certificate, 0, len(paths))
	for _, path := range paths {
		cert, err := loadCertificateFromPEMFile(path, ext)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func loadCertificateFromPEMFile(path string, ext *cryptoutil.Extensions) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read verify cert file: %w", err)
	}

	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("decode verify cert pem")
	}

	if ext != nil {
		return ext.ParseCertificate(block.Bytes)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse verify cert: %w", err)
	}

	return cert, nil
}

// dropXSIType removes all xsi:type attributes from all elements in the document.
// This mirrors pyFF's drop_xsi_type pipe which cleans up metadata that carries
// xsi:type annotations before signing — some validators reject such attributes.
func dropXSIType(xmlData []byte) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return nil, fmt.Errorf("drop_xsi_type parse xml: %w", err)
	}
	if doc.Root() == nil {
		return xmlData, nil
	}
	removeXSITypeAttr(doc.Root())
	return doc.WriteToBytes()
}

// removeXSITypeAttr recursively removes xsi:type attributes from el and its
// descendants.
func removeXSITypeAttr(el *etree.Element) {
	filtered := el.Attr[:0]
	for _, a := range el.Attr {
		// Match any attribute named "type" in the xsi namespace, regardless of prefix.
		if a.Key == "type" && strings.Contains(a.Space, "XMLSchema-instance") {
			continue
		}
		if a.Space == "xsi" && a.Key == "type" {
			continue
		}
		filtered = append(filtered, a)
	}
	el.Attr = filtered
	for _, child := range el.ChildElements() {
		removeXSITypeAttr(child)
	}
}
