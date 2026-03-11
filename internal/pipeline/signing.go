package pipeline

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	vcpki "vc/pkg/pki"

	"github.com/beevik/etree"
	xmldsig "github.com/russellhaering/goxmldsig"
)

func signXMLDocument(xmlData []byte, cfg SignStep) ([]byte, error) {
	km, err := loadKeyMaterialForSign(cfg)
	if err != nil {
		return nil, err
	}

	signer, ok := km.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}
	if km.Cert == nil {
		return nil, fmt.Errorf("no signing certificate available")
	}

	ctx, err := xmldsig.NewSigningContext(signer, [][]byte{km.Cert.Raw})
	if err != nil {
		return nil, fmt.Errorf("create signing context: %w", err)
	}
	ctx.Canonicalizer = xmldsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
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

func loadKeyMaterialForSign(cfg SignStep) (*vcpki.KeyMaterial, error) {
	keyCfg := &vcpki.KeyConfig{
		PrivateKeyPath: cfg.Key,
		ChainPath:      cfg.Cert,
	}

	if cfg.PKCS11 != nil {
		keyCfg.PKCS11 = &vcpki.PKCS11Config{
			ModulePath: cfg.PKCS11.ModulePath,
			SlotID:     cfg.PKCS11.SlotID,
			PIN:        cfg.PKCS11.PIN,
			KeyLabel:   cfg.PKCS11.KeyLabel,
			KeyID:      cfg.PKCS11.KeyID,
		}
		keyCfg.EnableHSM = true
		if cfg.Key != "" {
			keyCfg.EnableFile = true
			keyCfg.Priority = []vcpki.KeySource{vcpki.KeySourceHSM, vcpki.KeySourceFile}
		}
	}

	loader := vcpki.NewKeyLoader()
	km, err := loader.LoadKeyMaterial(keyCfg)
	if err != nil {
		return nil, fmt.Errorf("load signing key material: %w", err)
	}

	return km, nil
}

func verifyXMLDocument(xmlData []byte, cfg VerifyStep) error {
	if cfg.Cert == "" {
		return fmt.Errorf("verify requires cert")
	}

	cert, err := loadCertificateFromPEMFile(cfg.Cert)
	if err != nil {
		return err
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return fmt.Errorf("parse xml for verification: %w", err)
	}
	if doc.Root() == nil {
		return fmt.Errorf("cannot verify empty xml document")
	}

	ctx := xmldsig.NewDefaultValidationContext(&xmldsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})

	if _, err := ctx.Validate(doc.Root()); err != nil {
		return fmt.Errorf("verify xml signature: %w", err)
	}

	return nil
}

func loadCertificateFromPEMFile(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read verify cert file: %w", err)
	}

	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("decode verify cert pem")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse verify cert: %w", err)
	}

	return cert, nil
}
