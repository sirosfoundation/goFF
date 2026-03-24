package pipeline

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDropXSIType(t *testing.T) {
	input := `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
		xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
		entityID="https://example.org">
		<md:Extensions xsi:type="md:ExtensionsType">
			<mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute">
				<saml:Attribute xsi:type="saml:AttributeType" Name="test"/>
			</mdattr:EntityAttributes>
		</md:Extensions>
	</md:EntityDescriptor>`

	out, err := dropXSIType([]byte(input))
	if err != nil {
		t.Fatalf("dropXSIType: %v", err)
	}
	if strings.Contains(string(out), `xsi:type`) {
		t.Errorf("output still contains xsi:type: %s", out)
	}
	// Ensure structural elements remain
	if !strings.Contains(string(out), "EntityDescriptor") {
		t.Error("EntityDescriptor element missing from output")
	}
}

func TestDropXSITypeEmptyRoot(t *testing.T) {
	// Empty document (valid XML with no root)
	out, err := dropXSIType([]byte(`<?xml version="1.0"?>`))
	if err != nil {
		t.Fatalf("dropXSIType empty root: %v", err)
	}
	if len(out) == 0 {
		t.Error("expected non-empty output for XML declaration")
	}
}

func TestDropXSITypeInvalidXML(t *testing.T) {
	_, err := dropXSIType([]byte(`<broken`))
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}

func TestResolveHSMPINFromFile(t *testing.T) {
	dir := t.TempDir()
	pinFile := filepath.Join(dir, "pin.txt")
	if err := os.WriteFile(pinFile, []byte("secret123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pin, err := resolveHSMPIN(&PKCS11SignSettings{PINFile: pinFile})
	if err != nil {
		t.Fatalf("resolveHSMPIN from file: %v", err)
	}
	if pin != "secret123" {
		t.Errorf("expected 'secret123', got %q", pin)
	}
}

func TestResolveHSMPINFromEnv(t *testing.T) {
	t.Setenv("TEST_GOFFE_PIN", "envpin")
	pin, err := resolveHSMPIN(&PKCS11SignSettings{PINEnv: "TEST_GOFFE_PIN"})
	if err != nil {
		t.Fatalf("resolveHSMPIN from env: %v", err)
	}
	if pin != "envpin" {
		t.Errorf("expected 'envpin', got %q", pin)
	}
}

func TestResolveHSMPINFromEnvEmpty(t *testing.T) {
	t.Setenv("TEST_GOFFE_PIN_EMPTY", "")
	_, err := resolveHSMPIN(&PKCS11SignSettings{PINEnv: "TEST_GOFFE_PIN_EMPTY"})
	if err == nil {
		t.Error("expected error when env var is empty")
	}
}

func TestResolveHSMPINLiteral(t *testing.T) {
	pin, err := resolveHSMPIN(&PKCS11SignSettings{PIN: "literal"})
	if err != nil {
		t.Fatalf("resolveHSMPIN literal: %v", err)
	}
	if pin != "literal" {
		t.Errorf("expected 'literal', got %q", pin)
	}
}

func TestResolveHSMPINFileNotFound(t *testing.T) {
	_, err := resolveHSMPIN(&PKCS11SignSettings{PINFile: "/nonexistent/pin.txt"})
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadCertificateFromPEMFile(t *testing.T) {
	certFile := writeTestCert(t)
	cert, err := loadCertificateFromPEMFile(certFile, nil)
	if err != nil {
		t.Fatalf("loadCertificateFromPEMFile: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
}

func TestLoadCertificateFromPEMFileNotFound(t *testing.T) {
	_, err := loadCertificateFromPEMFile("/nonexistent/cert.pem", nil)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadCertificateFromPEMFileInvalid(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(f, []byte("not a pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadCertificateFromPEMFile(f, nil)
	if err == nil {
		t.Error("expected error for non-PEM content")
	}
}

func TestLoadVerifyCerts(t *testing.T) {
	certFile := writeTestCert(t)
	cfg := VerifyStep{
		Cert:  certFile,
		Certs: []string{certFile},
	}
	certs, err := loadVerifyCerts(cfg, nil)
	if err != nil {
		t.Fatalf("loadVerifyCerts: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("expected 2 certs, got %d", len(certs))
	}
}

func TestLoadVerifyCertsEmpty(t *testing.T) {
	certs, err := loadVerifyCerts(VerifyStep{}, nil)
	if err != nil {
		t.Fatalf("loadVerifyCerts empty: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs, got %d", len(certs))
	}
}

func writeTestCert(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cert"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	f := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(f, pemData, 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}
