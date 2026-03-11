package app

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunBatchRequiresPipeline(t *testing.T) {
	err := RunBatch(t.Context(), BatchOptions{})
	if err == nil {
		t.Fatal("expected error when pipeline is missing")
	}
}

func TestRunServerRequiresPipeline(t *testing.T) {
	err := RunServer(t.Context(), ServerOptions{})
	if err == nil {
		t.Fatal("expected error when pipeline is missing")
	}
}

func TestRunBatchExecutesPipelineFixture(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "basic.yaml")
	outDir := t.TempDir()

	err := RunBatch(t.Context(), BatchOptions{PipelinePath: fixture, OutputDir: outDir})
	if err != nil {
		t.Fatalf("RunBatch returned error: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(outDir, "entities.txt"))
	if err != nil {
		t.Fatalf("failed to read published output: %v", err)
	}

	if string(b) != "https://idp.example.org/idp\n" {
		t.Fatalf("unexpected output: %q", string(b))
	}
}

func TestRunBatchSelectPredicateFixtures(t *testing.T) {
	tests := []struct {
		name         string
		pipelineFile string
		outputFile   string
		expectedFile string
	}{
		{
			name:         "select by role",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "select-by-role-idp.yaml"),
			outputFile:   "role-idp.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "role-idp.txt"),
		},
		{
			name:         "select by roles all",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "select-by-roles-all.yaml"),
			outputFile:   "roles-all.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "roles-all.txt"),
		},
		{
			name:         "select by entity category",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "select-by-entity-category.yaml"),
			outputFile:   "category-rs.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "category-rs.txt"),
		},
		{
			name:         "select by registration authority",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "select-by-registration-authority.yaml"),
			outputFile:   "reg-auth.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "reg-auth.txt"),
		},
		{
			name:         "select by source scoped xpath",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "select-by-source-xpath.yaml"),
			outputFile:   "source-xpath.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "source-xpath.txt"),
		},
		{
			name:         "select by intersection",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "select-by-intersection.yaml"),
			outputFile:   "intersection.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "intersection.txt"),
		},
		{
			name:         "select dedup false keeps duplicates",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "select-dedup-false-alias.yaml"),
			outputFile:   "select-dedup-false.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "select-dedup-false.txt"),
		},
		{
			name:         "select as alias can be reloaded",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "select-alias-reload.yaml"),
			outputFile:   "select-alias-reload.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "select-alias-reload.txt"),
		},
		{
			name:         "setattr category enriches current entities",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "setattr-category.yaml"),
			outputFile:   "setattr-category.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "setattr-category.txt"),
		},
		{
			name:         "setattr structured prefix match",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "setattr-structured-match.yaml"),
			outputFile:   "setattr-structured-match.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "setattr-structured-match.txt"),
		},
		{
			name:         "reginfo authority enriches current entities",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "reginfo-authority.yaml"),
			outputFile:   "reginfo-authority.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "reginfo-authority.txt"),
		},
		{
			name:         "reginfo structured policy prefix match",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "reginfo-structured-match.yaml"),
			outputFile:   "reginfo-structured-match.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "reginfo-structured-match.txt"),
		},
		{
			name:         "pubinfo publisher enriches current entities",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "pubinfo-match.yaml"),
			outputFile:   "pubinfo-match.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "pubinfo-match.txt"),
		},
		{
			name:         "pubinfo structured publisher prefix match",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "pubinfo-structured-match.yaml"),
			outputFile:   "pubinfo-structured-match.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "pubinfo-structured-match.txt"),
		},
		{
			name:         "pubinfo url and lang structured match",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "pubinfo-url-lang-match.yaml"),
			outputFile:   "pubinfo-url-lang-match.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "pubinfo-url-lang-match.txt"),
		},
		{
			name:         "pubinfo values structured match",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "pubinfo-values-structured-match.yaml"),
			outputFile:   "pubinfo-values-structured-match.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "pubinfo-values-structured-match.txt"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			outDir := t.TempDir()

			err := RunBatch(t.Context(), BatchOptions{PipelinePath: tc.pipelineFile, OutputDir: outDir})
			if err != nil {
				t.Fatalf("RunBatch returned error: %v", err)
			}

			got, err := os.ReadFile(filepath.Join(outDir, tc.outputFile))
			if err != nil {
				t.Fatalf("failed reading output file: %v", err)
			}

			expected, err := os.ReadFile(tc.expectedFile)
			if err != nil {
				t.Fatalf("failed reading expected file: %v", err)
			}

			if string(got) != string(expected) {
				t.Fatalf("output mismatch\n--- got ---\n%s\n--- expected ---\n%s", string(got), string(expected))
			}
		})
	}
}

func TestRunBatchFilterPickFirstFixtures(t *testing.T) {
	tests := []struct {
		name         string
		pipelineFile string
		outputFile   string
		expectedFile string
	}{
		{
			name:         "filter uses current working set",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "filter-current-only.yaml"),
			outputFile:   "filter-current-only.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "filter-current-only.txt"),
		},
		{
			name:         "pick can select from repository",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "pick-repository.yaml"),
			outputFile:   "pick-repository.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "pick-repository.txt"),
		},
		{
			name:         "first publishes single entity xml",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "first-single-entity.yaml"),
			outputFile:   "first-single.xml",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "first-single.xml"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			outDir := t.TempDir()

			err := RunBatch(t.Context(), BatchOptions{PipelinePath: tc.pipelineFile, OutputDir: outDir})
			if err != nil {
				t.Fatalf("RunBatch returned error: %v", err)
			}

			got, err := os.ReadFile(filepath.Join(outDir, tc.outputFile))
			if err != nil {
				t.Fatalf("failed reading output file: %v", err)
			}

			expected, err := os.ReadFile(tc.expectedFile)
			if err != nil {
				t.Fatalf("failed reading expected file: %v", err)
			}

			if string(got) != string(expected) {
				t.Fatalf("output mismatch\n--- got ---\n%s\n--- expected ---\n%s", string(got), string(expected))
			}
		})
	}
}

func TestRunBatchSortAndFinalizeFixtures(t *testing.T) {
	tests := []struct {
		name         string
		pipelineFile string
		outputFile   string
		expectedFile string
	}{
		{
			name:         "sort default orders by entity id",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "sort-default-batch.yaml"),
			outputFile:   "sort-default.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "sort-default.txt"),
		},
		{
			name:         "sort xpath orders by metadata attribute value",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "sort-xpath-batch.yaml"),
			outputFile:   "sort-xpath.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "sort-xpath.txt"),
		},
		{
			name:         "finalize emits expected aggregate xml",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "finalize-xml.yaml"),
			outputFile:   "aggregate.xml",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "aggregate.xml"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			outDir := t.TempDir()

			err := RunBatch(t.Context(), BatchOptions{PipelinePath: tc.pipelineFile, OutputDir: outDir})
			if err != nil {
				t.Fatalf("RunBatch returned error: %v", err)
			}

			got, err := os.ReadFile(filepath.Join(outDir, tc.outputFile))
			if err != nil {
				t.Fatalf("failed reading output file: %v", err)
			}

			expected, err := os.ReadFile(tc.expectedFile)
			if err != nil {
				t.Fatalf("failed reading expected file: %v", err)
			}

			if string(got) != string(expected) {
				t.Fatalf("output mismatch\n--- got ---\n%s\n--- expected ---\n%s", string(got), string(expected))
			}
		})
	}
}

func TestRunBatchWhenWrapperFixtures(t *testing.T) {
	tests := []struct {
		name         string
		pipelineFile string
		outputFile   string
		expectedFile string
	}{
		{
			name:         "when update wrapper executes update branch",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "when-update-batch.yaml"),
			outputFile:   "when-update.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "when-update.txt"),
		},
		{
			name:         "when x wrapper executes while request branches are ignored",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "when-x-batch.yaml"),
			outputFile:   "when-x.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "when-x.txt"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			outDir := t.TempDir()

			err := RunBatch(t.Context(), BatchOptions{PipelinePath: tc.pipelineFile, OutputDir: outDir})
			if err != nil {
				t.Fatalf("RunBatch returned error: %v", err)
			}

			got, err := os.ReadFile(filepath.Join(outDir, tc.outputFile))
			if err != nil {
				t.Fatalf("failed reading output file: %v", err)
			}

			expected, err := os.ReadFile(tc.expectedFile)
			if err != nil {
				t.Fatalf("failed reading expected file: %v", err)
			}

			if string(got) != string(expected) {
				t.Fatalf("output mismatch\n--- got ---\n%s\n--- expected ---\n%s", string(got), string(expected))
			}
		})
	}
}

func TestRunBatchPublishPathFixtures(t *testing.T) {
	tests := []struct {
		name         string
		pipelineFile string
		outputFile   string
		expectedFile string
	}{
		{
			name:         "publish inline shorthand writes root output",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "publish-inline-batch.yaml"),
			outputFile:   "inline-publish.txt",
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "publish-inline.txt"),
		},
		{
			name:         "publish mapping as writes nested output",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "publish-mapping-as-batch.yaml"),
			outputFile:   filepath.Join("nested", "mapping-as-publish.txt"),
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "mapping-as-publish.txt"),
		},
		{
			name:         "publish output as resource writes nested output",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "publish-output-as-resource-batch.yaml"),
			outputFile:   filepath.Join("nested", "resource-publish.txt"),
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "resource-publish.txt"),
		},
		{
			name:         "publish output as writes nested output",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "publish-output-as-batch.yaml"),
			outputFile:   filepath.Join("nested", "output-as-publish.txt"),
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "publish-output-as-publish.txt"),
		},
		{
			name:         "publish mapping resource writes nested output",
			pipelineFile: filepath.Join("..", "..", "tests", "fixtures", "pipelines", "publish-mapping-resource.yaml"),
			outputFile:   filepath.Join("nested", "mapping-resource.txt"),
			expectedFile: filepath.Join("..", "..", "tests", "fixtures", "expected", "resource-publish.txt"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			outDir := t.TempDir()

			err := RunBatch(t.Context(), BatchOptions{PipelinePath: tc.pipelineFile, OutputDir: outDir})
			if err != nil {
				t.Fatalf("RunBatch returned error: %v", err)
			}

			got, err := os.ReadFile(filepath.Join(outDir, tc.outputFile))
			if err != nil {
				t.Fatalf("failed reading output file: %v", err)
			}

			expected, err := os.ReadFile(tc.expectedFile)
			if err != nil {
				t.Fatalf("failed reading expected file: %v", err)
			}

			if string(got) != string(expected) {
				t.Fatalf("output mismatch\n--- got ---\n%s\n--- expected ---\n%s", string(got), string(expected))
			}
		})
	}
}

func TestRunBatchPublishHashAndStoreSideEffects(t *testing.T) {
	pipelinePath := filepath.Join(t.TempDir(), "publish-side-effects.yaml")
	pipeline := `pipeline:
  - load:
      entities:
        - https://idp.example.org/idp
  - publish:
      output: side-effects.txt
      hash_link: true
      update_store: true
      store_dir: store
`
	if err := os.WriteFile(pipelinePath, []byte(pipeline), 0o600); err != nil {
		t.Fatalf("failed writing publish side-effects pipeline: %v", err)
	}

	outDir := t.TempDir()
	err := RunBatch(t.Context(), BatchOptions{PipelinePath: pipelinePath, OutputDir: outDir})
	if err != nil {
		t.Fatalf("RunBatch returned error: %v", err)
	}

	body := []byte("https://idp.example.org/idp\n")
	h := sha256.Sum256(body)

	hashLinkPath := filepath.Join(outDir, "side-effects.txt.sha256")
	hashLink, err := os.ReadFile(hashLinkPath)
	if err != nil {
		t.Fatalf("failed reading hash link file: %v", err)
	}
	wantHashLink := fmt.Sprintf("%x  %s\n", h[:], "side-effects.txt")
	if string(hashLink) != wantHashLink {
		t.Fatalf("unexpected hash link content: %q", string(hashLink))
	}

	storePath := filepath.Join(outDir, "store", fmt.Sprintf("%x.txt", h[:]))
	stored, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("failed reading store file: %v", err)
	}
	if string(stored) != string(body) {
		t.Fatalf("unexpected store file content: %q", string(stored))
	}

	linkPath := filepath.Join(outDir, "side-effects.txt.link")
	linkBody, err := os.ReadFile(linkPath)
	if err != nil {
		t.Fatalf("failed reading link file: %v", err)
	}
	if string(linkBody) != filepath.Join("store", fmt.Sprintf("%x.txt", h[:]))+"\n" {
		t.Fatalf("unexpected link file content: %q", string(linkBody))
	}
}

func TestRunBatchSignAndVerifyPipeline(t *testing.T) {
	certFile, keyFile := writeTestCertAndKey(t)

	pipelinePath := filepath.Join(t.TempDir(), "sign-verify.yaml")
	pipeline := fmt.Sprintf(`pipeline:
  - load:
      entities:
        - https://idp.example.org/idp
  - finalize:
      Name: https://metadata.example.org/aggregate
  - sign:
      key: %s
      cert: %s
  - verify:
      cert: %s
  - publish:
      output: signed.xml
`, keyFile, certFile, certFile)

	if err := os.WriteFile(pipelinePath, []byte(pipeline), 0o600); err != nil {
		t.Fatalf("failed writing sign-verify pipeline: %v", err)
	}

	outDir := t.TempDir()
	err := RunBatch(t.Context(), BatchOptions{PipelinePath: pipelinePath, OutputDir: outDir})
	if err != nil {
		t.Fatalf("RunBatch returned error: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(outDir, "signed.xml"))
	if err != nil {
		t.Fatalf("failed reading signed output: %v", err)
	}

	xml := string(b)
	if !strings.Contains(xml, "<ds:Signature") && !strings.Contains(xml, ":Signature") {
		t.Fatalf("expected signature in signed output, got: %s", xml)
	}
}

func TestRunBatchSignVerifyFinalizeDeterministicOutput(t *testing.T) {
	certFile, keyFile := writeTestCertAndKey(t)

	pipelinePath := filepath.Join(t.TempDir(), "deterministic-sign-verify.yaml")
	pipeline := fmt.Sprintf(`pipeline:
  - load:
      entities:
        - https://idp.example.org/idp
        - https://sp.example.org/sp
  - sort:
      order_by: "@entityID"
  - finalize:
      Name: https://metadata.example.org/deterministic
      cacheDuration: PT1H
      validUntil: 2030-01-01T00:00:00Z
  - sign:
      key: %s
      cert: %s
  - verify:
      cert: %s
  - publish:
      output: deterministic-signed.xml
`, keyFile, certFile, certFile)

	if err := os.WriteFile(pipelinePath, []byte(pipeline), 0o600); err != nil {
		t.Fatalf("failed writing deterministic sign/verify pipeline: %v", err)
	}

	outDir1 := t.TempDir()
	outDir2 := t.TempDir()

	if err := RunBatch(t.Context(), BatchOptions{PipelinePath: pipelinePath, OutputDir: outDir1}); err != nil {
		t.Fatalf("first RunBatch returned error: %v", err)
	}

	if err := RunBatch(t.Context(), BatchOptions{PipelinePath: pipelinePath, OutputDir: outDir2}); err != nil {
		t.Fatalf("second RunBatch returned error: %v", err)
	}

	b1, err := os.ReadFile(filepath.Join(outDir1, "deterministic-signed.xml"))
	if err != nil {
		t.Fatalf("failed reading first signed output: %v", err)
	}

	b2, err := os.ReadFile(filepath.Join(outDir2, "deterministic-signed.xml"))
	if err != nil {
		t.Fatalf("failed reading second signed output: %v", err)
	}

	if string(b1) != string(b2) {
		t.Fatalf("deterministic signed output mismatch between runs")
	}

	xml := string(b1)
	if !strings.Contains(xml, "Name=\"https://metadata.example.org/deterministic\"") {
		t.Fatalf("expected finalize Name in signed output, got: %s", xml)
	}
	if !strings.Contains(xml, "cacheDuration=\"PT1H\"") {
		t.Fatalf("expected finalize cacheDuration in signed output, got: %s", xml)
	}
	if !strings.Contains(xml, "validUntil=\"2030-01-01T00:00:00Z\"") {
		t.Fatalf("expected finalize validUntil in signed output, got: %s", xml)
	}
	if !strings.Contains(xml, "<ds:Signature") && !strings.Contains(xml, ":Signature") {
		t.Fatalf("expected signature in signed output, got: %s", xml)
	}
}

func writeTestCertAndKey(t *testing.T) (certFile string, keyFile string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating rsa key: %v", err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          newSerial(t),
		Subject:               pkix.Name{CommonName: "goff-app-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed creating cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	certFile = filepath.Join(t.TempDir(), "test.crt")
	keyFile = filepath.Join(t.TempDir(), "test.key")

	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("failed writing cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("failed writing key: %v", err)
	}

	return certFile, keyFile
}

func newSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("failed generating serial: %v", err)
	}
	return n
}
