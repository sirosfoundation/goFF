package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunServerServesHealthz(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "pipelines", "basic.yaml")

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunServer(ctx, ServerOptions{PipelinePath: fixture, ListenAddr: addr})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, reqErr := http.Get(fmt.Sprintf("http://%s/healthz", addr))
		if reqErr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}

		if time.Now().After(deadline) {
			t.Fatal("server did not become healthy in time")
		}
		time.Sleep(20 * time.Millisecond)
	}

	readyResp, err := http.Get(fmt.Sprintf("http://%s/readyz", addr))
	if err != nil {
		t.Fatalf("failed calling /readyz: %v", err)
	}
	_ = readyResp.Body.Close()
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("expected /readyz 200, got %d", readyResp.StatusCode)
	}

	metricsResp, err := http.Get(fmt.Sprintf("http://%s/metrics", addr))
	if err != nil {
		t.Fatalf("failed calling /metrics: %v", err)
	}
	defer metricsResp.Body.Close()
	if metricsResp.StatusCode != http.StatusOK {
		t.Fatalf("expected /metrics 200, got %d", metricsResp.StatusCode)
	}
	var metricsBody map[string]any
	if err := json.NewDecoder(metricsResp.Body).Decode(&metricsBody); err != nil {
		t.Fatalf("invalid /metrics body: %v", err)
	}
	if metricsBody["requests"] == nil {
		t.Fatalf("expected requests section in metrics body: %#v", metricsBody)
	}
	if metricsBody["server"] == nil {
		t.Fatalf("expected server section in metrics body: %#v", metricsBody)
	}
	if metricsBody["refresh"] == nil {
		t.Fatalf("expected refresh section in metrics body: %#v", metricsBody)
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunServer returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunServer did not return after context cancellation")
	}
}

func TestRunServerRefreshesFromFileSource(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	writeFile(t, metadataPath, metadataXML("https://idp.example.org/idp-1"))

	pipelinePath := filepath.Join(t.TempDir(), "pipeline.yaml")
	writeFile(t, pipelinePath, fmt.Sprintf(`- load:
    files:
      - %s
`, metadataPath))

	addr := reserveAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunServer(ctx, ServerOptions{
			PipelinePath: pipelinePath,
			ListenAddr:   addr,
			RefreshEvery: 100 * time.Millisecond,
		})
	}()

	waitForEntity(t, addr, "https://idp.example.org/idp-1", 3*time.Second)

	writeFile(t, metadataPath, metadataXML("https://idp.example.org/idp-2"))
	waitForEntity(t, addr, "https://idp.example.org/idp-2", 3*time.Second)

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunServer returned error: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("RunServer did not return after context cancellation")
	}
}

func TestRunServerRefreshesFromURLSource(t *testing.T) {
	current := "https://idp.example.org/idp-1"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte(metadataXML(current)))
	}))
	defer ts.Close()

	pipelinePath := filepath.Join(t.TempDir(), "pipeline.yaml")
	writeFile(t, pipelinePath, fmt.Sprintf(`- load:
    urls:
      - %s
`, ts.URL))

	addr := reserveAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunServer(ctx, ServerOptions{
			PipelinePath: pipelinePath,
			ListenAddr:   addr,
			RefreshEvery: 100 * time.Millisecond,
		})
	}()

	waitForEntity(t, addr, "https://idp.example.org/idp-1", 3*time.Second)
	current = "https://idp.example.org/idp-2"
	waitForEntity(t, addr, "https://idp.example.org/idp-2", 3*time.Second)

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunServer returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunServer did not return after context cancellation")
	}
}

func TestRunServerRefreshConcurrentRequestLoad(t *testing.T) {
	metadataPath := filepath.Join(t.TempDir(), "metadata.xml")
	entity1 := "https://idp.example.org/idp-1"
	entity2 := "https://idp.example.org/idp-2"
	writeFile(t, metadataPath, metadataXML(entity1))

	pipelinePath := filepath.Join(t.TempDir(), "pipeline.yaml")
	writeFile(t, pipelinePath, fmt.Sprintf(`- load:
    files:
      - %s
`, metadataPath))

	addr := reserveAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunServer(ctx, ServerOptions{
			PipelinePath: pipelinePath,
			ListenAddr:   addr,
			RefreshEvery: 50 * time.Millisecond,
		})
	}()

	waitForEntity(t, addr, entity1, 3*time.Second)

	loadCtx, stopLoad := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer stopLoad()

	var reqErrors atomic.Int64
	var badStatus atomic.Int64
	var wg sync.WaitGroup

	// Share a single transport so we can explicitly drain its keep-alive pool
	// before cancelling the server, avoiding a shutdown timeout race.
	sharedTransport := &http.Transport{MaxIdleConns: 30, MaxIdleConnsPerHost: 30}

	requestWorker := func() {
		defer wg.Done()
		client := &http.Client{Timeout: 250 * time.Millisecond, Transport: sharedTransport}
		for {
			select {
			case <-loadCtx.Done():
				return
			default:
			}

			// Repository listing should remain available and valid under refresh churn.
			resp, err := client.Get(fmt.Sprintf("http://%s/entities", addr))
			if err != nil {
				reqErrors.Add(1)
				continue
			}
			if resp.StatusCode != http.StatusOK {
				badStatus.Add(1)
			}
			_ = resp.Body.Close()

			// Entity lookups may legitimately return 404 during swaps, but not 5xx.
			resp, err = client.Get(fmt.Sprintf("http://%s/entities/%s.xml", addr, "https:%2F%2Fidp.example.org%2Fidp-1"))
			if err != nil {
				reqErrors.Add(1)
				continue
			}
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
				badStatus.Add(1)
			}
			_ = resp.Body.Close()

			resp, err = client.Get(fmt.Sprintf("http://%s/entities/%s.xml", addr, "https:%2F%2Fidp.example.org%2Fidp-2"))
			if err != nil {
				reqErrors.Add(1)
				continue
			}
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
				badStatus.Add(1)
			}
			_ = resp.Body.Close()
		}
	}

	workers := 12
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go requestWorker()
	}

	// Trigger multiple repository swaps while requests are in flight.
	writeFile(t, metadataPath, metadataXML(entity2))
	waitForEntity(t, addr, entity2, 3*time.Second)
	time.Sleep(120 * time.Millisecond)
	writeFile(t, metadataPath, metadataXML(entity1))
	waitForEntity(t, addr, entity1, 3*time.Second)
	time.Sleep(120 * time.Millisecond)
	writeFile(t, metadataPath, metadataXML(entity2))
	waitForEntity(t, addr, entity2, 3*time.Second)

	stopLoad()
	wg.Wait()
	sharedTransport.CloseIdleConnections() // drain pool before server shutdown to avoid deadline race

	if reqErrors.Load() != 0 {
		t.Fatalf("unexpected request errors during concurrent refresh load: %d", reqErrors.Load())
	}
	if badStatus.Load() != 0 {
		t.Fatalf("unexpected non-200/404 statuses during concurrent refresh load: %d", badStatus.Load())
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunServer returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunServer did not return after context cancellation")
	}
}

func reserveAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func waitForEntity(t *testing.T, addr string, entityID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)

	for {
		resp, err := http.Get(fmt.Sprintf("http://%s/entities", addr))
		if err == nil {
			var body struct {
				Entities []string `json:"entities"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&body)
			_ = resp.Body.Close()

			if contains(body.Entities, entityID) {
				return
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("entity %q not observed before timeout", entityID)
		}

		time.Sleep(25 * time.Millisecond)
	}
}

func contains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed writing %s: %v", path, err)
	}
}

func metadataXML(entityID string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID=%q/>
</md:EntitiesDescriptor>`, entityID)
}
