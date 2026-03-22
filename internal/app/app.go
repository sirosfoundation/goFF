package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sirosfoundation/goff/internal/mdq"
	"github.com/sirosfoundation/goff/internal/pipeline"
	"github.com/sirosfoundation/goff/internal/repo"
)

// BatchOptions holds command-line options for batch execution.
type BatchOptions struct {
	PipelinePath string
	OutputDir    string
	Verbose      bool
}

// ServerOptions holds command-line options for server execution.
type ServerOptions struct {
	PipelinePath string
	ListenAddr   string
	OutputDir    string
	RefreshEvery time.Duration
	// BaseURL is the externally-visible base URL (e.g. "https://mdq.example.org").
	// Used to derive @Name on aggregate responses.  When empty, the value is
	// auto-detected from X-Forwarded-Proto / X-Forwarded-Host / Host headers.
	BaseURL string
	// CacheDuration is an ISO 8601 duration (e.g. "PT48H") set as
	// @cacheDuration on aggregate XML responses and as Cache-Control max-age.
	CacheDuration string
	// ValidUntil is an RFC 3339 timestamp or a "+<go-duration>" offset
	// (e.g. "+48h") set as @validUntil on aggregate XML responses and as
	// the Expires header.
	ValidUntil string
	// TLSCert and TLSKey enable HTTPS when both are set.
	TLSCert string
	TLSKey  string
	// ShutdownTimeout is the maximum time to wait for in-flight requests to
	// complete during a graceful shutdown.  Defaults to 15 seconds.
	ShutdownTimeout time.Duration
	// EntityRendererMode controls the JSON serialization strategy for
	// GET /entities/{id} with Accept: application/json.
	//
	//   ""  or "auto"   IndexedDiscoRenderer when the pipeline produced disco
	//                   entries, MinimalRenderer otherwise.
	//   "minimal"       always {"entityID":"..."} (backward-compatible).
	//   "disco"         always IndexedDiscoRenderer (empty index when no disco
	//                   step ran, causing entity-ID-only fallback per entity).
	EntityRendererMode string
}

type serverRuntimeMetrics struct {
	ready               atomic.Bool
	refreshSuccessTotal atomic.Uint64
	refreshFailureTotal atomic.Uint64
	lastRefreshUnix     atomic.Int64
	lastRefreshError    atomic.Value // stores string; empty means last refresh succeeded
	// staleCount tracks consecutive refresh failures; reset to 0 on success.
	staleCount atomic.Uint64
	// staleSinceUnix is set to the Unix time of the first consecutive failure;
	// reset to 0 on a successful refresh.
	staleSinceUnix atomic.Int64
	// aggregateCfg holds the current merged SAML aggregate configuration
	// (pipeline finalize values + CLI overrides).  Updated atomically on reload.
	aggregateCfg atomic.Pointer[pipeline.AggregateConfig]
	// discoJSON holds the discovery-service JSON feed entries built by the most
	// recent discojson step.  Updated atomically on reload.  Nil pointer means
	// no disco feed was produced by the pipeline.
	discoJSON atomic.Pointer[[]pipeline.DiscoEntry]
	// renderer holds the current entity JSON renderer for /entities/{id}.
	// Updated atomically on reload so that adding or removing a discojson step
	// from the pipeline transparently upgrades or downgrades the renderer.
	renderer atomic.Pointer[mdq.EntityRenderer]
}

// RunBatch validates input, parses the pipeline, and executes it in batch mode.
func RunBatch(_ context.Context, opts BatchOptions) error {
	if opts.PipelinePath == "" {
		return fmt.Errorf("%w: --pipeline is required", ErrInvalidInput)
	}

	p, err := pipeline.ParseFile(opts.PipelinePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPipelineParse, err)
	}

	var execOpts pipeline.ExecuteOptions
	if opts.Verbose {
		execOpts.Progress = func(step int, action, msg string) {
			slog.Info("step", "n", step, "action", action, "msg", msg)
		}
	}

	res, err := pipeline.Execute(p, opts.OutputDir, execOpts)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPipelineExecute, err)
	}

	slog.Info("batch complete", "pipeline", opts.PipelinePath, "output", opts.OutputDir, "entities", len(res.Entities))
	return nil
}

// RunServer builds a repository from pipeline output and starts an MDQ-like server.
func RunServer(ctx context.Context, opts ServerOptions) error {
	if opts.PipelinePath == "" {
		return fmt.Errorf("%w: --pipeline is required", ErrInvalidInput)
	}

	shutdownTimeout := opts.ShutdownTimeout
	if shutdownTimeout <= 0 {
		shutdownTimeout = 15 * time.Second
	}

	outputDir := opts.OutputDir
	cleanup := func() {}
	if outputDir == "" {
		tmpDir, err := os.MkdirTemp("", "goff-server-pipeline-*")
		if err != nil {
			return fmt.Errorf("%w: create temp output dir: %v", ErrServerRuntime, err)
		}
		outputDir = tmpDir
		cleanup = func() { _ = os.RemoveAll(tmpDir) }
	}
	defer cleanup()

	res, err := runPipeline(opts.PipelinePath, outputDir)
	if err != nil {
		return err
	}

	r := repo.New(res.Entities, res.EntityXML)
	metrics := &serverRuntimeMetrics{}
	metrics.ready.Store(true)
	metrics.refreshSuccessTotal.Store(1)
	metrics.lastRefreshUnix.Store(time.Now().Unix())

	// Merge pipeline finalize values with CLI overrides (CLI takes precedence).
	initAC := mergeAggregateConfig(opts, res.Finalize)
	metrics.aggregateCfg.Store(&initAC)

	// Store initial disco JSON from pipeline (may be nil if no discojson step ran).
	initDisco := res.DiscoJSON
	metrics.discoJSON.Store(&initDisco)

	// Select and store initial entity renderer based on mode + pipeline output.
	initRenderer := selectRenderer(opts.EntityRendererMode, res.DiscoJSON)
	metrics.renderer.Store(&initRenderer)

	h := mdq.NewHandler(
		r,
		mdq.WithReadiness(func() bool { return metrics.ready.Load() }),
		mdq.WithBaseURL(opts.BaseURL),
		mdq.WithAggregateConfigFunc(func() pipeline.AggregateConfig {
			if p := metrics.aggregateCfg.Load(); p != nil {
				return *p
			}
			return pipeline.AggregateConfig{}
		}),
		mdq.WithDiscoJSON(func() []pipeline.DiscoEntry {
			if p := metrics.discoJSON.Load(); p != nil {
				return *p
			}
			return nil
		}),
		mdq.WithEntityRendererFunc(func() mdq.EntityRenderer {
			if p := metrics.renderer.Load(); p != nil {
				return *p
			}
			return mdq.MinimalRenderer{}
		}),
		mdq.WithExtraMetrics(func() map[string]any {
			return map[string]any{
				"server": map[string]any{
					"ready": metrics.ready.Load(),
				},
				"refresh": map[string]any{
					"success_total":     metrics.refreshSuccessTotal.Load(),
					"failure_total":     metrics.refreshFailureTotal.Load(),
					"last_refresh_unix": metrics.lastRefreshUnix.Load(),
					"entity_count":      len(r.List()),
					"last_error":        func() string { s, _ := metrics.lastRefreshError.Load().(string); return s }(),
					"stale_count":       metrics.staleCount.Load(),
					"stale_since_unix":  metrics.staleSinceUnix.Load(),
				},
			}
		}),
	)

	srv := &http.Server{
		Addr:              opts.ListenAddr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      60 * time.Second, // generous for large XML aggregate responses
		IdleTimeout:       120 * time.Second,
	}

	if opts.TLSCert != "" && opts.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(opts.TLSCert, opts.TLSKey)
		if err != nil {
			return fmt.Errorf("%w: load TLS key pair: %v", ErrServerRuntime, err)
		}
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	slog.Info("server starting", "pipeline", opts.PipelinePath, "listen", opts.ListenAddr, "entities", len(res.Entities))

	if opts.RefreshEvery > 0 {
		go runRefreshLoop(ctx, r, opts.PipelinePath, outputDir, opts.RefreshEvery, metrics, opts)
	}

	// SIGHUP triggers an immediate out-of-band pipeline refresh.
	sigHUP := make(chan os.Signal, 1)
	signal.Notify(sigHUP, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigHUP:
				slog.Info("SIGHUP received — refreshing pipeline")
				reloadPipeline(r, opts.PipelinePath, outputDir, metrics, opts)
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		if srv.TLSConfig != nil {
			errCh <- srv.ListenAndServeTLS("", "")
		} else {
			errCh <- srv.ListenAndServe()
		}
	}()

	select {
	case <-ctx.Done():
		metrics.ready.Store(false)
		signal.Stop(sigHUP)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("%w: shutdown server: %v", ErrServerRuntime, err)
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("%w: %v", ErrServerRuntime, err)
	}
}

// reloadPipeline re-runs the pipeline and atomically replaces the repository,
// aggregate config, and discovery JSON.
func reloadPipeline(r *repo.Repository, pipelinePath, outputDir string, metrics *serverRuntimeMetrics, opts ServerOptions) {
	res, err := runPipeline(pipelinePath, outputDir)
	if err != nil {
		if metrics != nil {
			metrics.refreshFailureTotal.Add(1)
			metrics.lastRefreshError.Store(err.Error())
			metrics.staleCount.Add(1)
			if metrics.staleSinceUnix.Load() == 0 {
				metrics.staleSinceUnix.Store(time.Now().Unix())
			}
		}
		slog.Error("refresh failed", "err", err)
		return
	}
	r.Replace(res.Entities, res.EntityXML)
	if metrics != nil {
		// Update aggregate config from merged pipeline finalize + CLI opts.
		newAC := mergeAggregateConfig(opts, res.Finalize)
		metrics.aggregateCfg.Store(&newAC)

		// Update disco JSON feed.
		newDisco := res.DiscoJSON
		metrics.discoJSON.Store(&newDisco)

		// Update entity renderer; renderer type changes if a discojson step is
		// added or removed between refreshes.
		newRenderer := selectRenderer(opts.EntityRendererMode, res.DiscoJSON)
		metrics.renderer.Store(&newRenderer)

		metrics.refreshSuccessTotal.Add(1)
		metrics.lastRefreshUnix.Store(time.Now().Unix())
		metrics.lastRefreshError.Store("")
		metrics.staleCount.Store(0)
		metrics.staleSinceUnix.Store(0)
	}
	slog.Info("refresh complete", "entities", len(res.Entities))
}

func runRefreshLoop(ctx context.Context, r *repo.Repository, pipelinePath string, outputDir string, every time.Duration, metrics *serverRuntimeMetrics, opts ServerOptions) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reloadPipeline(r, pipelinePath, outputDir, metrics, opts)
		}
	}
}

func runPipeline(pipelinePath string, outputDir string) (pipeline.Result, error) {
	p, err := pipeline.ParseFile(pipelinePath)
	if err != nil {
		return pipeline.Result{}, fmt.Errorf("%w: %v", ErrPipelineParse, err)
	}

	res, err := pipeline.Execute(p, outputDir)
	if err != nil {
		return pipeline.Result{}, fmt.Errorf("%w: %v", ErrPipelineExecute, err)
	}

	return res, nil
}

// mergeAggregateConfig builds a pipeline.AggregateConfig from the pipeline's
// finalize step values, with CLI option overrides taking precedence.
// Priority: CLI opts > pipeline finalize defaults.
func mergeAggregateConfig(opts ServerOptions, finalize pipeline.FinalizeStep) pipeline.AggregateConfig {
	name := finalize.Name
	if opts.BaseURL != "" {
		name = opts.BaseURL + "/entities"
	}
	cacheDuration := finalize.CacheDuration
	if opts.CacheDuration != "" {
		cacheDuration = opts.CacheDuration
	}
	validUntil := finalize.ValidUntil
	if opts.ValidUntil != "" {
		validUntil = opts.ValidUntil
	}
	return pipeline.AggregateConfig{
		Name:          name,
		CacheDuration: cacheDuration,
		ValidUntil:    validUntil,
	}
}

// selectRenderer picks the EntityRenderer appropriate for the given mode and
// available disco entries.
//
//   - "" / "auto":  IndexedDiscoRenderer when entries are available, else MinimalRenderer.
//   - "minimal":    always MinimalRenderer.
//   - "disco":      IndexedDiscoRenderer regardless (empty index → entity-ID fallback).
func selectRenderer(mode string, discoEntries []pipeline.DiscoEntry) mdq.EntityRenderer {
	switch strings.ToLower(mode) {
	case "minimal":
		return mdq.MinimalRenderer{}
	case "disco":
		return mdq.NewIndexedDiscoRenderer(discoEntries)
	default: // "auto" or ""
		if len(discoEntries) > 0 {
			return mdq.NewIndexedDiscoRenderer(discoEntries)
		}
		return mdq.MinimalRenderer{}
	}
}
