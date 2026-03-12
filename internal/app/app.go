package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
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
}

type serverRuntimeMetrics struct {
	ready               atomic.Bool
	refreshSuccessTotal atomic.Uint64
	refreshFailureTotal atomic.Uint64
	lastRefreshUnix     atomic.Int64
	lastRefreshError    atomic.Value // stores string; empty means last refresh succeeded
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
			fmt.Printf("[step %d] %s: %s\n", step, action, msg)
		}
	}

	res, err := pipeline.Execute(p, opts.OutputDir, execOpts)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPipelineExecute, err)
	}

	fmt.Printf("batch mode: pipeline=%s output=%s entities=%d\n", opts.PipelinePath, opts.OutputDir, len(res.Entities))
	return nil
}

// RunServer builds a repository from pipeline output and starts an MDQ-like server.
func RunServer(ctx context.Context, opts ServerOptions) error {
	if opts.PipelinePath == "" {
		return fmt.Errorf("%w: --pipeline is required", ErrInvalidInput)
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

	h := mdq.NewHandler(
		r,
		mdq.WithReadiness(func() bool { return metrics.ready.Load() }),
		mdq.WithBaseURL(opts.BaseURL),
		mdq.WithAggregateConfig(pipeline.AggregateConfig{
			CacheDuration: opts.CacheDuration,
			ValidUntil:    opts.ValidUntil,
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
				},
			}
		}),
	)
	srv := &http.Server{Addr: opts.ListenAddr, Handler: h}

	fmt.Printf("server mode: pipeline=%s listen=%s entities=%d\n", opts.PipelinePath, opts.ListenAddr, len(res.Entities))

	if opts.RefreshEvery > 0 {
		go runRefreshLoop(ctx, r, opts.PipelinePath, outputDir, opts.RefreshEvery, metrics)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		metrics.ready.Store(false)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

func runRefreshLoop(ctx context.Context, r *repo.Repository, pipelinePath string, outputDir string, every time.Duration, metrics *serverRuntimeMetrics) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			res, err := runPipeline(pipelinePath, outputDir)
			if err != nil {
				if metrics != nil {
					metrics.refreshFailureTotal.Add(1)
					metrics.lastRefreshError.Store(err.Error())
				}
				log.Printf("goff refresh error: %v", err)
				continue
			}

			r.Replace(res.Entities, res.EntityXML)
			if metrics != nil {
				metrics.refreshSuccessTotal.Add(1)
				metrics.lastRefreshUnix.Store(time.Now().Unix())
				metrics.lastRefreshError.Store("")
			}
			log.Printf("goff refresh complete: entities=%d", len(res.Entities))
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
