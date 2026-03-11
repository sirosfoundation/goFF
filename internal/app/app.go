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
}

// ServerOptions holds command-line options for server execution.
type ServerOptions struct {
	PipelinePath string
	ListenAddr   string
	OutputDir    string
	RefreshEvery time.Duration
}

type serverRuntimeMetrics struct {
	ready               atomic.Bool
	refreshSuccessTotal atomic.Uint64
	refreshFailureTotal atomic.Uint64
	lastRefreshUnix     atomic.Int64
}

// RunBatch validates input and executes a placeholder batch workflow.
func RunBatch(_ context.Context, opts BatchOptions) error {
	if opts.PipelinePath == "" {
		return fmt.Errorf("%w: --pipeline is required", ErrInvalidInput)
	}

	p, err := pipeline.ParseFile(opts.PipelinePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPipelineParse, err)
	}

	res, err := pipeline.Execute(p, opts.OutputDir)
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
		mdq.WithExtraMetrics(func() map[string]any {
			return map[string]any{
				"server": map[string]any{
					"ready": metrics.ready.Load(),
				},
				"refresh": map[string]any{
					"success_total":  metrics.refreshSuccessTotal.Load(),
					"failure_total":  metrics.refreshFailureTotal.Load(),
					"last_refresh_unix": metrics.lastRefreshUnix.Load(),
					"entity_count":   len(r.List()),
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
				}
				log.Printf("goff refresh error: %v", err)
				continue
			}

				r.Replace(res.Entities, res.EntityXML)
			if metrics != nil {
				metrics.refreshSuccessTotal.Add(1)
				metrics.lastRefreshUnix.Store(time.Now().Unix())
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
