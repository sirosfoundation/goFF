package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/sirosfoundation/goff/internal/app"
)

// envOr returns the environment variable value for key if set and non-empty,
// otherwise it returns def.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envDurOr returns a time.Duration from an environment variable,
// falling back to def on parse failure or empty value.
func envDurOr(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		slog.Warn("invalid duration in env var, using default", "key", key, "value", v)
	}
	return def
}

// configureLogging initialises the default slog logger from environment variables.
//
//	GOFF_LOG_LEVEL  : debug | info (default) | warn | error
//	GOFF_LOG_FORMAT : text (default) | json
func configureLogging() {
	var level slog.Level
	switch strings.ToLower(os.Getenv("GOFF_LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.EqualFold(os.Getenv("GOFF_LOG_FORMAT"), "json") {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
}

// Version is injected by build flags.
var Version = "dev"

const (
	exitOK            = 0
	exitInvalidUsage  = 2
	exitPipelineParse = 3
	exitPipelineRun   = 4
	exitServerRuntime = 5
)

func main() {
	configureLogging()
	ctx := context.Background()

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(exitInvalidUsage)
	}

	cmd := os.Args[1]
	switch cmd {
	case "version":
		fmt.Printf("%s (features: %s)\n", Version, buildFeatures)
	case "batch":
		batchFlags := flag.NewFlagSet("batch", flag.ExitOnError)
		pipeline := batchFlags.String("pipeline", envOr("GOFF_PIPELINE", ""), "Path to pipeline YAML (env: GOFF_PIPELINE)")
		output := batchFlags.String("output", envOr("GOFF_OUTPUT", "./out"), "Output directory (env: GOFF_OUTPUT)")
		verbose := batchFlags.Bool("verbose", false, "Print per-step progress")
		_ = batchFlags.Parse(os.Args[2:])

		err := app.RunBatch(ctx, app.BatchOptions{PipelinePath: *pipeline, OutputDir: *output, Verbose: *verbose})
		if err != nil {
			fmt.Fprintf(os.Stderr, "batch error: %v\n", err)
			os.Exit(exitCodeForError(err))
		}
	case "server":
		serverFlags := flag.NewFlagSet("server", flag.ExitOnError)
		pipeline := serverFlags.String("pipeline", envOr("GOFF_PIPELINE", ""), "Path to pipeline YAML (env: GOFF_PIPELINE)")
		listen := serverFlags.String("listen", envOr("GOFF_LISTEN", ":8080"), "HTTP listen address (env: GOFF_LISTEN)")
		output := serverFlags.String("output", envOr("GOFF_OUTPUT_DIR", ""), "Pipeline output directory (optional, env: GOFF_OUTPUT_DIR)")
		refreshEvery := serverFlags.Duration("refresh-interval", envDurOr("GOFF_REFRESH_INTERVAL", 5*time.Minute), "Pipeline refresh interval (0 disables, env: GOFF_REFRESH_INTERVAL)")
		baseURL := serverFlags.String("base-url", envOr("GOFF_BASE_URL", ""), "Externally-visible base URL (env: GOFF_BASE_URL)")
		cacheDuration := serverFlags.String("cache-duration", envOr("GOFF_CACHE_DURATION", ""), "ISO 8601 cache duration for XML responses (env: GOFF_CACHE_DURATION)")
		validUntil := serverFlags.String("valid-until", envOr("GOFF_VALID_UNTIL", ""), "RFC 3339 or +<duration> validUntil (env: GOFF_VALID_UNTIL)")
		tlsCert := serverFlags.String("tls-cert", envOr("GOFF_TLS_CERT", ""), "Path to TLS certificate PEM file (env: GOFF_TLS_CERT)")
		tlsKey := serverFlags.String("tls-key", envOr("GOFF_TLS_KEY", ""), "Path to TLS private key PEM file (env: GOFF_TLS_KEY)")
		shutdownTimeout := serverFlags.Duration("shutdown-timeout", envDurOr("GOFF_SHUTDOWN_TIMEOUT", 15*time.Second), "Graceful shutdown timeout (env: GOFF_SHUTDOWN_TIMEOUT)")
		entityRenderer := serverFlags.String("entity-renderer", envOr("GOFF_ENTITY_RENDERER", "auto"), "Entity JSON renderer: auto|minimal|disco (env: GOFF_ENTITY_RENDERER)")
		_ = serverFlags.Parse(os.Args[2:])

		err := app.RunServer(ctx, app.ServerOptions{
			PipelinePath:       *pipeline,
			ListenAddr:         *listen,
			OutputDir:          *output,
			RefreshEvery:       *refreshEvery,
			BaseURL:            *baseURL,
			CacheDuration:      *cacheDuration,
			ValidUntil:         *validUntil,
			TLSCert:            *tlsCert,
			TLSKey:             *tlsKey,
			ShutdownTimeout:    *shutdownTimeout,
			EntityRendererMode: *entityRenderer,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(exitCodeForError(err))
		}
	default:
		printUsage()
		os.Exit(exitInvalidUsage)
	}
}

func exitCodeForError(err error) int {
	if err == nil {
		return exitOK
	}

	switch {
	case errors.Is(err, app.ErrInvalidInput):
		return exitInvalidUsage
	case errors.Is(err, app.ErrPipelineParse):
		return exitPipelineParse
	case errors.Is(err, app.ErrPipelineExecute):
		return exitPipelineRun
	case errors.Is(err, app.ErrServerRuntime):
		return exitServerRuntime
	default:
		return 1
	}
}

func printUsage() {
	fmt.Println("goff <command> [flags]")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("  version                  Print version")
	fmt.Println("  batch  --pipeline <p>    Run pipeline in batch mode")
	fmt.Println("  server --pipeline <p>    Build repository and run MDQ server (xml/json content negotiation)")
	fmt.Println("")
	fmt.Println("Server flags (all have matching GOFF_* env vars):")
	fmt.Println("  --pipeline <path>         (env: GOFF_PIPELINE)")
	fmt.Println("  --listen <addr>           (env: GOFF_LISTEN, default :8080)")
	fmt.Println("  --refresh-interval <dur>  (env: GOFF_REFRESH_INTERVAL, default 5m)")
	fmt.Println("  --base-url <url>          (env: GOFF_BASE_URL)")
	fmt.Println("  --cache-duration <ISO>    (env: GOFF_CACHE_DURATION)")
	fmt.Println("  --valid-until <ts>        (env: GOFF_VALID_UNTIL)")
	fmt.Println("  --tls-cert <path>         (env: GOFF_TLS_CERT)")
	fmt.Println("  --tls-key <path>          (env: GOFF_TLS_KEY)")
	fmt.Println("  --shutdown-timeout <dur>  (env: GOFF_SHUTDOWN_TIMEOUT, default 15s)")
	fmt.Println("  --entity-renderer <mode>  (env: GOFF_ENTITY_RENDERER, default auto; values: auto|minimal|disco)")
}
