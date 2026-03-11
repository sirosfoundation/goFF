package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sirosfoundation/goff/internal/app"
)

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
	ctx := context.Background()

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(exitInvalidUsage)
	}

	cmd := os.Args[1]
	switch cmd {
	case "version":
		fmt.Println(Version)
	case "batch":
		batchFlags := flag.NewFlagSet("batch", flag.ExitOnError)
		pipeline := batchFlags.String("pipeline", "", "Path to pipeline YAML")
		output := batchFlags.String("output", "./out", "Output directory")
		_ = batchFlags.Parse(os.Args[2:])

		err := app.RunBatch(ctx, app.BatchOptions{PipelinePath: *pipeline, OutputDir: *output})
		if err != nil {
			fmt.Fprintf(os.Stderr, "batch error: %v\n", err)
			os.Exit(exitCodeForError(err))
		}
	case "server":
		serverFlags := flag.NewFlagSet("server", flag.ExitOnError)
		pipeline := serverFlags.String("pipeline", "", "Path to pipeline YAML used to build repository")
		listen := serverFlags.String("listen", ":8080", "HTTP listen address")
		output := serverFlags.String("output", "", "Pipeline output directory used during refresh runs (optional)")
		refreshEvery := serverFlags.Duration("refresh-interval", 5*time.Minute, "Pipeline refresh interval (0 disables refresh loop)")
		_ = serverFlags.Parse(os.Args[2:])

		err := app.RunServer(ctx, app.ServerOptions{PipelinePath: *pipeline, ListenAddr: *listen, OutputDir: *output, RefreshEvery: *refreshEvery})
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
}
