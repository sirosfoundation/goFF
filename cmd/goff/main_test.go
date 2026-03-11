package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/sirosfoundation/goff/internal/app"
)

func TestExitCodeForError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "nil", err: nil, want: exitOK},
		{name: "invalid input", err: app.ErrInvalidInput, want: exitInvalidUsage},
		{name: "pipeline parse", err: app.ErrPipelineParse, want: exitPipelineParse},
		{name: "pipeline execute", err: app.ErrPipelineExecute, want: exitPipelineRun},
		{name: "server runtime", err: app.ErrServerRuntime, want: exitServerRuntime},
		{name: "unknown", err: errors.New("boom"), want: 1},
		{name: "wrapped parse", err: fmt.Errorf("wrapped: %w", app.ErrPipelineParse), want: exitPipelineParse},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCodeForError(tc.err); got != tc.want {
				t.Fatalf("exitCodeForError() = %d, want %d", got, tc.want)
			}
		})
	}
}
