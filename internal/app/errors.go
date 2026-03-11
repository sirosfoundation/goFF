package app

import "errors"

var (
	// ErrInvalidInput indicates missing or invalid CLI-provided input.
	ErrInvalidInput = errors.New("invalid input")
	// ErrPipelineParse indicates pipeline parsing or loading failed.
	ErrPipelineParse = errors.New("pipeline parse failed")
	// ErrPipelineExecute indicates pipeline execution failed after parsing.
	ErrPipelineExecute = errors.New("pipeline execution failed")
	// ErrServerRuntime indicates server startup or runtime failures.
	ErrServerRuntime = errors.New("server runtime failed")
)
