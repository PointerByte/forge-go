// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package traces

import (
	"context"
	"errors"
	"sync"

	"github.com/PointerByte/forge-go/logger/builder"
)

var initLoggerFn = builder.InitLogger

// InitTelemetry initializes every OpenTelemetry signal Forge owns — logs,
// metrics and traces — and returns a single bounded shutdown for all of them.
//
// It is the one-call entry point for applications that do not use the Gin or
// gRPC server bootstraps, which compose the same pipelines in the same order
// themselves. logDir is the directory the structured logger writes its rotated
// files to; it is used exactly as builder.InitLogger uses it.
//
// Each signal is configured independently through the standard environment
// variables (OTEL_LOGS_EXPORTER, OTEL_METRICS_EXPORTER, OTEL_TRACES_EXPORTER),
// and OTEL_SDK_DISABLED turns all of them off at once. With telemetry disabled
// no exporter is constructed and no collector is contacted, so an application
// that never runs a collector keeps working — the structured logger still
// writes to its local sinks.
//
// The returned shutdown flushes logs, then metrics, then traces, which is the
// order that lets a log record emitted during metric or trace shutdown still
// reach an exporter. It honours the deadline of the context it is given, so an
// unreachable collector delays shutdown by at most that deadline instead of
// blocking forever. Calling it more than once is safe and returns the result of
// the first call.
func InitTelemetry(ctx context.Context, logDir string) (func(context.Context) error, error) {
	loggerProvider, err := initLoggerFn(ctx, logDir)
	if err != nil {
		return nil, err
	}

	shutdownOtel, err := initOtelFn(ctx)
	if err != nil {
		return nil, errors.Join(err, loggerProvider.Shutdown(ctx))
	}

	var (
		once     sync.Once
		shutdown error
	)
	return func(ctx context.Context) error {
		once.Do(func() {
			shutdown = errors.Join(
				loggerProvider.Shutdown(ctx),
				shutdownOtel(ctx),
			)
		})
		return shutdown
	}, nil
}
