// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/spf13/viper"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	// logsExporterEnv selects the log exporter, mirroring OTEL_TRACES_EXPORTER
	// and OTEL_METRICS_EXPORTER.
	logsExporterEnv = "OTEL_LOGS_EXPORTER"
	// logsProtocolEnv and otlpProtocolEnv select the OTLP transport, the
	// signal-specific variable taking precedence over the shared one.
	logsProtocolEnv = "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL"
	otlpProtocolEnv = "OTEL_EXPORTER_OTLP_PROTOCOL"

	exporterNone      = "none"
	exporterOTLP      = "otlp"
	protocolHTTPProto = "http/protobuf"
)

var new = otlploghttp.New
var newLoggerProvider = sdklog.NewLoggerProvider
var resourceDefault = resource.Default
var newSchemaless = resource.NewSchemaless
var resourceMerge = resource.Merge

// signalExporterName returns the first non-empty exporter name configured in
// key, or fallback when the variable is unset, empty, or made up only of empty
// entries.
//
// The logger is a standalone module and cannot import the root module's
// equivalent helper, so the semantics are reproduced here: comma-separated
// list, first non-empty entry wins, trimmed and lowercased.
func signalExporterName(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		value = fallback
	}

	for item := range strings.SplitSeq(value, ",") {
		name := strings.ToLower(strings.TrimSpace(item))
		if name != "" {
			return name
		}
	}
	return fallback
}

// signalProtocol resolves the OTLP protocol for logs, preferring the
// signal-specific variable over the shared one.
func signalProtocol() string {
	if value := strings.TrimSpace(os.Getenv(logsProtocolEnv)); value != "" {
		return strings.ToLower(value)
	}
	if value := strings.TrimSpace(os.Getenv(otlpProtocolEnv)); value != "" {
		return strings.ToLower(value)
	}
	return protocolHTTPProto
}

// newLogExporter creates the exporter named by exporterName, which the caller
// has already resolved and verified not to be "none".
func newLogExporter(ctx context.Context, exporterName string) (sdklog.Exporter, error) {
	switch exporterName {
	case exporterOTLP:
		switch signalProtocol() {
		case protocolHTTPProto:
			exporter, err := new(ctx)
			if err != nil {
				return nil, err
			}
			return exporter, nil
		default:
			return nil, errors.New("unsupported " + logsProtocolEnv + " value")
		}
	default:
		return nil, errors.New("unsupported " + logsExporterEnv + " value")
	}
}

// newCofigLoggerProvider builds the logger provider selected by the current
// OTEL log configuration. The second result reports whether log export is
// enabled, so callers can skip the bridge that feeds the provider.
//
// Export is off unless OTEL_LOGS_EXPORTER asks for it: an exporter built with
// the spec defaults targets https://localhost:4318/v1/logs, and every failed
// batch export is reported through otel.Handle, which lands back in this
// package's own slog handler.
func newCofigLoggerProvider(ctx context.Context) (*sdklog.LoggerProvider, bool, error) {
	exporterName := signalExporterName(logsExporterEnv, exporterNone)
	if exporterName == exporterNone {
		// A provider without processors is valid: it drops every record and
		// shuts down cleanly, so callers keep a non-nil provider to close.
		return newLoggerProvider(), false, nil
	}

	exporter, err := newLogExporter(ctx, exporterName)
	if err != nil {
		return nil, false, err
	}
	res, err := resourceMerge(
		resourceDefault(),
		newSchemaless(
			semconv.ServiceName(viperdata.GetViperData(string(viperdata.AppAtribute)).(string)),
			semconv.ServiceVersion(viperdata.GetViperData(string(viperdata.AppVersionAtribute)).(string)),
		),
	)
	if err != nil {
		return nil, false, err
	}

	provider := newLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
		sdklog.WithResource(res),
	)
	return provider, true, nil
}

var _newCofigLoggerProvider = newCofigLoggerProvider
var filepathAbs = filepath.Abs

// InitLogger initializes and configures the application's logger.
// It builds the log file path, configures the OpenTelemetry logger provider,
// and returns the logger provider so it can be shut down gracefully when needed.
//
// The returned provider is never nil on success. Log export is disabled unless
// OTEL_LOGS_EXPORTER selects an exporter, in which case the provider carries no
// processor and the OpenTelemetry bridge is not attached to the slog handler.
//
// When running the application as a server, logging is already initialized
// automatically, so calling this function manually is not necessary.
// However, in non-server contexts, you can call InitLogger to set up logging.
func InitLogger(ctx context.Context, dir string) (*sdklog.LoggerProvider, error) {
	// ---- File path configuration ----
	filePath := viperdata.GetViperData(string(viperdata.AppAtribute)).(string) + ".log"
	fileStr := filepath.Join(dir, filePath)

	// Save path complete
	bsFile, err := filepathAbs(fileStr)
	if err != nil {
		return nil, err
	}
	dir = filepath.Dir(bsFile)
	fullPath := filepath.Join(dir, filePath)

	// ---- Telemetry ----
	lp, exportEnabled, err := _newCofigLoggerProvider(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger provider: %v", err)
	}

	// Attach the bridge only when something consumes it, so a disabled export
	// costs nothing per record instead of building records that are dropped.
	var otelHandlers []slog.Handler
	if exportEnabled {
		otelHandlers = append(otelHandlers, otelslog.NewHandler(
			"github.com/PointerByte/forge-go/logger",
			otelslog.WithLoggerProvider(lp),
			otelslog.WithSource(true),
		))
	}

	var mw io.Writer = os.Stdout
	if viperdata.GetViperData(string(viperdata.LoggerRotateEnableAtribute)).(bool) {
		// ---- Lumberjack Logger ----
		logFile := &lumberjack.Logger{
			Filename:   fullPath,
			MaxSize:    viperdata.GetViperData(string(viperdata.LoggerRotateMaxSizeAtribute)).(int),
			MaxAge:     viperdata.GetViperData(string(viperdata.LoggerRotateMaxAgeAtribute)).(int),
			MaxBackups: viperdata.GetViperData(string(viperdata.LoggerRotateMaxBackupsAtribute)).(int),
			Compress:   viperdata.GetViperData(string(viperdata.LoggerCompressMaxAgeAtribute)).(bool),
		}
		// --- MultiWriter: file + console ---
		mw = io.MultiWriter(os.Stdout, logFile)
	} else {
		mw = os.Stdout
	}

	// ---- New handler slog ----
	newJsonHandler := newHandler(setLevel(), mw, otelHandlers...)
	slog.SetDefault(slog.New(newJsonHandler))

	return lp, nil
}

func setLevel() slog.Level {
	switch viperdata.GetViperData(string(viperdata.LoggerLevelAtribute)).(string) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func EnableModeTest() {
	viper.Set(string(viperdata.LoggerModeTestAtribute), true)
	viperdata.ResetViperDataSingleton()
}

func DisableModeTest() {
	viper.Set(string(viperdata.LoggerModeTestAtribute), false)
	viperdata.ResetViperDataSingleton()
}

// IsModeTest reports whether logger test mode is effectively enabled.
func IsModeTest() bool {
	mode, _ := viperdata.GetViperData(string(viperdata.LoggerModeTestAtribute)).(bool)
	return mode
}
