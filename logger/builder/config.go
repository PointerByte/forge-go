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
	"strconv"
	"strings"

	"github.com/PointerByte/forge-go/logger/common"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/spf13/viper"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	logglobal "go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
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

	// sdkDisabledEnv turns every OpenTelemetry signal off, logs included. The
	// traces package honours the same variable.
	sdkDisabledEnv = "OTEL_SDK_DISABLED"

	exporterNone      = "none"
	exporterOTLP      = "otlp"
	protocolHTTPProto = "http/protobuf"
	protocolGRPC      = "grpc"

	// instrumentationName is the instrumentation scope of the records the
	// slog bridge emits.
	instrumentationName = common.InstrumentationName
)

var new = otlploghttp.New
var newGRPC = otlploggrpc.New
var newLoggerProvider = sdklog.NewLoggerProvider
var resourceNewFn = resource.New
var newSchemaless = resource.NewSchemaless
var resourceMerge = resource.Merge
var setLoggerProvider = logglobal.SetLoggerProvider

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
//
// Both OTLP transports are supported, selected by
// OTEL_EXPORTER_OTLP_LOGS_PROTOCOL (or OTEL_EXPORTER_OTLP_PROTOCOL), so logs
// have the same transport choice as traces and metrics.
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
		case protocolGRPC:
			exporter, err := newGRPC(ctx)
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

// newLogResource builds the resource attached to exported log records.
//
// It uses the same detectors as the root module's trace and metric resource, so
// a single process does not describe itself differently per signal, and
// OTEL_RESOURCE_ATTRIBUTES / OTEL_SERVICE_NAME reach the logs pipeline. The
// application's own app.name / app.version are applied only as a fallback, so a
// deployment that sets the standard environment variables keeps control of its
// identity.
func newLogResource(ctx context.Context) (*resource.Resource, error) {
	detected, err := resourceNewFn(ctx,
		resource.WithFromEnv(),
		resource.WithProcess(),
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithOS(),
	)
	if err != nil {
		return nil, err
	}

	attributes := make([]attribute.KeyValue, 0, 2)
	if !hasServiceNameEnv() {
		if name, _ := viperdata.GetViperData(string(viperdata.AppAtribute)).(string); strings.TrimSpace(name) != "" {
			attributes = append(attributes, semconv.ServiceName(name))
		}
	}
	if version, _ := viperdata.GetViperData(string(viperdata.AppVersionAtribute)).(string); strings.TrimSpace(version) != "" {
		attributes = append(attributes, semconv.ServiceVersion(version))
	}
	if len(attributes) == 0 {
		return detected, nil
	}
	return resourceMerge(detected, newSchemaless(attributes...))
}

// hasServiceNameEnv reports whether the service name is already defined through
// standard OpenTelemetry environment variables, in which case the application's
// app.name must not override it.
func hasServiceNameEnv() bool {
	if strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")) != "" {
		return true
	}
	for item := range strings.SplitSeq(os.Getenv("OTEL_RESOURCE_ATTRIBUTES"), ",") {
		key, _, found := strings.Cut(strings.TrimSpace(item), "=")
		if found && strings.TrimSpace(key) == string(semconv.ServiceNameKey) {
			return true
		}
	}
	return false
}

// isEnvTrue parses a boolean environment variable using strconv.ParseBool.
func isEnvTrue(key string) bool {
	value, ok := os.LookupEnv(key)
	if !ok {
		return false
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	return err == nil && parsed
}

// newCofigLoggerProvider builds the logger provider selected by the current
// OTEL log configuration. The second result reports whether log export is
// enabled, so callers can skip the bridge that feeds the provider.
//
// Export is off unless OTEL_LOGS_EXPORTER asks for it, and always off when
// OTEL_SDK_DISABLED is true: an exporter built with the spec defaults targets
// https://localhost:4318/v1/logs, and every failed batch export is reported
// through otel.Handle, which lands back in this package's own slog handler.
func newCofigLoggerProvider(ctx context.Context) (*sdklog.LoggerProvider, bool, error) {
	exporterName := signalExporterName(logsExporterEnv, exporterNone)
	if exporterName == exporterNone || isEnvTrue(sdkDisabledEnv) {
		// A provider without processors is valid: it drops every record and
		// shuts down cleanly, so callers keep a non-nil provider to close.
		return newLoggerProvider(), false, nil
	}

	exporter, err := newLogExporter(ctx, exporterName)
	if err != nil {
		return nil, false, err
	}
	res, err := newLogResource(ctx)
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
			instrumentationName,
			otelslog.WithLoggerProvider(lp),
			otelslog.WithSource(true),
		))
		// Publish the provider globally so code using go.opentelemetry.io/otel/log
		// directly (other Forge modules, third-party libraries) reaches the same
		// pipeline instead of a no-op.
		setLoggerProvider(lp)
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
