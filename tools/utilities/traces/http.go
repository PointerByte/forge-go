// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package traces

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	autosdk "go.opentelemetry.io/auto/sdk"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	oteltrace "go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelprometheus "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// instrumentationName is the instrumentation scope reported by every tracer and
// meter this package creates. It identifies Forge as the instrumentation
// library, which is what an OpenTelemetry scope is for; the service identity
// travels in the resource, not in the scope.
const instrumentationName = "github.com/PointerByte/forge-go/tools/utilities/traces"

var (
	initOtelFn              = InitOtel
	autoTracerProviderFn    = autosdk.TracerProvider
	initResourceFn          = newResource
	initTracerProviderFn    = newTracerProvider
	initMeterProviderFn     = newMeterProvider
	resourceNewFn           = resource.New
	executableFn            = os.Executable
	otlpTraceGRPCNewFn      = otlptracegrpc.New
	otlpTraceHTTPNewFn      = otlptracehttp.New
	stdoutTraceNewFn        = stdouttrace.New
	otlpMetricGRPCNewFn     = otlpmetricgrpc.New
	otlpMetricHTTPNewFn     = otlpmetrichttp.New
	prometheusExporterNewFn = otelprometheus.New
)

// initMu serializes InitOtel so a repeated initialization cannot interleave
// with itself, and previousShutdown holds the shutdown of the pipeline this
// package installed last.
var (
	initMu           sync.Mutex
	previousShutdown func(context.Context) error
)

// InitOtel initializes the global OpenTelemetry propagator, tracer provider,
// and meter provider.
//
// Behavior is driven mainly by standard OTEL_* environment variables. When
// OTEL_SDK_DISABLED is true, the package installs no-op providers and returns a
// shutdown function that does nothing.
//
// Calling InitOtel again replaces the pipeline: the providers installed by the
// previous call are shut down first, using ctx, so a repeated initialization
// cannot leak exporters or leave two batch processors running. The returned
// shutdown function is idempotent — calling it more than once is safe and
// returns the result of the first call.
//
// On success it returns a shutdown function that must be called during
// application shutdown to flush and release tracing and metrics resources. It
// respects the deadline of the context it is given, so an unreachable collector
// cannot block shutdown indefinitely.
func InitOtel(ctx context.Context) (func(context.Context) error, error) {
	initMu.Lock()
	defer initMu.Unlock()

	// Replacing the globals without draining the previous pipeline would leak
	// its exporter and its batch processor goroutine.
	if previousShutdown != nil {
		_ = previousShutdown(ctx)
		previousShutdown = nil
	}

	otel.SetTextMapPropagator(newPropagator())

	if isEnvTrue("OTEL_SDK_DISABLED") {
		otel.SetTracerProvider(tracenoop.NewTracerProvider())
		otel.SetMeterProvider(metricnoop.NewMeterProvider())
		return func(context.Context) error { return nil }, nil
	}

	res, err := initResourceFn(ctx)
	if err != nil {
		return nil, err
	}

	tp, shutdownTrace, err := initTracerProviderFn(ctx, res)
	if err != nil {
		return nil, err
	}
	otel.SetTracerProvider(tp)

	mp, shutdownMetrics, err := initMeterProviderFn(ctx, res)
	if err != nil {
		// The tracer provider is already installed; drain it rather than
		// leaving a half-initialized pipeline behind.
		if shutdownTrace != nil {
			err = errors.Join(err, shutdownTrace(ctx))
		}
		return nil, err
	}
	otel.SetMeterProvider(mp)

	// Metrics before traces: the recommended flush order is
	// logs -> metrics -> traces, and logs are owned by the logger module.
	// InitTelemetry composes the three signals in that order.
	shutdowns := make([]func(context.Context) error, 0, 2)
	if shutdownMetrics != nil {
		shutdowns = append(shutdowns, shutdownMetrics)
	}
	if shutdownTrace != nil {
		shutdowns = append(shutdowns, shutdownTrace)
	}

	shutdown := onceShutdown(func(ctx context.Context) error {
		var err error
		for _, shutdown := range shutdowns {
			err = errors.Join(err, shutdown(ctx))
		}
		return err
	})
	previousShutdown = shutdown
	return shutdown, nil
}

// onceShutdown wraps a shutdown function so repeated calls are safe and return
// the outcome of the first one.
func onceShutdown(shutdown func(context.Context) error) func(context.Context) error {
	var (
		once sync.Once
		err  error
	)
	return func(ctx context.Context) error {
		once.Do(func() { err = shutdown(ctx) })
		return err
	}
}

// MiddlewareOtel returns a Gin middleware that instruments incoming HTTP
// requests with OpenTelemetry.
//
// The middleware uses the globally configured propagator, tracer provider, and
// meter provider. Paths configured in `traces.SkipPaths` are excluded when the
// request URL contains any of those values.
func MiddlewareOtel() gin.HandlerFunc {
	skipPaths := viper.GetStringSlice("traces.SkipPaths")
	return otelgin.Middleware(
		serviceName(),
		otelgin.WithTracerProvider(otel.GetTracerProvider()),
		otelgin.WithMeterProvider(otel.GetMeterProvider()),
		otelgin.WithPropagators(otel.GetTextMapPropagator()),
		otelgin.WithFilter(func(request *http.Request) bool {
			for _, s := range skipPaths {
				if strings.Contains(request.URL.Path, s) {
					return false
				}
			}
			return true
		}),
	)
}

// newTracerProvider builds the tracer provider selected by the current OTEL
// configuration.
func newTracerProvider(ctx context.Context, res *resource.Resource) (oteltrace.TracerProvider, func(context.Context) error, error) {
	if isEnvTrue("OTEL_GO_AUTO_GLOBAL") {
		return autoTracerProviderFn(), nil, nil
	}

	exporterName := signalExporterName("OTEL_TRACES_EXPORTER", "none")
	if exporterName == "none" {
		return tracenoop.NewTracerProvider(), nil, nil
	}

	exporter, err := newTraceExporter(ctx, exporterName)
	if err != nil {
		return nil, nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(newSampler()),
		sdktrace.WithSpanProcessor(sdktrace.NewBatchSpanProcessor(exporter)),
		sdktrace.WithRawSpanLimits(sdktrace.NewSpanLimits()),
	)

	return tp, tp.Shutdown, nil
}

// newTraceExporter resolves and creates the trace exporter configured through
// OTEL_TRACES_EXPORTER and OTLP protocol variables.
func newTraceExporter(ctx context.Context, exporterName string) (sdktrace.SpanExporter, error) {
	switch exporterName {
	case "otlp":
		switch signalProtocol("traces") {
		case "grpc":
			return otlpTraceGRPCNewFn(ctx)
		case "http/protobuf":
			return otlpTraceHTTPNewFn(ctx)
		default:
			return nil, errors.New("unsupported OTEL_EXPORTER_OTLP_TRACES_PROTOCOL value")
		}
	case "console", "logging":
		return stdoutTraceNewFn(stdouttrace.WithPrettyPrint())
	default:
		return nil, errors.New("unsupported OTEL_TRACES_EXPORTER value")
	}
}

// newMeterProvider builds the meter provider selected by the current OTEL
// metrics configuration.
func newMeterProvider(ctx context.Context, res *resource.Resource) (otelmetric.MeterProvider, func(context.Context) error, error) {
	exporterName := signalExporterName("OTEL_METRICS_EXPORTER", "none")
	if exporterName == "none" {
		return metricnoop.NewMeterProvider(), nil, nil
	}

	reader, err := newMetricReader(ctx, exporterName)
	if err != nil {
		return nil, nil, err
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
	)

	return mp, mp.Shutdown, nil
}

// newMetricReader creates the metrics reader required by the configured
// exporter.
func newMetricReader(ctx context.Context, exporterName string) (sdkmetric.Reader, error) {
	switch exporterName {
	case "otlp":
		switch signalProtocol("metrics") {
		case "grpc":
			exporter, err := otlpMetricGRPCNewFn(ctx)
			if err != nil {
				return nil, err
			}
			return sdkmetric.NewPeriodicReader(exporter), nil
		case "http/protobuf":
			exporter, err := otlpMetricHTTPNewFn(ctx)
			if err != nil {
				return nil, err
			}
			return sdkmetric.NewPeriodicReader(exporter), nil
		default:
			return nil, errors.New("unsupported OTEL_EXPORTER_OTLP_METRICS_PROTOCOL value")
		}
	case "prometheus":
		return prometheusExporterNewFn()
	default:
		return nil, errors.New("unsupported OTEL_METRICS_EXPORTER value")
	}
}

// newResource assembles the OpenTelemetry resource metadata for the process.
func newResource(ctx context.Context) (*resource.Resource, error) {
	options := []resource.Option{
		resource.WithFromEnv(),
		resource.WithProcess(),
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithOS(),
	}

	customAttrs := make([]attribute.KeyValue, 0, 2)
	if !hasServiceNameEnv() {
		customAttrs = append(customAttrs, semconv.ServiceName(serviceName()))
	}
	if version := strings.TrimSpace(viper.GetString("app.version")); version != "" {
		customAttrs = append(customAttrs, semconv.ServiceVersion(version))
	}
	if len(customAttrs) > 0 {
		options = append(options, resource.WithAttributes(customAttrs...))
	}

	return resourceNewFn(ctx, options...)
}

// newPropagator builds the propagator chain declared in OTEL_PROPAGATORS.
func newPropagator() propagation.TextMapPropagator {
	raw := strings.TrimSpace(os.Getenv("OTEL_PROPAGATORS"))
	if raw == "" {
		raw = "tracecontext,baggage"
	}

	propagators := make([]propagation.TextMapPropagator, 0, 4)
	for _, item := range strings.Split(raw, ",") {
		switch strings.ToLower(strings.TrimSpace(item)) {
		case "", "none":
		case "tracecontext":
			propagators = append(propagators, propagation.TraceContext{})
		case "baggage":
			propagators = append(propagators, propagation.Baggage{})
		case "b3":
			propagators = append(propagators, b3.New())
		case "b3multi":
			propagators = append(propagators, b3.New(b3.WithInjectEncoding(b3.B3MultipleHeader)))
		}
	}

	if len(propagators) == 0 {
		return propagation.NewCompositeTextMapPropagator()
	}
	return propagation.NewCompositeTextMapPropagator(propagators...)
}

// newSampler resolves the trace sampling strategy from OTEL_TRACES_SAMPLER.
func newSampler() sdktrace.Sampler {
	name := strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER")))
	arg := strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER_ARG"))

	switch name {
	case "", "parentbased_always_on":
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	case "always_on":
		return sdktrace.AlwaysSample()
	case "always_off":
		return sdktrace.NeverSample()
	case "traceidratio":
		return sdktrace.TraceIDRatioBased(parseRatio(arg))
	case "parentbased_always_off":
		return sdktrace.ParentBased(sdktrace.NeverSample())
	case "parentbased_traceidratio":
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(parseRatio(arg)))
	default:
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	}
}

// signalExporterName returns the first non-empty exporter name configured for a
// signal, or the provided fallback.
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

// signalProtocol resolves the OTLP protocol for a given signal, preferring the
// signal-specific variable over the shared one.
func signalProtocol(signal string) string {
	signalKey := "OTEL_EXPORTER_OTLP_" + strings.ToUpper(signal) + "_PROTOCOL"
	if value := strings.TrimSpace(os.Getenv(signalKey)); value != "" {
		return strings.ToLower(value)
	}
	if value := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")); value != "" {
		return strings.ToLower(value)
	}
	return "http/protobuf"
}

// hasServiceNameEnv reports whether the service name is already defined through
// standard OTEL environment variables.
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

// serviceName resolves the service name from application config or a fallback
// based on the executable name.
func serviceName() string {
	if name := strings.TrimSpace(viper.GetString("app.name")); name != "" {
		return name
	}
	if executable, err := executableFn(); err == nil {
		return "unknown_service:" + filepath.Base(executable)
	}
	return "unknown_service:gin"
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

// parseRatio parses a sampler ratio and clamps it to the [0, 1] range.
func parseRatio(raw string) float64 {
	ratio, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 1
	}
	if ratio < 0 {
		return 0
	}
	if ratio > 1 {
		return 1
	}
	return ratio
}
