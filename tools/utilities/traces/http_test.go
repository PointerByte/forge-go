// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package traces

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	otlptrace "go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelmetric "go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	oteltrace "go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

func resetTestState(t *testing.T) {
	t.Helper()

	origInitResourceFn := initResourceFn
	origInitTracerProviderFn := initTracerProviderFn
	origInitMeterProviderFn := initMeterProviderFn
	origAutoTracerProviderFn := autoTracerProviderFn
	origResourceNewFn := resourceNewFn
	origExecutableFn := executableFn
	origOTLPTraceGRPCNewFn := otlpTraceGRPCNewFn
	origOTLPTraceHTTPNewFn := otlpTraceHTTPNewFn
	origStdoutTraceNewFn := stdoutTraceNewFn
	origOTLPMetricGRPCNewFn := otlpMetricGRPCNewFn
	origOTLPMetricHTTPNewFn := otlpMetricHTTPNewFn
	origPrometheusExporterNewFn := prometheusExporterNewFn
	origTP := otel.GetTracerProvider()
	origMP := otel.GetMeterProvider()
	origProp := otel.GetTextMapPropagator()

	t.Cleanup(func() {
		initResourceFn = origInitResourceFn
		initTracerProviderFn = origInitTracerProviderFn
		initMeterProviderFn = origInitMeterProviderFn
		autoTracerProviderFn = origAutoTracerProviderFn
		resourceNewFn = origResourceNewFn
		executableFn = origExecutableFn
		otlpTraceGRPCNewFn = origOTLPTraceGRPCNewFn
		otlpTraceHTTPNewFn = origOTLPTraceHTTPNewFn
		stdoutTraceNewFn = origStdoutTraceNewFn
		otlpMetricGRPCNewFn = origOTLPMetricGRPCNewFn
		otlpMetricHTTPNewFn = origOTLPMetricHTTPNewFn
		prometheusExporterNewFn = origPrometheusExporterNewFn
		otel.SetTracerProvider(origTP)
		otel.SetMeterProvider(origMP)
		otel.SetTextMapPropagator(origProp)
		viper.Reset()
	})

	viper.Reset()
	otel.SetTracerProvider(tracenoop.NewTracerProvider())
	otel.SetMeterProvider(metricnoop.NewMeterProvider())
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
}

func TestInitOtelSDKDisabled(t *testing.T) {
	resetTestState(t)
	t.Setenv("OTEL_SDK_DISABLED", "true")

	shutdown, err := InitOtel(context.Background())
	if err != nil {
		t.Fatalf("InitOtel returned error: %v", err)
	}
	if shutdown == nil {
		t.Fatal("expected shutdown function")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown returned error: %v", err)
	}
}

func TestInitOtelResourceError(t *testing.T) {
	resetTestState(t)
	wantErr := errors.New("resource error")
	initResourceFn = func(context.Context) (*resource.Resource, error) {
		return nil, wantErr
	}

	shutdown, err := InitOtel(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected %v, got %v", wantErr, err)
	}
	if shutdown != nil {
		t.Fatal("expected nil shutdown on error")
	}
}

func TestInitOtelTracerProviderError(t *testing.T) {
	resetTestState(t)
	wantErr := errors.New("tracer error")
	initResourceFn = func(context.Context) (*resource.Resource, error) {
		return resource.Empty(), nil
	}
	initTracerProviderFn = func(context.Context, *resource.Resource) (oteltrace.TracerProvider, func(context.Context) error, error) {
		return nil, nil, wantErr
	}

	shutdown, err := InitOtel(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected %v, got %v", wantErr, err)
	}
	if shutdown != nil {
		t.Fatal("expected nil shutdown on error")
	}
}

func TestInitOtelMeterProviderError(t *testing.T) {
	resetTestState(t)
	wantErr := errors.New("meter error")
	initResourceFn = func(context.Context) (*resource.Resource, error) {
		return resource.Empty(), nil
	}
	initTracerProviderFn = func(context.Context, *resource.Resource) (oteltrace.TracerProvider, func(context.Context) error, error) {
		return tracenoop.NewTracerProvider(), func(context.Context) error { return nil }, nil
	}
	initMeterProviderFn = func(context.Context, *resource.Resource) (otelmetric.MeterProvider, func(context.Context) error, error) {
		return nil, nil, wantErr
	}

	shutdown, err := InitOtel(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected %v, got %v", wantErr, err)
	}
	if shutdown != nil {
		t.Fatal("expected nil shutdown on error")
	}
}

func TestInitOtelSuccessJoinsShutdownErrors(t *testing.T) {
	resetTestState(t)
	traceErr := errors.New("trace shutdown error")
	metricErr := errors.New("metric shutdown error")
	initResourceFn = func(context.Context) (*resource.Resource, error) {
		return resource.Empty(), nil
	}
	initTracerProviderFn = func(context.Context, *resource.Resource) (oteltrace.TracerProvider, func(context.Context) error, error) {
		return tracenoop.NewTracerProvider(), func(context.Context) error { return traceErr }, nil
	}
	initMeterProviderFn = func(context.Context, *resource.Resource) (otelmetric.MeterProvider, func(context.Context) error, error) {
		return metricnoop.NewMeterProvider(), func(context.Context) error { return metricErr }, nil
	}

	shutdown, err := InitOtel(context.Background())
	if err != nil {
		t.Fatalf("InitOtel returned error: %v", err)
	}

	err = shutdown(context.Background())
	if !errors.Is(err, traceErr) || !errors.Is(err, metricErr) {
		t.Fatalf("expected joined shutdown error, got %v", err)
	}
}

func TestMiddlewareOtel(t *testing.T) {
	resetTestState(t)
	gin.SetMode(gin.TestMode)
	viper.Set("app.name", "trace-service")
	viper.Set("traces.SkipPaths", []string{"/health"})
	otel.SetTracerProvider(tracenoop.NewTracerProvider())
	otel.SetMeterProvider(metricnoop.NewMeterProvider())
	otel.SetTextMapPropagator(newPropagator())

	router := gin.New()
	router.Use(MiddlewareOtel())
	router.GET("/health", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	router.GET("/users/:id", func(c *gin.Context) {
		c.Status(http.StatusAccepted)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for health, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/users/42", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for instrumented route, got %d", rec.Code)
	}
}

func TestNewTracerProviderPaths(t *testing.T) {
	t.Run("auto global", func(t *testing.T) {
		resetTestState(t)
		t.Setenv("OTEL_GO_AUTO_GLOBAL", "true")
		autoTracerProviderFn = func() oteltrace.TracerProvider {
			return tracenoop.NewTracerProvider()
		}

		tp, shutdown, err := newTracerProvider(context.Background(), resource.Empty())
		if err != nil {
			t.Fatalf("newTracerProvider returned error: %v", err)
		}
		if tp == nil || shutdown != nil {
			t.Fatalf("unexpected tracer provider result: tp nil=%t shutdown nil=%t", tp == nil, shutdown == nil)
		}
	})

	t.Run("none exporter", func(t *testing.T) {
		resetTestState(t)
		t.Setenv("OTEL_TRACES_EXPORTER", "none")

		tp, shutdown, err := newTracerProvider(context.Background(), resource.Empty())
		if err != nil {
			t.Fatalf("newTracerProvider returned error: %v", err)
		}
		if tp == nil || shutdown != nil {
			t.Fatalf("unexpected tracer provider result: tp nil=%t shutdown nil=%t", tp == nil, shutdown == nil)
		}
	})

	t.Run("success", func(t *testing.T) {
		resetTestState(t)
		t.Setenv("OTEL_TRACES_EXPORTER", "console")

		tp, shutdown, err := newTracerProvider(context.Background(), resource.Empty())
		if err != nil {
			t.Fatalf("newTracerProvider returned error: %v", err)
		}
		if tp == nil || shutdown == nil {
			t.Fatalf("expected tracer provider and shutdown, got tp nil=%t shutdown nil=%t", tp == nil, shutdown == nil)
		}
	})
}

func TestNewTraceExporter(t *testing.T) {
	t.Run("unsupported exporter", func(t *testing.T) {
		resetTestState(t)
		exp, err := newTraceExporter(context.Background(), "zipkin")
		if err == nil || exp != nil {
			t.Fatalf("expected unsupported exporter error, got exp=%v err=%v", exp, err)
		}
	})

	t.Run("unsupported protocol", func(t *testing.T) {
		resetTestState(t)
		t.Setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "invalid")
		exp, err := newTraceExporter(context.Background(), "otlp")
		if err == nil || exp != nil {
			t.Fatalf("expected unsupported protocol error, got exp=%v err=%v", exp, err)
		}
	})

	t.Run("grpc error", func(t *testing.T) {
		resetTestState(t)
		wantErr := errors.New("grpc ctor error")
		t.Setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "grpc")
		otlpTraceGRPCNewFn = func(context.Context, ...otlptracegrpc.Option) (*otlptrace.Exporter, error) {
			return nil, wantErr
		}
		_, err := newTraceExporter(context.Background(), "otlp")
		if err == nil || err.Error() != wantErr.Error() {
			t.Fatalf("expected %v, got err=%v", wantErr, err)
		}
	})

	t.Run("http error", func(t *testing.T) {
		resetTestState(t)
		wantErr := errors.New("http ctor error")
		t.Setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "http/protobuf")
		otlpTraceHTTPNewFn = func(context.Context, ...otlptracehttp.Option) (*otlptrace.Exporter, error) {
			return nil, wantErr
		}
		_, err := newTraceExporter(context.Background(), "otlp")
		if err == nil || err.Error() != wantErr.Error() {
			t.Fatalf("expected %v, got err=%v", wantErr, err)
		}
	})

	t.Run("console success", func(t *testing.T) {
		resetTestState(t)
		exp, err := newTraceExporter(context.Background(), "console")
		if err != nil || exp == nil {
			t.Fatalf("expected console exporter, got exp=%v err=%v", exp, err)
		}
	})
}

func TestNewMeterProviderAndReader(t *testing.T) {
	t.Run("default none exporter", func(t *testing.T) {
		resetTestState(t)

		mp, shutdown, err := newMeterProvider(context.Background(), resource.Empty())
		if err != nil {
			t.Fatalf("newMeterProvider returned error: %v", err)
		}
		if mp == nil || shutdown != nil {
			t.Fatalf("unexpected meter provider result: mp nil=%t shutdown nil=%t", mp == nil, shutdown == nil)
		}
	})

	t.Run("none exporter", func(t *testing.T) {
		resetTestState(t)
		t.Setenv("OTEL_METRICS_EXPORTER", "none")

		mp, shutdown, err := newMeterProvider(context.Background(), resource.Empty())
		if err != nil {
			t.Fatalf("newMeterProvider returned error: %v", err)
		}
		if mp == nil || shutdown != nil {
			t.Fatalf("unexpected meter provider result: mp nil=%t shutdown nil=%t", mp == nil, shutdown == nil)
		}
	})

	t.Run("prometheus success", func(t *testing.T) {
		resetTestState(t)
		t.Setenv("OTEL_METRICS_EXPORTER", "prometheus")

		mp, shutdown, err := newMeterProvider(context.Background(), resource.Empty())
		if err != nil {
			t.Fatalf("newMeterProvider returned error: %v", err)
		}
		if mp == nil || shutdown == nil {
			t.Fatalf("expected meter provider and shutdown, got mp nil=%t shutdown nil=%t", mp == nil, shutdown == nil)
		}
	})

	t.Run("unsupported exporter", func(t *testing.T) {
		resetTestState(t)
		reader, err := newMetricReader(context.Background(), "statsd")
		if err == nil || reader != nil {
			t.Fatalf("expected unsupported exporter error, got reader=%v err=%v", reader, err)
		}
	})

	t.Run("unsupported protocol", func(t *testing.T) {
		resetTestState(t)
		t.Setenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", "invalid")
		reader, err := newMetricReader(context.Background(), "otlp")
		if err == nil || reader != nil {
			t.Fatalf("expected unsupported protocol error, got reader=%v err=%v", reader, err)
		}
	})

	t.Run("grpc error", func(t *testing.T) {
		resetTestState(t)
		wantErr := errors.New("metric grpc error")
		t.Setenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", "grpc")
		otlpMetricGRPCNewFn = func(context.Context, ...otlpmetricgrpc.Option) (*otlpmetricgrpc.Exporter, error) {
			return nil, wantErr
		}
		reader, err := newMetricReader(context.Background(), "otlp")
		if !errors.Is(err, wantErr) || reader != nil {
			t.Fatalf("expected %v, got reader=%v err=%v", wantErr, reader, err)
		}
	})

	t.Run("http error", func(t *testing.T) {
		resetTestState(t)
		wantErr := errors.New("metric http error")
		t.Setenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", "http/protobuf")
		otlpMetricHTTPNewFn = func(context.Context, ...otlpmetrichttp.Option) (*otlpmetrichttp.Exporter, error) {
			return nil, wantErr
		}
		reader, err := newMetricReader(context.Background(), "otlp")
		if !errors.Is(err, wantErr) || reader != nil {
			t.Fatalf("expected %v, got reader=%v err=%v", wantErr, reader, err)
		}
	})
}

func TestNewResource(t *testing.T) {
	t.Run("service from viper and version", func(t *testing.T) {
		resetTestState(t)
		viper.Set("app.name", "svc-name")
		viper.Set("app.version", "1.2.3")

		res, err := newResource(context.Background())
		if err != nil {
			t.Fatalf("newResource returned error: %v", err)
		}

		if got, ok := res.Set().Value(semconv.ServiceNameKey); !ok || got.AsString() != "svc-name" {
			t.Fatalf("expected service.name=svc-name, got %v %v", got, ok)
		}
		if got, ok := res.Set().Value(semconv.ServiceVersionKey); !ok || got.AsString() != "1.2.3" {
			t.Fatalf("expected service.version=1.2.3, got %v %v", got, ok)
		}
	})

	t.Run("service from env wins", func(t *testing.T) {
		resetTestState(t)
		t.Setenv("OTEL_SERVICE_NAME", "env-service")
		viper.Set("app.name", "viper-service")

		res, err := newResource(context.Background())
		if err != nil {
			t.Fatalf("newResource returned error: %v", err)
		}

		if got, ok := res.Set().Value(semconv.ServiceNameKey); !ok || got.AsString() != "env-service" {
			t.Fatalf("expected service.name=env-service, got %v %v", got, ok)
		}
	})

	t.Run("resource ctor error", func(t *testing.T) {
		resetTestState(t)
		wantErr := errors.New("resource ctor error")
		resourceNewFn = func(context.Context, ...resource.Option) (*resource.Resource, error) {
			return nil, wantErr
		}

		res, err := newResource(context.Background())
		if !errors.Is(err, wantErr) || res != nil {
			t.Fatalf("expected %v, got res=%v err=%v", wantErr, res, err)
		}
	})
}

func TestNewPropagator(t *testing.T) {
	resetTestState(t)
	t.Setenv("OTEL_PROPAGATORS", "tracecontext,baggage,b3,b3multi,none,unknown")

	prop := newPropagator()
	if prop == nil {
		t.Fatal("expected propagator")
	}
	if len(prop.Fields()) == 0 {
		t.Fatal("expected propagated fields")
	}
}

func TestNewSampler(t *testing.T) {
	tests := []struct {
		name string
		env  string
		arg  string
	}{
		{name: "default", env: "", arg: ""},
		{name: "always_on", env: "always_on", arg: ""},
		{name: "always_off", env: "always_off", arg: ""},
		{name: "traceidratio", env: "traceidratio", arg: "0.4"},
		{name: "parentbased_always_off", env: "parentbased_always_off", arg: ""},
		{name: "parentbased_traceidratio", env: "parentbased_traceidratio", arg: "0.6"},
		{name: "unknown", env: "wat", arg: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetTestState(t)
			t.Setenv("OTEL_TRACES_SAMPLER", tt.env)
			t.Setenv("OTEL_TRACES_SAMPLER_ARG", tt.arg)

			sampler := newSampler()
			if sampler == nil {
				t.Fatal("expected sampler")
			}
			params := sdktrace.SamplingParameters{}
			decision := sampler.ShouldSample(params)
			if decision.Decision == sdktrace.Drop && tt.env == "always_on" {
				t.Fatal("always_on sampler dropped span")
			}
		})
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("signalExporterName", func(t *testing.T) {
		resetTestState(t)
		t.Setenv("OTEL_TRACES_EXPORTER", " none , console ")
		if got := signalExporterName("OTEL_TRACES_EXPORTER", "otlp"); got != "none" {
			t.Fatalf("expected none, got %s", got)
		}

		t.Setenv("OTEL_TRACES_EXPORTER", "   ")
		if got := signalExporterName("OTEL_TRACES_EXPORTER", "otlp"); got != "otlp" {
			t.Fatalf("expected fallback otlp, got %s", got)
		}
	})

	t.Run("signalProtocol", func(t *testing.T) {
		resetTestState(t)
		t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
		if got := signalProtocol("traces"); got != "grpc" {
			t.Fatalf("expected grpc, got %s", got)
		}

		t.Setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "http/protobuf")
		if got := signalProtocol("traces"); got != "http/protobuf" {
			t.Fatalf("expected http/protobuf, got %s", got)
		}
	})

	t.Run("hasServiceNameEnv", func(t *testing.T) {
		resetTestState(t)
		if hasServiceNameEnv() {
			t.Fatal("did not expect service env")
		}

		t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "service.name=svc,env=dev")
		if !hasServiceNameEnv() {
			t.Fatal("expected service.name in OTEL_RESOURCE_ATTRIBUTES")
		}
	})

	t.Run("serviceName", func(t *testing.T) {
		resetTestState(t)
		viper.Set("app.name", "viper-name")
		if got := serviceName(); got != "viper-name" {
			t.Fatalf("expected viper-name, got %s", got)
		}

		viper.Reset()
		executableFn = func() (string, error) {
			return "/tmp/myapp", nil
		}
		if got := serviceName(); got != "unknown_service:myapp" {
			t.Fatalf("expected unknown_service:myapp, got %s", got)
		}

		executableFn = func() (string, error) {
			return "", errors.New("boom")
		}
		if got := serviceName(); got != "unknown_service:gin" {
			t.Fatalf("expected unknown_service:gin, got %s", got)
		}
	})

	t.Run("isEnvTrue", func(t *testing.T) {
		resetTestState(t)
		if isEnvTrue("MISSING_ENV") {
			t.Fatal("missing env should be false")
		}
		t.Setenv("BOOL_ENV", "true")
		if !isEnvTrue("BOOL_ENV") {
			t.Fatal("expected true")
		}
		t.Setenv("BOOL_ENV", "not-bool")
		if isEnvTrue("BOOL_ENV") {
			t.Fatal("invalid bool should be false")
		}
	})

	t.Run("parseRatio", func(t *testing.T) {
		cases := []struct {
			in   string
			want float64
		}{
			{in: "0.25", want: 0.25},
			{in: "-1", want: 0},
			{in: "2", want: 1},
			{in: "bad", want: 1},
		}

		for _, tc := range cases {
			if got := parseRatio(tc.in); got != tc.want {
				t.Fatalf("parseRatio(%q): want %v, got %v", tc.in, tc.want, got)
			}
		}
	})
}
