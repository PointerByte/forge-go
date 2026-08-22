// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/spf13/viper"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
)

// otelLogEnvKeys drive log export. Every case clears all of them and then sets
// only what it declares, so the surrounding process environment cannot change
// the outcome.
var otelLogEnvKeys = []string{logsExporterEnv, logsProtocolEnv, otlpProtocolEnv, sdkDisabledEnv}

func withOtelLogEnv(t *testing.T, env map[string]string) {
	t.Helper()

	for _, key := range otelLogEnvKeys {
		original, had := os.LookupEnv(key)
		t.Cleanup(func() {
			if had {
				_ = os.Setenv(key, original)
				return
			}
			_ = os.Unsetenv(key)
		})

		if value, ok := env[key]; ok {
			_ = os.Setenv(key, value)
			continue
		}
		_ = os.Unsetenv(key)
	}
}

func Test_signalExporterName(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "unset falls back",
			want: exporterNone,
		},
		{
			name: "empty falls back",
			env:  map[string]string{logsExporterEnv: ""},
			want: exporterNone,
		},
		{
			name: "blank falls back",
			env:  map[string]string{logsExporterEnv: "   "},
			want: exporterNone,
		},
		{
			name: "only separators fall back",
			env:  map[string]string{logsExporterEnv: " , , "},
			want: exporterNone,
		},
		{
			name: "trimmed and lowercased",
			env:  map[string]string{logsExporterEnv: "  OTLP  "},
			want: exporterOTLP,
		},
		{
			name: "first non-empty entry wins",
			env:  map[string]string{logsExporterEnv: " OTLP , none "},
			want: exporterOTLP,
		},
		{
			name: "leading empty entries skipped",
			env:  map[string]string{logsExporterEnv: ",,none"},
			want: exporterNone,
		},
		{
			name: "unknown value is returned for the caller to reject",
			env:  map[string]string{logsExporterEnv: "Console"},
			want: "console",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withOtelLogEnv(t, tt.env)

			if got := signalExporterName(logsExporterEnv, exporterNone); got != tt.want {
				t.Fatalf("signalExporterName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test_signalProtocol(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "defaults to http/protobuf",
			want: protocolHTTPProto,
		},
		{
			name: "signal variable wins over the shared one",
			env: map[string]string{
				logsProtocolEnv: "HTTP/Protobuf",
				otlpProtocolEnv: "grpc",
			},
			want: protocolHTTPProto,
		},
		{
			name: "shared variable is used when the signal one is unset",
			env:  map[string]string{otlpProtocolEnv: " GRPC "},
			want: "grpc",
		},
		{
			name: "blank signal variable falls through to the shared one",
			env: map[string]string{
				logsProtocolEnv: "   ",
				otlpProtocolEnv: "grpc",
			},
			want: "grpc",
		},
		{
			name: "blank variables fall back to the default",
			env: map[string]string{
				logsProtocolEnv: " ",
				otlpProtocolEnv: " ",
			},
			want: protocolHTTPProto,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withOtelLogEnv(t, tt.env)

			if got := signalProtocol(); got != tt.want {
				t.Fatalf("signalProtocol() = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test_newCofigLoggerProvider(t *testing.T) {
	origNew := new
	origNewGRPC := newGRPC
	origNewLoggerProvider := newLoggerProvider
	origResourceNew := resourceNewFn
	origResourceNewWithAttributes := newSchemaless
	origResourceMerge := resourceMerge

	defer func() {
		new = origNew
		newGRPC = origNewGRPC
		newLoggerProvider = origNewLoggerProvider
		resourceNewFn = origResourceNew
		newSchemaless = origResourceNewWithAttributes
		resourceMerge = origResourceMerge
	}()

	const providerNotCalled = -1

	tests := []struct {
		name              string
		env               map[string]string
		exporterErr       bool
		mergeErr          bool
		wantErrContains   string
		wantEnabled       bool
		wantExporterCalls int
		wantProviderOpts  int
	}{
		{
			name:             "export disabled without configuration",
			wantProviderOpts: 0,
		},
		{
			name:             "export disabled explicitly",
			env:              map[string]string{logsExporterEnv: "none"},
			wantProviderOpts: 0,
		},
		{
			name:             "export disabled by an empty value",
			env:              map[string]string{logsExporterEnv: "  "},
			wantProviderOpts: 0,
		},
		{
			name:              "otlp enables export",
			env:               map[string]string{logsExporterEnv: "otlp"},
			wantEnabled:       true,
			wantExporterCalls: 1,
			wantProviderOpts:  2,
		},
		{
			name:              "otlp is resolved from a spaced upper-case list",
			env:               map[string]string{logsExporterEnv: " OTLP , none "},
			wantEnabled:       true,
			wantExporterCalls: 1,
			wantProviderOpts:  2,
		},
		{
			name: "otlp accepts an explicit http/protobuf protocol",
			env: map[string]string{
				logsExporterEnv: "otlp",
				logsProtocolEnv: "http/protobuf",
			},
			wantEnabled:       true,
			wantExporterCalls: 1,
			wantProviderOpts:  2,
		},
		{
			name:             "unsupported exporter value",
			env:              map[string]string{logsExporterEnv: "console"},
			wantErrContains:  logsExporterEnv,
			wantProviderOpts: providerNotCalled,
		},
		{
			name: "otlp accepts an explicit grpc protocol",
			env: map[string]string{
				logsExporterEnv: "otlp",
				logsProtocolEnv: "grpc",
			},
			wantEnabled:       true,
			wantExporterCalls: 1,
			wantProviderOpts:  2,
		},
		{
			name: "unsupported protocol value",
			env: map[string]string{
				logsExporterEnv: "otlp",
				logsProtocolEnv: "http/json",
			},
			wantErrContains:  logsProtocolEnv,
			wantProviderOpts: providerNotCalled,
		},
		{
			name: "sdk disabled turns log export off",
			env: map[string]string{
				logsExporterEnv: "otlp",
				sdkDisabledEnv:  "true",
			},
			wantProviderOpts: 0,
		},
		{
			name:              "exporter constructor error",
			env:               map[string]string{logsExporterEnv: "otlp"},
			exporterErr:       true,
			wantErrContains:   "exporter error",
			wantExporterCalls: 1,
			wantProviderOpts:  providerNotCalled,
		},
		{
			name:              "resource merge error",
			env:               map[string]string{logsExporterEnv: "otlp"},
			mergeErr:          true,
			wantErrContains:   "merge error",
			wantExporterCalls: 1,
			wantProviderOpts:  providerNotCalled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			viperdata.ResetViperDataSingleton()
			viper.Set("app.name", "test-app")
			viper.Set("app.version", "1.0.0")

			withOtelLogEnv(t, tt.env)

			exporterCalls := 0
			new = func(ctx context.Context, opts ...otlploghttp.Option) (*otlploghttp.Exporter, error) {
				exporterCalls++
				if tt.exporterErr {
					return nil, errors.New("exporter error")
				}
				return &otlploghttp.Exporter{}, nil
			}
			newGRPC = func(ctx context.Context, opts ...otlploggrpc.Option) (*otlploggrpc.Exporter, error) {
				exporterCalls++
				if tt.exporterErr {
					return nil, errors.New("exporter error")
				}
				return &otlploggrpc.Exporter{}, nil
			}
			resourceNewFn = func(context.Context, ...resource.Option) (*resource.Resource, error) {
				return resource.Empty(), nil
			}
			newSchemaless = func(attrs ...attribute.KeyValue) *resource.Resource {
				return resource.Empty()
			}
			resourceMerge = func(a, b *resource.Resource) (*resource.Resource, error) {
				if tt.mergeErr {
					return nil, errors.New("merge error")
				}
				return resource.Empty(), nil
			}

			wantProvider := sdklog.NewLoggerProvider()
			providerOpts := providerNotCalled
			newLoggerProvider = func(opts ...sdklog.LoggerProviderOption) *sdklog.LoggerProvider {
				providerOpts = len(opts)
				return wantProvider
			}

			got, enabled, err := newCofigLoggerProvider(context.Background())

			if exporterCalls != tt.wantExporterCalls {
				t.Fatalf("exporter constructor calls = %d, want %d", exporterCalls, tt.wantExporterCalls)
			}
			if providerOpts != tt.wantProviderOpts {
				t.Fatalf("newLoggerProvider() options = %d, want %d", providerOpts, tt.wantProviderOpts)
			}

			if tt.wantErrContains != "" {
				if err == nil {
					t.Fatalf("newCofigLoggerProvider() error = nil, want one containing %q", tt.wantErrContains)
				}
				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Fatalf("newCofigLoggerProvider() error = %v, want one containing %q", err, tt.wantErrContains)
				}
				if got != nil {
					t.Fatalf("newCofigLoggerProvider() = %v, want nil", got)
				}
				if enabled {
					t.Fatal("newCofigLoggerProvider() reported export enabled on error")
				}
				return
			}

			if err != nil {
				t.Fatalf("newCofigLoggerProvider() unexpected error = %v", err)
			}
			if got != wantProvider {
				t.Fatalf("newCofigLoggerProvider() provider = %p, want %p", got, wantProvider)
			}
			if enabled != tt.wantEnabled {
				t.Fatalf("newCofigLoggerProvider() enabled = %v, want %v", enabled, tt.wantEnabled)
			}
		})
	}
}

// Test_newCofigLoggerProvider_disabledProviderIsUsable exercises the real SDK
// rather than the seams: a processor-less provider must accept records and shut
// down cleanly, because callers register its Shutdown unconditionally.
func Test_newCofigLoggerProvider_disabledProviderIsUsable(t *testing.T) {
	origNew := new
	defer func() { new = origNew }()

	new = func(ctx context.Context, opts ...otlploghttp.Option) (*otlploghttp.Exporter, error) {
		t.Fatal("exporter constructor should not be called when export is disabled")
		return nil, nil
	}

	withOtelLogEnv(t, nil)

	provider, enabled, err := newCofigLoggerProvider(context.Background())
	if err != nil {
		t.Fatalf("newCofigLoggerProvider() unexpected error = %v", err)
	}
	if enabled {
		t.Fatal("newCofigLoggerProvider() enabled = true, want false")
	}
	if provider == nil {
		t.Fatal("newCofigLoggerProvider() returned nil provider")
	}

	if err := provider.ForceFlush(context.Background()); err != nil {
		t.Fatalf("LoggerProvider.ForceFlush() error = %v", err)
	}
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatalf("LoggerProvider.Shutdown() error = %v", err)
	}
	// Callers may shut down more than once through joined error paths.
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatalf("second LoggerProvider.Shutdown() error = %v", err)
	}
}

// installedHandler returns the handler InitLogger installed as the slog
// default, so tests can assert which secondary handlers it forwards to.
func installedHandler(t *testing.T) *jsonHandler {
	t.Helper()

	handler, ok := slog.Default().Handler().(*jsonHandler)
	if !ok {
		t.Fatalf("slog default handler = %T, want *jsonHandler", slog.Default().Handler())
	}
	return handler
}

func TestInitLogger(t *testing.T) {
	tmpDir := t.TempDir()

	origProviderFactory := _newCofigLoggerProvider
	origFilepathAbs := filepathAbs
	origDefaultLogger := slog.Default()
	defer func() {
		_newCofigLoggerProvider = origProviderFactory
		filepathAbs = origFilepathAbs
		slog.SetDefault(origDefaultLogger)
	}()

	rotationViper := func() {
		viper.Set(string(viperdata.AppAtribute), "my-app")
		viper.Set(string(viperdata.LoggerRotateEnableAtribute), true)
		viper.Set(string(viperdata.LoggerRotateMaxSizeAtribute), 10)
		viper.Set(string(viperdata.LoggerRotateMaxAgeAtribute), 7)
		viper.Set(string(viperdata.LoggerRotateMaxBackupsAtribute), 3)
		viper.Set(string(viperdata.LoggerCompressMaxAgeAtribute), true)
	}

	tests := []struct {
		name             string
		ctx              context.Context
		dir              string
		env              map[string]string
		setupViper       func()
		setupProvider    func(t *testing.T)
		setupFilepathAbs func(t *testing.T)
		wantErr          bool
		validate         func(t *testing.T, lp *sdklog.LoggerProvider, err error)
	}{
		{
			name:       "success with log rotation enabled",
			ctx:        context.Background(),
			dir:        tmpDir,
			setupViper: rotationViper,
			setupProvider: func(t *testing.T) {
				t.Helper()
				_newCofigLoggerProvider = func(ctx context.Context) (*sdklog.LoggerProvider, bool, error) {
					return sdklog.NewLoggerProvider(), true, nil
				}
			},
			setupFilepathAbs: func(t *testing.T) {
				t.Helper()
				filepathAbs = filepath.Abs
			},
			wantErr: false,
			validate: func(t *testing.T, lp *sdklog.LoggerProvider, err error) {
				t.Helper()

				if err != nil {
					t.Fatalf("InitLogger() unexpected error = %v", err)
				}
				if lp == nil {
					t.Fatal("InitLogger() returned nil logger provider")
				}

				if err := lp.Shutdown(context.Background()); err != nil {
					t.Fatalf("LoggerProvider.Shutdown() error = %v", err)
				}
			},
		},
		{
			name:       "enabled export attaches the otel bridge handler",
			ctx:        context.Background(),
			dir:        tmpDir,
			setupViper: rotationViper,
			setupProvider: func(t *testing.T) {
				t.Helper()
				_newCofigLoggerProvider = func(ctx context.Context) (*sdklog.LoggerProvider, bool, error) {
					return sdklog.NewLoggerProvider(), true, nil
				}
			},
			setupFilepathAbs: func(t *testing.T) {
				t.Helper()
				filepathAbs = filepath.Abs
			},
			wantErr: false,
			validate: func(t *testing.T, lp *sdklog.LoggerProvider, err error) {
				t.Helper()

				if handlers := installedHandler(t).handlers; len(handlers) != 1 {
					t.Fatalf("installed secondary handlers = %d, want 1", len(handlers))
				}
			},
		},
		{
			name:       "disabled export attaches no otel bridge handler",
			ctx:        context.Background(),
			dir:        tmpDir,
			setupViper: rotationViper,
			setupProvider: func(t *testing.T) {
				t.Helper()
				_newCofigLoggerProvider = func(ctx context.Context) (*sdklog.LoggerProvider, bool, error) {
					return sdklog.NewLoggerProvider(), false, nil
				}
			},
			setupFilepathAbs: func(t *testing.T) {
				t.Helper()
				filepathAbs = filepath.Abs
			},
			wantErr: false,
			validate: func(t *testing.T, lp *sdklog.LoggerProvider, err error) {
				t.Helper()

				if lp == nil {
					t.Fatal("InitLogger() returned nil logger provider with export disabled")
				}
				if handlers := installedHandler(t).handlers; len(handlers) != 0 {
					t.Fatalf("installed secondary handlers = %d, want 0", len(handlers))
				}
				if err := lp.Shutdown(context.Background()); err != nil {
					t.Fatalf("LoggerProvider.Shutdown() error = %v", err)
				}
			},
		},
		{
			name:       "no otel configuration disables export end to end",
			ctx:        context.Background(),
			dir:        tmpDir,
			setupViper: rotationViper,
			setupProvider: func(t *testing.T) {
				t.Helper()
				_newCofigLoggerProvider = origProviderFactory

				origNew := new
				t.Cleanup(func() { new = origNew })
				new = func(ctx context.Context, opts ...otlploghttp.Option) (*otlploghttp.Exporter, error) {
					t.Fatal("exporter constructor should not be called without OTEL_LOGS_EXPORTER")
					return nil, nil
				}
			},
			setupFilepathAbs: func(t *testing.T) {
				t.Helper()
				filepathAbs = filepath.Abs
			},
			wantErr: false,
			validate: func(t *testing.T, lp *sdklog.LoggerProvider, err error) {
				t.Helper()

				if lp == nil {
					t.Fatal("InitLogger() returned nil logger provider")
				}
				if handlers := installedHandler(t).handlers; len(handlers) != 0 {
					t.Fatalf("installed secondary handlers = %d, want 0", len(handlers))
				}
				if err := lp.Shutdown(context.Background()); err != nil {
					t.Fatalf("LoggerProvider.Shutdown() error = %v", err)
				}
			},
		},
		{
			name:       "unsupported exporter value fails initialization",
			ctx:        context.Background(),
			dir:        tmpDir,
			env:        map[string]string{logsExporterEnv: "console"},
			setupViper: rotationViper,
			setupProvider: func(t *testing.T) {
				t.Helper()
				_newCofigLoggerProvider = origProviderFactory
			},
			setupFilepathAbs: func(t *testing.T) {
				t.Helper()
				filepathAbs = filepath.Abs
			},
			wantErr: true,
			validate: func(t *testing.T, lp *sdklog.LoggerProvider, err error) {
				t.Helper()

				if err == nil {
					t.Fatal("InitLogger() expected error, got nil")
				}
				if !strings.Contains(err.Error(), logsExporterEnv) {
					t.Fatalf("InitLogger() error = %v, want one naming %s", err, logsExporterEnv)
				}
				if lp != nil {
					t.Fatal("InitLogger() returned non-nil logger provider on error")
				}
			},
		},
		{
			name:       "provider error with log rotation enabled",
			ctx:        context.Background(),
			dir:        tmpDir,
			setupViper: rotationViper,
			setupProvider: func(t *testing.T) {
				t.Helper()
				_newCofigLoggerProvider = func(ctx context.Context) (*sdklog.LoggerProvider, bool, error) {
					return nil, false, errors.New("provider error")
				}
			},
			setupFilepathAbs: func(t *testing.T) {
				t.Helper()
				filepathAbs = filepath.Abs
			},
			wantErr: true,
			validate: func(t *testing.T, lp *sdklog.LoggerProvider, err error) {
				t.Helper()
				if err == nil {
					t.Fatal("InitLogger() expected error, got nil")
				}
				if lp != nil {
					t.Fatal("InitLogger() returned non-nil logger provider on error")
				}
			},
		},
		{
			name:       "filepathAbs returns error",
			ctx:        context.Background(),
			dir:        tmpDir,
			setupViper: rotationViper,
			setupProvider: func(t *testing.T) {
				t.Helper()
				_newCofigLoggerProvider = func(ctx context.Context) (*sdklog.LoggerProvider, bool, error) {
					t.Fatal("_newCofigLoggerProvider should not be called when filepathAbs fails")
					return nil, false, nil
				}
			},
			setupFilepathAbs: func(t *testing.T) {
				t.Helper()
				filepathAbs = func(path string) (string, error) {
					return "", errors.New("filepathAbs error")
				}
			},
			wantErr: true,
			validate: func(t *testing.T, lp *sdklog.LoggerProvider, err error) {
				t.Helper()
				if err == nil {
					t.Fatal("InitLogger() expected error, got nil")
				}
				if err.Error() != "filepathAbs error" {
					t.Fatalf("InitLogger() error = %v, want %q", err, "filepathAbs error")
				}
				if lp != nil {
					t.Fatal("InitLogger() returned non-nil logger provider on filepathAbs error")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			viperdata.ResetViperDataSingleton()

			_newCofigLoggerProvider = origProviderFactory
			filepathAbs = origFilepathAbs

			withOtelLogEnv(t, tt.env)
			tt.setupViper()
			tt.setupProvider(t)
			tt.setupFilepathAbs(t)

			lp, err := InitLogger(tt.ctx, tt.dir)
			if (err != nil) != tt.wantErr {
				t.Fatalf("InitLogger() error = %v, wantErr %v", err, tt.wantErr)
			}

			tt.validate(t, lp, err)
		})
	}
}

func TestEnableModeTest(t *testing.T) {
	viper.Reset()
	t.Cleanup(func() {
		viper.Reset()
		viperdata.ResetViperDataSingleton()
	})
	viper.Set(string(viperdata.LoggerModeTestAtribute), false)
	viperdata.ResetViperDataSingleton()

	EnableModeTest()

	got := IsModeTest()
	if !got {
		t.Fatalf("EnableModeTest() = %v, want true", got)
	}
}

func TestDisableModeTest(t *testing.T) {
	viper.Reset()
	t.Cleanup(func() {
		viper.Reset()
		viperdata.ResetViperDataSingleton()
	})
	viper.Set(string(viperdata.LoggerModeTestAtribute), true)
	viperdata.ResetViperDataSingleton()

	DisableModeTest()

	got := IsModeTest()
	if got {
		t.Fatalf("DisableModeTest() = %v, want false", got)
	}
}

func Test_setLevel(t *testing.T) {
	tests := []struct {
		name  string
		level string
		want  slog.Level
	}{
		{
			name:  "debug level",
			level: "debug",
			want:  slog.LevelDebug,
		},
		{
			name:  "info level",
			level: "info",
			want:  slog.LevelInfo,
		},
		{
			name:  "warn level",
			level: "warn",
			want:  slog.LevelWarn,
		},
		{
			name:  "error level",
			level: "error",
			want:  slog.LevelError,
		},
		{
			name:  "default level",
			level: "something-else",
			want:  slog.LevelInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			viper.Reset()
			viperdata.ResetViperDataSingleton()

			viper.Set(string(viperdata.LoggerLevelAtribute), tt.level)

			got := setLevel()

			if got != tt.want {
				t.Errorf("setLevel() = %v, want %v", got, tt.want)
			}
		})
	}
}
