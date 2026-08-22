# OpenTelemetry Audit — forge-go

Date: 2026-08-22
Toolchain used for the audit: `go1.26.7 linux/amd64` (`go env GOVERSION` = `go1.26.7`).
Baseline commit: `a8f8e65`.
Method: read of the actual current source (no reliance on prior analyses), plus
inspection of the resolved module cache for `go.opentelemetry.io/otel@v1.45.0`,
`otelgrpc@v0.69.0`/`@v0.70.0` and `otelgin@v0.70.0`.

## 1. Where OpenTelemetry lives today

| Area | Package | Role |
| --- | --- | --- |
| Traces + metrics bootstrap | `tools/utilities/traces` (`http.go`) | `InitOtel`, propagator, resource, sampler, exporters |
| Gin instrumentation | `tools/utilities/traces` (`http.go`) | `MiddlewareOtel` → `otelgin` |
| gRPC server instrumentation | `tools/utilities/traces` (`grpc.go`) | hand-written `MiddlewareOtelGRPCUnary` / `MiddlewareOtelGRPCStream` |
| gRPC client instrumentation | `config/client/grpc/IClient.go` | `otelgrpc.NewClientHandler()` (official) |
| Logs bootstrap | `logger/builder/config.go` | `InitLogger` → `sdklog.LoggerProvider` + `otelslog` bridge |
| Log/trace correlation | `logger/builder/context.go`, `logger/builder/formatLog.go` | `builder.Context` trace id |
| HTTP request span (logger) | `logger/middlewares/http/http.go` | second server span |
| gRPC request span (logger) | `logger/middlewares/grpc/grpc.go` | second server span |
| Crypto spans | `encrypt/internal/trace` | wraps `builder.Context.TraceInit/TraceEnd` |
| AWS SDK spans | `encrypt/aws-kms/repository.go` | `otelaws.AppendMiddlewares` (official) |

## 2. Dependency inventory (before)

Root module (`.`):

| Module | Version |
| --- | --- |
| `go.opentelemetry.io/otel` | v1.44.0 |
| `go.opentelemetry.io/otel/sdk` | v1.44.0 |
| `go.opentelemetry.io/otel/trace` | v1.44.0 |
| `go.opentelemetry.io/otel/metric` | v1.44.0 |
| `go.opentelemetry.io/otel/sdk/metric` | v1.44.0 |
| `go.opentelemetry.io/otel/sdk/log` | v0.20.0 (indirect) |
| `go.opentelemetry.io/otel/log` | v0.20.0 (indirect) |
| `go.opentelemetry.io/otel/exporters/otlp/otlptrace{,grpc,http}` | v1.44.0 |
| `go.opentelemetry.io/otel/exporters/otlp/otlpmetric{grpc,http}` | v1.44.0 |
| `go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp` | v0.20.0 (indirect) |
| `go.opentelemetry.io/otel/exporters/prometheus` | v0.66.0 |
| `go.opentelemetry.io/otel/exporters/stdout/stdouttrace` | v1.44.0 |
| `go.opentelemetry.io/contrib/instrumentation/.../otelgin` | v0.69.0 |
| `go.opentelemetry.io/contrib/instrumentation/.../otelgrpc` | v0.69.0 |
| `go.opentelemetry.io/contrib/bridges/otelslog` | v0.19.0 (indirect) |
| `go.opentelemetry.io/contrib/propagators/b3` | v1.44.0 |
| `go.opentelemetry.io/auto/sdk` | v1.2.1 |
| `go.opentelemetry.io/proto/otlp` | v1.10.0 (indirect) |
| semconv package in use | `go.opentelemetry.io/otel/semconv/v1.37.0` |

`logger`: same train, `otelslog v0.19.0` + `otlploghttp v0.20.0` direct.
`encrypt`: `otelaws v0.69.0`, `otel v1.44.0`, `otel/sdk v1.44.0`; carries
`otelhttp v0.67.0` indirect — an older contrib minor than the rest of the tree.
`security`: OTel only indirect.

The set is internally consistent at otel 1.44 / contrib 0.69 / log 0.20, one
release behind the current train (otel 1.45.0 / contrib 0.70.0 / log 0.21.0 /
prometheus 0.67.0). No unused OTel dependency was found: `auto/sdk` is reached
through the `OTEL_GO_AUTO_GLOBAL` branch of `newTracerProvider`, `b3` through
`OTEL_PROPAGATORS`, `otelgrpc` through the gRPC client dial options.

## 3. Signal-by-signal findings

### Traces — works, with defects

* One `TracerProvider`, batch span processor, `resource.New` with
  `WithFromEnv/WithProcess/WithTelemetrySDK/WithHost/WithOS`, `service.name`
  from `app.name`, `service.version` from `app.version`, standard
  `OTEL_TRACES_SAMPLER` handling. All correct.
* Default `OTEL_TRACES_EXPORTER` is `none`, so traces are opt-in. Correct for a
  library, but undocumented as such.
* `InitOtel` can be called repeatedly and each call overwrites the global
  providers, leaking the previous ones (no shutdown of the replaced provider).
* Shutdown order is traces-then-metrics; the spec-recommended order is
  logs → metrics → traces.

### Metrics — works

* One `MeterProvider`, one reader, OTLP (grpc/http) or Prometheus. No duplicate
  readers.
* `MiddlewareOtel` adds `otelgin.WithGinMetricAttributeFn` emitting
  non-standard `route` and `method` metric attributes that duplicate the
  `http.route` / `http.request.method` attributes `otelgin` already records.

### Logs — a real pipeline exists, but it is incomplete

`logger/builder/config.go` builds `sdklog.LoggerProvider` +
`sdklog.NewBatchProcessor` + `otlploghttp` and bridges `log/slog` into it with
`otelslog`, gated on `OTEL_LOGS_EXPORTER`. Gaps:

* **No OTLP/gRPC transport** — `OTEL_EXPORTER_OTLP_LOGS_PROTOCOL=grpc` is a hard
  error, while traces and metrics support both transports.
* **`OTEL_SDK_DISABLED` is ignored** by the logs pipeline; traces and metrics
  honour it.
* **Resource drift** — logs use `resource.Default()` merged with `service.name`
  / `service.version` from viper, while traces/metrics use the much richer
  `resource.New(...)`. The same process therefore exports logs and spans under
  different resource attribute sets, and `OTEL_RESOURCE_ATTRIBUTES` /
  `OTEL_SERVICE_NAME` do not reach the logs resource.
* The global `LoggerProvider` is never set, so third-party `otel/log` users get
  a no-op.

### Log / trace correlation — produces fabricated trace ids

`builder.New(ctx)` unconditionally generates `strings.ReplaceAll(uuid.NewString(),
"-", "")` and stores it as the log `traceID`, **even when the context already
carries a valid, recording span**. Only the HTTP and gRPC middlewares later
overwrite it with the real span's trace id. Every other entry point
(`builder.New(context.Background())`, jobs, workers, CLI code, library calls
under an active span) emits a 32-hex-char value that looks like a W3C trace id
but correlates with nothing. `spanID` is never emitted at the entry level, only
per `Process`.

### Propagation — correct

`OTEL_PROPAGATORS`, default `tracecontext,baggage`, plus `b3`/`b3multi`.
Composite propagator installed globally. Applies to Gin (via `otelgin`), the
gRPC client (via `otelgrpc`) and the hand-written gRPC server carrier.
A separate `X-Trace-Id`-style correlation id (`common.TraceIDHeader`) coexists;
it is a logging concern and does not replace W3C propagation.

### HTTP — duplicate server spans

`config/server/gin/config.go` registers **both**:

```
traces.MiddlewareOtel()                 // otelgin  -> SpanKindServer
httpMiddlewaresLogger.InitLogger()      // logger   -> SpanKindServer
```

Every request therefore produces **two server spans**. The logger's span is also
wrong on its own terms: it is named after the service (`app.name`) instead of
`{method} {route}`, and carries no HTTP semantic attributes.

### gRPC — duplicate server spans **and** obsolete semantic conventions

`config/server/grpc/config.go` chains `traces.MiddlewareOtelGRPCUnary()` and
`loggerGRPCMiddlewares.InitLoggerUnaryServerInterceptor()`, both starting a
`SpanKindServer` span → **two server spans per RPC** (same for streams).

`tools/utilities/traces/grpc.go` is a Forge reimplementation of OpenTelemetry
gRPC instrumentation that emits the *superseded* RPC conventions:

| Emitted today | Current convention (semconv v1.43.0) |
| --- | --- |
| `rpc.system` = "grpc" | `rpc.system.name` = "grpc" |
| `rpc.service`, `rpc.method` (split) | `rpc.method` = fully-qualified `Service/Method` |
| `rpc.grpc.status_code` (int) | `rpc.response.status_code` (string, e.g. `"OK"`, `"DEADLINE_EXCEEDED"`) |
| — | `error.type` |

Meanwhile `otelgrpc` **is already a direct dependency** and, since v0.69.0,
defaults to `semconvModeNew` (semconv v1.43.0), honours
`OTEL_SEMCONV_STABILITY_OPT_IN=rpc/old|rpc/dup`, and emits
`rpc.server.call.duration` / `rpc.client.call.duration` metrics — none of which
the hand-written interceptor provides. It is used for the gRPC **client** only;
the server side reimplements a worse version of it.

`otelgrpc` v0.70.0 no longer exports the deprecated interceptor constructors:
`stats.Handler` (`NewServerHandler`/`NewClientHandler`) is the only supported
server path.

### Resource attributes / semantic conventions

`semconv/v1.37.0` is pinned in `traces/http.go` and `logger/builder/config.go`,
while `otelgin` v0.69/0.70 and `otelgrpc` v0.69/0.70 both emit `semconv/v1.43.0`
— the process mixes two schema URLs.

### Shutdown

* `InitOtel` returns a joined shutdown; `gin`/`grpc` bootstraps run it under a
  30s `context.WithTimeout`, so it is bounded. Good.
* Order is wrong (see above) and the logs provider is shut down by a separate
  handler registered by the caller, so there is no single documented shutdown
  entry point.
* `logger/main.go`'s demo shutdown uses `context.WithCancel` (no deadline).

### Security / cardinality

* No header or gRPC-metadata allowlist: `formatter.Details.SetHeaders` captures
  **every** header/metadata key except a user-supplied `logger.ignoredHeaders`
  denylist, and `logger.sensibleKeys` redaction is empty by default. These land
  in the local structured log; they do **not** reach OTLP, because the
  `otelslog` bridge only forwards the message and `slog` attributes.
* Metric attributes are bounded (`c.FullPath()` route template, method), but the
  custom `route`/`method` keys are non-standard.

### Tests

`tools/utilities/traces/{http,grpc}_test.go`, `logger/builder/config_test.go` and
the server config tests cover initialization branches and exporter selection.
Not covered: duplicate-span detection, current RPC semantic conventions,
log/trace correlation, collector-unavailable behaviour, repeated init.

## 4. Summary of defects to correct

1. Two HTTP server spans per request.
2. Two gRPC server spans per RPC.
3. Obsolete RPC semantic conventions as the canonical Forge representation.
4. Official `otelgrpc` present but unused on the server side.
5. Logs pipeline missing OTLP/gRPC, ignoring `OTEL_SDK_DISABLED`, and using a
   different resource from traces/metrics.
6. Fabricated trace ids in structured logs when a real span context exists.
7. Mixed semconv schema versions (v1.37.0 vs v1.43.0).
8. Non-standard `route`/`method` HTTP metric attributes duplicating semconv.
9. Shutdown order not logs → metrics → traces; no single telemetry shutdown.
10. Repeated `InitOtel` silently leaks the previously installed providers.
