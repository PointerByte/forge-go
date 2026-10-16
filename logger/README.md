# forge-go Logger

`logger` provides forge-go's structured logging layer. It configures a global
`slog` logger, formats entries as JSON, text, or a custom template, exports logs
through OpenTelemetry, and includes Gin and gRPC middleware for request-scoped
logs.

## Installation

```bash
go get github.com/PointerByte/forge-go/logger
```

Update the dependencies used by the current module:

```bash
go get -u ./...
```

Install Staticcheck:

```bash
go install honnef.co/go/tools/cmd/staticcheck@latest
```

Run Staticcheck for this module:

```bash
staticcheck ./...
```

Use Staticcheck before opening a change. It complements `go test` and `go vet`
by finding suspicious code patterns, incorrect API usage, unreachable code,
deprecated calls, and simplifications that can hide bugs even when the code
still compiles.

## Packages

- `builder`: logger initialization, context-aware logging, and trace sections
- `common`: shared context keys used by HTTP and gRPC middleware
- `middlewares/http`: Gin middleware
- `middlewares/grpc`: gRPC interceptors
- `formatter`: structured log models and formatter implementations
- `sanitizer`: redaction of sensitive keys before formatting and export
- `viperData`: viper-backed configuration cache used by the logger
- `utilities`: small caller-tracing helpers

## Configuration

The module reads configuration from `viper`. It does not load files by itself,
so your application should load `application.yaml`, `application.yml`, JSON, or
environment values before calling `builder.InitLogger(...)` or installing the
middlewares.

```yaml
app:
  name: service-template
  version: 0.0.1

server:
  gin:
    LoggerWithConfig:
      enabled: true
      SkipPaths:
        - /health
      SkipQueryString: false
  grpc:
    LoggerWithConfig:
      enabled: true
      SkipFunction: []

logger:
  dir: logs
  modeTest: false
  level: info
  ignoredHeaders:
    - Authorization
    - Cookie
  formatter: json
  formatDate: "2006-01-02T15:04:05.000Z07:00"
  bodyCaptureMaxBytes: 65536
  rotate:
    enable: true
    maxSize: 10
    maxBackups: 5
    maxAge: 30
    compress: true
  sensibleKeys:
    - password
    - pwd
    - email
    - phone
```

Main keys:

- `app.name`: service name included in log details and OTEL resource metadata
- `app.version`: service version included in OTEL resource metadata
- `server.gin.LoggerWithConfig.enabled`: enables final Gin request logs
- `server.gin.LoggerWithConfig.SkipPaths`: request paths skipped by Gin logging
- `server.gin.LoggerWithConfig.SkipQueryString`: omits query strings from logged paths
- `server.grpc.LoggerWithConfig.enabled`: enables final gRPC request logs
- `server.grpc.LoggerWithConfig.SkipFunction`: gRPC methods skipped by name (`SayHello`) or full method (`/pkg.Service/SayHello`)
- `logger.dir`: directory where the log file is created by callers that use this key; the file is named `<app.name>.log`
- `logger.modeTest`: suppresses logger output and trace collection in test mode
- `logger.level`: `debug`, `info`, `warn`, or `error`; any other value falls back to `info`
- `logger.ignoredHeaders`: headers filtered from structured request details, in addition to the built-in list below
- `logger.formatter`: `json`, `text`, or a custom Go template
- `logger.formatDate`: Go time layout of the `timestamp` field, in both the
  local line and the exported log body. The default is
  `viperdata.DefaultFormatDate`, `2006-01-02T15:04:05.000Z07:00`: local time
  with milliseconds and the zone offset (`Z` in UTC), which is valid RFC 3339.
  Setting a layout without an offset, such as `2006-01-02T15:04:05.000`, also
  changes the local line and breaks consumers that validate RFC 3339.
- `logger.bodyCaptureMaxBytes`: maximum bytes retained independently for an enabled request or response body; absent and non-positive values use 65536
- `logger.sensibleKeys`: case-insensitive keys or key fragments whose values are redacted before formatting, in addition to the built-in list below
- `logger.rotate.*`: file rotation settings backed by `lumberjack`

`viperData` caches values on first use. In tests that change viper values
inside the same process, call `viperdata.ResetViperDataSingleton()` before
re-reading logger configuration.

## Built-In Redaction

Both lists start from a baseline that configuration can extend but never
shorten, so credentials are kept out of logs even with an empty configuration.
Entries are compared case-insensitively and duplicates are merged.

- Headers never logged, `viperdata.DefaultIgnoredHeaders()`: `Authorization`,
  `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-Auth-Token`,
  `X-Csrf-Token`, `X-Xsrf-Token`
- Keys always redacted, `viperdata.DefaultSensibleKeys()`: `authorization`,
  `password`, `passwd`, `secret`, `token`, `access_token`, `refresh_token`,
  `id_token`, `client_secret`, `api_key`, `apikey`, `private_key`,
  `credentials`, `session`, `cookie`

## Sanitization Safety Bound

Because the built-in keys always apply, structured values are always sanitized
recursively, to a maximum depth of 32. Any uninspected subtree beyond that
bound is replaced with `sanitizer.RedactedValue` (`"[REDACTED]"`); the original
subtree is never returned. This also bounds cyclic inputs.

## Bounded Body Capture

Request and response body logging remains disabled by default. When enabled,
HTTP and gRPC middleware retain at most `logger.bodyCaptureMaxBytes` for each
side independently. A truncated side adds metadata without changing bodies
that fit:

```json
{
  "requestCapture": {
    "truncated": true,
    "capturedBytes": 65536,
    "limitBytes": 65536
  }
}
```

HTTP capture observes only bytes the handler consumes. It never drains an
unread request after the handler returns; an unread or partially read request
is marked truncated instead. The complete body still flows to the handler and
client. Streaming gRPC capture applies the limit to the aggregate messages on
each side and detaches retained values from their original backing storage.

## Initialize The Logger

```go
package main

import (
	"context"
	"path/filepath"

	"github.com/PointerByte/forge-go/logger/builder"
	"github.com/spf13/viper"
)

func main() {
	viper.SetConfigName("application")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	ctx := context.Background()
	lp, err := builder.InitLogger(ctx, filepath.Join(".", viper.GetString("logger.dir")))
	if err != nil {
		panic(err)
	}
	defer lp.Shutdown(ctx)

	builder.New(ctx).Info("logger initialized")
}
```

`builder.InitLogger` configures the process-wide `slog` default logger. It
writes to stdout and, when `logger.rotate.enable=true`, to a rotated log file.
It also creates an OpenTelemetry logger provider and returns it so the caller
can shut it down gracefully. The returned provider is never nil on success, so
`defer lp.Shutdown(ctx)` is always safe. When export is enabled the provider is
also installed as the global OpenTelemetry `LoggerProvider`, so code that uses
`go.opentelemetry.io/otel/log` directly reaches the same pipeline.

The Gin and gRPC server bootstraps in the root module call `InitLogger` for
you, and `traces.InitTelemetry` in the root module initializes it together with
traces and metrics.

Bound and record-level `slog` attributes are emitted under the optional
`attributes` object, with `WithGroup` nesting preserved. Messages and
attributes are sanitized before both local output and OpenTelemetry export.
Formatter, writer, and export encoding failures are returned by the handler
contract rather than panicking.

## OpenTelemetry Log Export

Log export is **off by default**. It is enabled only when `OTEL_LOGS_EXPORTER`
selects an exporter, matching the `none` default that `OTEL_TRACES_EXPORTER` and
`OTEL_METRICS_EXPORTER` already use in the root module:

| `OTEL_LOGS_EXPORTER` | Behavior                                                    |
| -------------------- | ----------------------------------------------------------- |
| unset, empty, `none` | No exporter, no processor, nothing exported                   |
| `otlp`               | OTLP exporter behind a batch processor                       |
| anything else        | `InitLogger` returns an error                                |

The value is read as a comma-separated list; the first non-empty entry wins
after trimming and lowercasing, so `" OTLP , none "` selects `otlp`.
`OTEL_SDK_DISABLED=true` disables export whatever `OTEL_LOGS_EXPORTER` says, as
it does for traces and metrics.

When `otlp` is selected, the transport comes from
`OTEL_EXPORTER_OTLP_LOGS_PROTOCOL`, falling back to
`OTEL_EXPORTER_OTLP_PROTOCOL` and then to `http/protobuf`. Both `http/protobuf`
and `grpc` are supported; any other value returns an error rather than
exporting over a transport the caller did not ask for. The endpoint and headers
follow the standard `OTEL_EXPORTER_OTLP_*` variables.

The log resource uses the same detectors as the root module's traces and
metrics, so `OTEL_RESOURCE_ATTRIBUTES` and `OTEL_SERVICE_NAME` apply to logs
too. `app.name` sets `service.name` only when neither variable defines it, and
`app.version` sets `service.version`.

```bash
# Export logs to a collector on the default OTLP HTTP endpoint.
export OTEL_LOGS_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318
```

> **Behavior change.** Before `logger/v0.0.62` an OTLP exporter was always
> created with the specification defaults, targeting
> `https://localhost:4318/v1/logs`. Without a collector there, every batch
> export failed, and `otel.Handle` routed each failure through the standard
> library `log` package into this logger at `INFO`, so the transport error
> became the dominant log line. Set `OTEL_LOGS_EXPORTER=otlp` to restore the
> previous behavior.

When export is disabled, the installed handler has no exporter at all, so
records cost nothing extra rather than being built and dropped.

### Exported Records

Each log call produces one local line and, with export enabled, one OTLP log
record built from the same entry:

- **Body**: the entry as a structured map, with the keys, nesting, values, and
  sanitization of the local JSON line (`details`, `process`, `attributes`,
  `traceID`, `spanID`, `timestamp`, `level`, `message`, `method`, `line`,
  `latency`), whatever `logger.formatter` prints locally. Integral numbers are
  exported as integers.
- **Trace context**: `trace_id` and `span_id` are the entry's `traceID` and
  `spanID`, which the middlewares record once per request, not the span live in
  the context when the log is written. An entry without `spanID` carries a
  fallback correlation id, and its record has no trace context.
- **Source**: `code.function.name` and `code.line.number` are the entry's
  `method` and `line`. `code.file.path` is not exported.
- **Timestamp and severity**: the record's timestamp is the entry's time, and
  its severity follows the level.

`slog` attributes are exported inside the body's `attributes` object, not as
record attributes. Completed `process` traces are cleared once an entry carrying
them reaches either sink, so they are never exported twice.

Because the body mirrors the local entry, captured headers and enabled bodies
in `details` are exported too, after the same header filtering and key
redaction as the local line. Review `logger.ignoredHeaders` and
`logger.sensibleKeys` before enabling export.

## Gin Middleware

```go
package main

import (
	"net/http"

	httpmiddlewares "github.com/PointerByte/forge-go/logger/middlewares/http"
	"github.com/gin-gonic/gin"
)

func main() {
	engine := gin.New()
	engine.Use(
		gin.Recovery(),
		httpmiddlewares.InitLogger(),
		httpmiddlewares.LoggerWithConfig(),
		httpmiddlewares.CaptureBody(),
	)

	engine.GET("/health", func(c *gin.Context) {
		httpmiddlewares.EnableBody(c, true, true)
		httpmiddlewares.PrintInfo(c, "health check")
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
}
```

Middleware roles:

- `InitLogger()` extracts distributed-tracing headers, creates a request-scoped logger context, and stores request metadata.
- `LoggerWithConfig()` emits the final structured HTTP log entry through Gin's logger hook.
- `CaptureBody()` captures consumed request bytes and emitted response bytes only when body logging is enabled, bounded by `logger.bodyCaptureMaxBytes`, so they can be included in `details.request` and `details.response` without storing disabled payloads.
- `EnableBody(c, request, response)` opts the final HTTP request log into request and response body emission. Bodies are disabled by default.
- `EnableTraceBody(c, request, response)` opts trace service entries into request and response body emission when `TraceEnd` is called. Trace bodies are disabled by default.

The helper functions `PrintInfo`, `PrintDebug`, `PrintWarn`, and `PrintError`
schedule a request-scoped log message from inside Gin handlers.

## gRPC Interceptors

```go
import loggrpc "github.com/PointerByte/forge-go/logger/middlewares/grpc"

grpcServer := grpc.NewServer(
	grpc.ChainUnaryInterceptor(
		loggrpc.InitLoggerUnaryServerInterceptor(),
		loggrpc.LoggerWithConfigUnaryServerInterceptor(),
		loggrpc.CaptureBodyUnaryServerInterceptor(),
	),
	grpc.ChainStreamInterceptor(
		loggrpc.InitLoggerStreamServerInterceptor(),
		loggrpc.LoggerWithConfigStreamServerInterceptor(),
		loggrpc.CaptureBodyStreamServerInterceptor(),
	),
)
```

The interceptors mirror the Gin middleware behavior for unary and streaming
RPCs: they build the request-scoped logger context, capture request/response
payloads, copy metadata into structured details, and write the final log when
the handler completes. Unary bodies and each streaming direction are bounded
independently by `logger.bodyCaptureMaxBytes`; streaming messages share the
limit for their direction.

Request and response bodies are disabled by default. Use
`loggrpc.EnableBody(ctxLogger, true, true)` to include them in the final gRPC
request log, and `loggrpc.EnableTraceBody(ctxLogger, true, true)` to include
trace service bodies. `loggrpc.DisableGRPCBody(ctx, request, response)` and
`loggrpc.DisableGRPCTraceBody(ctx, request, response)` set the same flags from
a plain `context.Context` and return the logger context for chaining.

Final gRPC request logging intentionally ignores `codes.Unauthenticated` and
`codes.PermissionDenied` errors, so JWT authorization failures do not emit
logger middleware logs.

Use `loggrpc.PrintInfo`, `PrintDebug`, `PrintWarn`, or `PrintError` with the
request logger context when a handler needs to choose the final log level and
message explicitly.

When you use the root `config/server/grpc` package, these interceptors are
installed for you.

## Context Logger

Use `builder.New(ctx)` outside Gin or gRPC handlers when you need a contextual
logger directly:

```go
ctxLogger := builder.New(context.Background())

ctxLogger.Info("application started")
ctxLogger.Debug("cache warmed")
ctxLogger.Warn("dependency latency is high")
ctxLogger.Error(errors.New("dependency failed"))
```

`Infof`, `Debugf`, `Warnf`, and `Errorf` accept a format string and arguments.

When the context carries an active span, the logger adopts its trace and span
ids, so the log line and the span correlate. Without one it generates a
correlation id for `traceID` and omits `spanID`.

## Trace Sections

`TraceInit` and `TraceEnd` add downstream calls or internal subprocesses to the
`process` array in the structured log (shown as `services` in the text format).

```go
process := &formatter.Process{
	System:  "users-service",
	Process: "list-users",
	Method:  "GET",
	Server:  "https://users.internal",
	Path:    "/users",
}

ctxLogger.TraceInit(process)
defer ctxLogger.TraceEnd(process)

process.Code = 200
```

Common use cases are outbound HTTP/gRPC calls, provider SDK calls, and internal
business steps that should appear under the same trace.

`TraceEnd` derives `status` from `Code`: `2xx` is `SUCCESS`, `3xx` is `OTHER`,
`4xx` is `CLIENT_ERROR`, `5xx` is `ERROR`, and any other non-zero code is
`UNKNOWN`. With `Code` left at `0`, a status set with `SetStatus` is kept and
an empty one becomes `SUCCESS`.

Trace service request and response bodies are disabled by default. In Gin
handlers use `httpmiddlewares.EnableTraceBody(c, true, true)`; in gRPC handlers
use `loggrpc.EnableTraceBody(ctxLogger, true, true)`.

## Formatters

The output format is selected with the `logger.formatter` config key (see the
configuration block above). It accepts three kinds of value:

- `json`: structured JSON output
- `text` or `txt`: human-readable text output
- any custom Go template accepted by `formatter.CustomFormatter`

### Selecting the format via configuration

```yaml
logger:
  formatter: json   # "json", "text" (alias "txt"), or a Go template string
```

The empty string and `text`/`txt` produce the text layout; `json` produces the
JSON layout; anything else is treated as a Go `text/template` and rendered per
log entry.

### JSON output

```json
{
  "level": "INFO",
  "timestamp": "2026-06-22T10:30:00.000-05:00",
  "traceID": "a1b2c3d4...",
  "message": "request completed",
  "details": { "system": "orders-api", "method": "GET", "path": "/api/v1/orders" },
  "process": [
    { "system": "orders-api", "process": "GetOrders", "status": "SUCCESS", "latency": 12 }
  ],
  "method": "handler.go",
  "line": 42,
  "latency": 12
}
```

The line is emitted on a single line; it is indented here for reading.
`spanID` follows `traceID` when the entry has a span, and `attributes` follows
`process` when `slog` attributes are present.

### Text output

```text
[2026-06-22T10:30:00.000-05:00] [INFO] [a1b2c3d4...] handler.go:42 - request completed latency=12ms | details={system=orders-api, method=GET, path=/api/v1/orders} | services=[{system=orders-api, process=GetOrders, status=SUCCESS, latency=12ms}]
```

When the entry has a span, the third bracket reads `[traceID/spanID]`.

### Custom templates

A custom format is any string that is not `json`, `text`, `txt`, or empty. It is
parsed as a Go `text/template` and executed against the `formatter.LogFormat`
value of each entry, so you can reference its exported fields directly:

| Field        | Type        | Description                                  |
| ------------ | ----------- | -------------------------------------------- |
| `.Timestamp`  | `string`         | Formatted timestamp (`logger.formatDate`)    |
| `.TraceID`    | `string`         | Trace id for the entry                       |
| `.SpanID`     | `string`         | Span id, empty when no span was active       |
| `.Level`      | `Level`          | `DEBUG` / `INFO` / `WARN` / `ERROR`          |
| `.Message`    | `string`         | Log message                                  |
| `.Details`    | `Details`        | Request details (system, method, path, etc.) |
| `.Process`    | `[]Process`      | Recorded spans/processes                     |
| `.Attributes` | `map[string]any` | `slog` attributes, nil when there are none   |
| `.Method`     | `string`         | Source file of the call site                 |
| `.Line`       | `int`            | Source line of the call site                 |
| `.Latency`    | `int64`          | Latency in milliseconds                      |

Templates can also use these registered helper functions:

- `json v` — marshals any value to JSON
- `buildDetails .Details` — normalizes `Details` into a map, dropping empty fields
- `buildServices .Process` — normalizes `[]Process` into a slice of maps

Set the template as the value of `logger.formatter` in `application.yaml`. It is
a single-line string (the template source), so use quotes and keep it on one
line:

```yaml
logger:
  formatter: '{{.Level}} | {{.Message}} | {{json (buildServices .Process)}}'
```

With the entry from the examples above, that produces:

```text
INFO | request completed | [{"latency":12,"process":"GetOrders","status":"SUCCESS","system":"orders-api"}]
```

**Important — custom templates cannot rename JSON keys.** After rendering,
`Format` checks whether the output is valid JSON: if it is, the bytes are
unmarshaled back into `LogFormat` and re-marshaled, so any key that does not
match a struct tag is dropped and the standard keys are emitted with their
struct-tag names. This `application.yaml/json` value:

```yaml
logger:
  formatter: '{"ts":{{json .Timestamp}},"lvl":{{json .Level}}}'
```

does **not** yield `{"ts":...,"lvl":...}`; it loses `ts`/`lvl` and falls back to
the default JSON keys with empty values. Custom templates only keep their own
labels when the rendered output is **not** valid JSON (like the `level | message
| …` form above) — full control over labels, at the cost of structured JSON.

## Testing

To silence log output and trace collection in tests:

```go
builder.EnableModeTest()
defer builder.DisableModeTest()
```

From the `logger` module directory:

```bash
go test ./...
go test -cover -covermode=atomic -coverprofile=coverage.out ./...
```
