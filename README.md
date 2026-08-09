# GoForge

GoForge is a modular Go toolkit for bootstrapping service-oriented
applications with shared conventions for configuration, HTTP and gRPC
transport, logging, OpenTelemetry, JWT security, background jobs, and small
runtime utilities.

The repository is organized as a Go workspace. The root module contains the
service bootstrap packages under `config` and `tools`; `logger`, `security`,
`encrypt`, and the CLIs are separate modules that can also be consumed on their
own.

Spanish documentation is available in [README.es.md](./README.es.md).

## What It Includes

- Gin HTTP server bootstrap with common middleware
- gRPC server bootstrap with unary and stream interceptors
- HTTP and gRPC clients with tracing hooks
- structured logging through the `logger` module
- OpenTelemetry traces, metrics, and instrumentation helpers
- JWT middleware through the `security` module
- local and cloud-backed cryptographic helpers through `encrypt`
- fixed-interval background jobs and simple worker utilities
- CLIs for service scaffolding and certificate generation

## Modules

- [root module](./go.mod): `github.com/PointerByte/forge-go`
- [logger](./logger/README.md): structured logging plus HTTP and gRPC middleware
- [security](./security/README.md): JWT services and Gin security middleware
- [encrypt](./encrypt/README.md): symmetric crypto, hashing, RSA, signatures, and KMS-oriented backends
- [cmd/qgo](./cmd/qgo/README.md): CLI for scaffolding Gin and gRPC services
- [cmd/go-openssl](./cmd/go-openssl/README.md): CLI for generating and reading PEM certificates and keys

## Installation

Install the root module:

```bash
go get github.com/PointerByte/forge-go
```

Or install only the modules you need:

```bash
go get github.com/PointerByte/forge-go/logger
go get github.com/PointerByte/forge-go/security
go get github.com/PointerByte/forge-go/encrypt
```

Update the dependencies used by the current module:

```bash
go get -u ./...
```

Install the CLIs:

```bash
go install github.com/PointerByte/forge-go/cmd/qgo@latest
go install github.com/PointerByte/forge-go/cmd/go-openssl@latest
```

## Configuration

GoForge applications keep runtime configuration under `resources/`.
`tools/utilities.LoadEnv(prefixPath)` is the shared runtime configuration
loader. It loads the selected application file into `viper`, merges optional
environment files, and applies process environment overrides before the server,
logger, OpenTelemetry, clients, and JWT helpers read configuration.

Use it when you build a custom entrypoint or command:

```go
if err := utilities.LoadEnv("."); err != nil {
	log.Fatal(err)
}

serviceName := viper.GetString("app.name")
```

Gin and gRPC server bootstraps call it for you. Custom code should call it
before reading from `viper` or initializing components that depend on
configuration.

`prefixPath` controls where configuration is searched:

- an empty value uses the current working directory
- a directory with `application.yml`, `application.yaml`, or `application.json`
  is used directly
- otherwise GoForge walks upward from `prefixPath` until it finds the nearest
  `resources/` directory with an application file
- if no parent `resources/` directory is found, it tries `prefixPath/resources`
  so the missing file error points at the expected location

Inside the resolved configuration directory, it checks these files in order:

1. `application.yml`
2. `application.yaml`
3. `application.json`

After the application file is read, it merges the environment files declared in
`env.files`. Relative file paths are resolved from the same directory as the
selected application file. Environment overrides are generated from the existing
configuration key path.

```yaml
env:
  files:
    - .env
    - .env.local
```

This keeps local files, deployment variables, and framework defaults on the
same `viper` instance, so Gin and gRPC behave consistently even when the
binary is started from a nested directory such as `cmd/example`.

Examples:

- `app.name` -> `APP_NAME`
- `server.gin.port` -> `SERVER_GIN_PORT`
- `server.gin.groups` -> `SERVER_GIN_GROUPS`
- `server.grpc.port` -> `SERVER_GRPC_PORT`
- `client.http.timeout` -> `CLIENT_HTTP_TIMEOUT`
- `client.grpc.tls.serverName` -> `CLIENT_GRPC_TLS_SERVERNAME`
- `jwt.hmac.secret` -> `JWT_HMAC_SECRET`
- `jwt.keys.private_key` -> `JWT_KEYS_PRIVATE_KEY`
- `jwt.keys.public_key` -> `JWT_KEYS_PUBLIC_KEY`

YAML is the recommended format for new applications.

### Minimal YAML

```yaml
app:
  name: GoForge-service
  version: 0.0.1

server:
  modeTest: false
  gin:
    port: ":8080"
    mode: release
    readHeaderTimeout: 5s
    groups:
      - /api/v1
    UseH2C: true
    rate:
      limit: 1000
      burst: 2000
    LoggerWithConfig:
      enabled: true
      SkipPaths:
        - /health
      SkipQueryString: false
  grpc:
    port: ":50051"
    rate:
      limit: 1000
      burst: 2000

client:
  http:
    timeout: 5s

logger:
  dir: logs
  level: info
  formatter: json
  formatDate: "2006-01-02T15:04:05.000"
  ignoredHeaders:
    - Authorization
    - Cookie

traces:
  SkipPaths:
    - /health

jwt:
  enable: false
  transport: header
  algorithm: EDDSA
  keys:
    private_key: ./certs/jwt/ed25519-key.pem
    public_key: ./certs/jwt/ed25519-public.pem
```

## Main Configuration Keys

### Application

- `app.name`: service name used by health endpoints and OpenTelemetry resource metadata
- `app.version`: service version reported by health endpoints and telemetry metadata
- `server.modeTest`: disables runtime behaviors such as background job execution during tests

### Gin Server

- `server.gin.port`: HTTP listen address
- `server.gin.mode`: Gin mode, for example `debug`, `release`, or `test`
- `server.gin.readHeaderTimeout`: maximum time allowed to read request headers
- `server.gin.groups`: route groups created by `config/server/gin`
- `server.gin.UseH2C`: enables HTTP/2 cleartext support
- `server.gin.rate.limit`: request rate for the built-in limiter; `0` disables it
- `server.gin.rate.burst`: burst size for the limiter
- `server.gin.LoggerWithConfig.enabled`: enables structured HTTP request logs
- `server.gin.LoggerWithConfig.SkipPaths`: paths skipped by the request logger
- `server.gin.LoggerWithConfig.SkipQueryString`: hides query strings in logged paths

Gin also supports `server.gin.autotls.*`, `server.gin.tls.*`, and
`server.gin.mtls.*` settings for automatic TLS, explicit TLS, and mTLS.

Recognized TLS version strings are `tlsv10`, `tlsv11`, `tlsv12`, and
`tlsv13`; the default is `tlsv12`. TLS 1.0 and 1.1 remain recognized only for
legacy compatibility and must not be selected for production deployments.
Supported client-auth values include `no_client_cert`, `request_client_cert`,
`require_any_client_cert`, `verify_client_cert_if_given`, and
`require_and_verify_client_cert`.

### gRPC Server

- `server.grpc.port`: gRPC listen address
- `server.grpc.rate.limit`: request rate for the built-in limiter; `0` disables it
- `server.grpc.rate.burst`: burst size for the limiter
- `server.grpc.tls.enable`: enables TLS on the gRPC server
- `server.grpc.tls.certFile`: server certificate path
- `server.grpc.tls.keyFile`: server private key path
- `server.grpc.tls.version`: minimum TLS version
- `server.grpc.mtls.enable`: enables mTLS validation
- `server.grpc.mtls.clientCAFile`: CA file used to validate client certificates
- `server.grpc.mtls.clientAuth`: client certificate policy

### Clients

- `client.http.timeout`: default timeout for configured HTTP clients
- `client.http.tls.*`: outbound HTTP TLS settings
- `client.http.mtls.*`: outbound HTTP mTLS client certificate settings
- `client.grpc.tls.*`: outbound gRPC TLS settings
- `client.grpc.mtls.*`: outbound gRPC mTLS client certificate settings

HTTP verb calls keep their request URL, body, context and headers isolated
when one `IRest` is used concurrently. `IRestGeneric` preserves the legacy
setter-based interface by serializing each configuration-and-request sequence.
Generic response bodies that are only discarded are streamed; traced
non-success bodies retain at most `logger.bodyCaptureMaxBytes` (65,536 bytes
by default) and report truncation metadata.

The legacy client keys `client.http.tls.insecureSkipVerify` and
`client.grpc.tls.insecureSkipVerify` deliberately disable certificate and host
verification. Never enable them in production; configure the corresponding
`caFile` and `serverName` instead. They remain available only for compatible
local/test deployments.

### Logger, Traces, and JWT

- `logger.dir`: directory for log files
- `logger.level`: minimum log level such as `debug`, `info`, `warn`, or `error`
- `logger.ignoredHeaders`: headers removed from structured logs
- `logger.formatter`: output format, usually `json` or `text`
- `logger.bodyCaptureMaxBytes`: maximum request or response prefix retained in
  structured logs; defaults to 65,536 bytes
- `logger.rotate.*`: file rotation settings
- `traces.SkipPaths`: HTTP paths skipped by Gin OpenTelemetry middleware
- `jwt.enable`: enables JWT middleware enforcement
- `jwt.transport`: token source, usually `header` or `cookie`
- `jwt.cookie.name`: cookie name when `jwt.transport` is `cookie`
- `jwt.algorithm`: signing algorithm such as `HS256`, `RS256`, `PS256`, or `EdDSA`; required when using `jwt.keys.*`
- `jwt.hmac.secret`: shared secret for `HS256`
- `jwt.keys.private_key`, `jwt.keys.public_key`: asymmetric key values or PEM file paths interpreted according to `jwt.algorithm`
- `jwt.rsa.*`, `jwt.eddsa.*`: legacy asymmetric key paths kept for compatibility

## HTTP Server

`config/server/gin.CreateApp()` loads configuration, initializes the logger and
OpenTelemetry, creates the shared `gin.Engine`, registers common middleware,
creates route groups from `server.gin.groups`, and registers `/health` under
each group.

```go
package main

import (
	"log"

	serverGin "github.com/PointerByte/forge-go/config/server/gin"
	"github.com/gin-gonic/gin"
)

func main() {
	srv, err := serverGin.CreateApp()
	if err != nil {
		log.Fatal(err)
	}

	api := serverGin.GetRoute("/api/v1")
	api.GET("/hello", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "ok"})
	})

	serverGin.Start(srv)
}
```

## gRPC Server

`config/server/grpc` loads configuration in `Serve()`, resolves
`server.grpc.port`, attaches logging and OpenTelemetry interceptors, supports
TLS and mTLS, and performs graceful shutdown on process signals.

```go
package main

import (
	"context"
	"log"

	pb "github.com/PointerByte/forge-go/config/proto"
	serverGRPC "github.com/PointerByte/forge-go/config/server/grpc"
	"google.golang.org/grpc"
)

type greeterServer struct {
	pb.UnimplementedGreeterServer
}

func (greeterServer) SayHello(_ context.Context, req *pb.HelloRequest) (*pb.HelloReply, error) {
	return &pb.HelloReply{Message: "hello " + req.GetName()}, nil
}

func (greeterServer) CreateChat(stream grpc.ClientStreamingServer[pb.ChatMessage, pb.ChatSummary]) error {
	return nil
}

func (greeterServer) StreamAlerts(stream grpc.BidiStreamingServer[pb.AlertMessage, pb.AlertMessage]) error {
	return nil
}

func main() {
	srv := serverGRPC.NewIConfig(nil, nil)
	if err := srv.Register(func(r grpc.ServiceRegistrar) {
		pb.RegisterGreeterServer(r, greeterServer{})
	}); err != nil {
		log.Fatal(err)
	}

	log.Fatal(srv.Serve())
}
```

## Clients

HTTP:

```go
client := clientHttp.NewGenericRest(10*time.Second, nil)

err := client.GetGeneric(ctx, clientHttp.RequestGeneric{
	System:   "users-service",
	Process:  "list-users",
	Host:     "https://api.example.com",
	Path:     "users",
	Response: &usersResponse,
})
```

gRPC:

```go
cli := clientGRPC.NewIClient(nil)
cli.SetAddress("localhost:50051")

greeter, err := clientGRPC.BuildClient(cli, pb.NewGreeterClient)
if err != nil {
	panic(err)
}

ctx := metadata.AppendToOutgoingContext(
	context.Background(),
	"authorization", "Bearer "+token,
)

resp, err := greeter.SayHello(ctx, &pb.HelloRequest{Name: "Manuel"})
if err != nil {
	panic(err)
}
```

Use `NewGenericRestFromConfig()` or the gRPC client TLS settings when you want
client transports to be built from `viper`.

## Background Work

`tools/jobs` provides fixed-interval in-process jobs. Jobs begin when
`jobs.StartJobs()` runs; `config/server/gin.Start(...)` calls it automatically.
When `server.modeTest=true`, jobs are not started. Use an id when a job must be
paused, resumed, or stopped individually.

```go
func registerJobs() error {
	timeout := 30 * time.Minute

	if err := jobs.JobWithID("refresh-cache", func() {
		refreshCache()
	}, time.Minute, &timeout); err != nil {
		return err
	}

	if err := jobs.PauseJob("refresh-cache"); err != nil {
		return err
	}
	if err := jobs.ResumeJob("refresh-cache"); err != nil {
		return err
	}
	return jobs.StopJob("refresh-cache")
}
```

`tools/workers` provides a small bounded worker loop through `SetWorkersLimit`,
`RunWorkers`, `AddTask`, `StopWorkers`, and `RestartWorkers`.

## Runtime Examples

The root module keeps runnable examples in
[cmd/example/main.go](./cmd/example/main.go). The repository root is the
library module, while `cmd/example` is the practical executable for trying the
Gin and gRPC bootstraps.

Use an application file like
[resources/application.yaml](./resources/application.yaml) before starting the
Gin example; it expects `/api/v1` in `server.gin.groups`. Run the examples from
the repository root.

Run the Gin example:

```bash
GoForge_EXAMPLE_SERVER=gin go run ./cmd/example
```

Run the gRPC example:

```bash
GoForge_EXAMPLE_SERVER=grpc go run ./cmd/example
```

The example command intentionally does not choose a server by default. If
`GoForge_EXAMPLE_SERVER` is not set to `gin` or `grpc`, it prints a usage
message instead of starting a server:

```text
Set GoForge_EXAMPLE_SERVER=gin or GoForge_EXAMPLE_SERVER=grpc to run a practical example server.
```

After the example moved from the repository root to `cmd/example`, `go run .`
is no longer the root example command. Use `go run ./cmd/example` from the
repository root, or `go run .` only when your shell is already inside
`cmd/example`.

## Development

The workspace uses Go `1.25.0`.

Install Staticcheck:

```bash
go install honnef.co/go/tools/cmd/staticcheck@latest
```

Run Staticcheck for the current module:

```bash
staticcheck ./...
```

Run it from each workspace module when you want to check the root module and
the submodules:

```bash
staticcheck ./...
cd logger && staticcheck ./...
cd ../security && staticcheck ./...
cd ../encrypt && staticcheck ./...
cd ../cmd/qgo && staticcheck ./...
cd ../go-openssl && staticcheck ./...
```

Use Staticcheck as part of the local quality pass before opening a change. It
complements `go test` and `go vet` by finding suspicious code patterns,
incorrect API usage, unreachable code, deprecated calls, and simplifications
that can hide bugs even when the code still compiles.

Run tests for the root module:

```bash
go test ./...
```

Run tests for a workspace module:

```bash
cd logger
go test ./...
```

### Security and vulnerability scanning

Run these checks as part of the local quality pass before opening a change.
Each tool covers a different class of problem, so they complement Staticcheck
and `go test` rather than replace them.

Scan the source for known vulnerabilities in the dependencies and the standard
library (reports only vulnerabilities reachable from your code):

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

Run the static security analyzer. `-exclude-generated` skips generated protobuf
files; `-exclude G402` skips the TLS-settings rule, which is handled through the
server/client TLS configuration rather than hard-coded:

```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
gosec -exclude G402 -exclude-generated ./...
```

Scan the working tree and git history for committed secrets. Document known
false positives in `.gitleaksignore` instead of disabling the rule:

```bash
gitleaks detect --no-git  --source .
gitleaks detect --no-git  --source . --verbose   # includes each finding's file, line, and matched value
```

Run `govulncheck` and `gosec` from each workspace module (as shown for
Staticcheck above) when you need to cover the submodules as well as the root.

Generate protobuf files after editing `config/proto/methods.proto`:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
protoc --go_out=. --go-grpc_out=. config/proto/methods.proto
```

Coverage for the current module:

```bash
go test -cover -covermode=atomic -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
go tool cover -html=coverage.out -o coverage.html
```
