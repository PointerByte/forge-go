# qgo

`qgo` is the GoForge service scaffolding CLI. It creates starter projects for
Gin HTTP services or gRPC services, writes the initial application
configuration, initializes `go.mod`, and runs `go mod tidy`.

## Install

```bash
go install github.com/PointerByte/forge-go/cmd/qgo@latest
```

Update the dependencies used by the current module:

```bash
go get -u ./...
```

## Commands

Create a Gin service:

```bash
qgo new gin
```

Create a gRPC service:

```bash
qgo new grpc
```

Both commands support interactive prompts and non-interactive flags.
When run in an interactive terminal, `qgo new ...` shows a short GoForge intro
animation before scaffolding.

## Non-Interactive Usage

```bash
qgo new gin \
  --module github.com/acme/orders-api \
  --app-name orders-api \
  --config-format yaml \
  --dir ./orders-api
```

```bash
qgo new grpc \
  --module github.com/acme/payments-rpc \
  --app-name payments-rpc \
  --config-format json \
  --dir ./payments-rpc
```

## Flags

| Flag | Short | Description |
| --- | --- | --- |
| `--module` | `-m` | Go module path used in `go mod init` |
| `--app-name` | `-a` | Value written to `app.name` in the generated config |
| `--config-format` | `-c` | `yaml` or `json`; interactive mode defaults to `yaml` |
| `--go-version` | `-g` | Go version written to `go.mod`; defaults to the installed Go version |
| `--dir` | `-d` | Output directory; defaults to `app.name` |

If a required flag is omitted, `qgo` asks for it interactively.
If `--go-version` is omitted, press Enter to use the installed Go version.

## Validation

- module path accepts letters, numbers, `.`, `_`, `/`, and `-`
- `app.name` accepts letters, numbers, `_`, and `-`
- spaces are rejected in both values
- config format must be `yaml` or `json`
- Go version must use `major.minor` or `major.minor.patch`
- the output directory must not already exist

## Generated Files

For both service types, `qgo` creates:

- `cmd/main.go`
- `resources/application.yaml` or `resources/application.json`
- `go.mod`, created by `go mod init <module>` and updated with the selected Go version
- `go.sum`, when dependency resolution needs it

After writing the files, it runs:

```bash
go mod init <module>
go mod edit -go=<version>
go mod tidy
```

`go mod tidy` downloads the GoForge dependencies required by the generated
service, so network access may be needed.

## Gin Scaffold

The Gin scaffold creates a `cmd/main.go` that:

- calls `serverGin.CreateApp()`
- retrieves the `/api/v1` route group with `serverGin.GetRoute("/api/v1")`
- registers `GET /hello`
- starts the server with `serverGin.Start(srv)`

The generated application config includes Gin server settings, logging,
OpenTelemetry flags, JWT defaults, HTTP/gRPC client TLS settings, and
TLS/mTLS placeholders for server certificates.

Run the generated service from its output directory:

```bash
go run ./cmd
```

Default HTTP port:

```text
:8080
```

## gRPC Scaffold

The gRPC scaffold creates a minimal `cmd/main.go` that:

- calls `serverGRPC.NewIConfig(nil, nil)`
- starts the server with `srv.Serve()`

The generated application config includes gRPC server settings, logging,
OpenTelemetry flags, JWT defaults, gRPC client TLS settings, and TLS/mTLS
placeholders.

Run the generated service from its output directory:

```bash
go run ./cmd
```

Default gRPC port:

```text
:50051
```

## Examples

Create a YAML Gin service in the default output directory:

```bash
qgo new gin -m github.com/acme/orders-api -a orders-api -c yaml
```

Create a JSON gRPC service in an explicit directory:

```bash
qgo new grpc \
  -m github.com/acme/payments-rpc \
  -a payments-rpc \
  -c json \
  -d ./services/payments-rpc
```

If the command succeeds, it prints:

```text
Service created in <absolute-output-directory>
```

## Development

From the `cmd/qgo` module directory:

```bash
go install honnef.co/go/tools/cmd/staticcheck@latest
staticcheck ./...
go test ./...
go test -cover -covermode=atomic -coverprofile=coverage.out ./...
```

Use Staticcheck before opening a change. It complements `go test` and `go vet`
by finding suspicious code patterns, incorrect API usage, unreachable code,
deprecated calls, and simplifications that can hide bugs even when the code
still compiles.
