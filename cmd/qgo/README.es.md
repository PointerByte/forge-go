# qgo

`qgo` es la CLI de scaffolding de servicios GoForge. Crea proyectos iniciales
para servicios HTTP con Gin o servicios gRPC, escribe la configuracion inicial,
inicializa `go.mod` y ejecuta `go mod tidy`.

## Instalacion

```bash
go install github.com/PointerByte/forge-go/cmd/qgo@latest
```

Actualizar las dependencias usadas por el modulo actual:

```bash
go get -u ./...
```

## Comandos

Crear un servicio Gin:

```bash
qgo new gin
```

Crear un servicio gRPC:

```bash
qgo new grpc
```

Ambos comandos soportan prompts interactivos y flags no interactivos.
Cuando se ejecuta en una terminal interactiva, `qgo new ...` muestra una breve
animacion de GoForge antes de generar el scaffold.

## Uso No Interactivo

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

| Flag | Short | Descripcion |
| --- | --- | --- |
| `--module` | `-m` | ruta del modulo Go usada en `go mod init` |
| `--app-name` | `-a` | valor escrito en `app.name` dentro de la configuracion generada |
| `--config-format` | `-c` | `yaml` o `json`; en modo interactivo el default es `yaml` |
| `--go-version` | `-g` | version de Go escrita en `go.mod`; por defecto usa la version de Go instalada |
| `--dir` | `-d` | directorio de salida; por defecto usa `app.name` |

Si omites un flag requerido, `qgo` lo pregunta de forma interactiva.
Si omites `--go-version`, presiona Enter para usar la version de Go instalada.

## Validacion

- la ruta del modulo acepta letras, numeros, `.`, `_`, `/` y `-`
- `app.name` acepta letras, numeros, `_` y `-`
- los espacios se rechazan en ambos valores
- el formato de configuracion debe ser `yaml` o `json`
- la version de Go debe usar `major.minor` o `major.minor.patch`
- el directorio de salida no debe existir previamente

## Archivos Generados

Para ambos tipos de servicio, `qgo` crea:

- `cmd/main.go`
- `resources/application.yaml` o `resources/application.json`
- `go.mod`, creado por `go mod init <modulo>` y actualizado con la version de Go elegida
- `go.sum`, cuando la resolucion de dependencias lo necesita

Despues de escribir los archivos, ejecuta:

```bash
go mod init <modulo>
go mod edit -go=<version>
go mod tidy
```

`go mod tidy` descarga las dependencias GoForge necesarias para el servicio
generado, asi que puede requerir acceso a red.

## Scaffold Gin

El scaffold Gin crea un `cmd/main.go` que:

- llama `serverGin.CreateApp()`
- obtiene el grupo `/api/v1` con `serverGin.GetRoute("/api/v1")`
- registra `GET /hello`
- inicia el servidor con `serverGin.Start(srv)`

La configuracion generada incluye settings del servidor Gin, logging, flags de
OpenTelemetry, defaults JWT, configuracion TLS para clientes HTTP/gRPC y
placeholders TLS/mTLS para certificados del servidor.

Ejecutar el servicio generado desde su directorio:

```bash
go run ./cmd
```

Puerto HTTP por defecto:

```text
:8080
```

## Scaffold gRPC

El scaffold gRPC crea un `cmd/main.go` minimo que:

- llama `serverGRPC.NewIConfig(nil, nil)`
- inicia el servidor con `srv.Serve()`

La configuracion generada incluye settings del servidor gRPC, logging, flags de
OpenTelemetry, defaults JWT, configuracion TLS del cliente gRPC y placeholders
TLS/mTLS.

Ejecutar el servicio generado desde su directorio:

```bash
go run ./cmd
```

Puerto gRPC por defecto:

```text
:50051
```

## Ejemplos

Crear un servicio Gin YAML en el directorio default:

```bash
qgo new gin -m github.com/acme/orders-api -a orders-api -c yaml
```

Crear un servicio gRPC JSON en un directorio explicito:

```bash
qgo new grpc \
  -m github.com/acme/payments-rpc \
  -a payments-rpc \
  -c json \
  -d ./services/payments-rpc
```

Si el comando termina bien, imprime:

```text
Service created in <directorio-absoluto-de-salida>
```

## Desarrollo

Desde el directorio del modulo `cmd/qgo`:

```bash
go install honnef.co/go/tools/cmd/staticcheck@latest
staticcheck ./...
go test ./...
go test -cover -covermode=atomic -coverprofile=coverage.out ./...
```

Usa Staticcheck antes de abrir un cambio. Complementa `go test` y `go vet`
detectando patrones sospechosos, uso incorrecto de APIs, codigo inalcanzable,
llamadas deprecadas y simplificaciones que pueden ocultar bugs aunque el
codigo todavia compile.
