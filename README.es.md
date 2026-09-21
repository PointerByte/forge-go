# forge-go

forge-go es un toolkit modular para arrancar aplicaciones de servicios en Go
con convenciones compartidas para configuracion, transporte HTTP y gRPC,
logging, OpenTelemetry, seguridad JWT, jobs en background y utilidades de
runtime.

El repositorio esta organizado como un workspace de Go. El modulo raiz contiene
los paquetes de bootstrap en `config` y `tools`; `logger`, `security`,
`encrypt` y las CLIs son modulos separados que tambien pueden consumirse de
forma independiente.

La documentacion en ingles esta disponible en [README.md](./README.md).

## Que Incluye

- bootstrap de servidor HTTP con Gin y middlewares comunes
- bootstrap de servidor gRPC con interceptores unary y stream
- clientes HTTP y gRPC con hooks de tracing
- logging estructurado mediante el modulo `logger`
- trazas, metricas y helpers de instrumentacion con OpenTelemetry
- middleware JWT mediante el modulo `security`
- criptografia local y backends orientados a KMS mediante `encrypt`
- jobs de intervalo fijo y utilidades simples de workers
- CLIs para generar servicios y certificados

## Modulos

- [modulo raiz](./go.mod): `github.com/PointerByte/forge-go`
- [logger](./logger/README.es.md): logging estructurado y middlewares HTTP/gRPC
- [security](./security/README.es.md): servicios JWT y middleware de seguridad para Gin
- [encrypt](./encrypt/README.es.md): cifrado simetrico, hashes, RSA, firmas y backends orientados a KMS
- [cmd/qgo](./cmd/qgo/README.es.md): CLI para generar servicios Gin y gRPC
- [cmd/go-openssl](./cmd/go-openssl/README.es.md): CLI para generar y leer certificados y llaves PEM

## Instalacion

Instalar el modulo raiz:

```bash
go get github.com/PointerByte/forge-go
```

O instalar solo los modulos que necesites:

```bash
go get github.com/PointerByte/forge-go/logger
go get github.com/PointerByte/forge-go/security
go get github.com/PointerByte/forge-go/encrypt
```

Actualizar las dependencias usadas por el modulo actual:

```bash
go get -u ./...
```

Instalar las CLIs:

```bash
go install github.com/PointerByte/forge-go/cmd/qgo@latest
go install github.com/PointerByte/forge-go/cmd/go-openssl@latest
```

## Configuracion

Las aplicaciones forge-go mantienen la configuracion de runtime en `resources/`.
`tools/utilities.LoadEnv(prefixPath)` es el loader compartido de configuracion
de runtime. Carga el archivo de aplicacion seleccionado en `viper`, mezcla
archivos de entorno opcionales y aplica overrides desde variables de entorno
del proceso antes de que el servidor, logger, OpenTelemetry, clientes y helpers
JWT lean configuracion.

Usalo cuando construyas un entrypoint o comando propio:

```go
if err := utilities.LoadEnv("."); err != nil {
	log.Fatal(err)
}

serviceName := viper.GetString("app.name")
```

Los bootstraps de Gin y gRPC lo llaman por ti. El codigo custom debe llamarlo
antes de leer desde `viper` o inicializar componentes que dependen de
configuracion.

`prefixPath` controla donde se busca la configuracion:

- un valor vacio usa el directorio de trabajo actual
- un directorio con `application.yml`, `application.yaml`, `application.json` o
  `default.ini` se usa directamente
- si no, forge-go sube desde `prefixPath` hasta encontrar la carpeta
  `resources/` mas cercana con alguno de esos archivos
- si no encuentra una carpeta `resources/` en los padres, intenta
  `prefixPath/resources` para que el error apunte a la ubicacion esperada

Dentro del directorio de configuracion resuelto, busca estos archivos en orden:

1. `application.yml`
2. `application.yaml`
3. `application.json`

Despues de leer el archivo de aplicacion, mezcla los archivos INI descritos mas
abajo y luego los archivos de entorno declarados en `env.files`. Las rutas
relativas se resuelven desde el mismo directorio del archivo de aplicacion
seleccionado. Los overrides por entorno se generan desde la ruta de claves ya
existente en la configuracion.

```yaml
env:
  files:
    - .env
    - .env.local
```

Esto mantiene archivos locales, variables de despliegue y defaults del
framework en la misma instancia de `viper`, para que Gin y gRPC se comporten de
forma consistente incluso cuando el binario se inicia desde un directorio
anidado como `cmd/example`.

Las fuentes se aplican en este orden, cada una sobrescribiendo a la anterior:

1. `application.yml`, `application.yaml` o `application.json`
2. `default.ini`
3. `<app.name>.ini`
4. los archivos listados en `env.files`
5. variables de entorno del proceso

Ejemplos:

- `app.name` -> `APP_NAME`
- `server.gin.port` -> `SERVER_GIN_PORT`
- `server.gin.groups` -> `SERVER_GIN_GROUPS`
- `server.grpc.port` -> `SERVER_GRPC_PORT`
- `client.http.timeout` -> `CLIENT_HTTP_TIMEOUT`
- `client.grpc.tls.serverName` -> `CLIENT_GRPC_TLS_SERVERNAME`
- `jwt.hmac.secret` -> `JWT_HMAC_SECRET`
- `jwt.keys.private_key` -> `JWT_KEYS_PRIVATE_KEY`
- `jwt.keys.public_key` -> `JWT_KEYS_PUBLIC_KEY`

YAML es el formato recomendado para aplicaciones nuevas.

### YAML Minimo

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

### Archivos INI

La configuracion tambien puede escribirse en INI. Dos archivos opcionales del
directorio de configuracion resuelto se mezclan sobre el archivo de aplicacion:

1. `default.ini`, el overlay compartido que cualquier proyecto puede aportar
2. `<app.name>.ini`, con el nombre de `app.name`

Un servicio creado como `dragon-cmk` lee entonces primero `default.ini` y
despues `dragon-cmk.ini`, asi que el archivo especifico del proyecto siempre
gana. Ambos son opcionales. `APP_NAME` selecciona el segundo archivo cuando esta
definida, lo que permite que un despliegue elija su overlay igual que
sobrescribe cualquier otra clave.

No hace falta un archivo de aplicacion cuando el directorio se configura solo
con INI: una carpeta `resources/` que unicamente tiene `default.ini` es un
directorio de configuracion valido. Un `.ini` ausente se ignora; uno mal formado
hace fallar a `LoadEnv` en vez de dejar la aplicacion a medio configurar.

```ini
; resources/default.ini
[app]
name = dragon-cmk
version = 0.0.1

[server.gin]
port = :8080
mode = release
readHeaderTimeout = 5s
groups = [/api/v1, /api/v2]
UseH2C = true

[server.gin.rate]
limit = 1000
burst = 2000

[logger]
level = info
formatter = json

[traces]
SkipPaths = /health
SkipPaths = /metrics

[jwt]
enable = false
algorithm = EDDSA
```

Los encabezados de seccion y las claves con puntos construyen la misma ruta, asi
que `[server.gin]` con `port` y `[server]` con `gin.port` definen ambos
`server.gin.port`. Un encabezado vacio `[]` vuelve a la raiz.

Los valores se tipan asi:

- una clave que el archivo de aplicacion ya declara conserva su tipo, por eso
  `groups = /v2, /v3` sigue siendo lista y `limit = 2500` sigue siendo numero
- una clave nueva se infiere: `true` y `false` pasan a booleano, los digitos a
  numero y el resto queda como texto
- `[a, b, c]` declara una lista de forma explicita, que es como una clave que
  el archivo de aplicacion no declara pasa a ser lista, incluidas las de un solo
  elemento como `SkipPaths = [/health]`
- repetir una clave agrega a una lista, por eso `SkipPaths` arriba da dos
  entradas
- entrecomillar un valor con `"` o `'` lo mantiene como texto y conserva sus
  espacios

Los comentarios empiezan con `;` o `#` al inicio de una linea, o despues de un
espacio en un valor sin comillas. Un marcador que no viene precedido de espacio
es parte del valor, por eso `password = abc#123` se lee completo.

## Claves Principales

### Aplicacion

- `app.name`: nombre del servicio usado por health endpoints y metadata OpenTelemetry
- `app.version`: version del servicio reportada en health endpoints y telemetria
- `server.modeTest`: deshabilita comportamientos de runtime como ejecucion de jobs durante pruebas

### Servidor Gin

- `server.gin.port`: direccion de escucha HTTP
- `server.gin.mode`: modo de Gin, por ejemplo `debug`, `release` o `test`
- `server.gin.readHeaderTimeout`: tiempo maximo permitido para leer headers de requests
- `server.gin.groups`: grupos de rutas creados por `config/server/gin`
- `server.gin.UseH2C`: habilita soporte HTTP/2 cleartext
- `server.gin.rate.limit`: tasa del limiter incorporado; `0` lo deshabilita
- `server.gin.rate.burst`: burst del limiter
- `server.gin.LoggerWithConfig.enabled`: habilita logs estructurados de requests HTTP
- `server.gin.LoggerWithConfig.SkipPaths`: rutas omitidas por el logger de requests
- `server.gin.LoggerWithConfig.SkipQueryString`: oculta query strings en paths logueados

Gin tambien soporta `server.gin.autotls.*`, `server.gin.tls.*` y
`server.gin.mtls.*` para TLS automatico, TLS explicito y mTLS.

Las versiones TLS reconocidas son `tlsv10`, `tlsv11`, `tlsv12` y `tlsv13`; el
valor por defecto es `tlsv12`. TLS 1.0 y 1.1 se reconocen solo por
compatibilidad legacy y no deben seleccionarse en despliegues de produccion.
Valores de client-auth soportados: `no_client_cert`, `request_client_cert`,
`require_any_client_cert`, `verify_client_cert_if_given` y
`require_and_verify_client_cert`.

### Servidor gRPC

- `server.grpc.port`: direccion de escucha gRPC
- `server.grpc.rate.limit`: tasa del limiter incorporado; `0` lo deshabilita
- `server.grpc.rate.burst`: burst del limiter
- `server.grpc.tls.enable`: habilita TLS en el servidor gRPC
- `server.grpc.tls.certFile`: ruta del certificado del servidor
- `server.grpc.tls.keyFile`: ruta de la llave privada del servidor
- `server.grpc.tls.version`: version minima TLS
- `server.grpc.mtls.enable`: habilita validacion mTLS
- `server.grpc.mtls.clientCAFile`: archivo CA para validar certificados cliente
- `server.grpc.mtls.clientAuth`: politica de certificados cliente

### Clientes

- `client.http.timeout`: timeout por defecto para clientes HTTP configurados
- `client.http.tls.*`: configuracion TLS HTTP saliente
- `client.http.mtls.*`: certificado cliente mTLS HTTP saliente
- `client.grpc.tls.*`: configuracion TLS gRPC saliente
- `client.grpc.mtls.*`: certificado cliente mTLS gRPC saliente

Las llamadas de verbos HTTP mantienen aislados URL, cuerpo, contexto y headers
cuando un mismo `IRest` se usa de forma concurrente. `IRestGeneric` conserva
la interfaz legacy basada en setters serializando cada secuencia de
configuracion y request. Los cuerpos genericos que solo se descartan se
procesan como stream; los cuerpos de respuestas no exitosas trazadas conservan
como maximo `logger.bodyCaptureMaxBytes` (65,536 bytes por defecto) e informan
metadata de truncamiento.

Las llaves legacy `client.http.tls.insecureSkipVerify` y
`client.grpc.tls.insecureSkipVerify` deshabilitan deliberadamente la
verificacion del certificado y del host. Nunca las habilites en produccion;
configura el `caFile` y `serverName` correspondientes. Se conservan solo para
despliegues locales/de prueba compatibles.

### Logger, Traces y JWT

- `logger.dir`: directorio de archivos de log
- `logger.level`: nivel minimo como `debug`, `info`, `warn` o `error`
- `logger.ignoredHeaders`: headers removidos de logs estructurados
- `logger.formatter`: formato de salida, normalmente `json` o `text`
- `logger.bodyCaptureMaxBytes`: prefijo maximo de request o respuesta retenido
  en logs estructurados; 65,536 bytes por defecto
- `logger.rotate.*`: configuracion de rotacion de archivos
- `traces.SkipPaths`: rutas HTTP omitidas por el middleware OpenTelemetry de Gin
- `jwt.enable`: habilita validacion JWT en middleware
- `jwt.transport`: origen del token, normalmente `header` o `cookie`
- `jwt.cookie.name`: nombre de cookie cuando `jwt.transport` es `cookie`
- `jwt.algorithm`: algoritmo de firma como `HS256`, `RS256`, `PS256` o `EdDSA`; requerido cuando usas `jwt.keys.*`
- `jwt.hmac.secret`: secreto compartido para `HS256`
- `jwt.keys.private_key`, `jwt.keys.public_key`: valores de llaves asimetricas o rutas PEM interpretadas segun `jwt.algorithm`
- `jwt.rsa.*`, `jwt.eddsa.*`: rutas legacy de llaves asimetricas mantenidas por compatibilidad

## Servidor HTTP

`config/server/gin.CreateApp()` carga configuracion, inicializa logger y
OpenTelemetry, crea el `gin.Engine` compartido, registra middlewares comunes,
crea grupos desde `server.gin.groups` y registra `/health` en cada grupo.

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

## Servidor gRPC

`config/server/grpc` carga configuracion en `Serve()`, resuelve
`server.grpc.port`, agrega interceptores de logging y OpenTelemetry, soporta
TLS y mTLS, y hace apagado graceful ante senales del proceso.

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

## Clientes

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

Usa `NewGenericRestFromConfig()` o las claves TLS del cliente gRPC cuando
quieras construir transportes desde `viper`.

## Trabajo En Background

`tools/jobs` ofrece jobs en proceso con intervalo fijo. Los jobs arrancan
cuando se ejecuta `jobs.StartJobs()`; los bootstraps de servidor Gin y gRPC no
lo llaman, asi que tu aplicacion debe invocarlo explicitamente. Cuando
`server.modeTest=true`, los jobs no arrancan. Usa un id cuando un job deba
pausarse, reanudarse o detenerse individualmente.

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

`tools/workers` ofrece un loop simple de workers acotados mediante
`SetWorkersLimit`, `SetParallelism`, `RunWorkers`, `AddTask`, `StopWorkers` y
`RestartWorkers`. El límite acota tanto la ejecución concurrente como la
capacidad de la cola, y su cambio alcanza a un dispatcher que ya está corriendo.

## Ejemplos Ejecutables

El modulo raiz mantiene ejemplos ejecutables en
[cmd/example/main.go](./cmd/example/main.go). La raiz del repositorio es el
modulo de libreria, mientras que `cmd/example` es el ejecutable practico para
probar los bootstraps Gin y gRPC.

Usa un archivo de aplicacion como
[resources/application.yaml](./resources/application.yaml) antes de arrancar el
ejemplo Gin; espera `/api/v1` en `server.gin.groups`. Ejecuta los ejemplos
desde la raiz del repositorio.

Ejecutar el ejemplo Gin:

```bash
GoForge_EXAMPLE_SERVER=gin go run ./cmd/example
```

Ejecutar el ejemplo gRPC:

```bash
GoForge_EXAMPLE_SERVER=grpc go run ./cmd/example
```

El comando de ejemplo intencionalmente no elige un servidor por default. Si
`GoForge_EXAMPLE_SERVER` no esta en `gin` o `grpc`, imprime un mensaje de uso
en vez de arrancar un servidor:

```text
Set GoForge_EXAMPLE_SERVER=gin or GoForge_EXAMPLE_SERVER=grpc to run a practical example server.
```

Despues de mover el ejemplo de la raiz del repositorio a `cmd/example`,
`go run .` ya no es el comando del ejemplo raiz. Usa `go run ./cmd/example`
desde la raiz del repositorio, o `go run .` solo cuando tu shell ya este dentro
de `cmd/example`.

## Desarrollo

El workspace usa Go `1.25.0`.

Instalar Staticcheck:

```bash
go install honnef.co/go/tools/cmd/staticcheck@latest
```

Ejecutar Staticcheck para el modulo actual:

```bash
staticcheck ./...
```

Ejecutalo desde cada modulo del workspace cuando quieras revisar el modulo
raiz y los submodulos:

```bash
staticcheck ./...
cd logger && staticcheck ./...
cd ../security && staticcheck ./...
cd ../encrypt && staticcheck ./...
cd ../cmd/qgo && staticcheck ./...
cd ../go-openssl && staticcheck ./...
```

Usa Staticcheck como parte de la revision local de calidad antes de abrir un
cambio. Complementa `go test` y `go vet` detectando patrones sospechosos,
uso incorrecto de APIs, codigo inalcanzable, llamadas deprecadas y
simplificaciones que pueden ocultar bugs aunque el codigo todavia compile.

Ejecutar pruebas del modulo raiz:

```bash
go test ./...
```

Ejecutar pruebas de un modulo del workspace:

```bash
cd logger
go test ./...
```

### Analisis de seguridad y vulnerabilidades

Ejecuta estas comprobaciones como parte de la revision local de calidad antes
de abrir un cambio. Cada herramienta cubre una clase distinta de problema, por
lo que complementan a Staticcheck y `go test` en lugar de reemplazarlos.

Analiza el codigo en busca de vulnerabilidades conocidas en las dependencias y
la biblioteca estandar (solo reporta vulnerabilidades alcanzables desde tu
codigo):

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

Ejecuta el analizador estatico de seguridad. `-exclude-generated` omite los
archivos protobuf generados; `-exclude G402` omite la regla de configuracion
TLS, que se gestiona mediante la configuracion TLS de servidor/cliente y no de
forma fija en el codigo:

```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
gosec -exclude G402 -exclude-generated ./...
```

Analiza el arbol de trabajo y el historial de git en busca de secretos
filtrados. Documenta los falsos positivos conocidos en `.gitleaksignore` en
lugar de desactivar la regla:

```bash
gitleaks detect --no-git  --source .
gitleaks detect --no-git  --source . --verbose   # incluye archivo, linea y valor detectado por cada hallazgo
```

Ejecuta `govulncheck` y `gosec` desde cada modulo del workspace (como se
muestra arriba para Staticcheck) cuando necesites cubrir los submodulos ademas
del modulo raiz.

Generar archivos protobuf despues de editar `config/proto/methods.proto`:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
protoc --go_out=. --go-grpc_out=. config/proto/methods.proto
```

Coverage para el modulo actual:

```bash
go test -cover -covermode=atomic -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
go tool cover -html=coverage.out -o coverage.html
```
