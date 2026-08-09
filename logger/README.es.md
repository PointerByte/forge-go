# GoForge Logger

`logger` provee la capa de logging estructurado de GoForge. Configura un
logger global basado en `slog`, formatea entradas como JSON, texto o template
custom, exporta logs mediante OpenTelemetry e incluye middleware Gin e
interceptores gRPC para logs asociados al request.

## Instalacion

```bash
go get github.com/PointerByte/forge-go/logger
```

Actualizar las dependencias usadas por el modulo actual:

```bash
go get -u ./...
```

Instalar Staticcheck:

```bash
go install honnef.co/go/tools/cmd/staticcheck@latest
```

Ejecutar Staticcheck para este modulo:

```bash
staticcheck ./...
```

Usa Staticcheck antes de abrir un cambio. Complementa `go test` y `go vet`
detectando patrones sospechosos, uso incorrecto de APIs, codigo inalcanzable,
llamadas deprecadas y simplificaciones que pueden ocultar bugs aunque el
codigo todavia compile.

## Paquetes

- `builder`: inicializacion del logger, logging con contexto y secciones de traza
- `common`: llaves de contexto compartidas por middlewares HTTP y gRPC
- `middlewares/http`: middleware Gin
- `middlewares/grpc`: interceptores gRPC
- `formatter`: modelos de log estructurado e implementaciones de formatter
- `viperData`: cache de configuracion respaldada por viper
- `utilities`: helpers pequenos para detectar caller

## Configuracion

El modulo lee configuracion desde `viper`. No carga archivos por si solo, asi
que tu aplicacion debe cargar `application.yaml`, `application.yml`, JSON o
variables de entorno antes de llamar `builder.InitLogger(...)` o instalar
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
  formatDate: "2006-01-02T15:04:05.000"
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

Claves principales:

- `app.name`: nombre del servicio incluido en details y metadata OTEL
- `app.version`: version del servicio incluida en metadata OTEL
- `server.gin.LoggerWithConfig.enabled`: habilita logs finales de requests Gin
- `server.gin.LoggerWithConfig.SkipPaths`: rutas omitidas por el logging Gin
- `server.gin.LoggerWithConfig.SkipQueryString`: omite query strings del path logueado
- `server.grpc.LoggerWithConfig.enabled`: habilita logs finales de requests gRPC
- `server.grpc.LoggerWithConfig.SkipFunction`: metodos gRPC omitidos por nombre (`SayHello`) o metodo completo (`/pkg.Service/SayHello`)
- `logger.dir`: directorio donde se crea el archivo de log cuando el caller usa esta clave
- `logger.modeTest`: suprime salida de logs y coleccion de trazas en modo test
- `logger.level`: `debug`, `info`, `warn` o `error`
- `logger.ignoredHeaders`: headers filtrados de los details estructurados
- `logger.formatter`: `json`, `text` o un template Go custom
- `logger.formatDate`: layout de timestamp
- `logger.bodyCaptureMaxBytes`: maximo de bytes retenidos de forma independiente para un request o response habilitado; valores ausentes o no positivos usan 65536
- `logger.sensibleKeys`: keys o fragmentos de key case-insensitive cuyos valores se redactan antes de formatear
- `logger.rotate.*`: configuracion de rotacion de archivos con `lumberjack`

`viperData` cachea valores en el primer uso. En tests que cambian valores de
viper dentro del mismo proceso, llama `viperdata.ResetViperDataSingleton()`
antes de volver a leer configuracion del logger.

## Limite Seguro De Sanitizacion

Cuando se configura al menos una entrada en `logger.sensibleKeys`, los valores
estructurados se sanitizan recursivamente hasta una profundidad maxima de 32.
Cualquier subarbol no inspeccionado que supere ese limite se reemplaza con
`sanitizer.RedactedValue` (`"[REDACTED]"`); nunca se devuelve el subarbol
original. Esto tambien acota inputs ciclicos.

## Captura De Bodies Acotada

El logging de request y response body sigue deshabilitado por default. Cuando
se habilita, los middlewares HTTP y gRPC retienen como maximo
`logger.bodyCaptureMaxBytes` para cada lado de forma independiente. Un lado
truncado agrega metadata sin cambiar los bodies que caben:

```json
{
  "requestCapture": {
    "truncated": true,
    "capturedBytes": 65536,
    "limitBytes": 65536
  }
}
```

La captura HTTP observa solo los bytes que consume el handler. Nunca drena un
request no leido despues de que termina el handler; un request no leido o
parcial se marca como truncado. El body completo sigue fluyendo al handler y
al cliente. La captura gRPC streaming aplica el limite al agregado de mensajes
de cada lado y separa los valores retenidos de su almacenamiento original.

## Inicializar El Logger

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

`builder.InitLogger` configura el logger `slog` default del proceso. Escribe en
stdout y, cuando `logger.rotate.enable=true`, tambien en un archivo rotado.
Tambien crea un logger provider de OpenTelemetry y lo devuelve para que el
caller pueda apagarlo de forma ordenada. El provider devuelto nunca es nil
cuando no hay error, asi que `defer lp.Shutdown(ctx)` siempre es seguro.

Los atributos ligados y por registro de `slog` se emiten bajo el objeto
opcional `attributes`, preservando la anidacion de `WithGroup`. Los mensajes y
atributos se sanitizan antes de la salida local y la exportacion OpenTelemetry.
Los errores del formatter, writer y handlers secundarios se retornan mediante
el contrato del handler en lugar de causar panic.

## Exportacion De Logs OpenTelemetry

La exportacion de logs esta **apagada por defecto**. Solo se activa cuando
`OTEL_LOGS_EXPORTER` selecciona un exportador, igual que el default `none` que
ya usan `OTEL_TRACES_EXPORTER` y `OTEL_METRICS_EXPORTER` en el modulo principal:

| `OTEL_LOGS_EXPORTER`      | Comportamiento                                                |
| ------------------------- | ------------------------------------------------------------- |
| sin definir, vacio, `none`| Sin exportador, sin procesador y sin puente de OpenTelemetry   |
| `otlp`                    | Exportador OTLP detras de un batch processor                   |
| cualquier otro valor      | `InitLogger` devuelve error                                    |

El valor se lee como lista separada por comas; gana la primera entrada no vacia
despues de recortar espacios y pasar a minusculas, asi que `" OTLP , none "`
selecciona `otlp`.

Cuando se selecciona `otlp`, el transporte sale de
`OTEL_EXPORTER_OTLP_LOGS_PROTOCOL`, con fallback a
`OTEL_EXPORTER_OTLP_PROTOCOL` y luego a `http/protobuf`. Cualquier otro
protocolo resuelto —incluido `grpc`, que este modulo no enlaza— devuelve error
en lugar de exportar por un transporte que el caller no pidio. El endpoint y los
headers siguen las variables estandar `OTEL_EXPORTER_OTLP_*`.

```bash
# Exportar logs a un collector en el endpoint OTLP HTTP por defecto.
export OTEL_LOGS_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318
```

> **Cambio de comportamiento.** Antes de `logger/v0.0.62` siempre se creaba un
> exportador OTLP con los defaults del spec, apuntando a
> `https://localhost:4318/v1/logs`. Sin un collector ahi, cada exportacion en
> lote fallaba, y `otel.Handle` enrutaba cada fallo por el paquete `log` de la
> biblioteca estandar hacia este logger en nivel `INFO`, de modo que el error de
> transporte se volvia la linea de log dominante. Define
> `OTEL_LOGS_EXPORTER=otlp` para recuperar el comportamiento anterior.

Cuando la exportacion esta desactivada, el puente `otelslog` no se engancha al
handler instalado, asi que los registros no tienen coste adicional en vez de
construirse y descartarse.

## Middleware Gin

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

Rol de cada middleware:

- `InitLogger()` extrae headers de tracing distribuido, crea el contexto logger del request y guarda metadata del request.
- `LoggerWithConfig()` emite el log HTTP estructurado final mediante el hook logger de Gin.
- `CaptureBody()` captura bytes consumidos del request y bytes emitidos del response solo cuando el logging de bodies esta habilitado, acotados por `logger.bodyCaptureMaxBytes`, para incluirlos en `details.request` y `details.response` sin guardar payloads deshabilitados.
- `EnableBody(c, request, response)` habilita la emision de request y response body en el log HTTP final. Los bodies estan deshabilitados por default.
- `EnableTraceBody(c, request, response)` habilita la emision de request y response body en las entradas de servicios de traza cuando se llama `TraceEnd`. Los bodies de traza estan deshabilitados por default.

Los helpers `PrintInfo`, `PrintDebug`, `PrintWarn` y `PrintError` programan un
mensaje de log asociado al request desde handlers Gin.

## Interceptores gRPC

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

Los interceptores replican el comportamiento de Gin para RPCs unary y stream:
crean el contexto logger del request, capturan payloads, copian metadata en los
details estructurados y escriben el log final cuando termina el handler. Los
bodies unary y cada direccion streaming se acotan de forma independiente con
`logger.bodyCaptureMaxBytes`; los mensajes streaming comparten el limite de su
direccion.

Los request y response bodies estan deshabilitados por default. Usa
`loggrpc.EnableBody(ctxLogger, true, true)` para incluirlos en el log gRPC
final, y `loggrpc.EnableTraceBody(ctxLogger, true, true)` para incluir bodies
en servicios de traza.

El logging gRPC final ignora intencionalmente errores `codes.Unauthenticated` y
`codes.PermissionDenied`, por lo que las fallas de autorizacion JWT no emiten
logs del middleware logger.

Usa `loggrpc.PrintInfo`, `PrintDebug`, `PrintWarn` o `PrintError` con el
contexto logger del request cuando un handler necesite elegir explicitamente el
nivel y mensaje del log final.

Cuando usas el paquete raiz `config/server/grpc`, estos interceptores se
instalan automaticamente.

## Logger Con Contexto

Usa `builder.New(ctx)` fuera de handlers Gin o gRPC cuando necesites un logger
contextual directamente:

```go
ctxLogger := builder.New(context.Background())

ctxLogger.Info("application started")
ctxLogger.Debug("cache warmed")
ctxLogger.Warn("dependency latency is high")
ctxLogger.Error(errors.New("dependency failed"))
```

## Secciones De Traza

`TraceInit` y `TraceEnd` agregan llamadas downstream o subprocesos internos al
array `services` del log estructurado.

```go
process := &formatter.Service{
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

Casos comunes: llamadas HTTP/gRPC salientes, llamadas a SDKs de proveedores y
pasos internos de negocio que deben aparecer bajo la misma traza.

Los request y response bodies de servicios de traza estan deshabilitados por
default. En handlers Gin usa `httpmiddlewares.EnableTraceBody(c, true, true)`;
en handlers gRPC usa `loggrpc.EnableTraceBody(ctxLogger, true, true)`.

## Formatters

El formato de salida se selecciona con la key de configuracion
`logger.formatter` (ver el bloque de configuracion mas arriba). Acepta tres
tipos de valor:

- `json`: salida JSON estructurada
- `text` o `txt`: salida de texto legible
- cualquier template Go custom aceptado por `formatter.CustomFormatter`

### Seleccionar el formato via configuracion

```yaml
logger:
  formatter: json   # "json", "text" (alias "txt"), o un string de template Go
```

El string vacio y `text`/`txt` producen el layout de texto; `json` produce el
layout JSON; cualquier otra cosa se trata como un `text/template` de Go y se
renderiza por cada entrada de log.

### Salida JSON

```json
{
  "timestamp": "2026-06-22T10:30:00.000",
  "traceID": "a1b2c3d4...",
  "level": "info",
  "message": "request completed",
  "details": { "system": "orders-api", "method": "GET", "path": "/api/v1/orders" },
  "process": [
    { "system": "orders-api", "process": "GetOrders", "status": "OK", "latency": 12 }
  ],
  "method": "handler.go",
  "line": 42,
  "latency": 12
}
```

### Salida de texto

```text
[2026-06-22T10:30:00.000] [info] [a1b2c3d4...] handler.go:42 - request completed latency=12ms | details={system=orders-api, method=GET, path=/api/v1/orders} | services=[{system=orders-api, process=GetOrders, status=OK, latency=12ms}]
```

### Templates custom

Un formato custom es cualquier string que no sea `json`, `text`, `txt` o vacio.
Se parsea como un `text/template` de Go y se ejecuta contra el valor
`formatter.LogFormat` de cada entrada, asi que puedes referenciar sus campos
exportados directamente:

| Campo        | Tipo        | Descripcion                                   |
| ------------ | ----------- | --------------------------------------------- |
| `.Timestamp` | `string`    | Timestamp formateado (`logger.formatDate`)    |
| `.TraceID`   | `string`    | Trace id de la entrada                        |
| `.Level`     | `Level`     | `debug` / `info` / `warn` / `error`           |
| `.Message`   | `string`    | Mensaje del log                               |
| `.Details`   | `Details`   | Detalles de la request (system, method, path) |
| `.Process`   | `[]Process` | Spans/procesos registrados                    |
| `.Method`    | `string`    | Archivo fuente del call site                  |
| `.Line`      | `int`       | Linea fuente del call site                    |
| `.Latency`   | `int64`     | Latencia en milisegundos                      |

Los templates tambien pueden usar estas funciones helper registradas:

- `json v` — serializa cualquier valor a JSON
- `buildDetails .Details` — normaliza `Details` en un map, descartando campos vacios
- `buildServices .Process` — normaliza `[]Process` en un slice de maps

Define el template como valor de `logger.formatter` en `application.yaml`. Es un
string de una sola linea (el codigo fuente del template), asi que usa comillas y
mantenlo en una linea:

```yaml
logger:
  formatter: '{{.Level}} | {{.Message}} | {{json (buildServices .Process)}}'
```

Con la entrada de los ejemplos de arriba, eso produce:

```text
info | request completed | [{"latency":12,"process":"GetOrders","status":"OK","system":"orders-api"}]
```

**Importante — los templates custom no pueden renombrar las keys JSON.** Tras
renderizar, `Format` comprueba si la salida es JSON valido: si lo es, los bytes
se deserializan de vuelta a `LogFormat` y se re-serializan, asi que cualquier
key que no coincida con un struct tag se descarta y se emiten las keys estandar
con sus nombres de struct tag. Este valor en `application.yaml/json`:

```yaml
logger:
  formatter: '{"ts":{{json .Timestamp}},"lvl":{{json .Level}}}'
```

**no** produce `{"ts":...,"lvl":...}`; pierde `ts`/`lvl` y recae en las keys JSON
por defecto con valores vacios. Los templates custom solo conservan sus propias
etiquetas cuando la salida renderizada **no** es JSON valido (como la forma
`level | message | …` de arriba) — control total sobre las etiquetas, a costa de
perder el JSON estructurado.

## Pruebas

Para silenciar salida de logs y coleccion de trazas en pruebas:

```go
builder.EnableModeTest()
defer builder.DisableModeTest()
```

Desde el directorio del modulo `logger`:

```bash
go test ./...
go test -cover -covermode=atomic -coverprofile=coverage.out ./...
```
