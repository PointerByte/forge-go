# forge-go Security

`security` provee servicios JWT y middleware Gin para autenticacion basada en
tokens. Usa `viper` para servicios configurados y depende de
`github.com/PointerByte/forge-go/encrypt` para helpers criptograficos.

## Instalacion

```bash
go get github.com/PointerByte/forge-go/security
```

Si tu aplicacion tambien necesita operaciones criptograficas directas, agrega:

```bash
go get github.com/PointerByte/forge-go/encrypt
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

- `auth/jwt`: creacion JWT, validacion de firma, lectura de claims y estrategias de firma
- `auth/cookies`: validacion JWT desde cookies HTTP
- `middlewares`: middleware Gin para bearer tokens, cookies y headers de
  seguridad, mas interceptores gRPC para bearer tokens

## Capacidades

- crear JWTs desde claims arbitrarios
- validar firmas y algoritmos de JWT compactos
- validar claims NumericDate `exp` y `nbf` presentes despues de verificar la firma
- decodificar claims en `map[string]any` o structs tipados
- agregar validadores a nivel servicio y por llamada
- usar contextos de request y timeouts a nivel servicio
- proteger rutas Gin mediante bearer token o cookie JWT
- proteger servicios gRPC mediante interceptores bearer unary y stream
- aplicar headers HTTP comunes de seguridad
- conectar estrategias de firma custom

## Configuracion

Este modulo no carga automaticamente `application.yaml`, `application.yml` ni
`application.json`. Carga configuracion en `viper` antes de usar
`NewConfiguredService`, `RequireJWT` o `RequireJWTCookie`.

```yaml
jwt:
  enable: true
  algorithm: EdDSA
  cookie:
    name: access_token
  keys:
    private_key: ./certs/jwt/ed25519-key.pem
    public_key: ./certs/jwt/ed25519-public.pem
```

Claves principales:

- `jwt.enable`: cuando esta explicitamente en `false`, los middlewares Gin y los
  interceptores gRPC dejan pasar requests. `RequireJWT` y `RequireJWTCookie` la
  leen al construir el middleware; los interceptores gRPC la leen en cada
  llamada
- `jwt.algorithm`: `HS256`, `RS256`, `PS256` o `EdDSA`, sin distinguir
  mayusculas; requerido por `NewConfiguredService` y por todo middleware que
  construye su servicio desde viper
- `jwt.cookie.name`: nombre de cookie usado por auth con cookies; default `access_token`
- `jwt.hmac.secret`: secreto compartido para `HS256`
- `jwt.keys.private_key`: valor de llave privada asimetrica o ruta a archivo PEM
- `jwt.keys.public_key`: valor de llave publica asimetrica o ruta a archivo PEM
- `jwt.rsa.private_key`, `jwt.rsa.public_key`: rutas legacy para llaves RSA
- `jwt.eddsa.private_key`, `jwt.eddsa.public_key`: rutas legacy para llaves Ed25519

El par generico `jwt.keys.*` se interpreta segun `jwt.algorithm`: usa `EdDSA`
para llaves Ed25519 y `RS256` o `PS256` para llaves RSA. Sin `jwt.algorithm`,
`NewConfiguredService` devuelve `ErrMissingAlgorithm`, y un valor desconocido
devuelve `ErrUnsupportedAlg`.

Los archivos `application.yaml` y `application.json` de este modulo son ejemplos
completos: incluyen `hmac`, `keys` y `jwt.algorithm` para documentar las
opciones disponibles.

`SetJWTAsymmetricKeys(priv, pub, alg)` guarda un par de llaves en
`jwt.keys.private_key` y `jwt.keys.public_key`; `alg` debe ser `rsa`, `rs256`,
`ps256` o `eddsa`.

Archivos de ejemplo:

- [application.yaml](./application.yaml)
- [application.json](./application.json)

## Servicio JWT

### Configurado Desde Viper

Con llaves asimetricas genericas, define `jwt.algorithm` para que el servicio
sepa como parsear y verificar el par de llaves:

```go
viper.Set("jwt.algorithm", "EdDSA")
viper.Set("jwt.keys.private_key", "./certs/jwt/ed25519-key.pem")
viper.Set("jwt.keys.public_key", "./certs/jwt/ed25519-public.pem")

service, err := jwtservice.NewConfiguredService(nil)
if err != nil {
	panic(err)
}
```

`NewConfiguredService` recibe un `*Validator` opcional y despacha segun
`jwt.algorithm` a `NewHMACService`, `NewRSAService`, `NewRSAPSSService` o
`NewEd25519Service`; llama uno de ellos directamente para omitir el despacho.

Las rutas legacy especificas por algoritmo, como `jwt.eddsa.*` y `jwt.rsa.*`,
siguen aceptandose por compatibilidad. Cuando una llave privada o publica
generica esta vacia, el constructor configurado de RSA, RSA-PSS o Ed25519 usa
la llave legacy correspondiente.

```go
package main

import (
	"context"

	jwtservice "github.com/PointerByte/forge-go/security/auth/jwt"
	"github.com/spf13/viper"
)

func main() {
	viper.Set(jwtservice.DefaultAlgorithmKey, "HS256")
	viper.Set(jwtservice.DefaultHMACSecretKey, "my-secret")

	var validator jwtservice.Validator = func(ctx context.Context, token jwtservice.Token) error {
		return nil
	}

	service, err := jwtservice.NewConfiguredService(&validator)
	if err != nil {
		panic(err)
	}

	token, err := service.Create(map[string]any{"user_id": "42"})
	if err != nil {
		panic(err)
	}

	var claims map[string]any
	if err := service.Read(token, &claims); err != nil {
		panic(err)
	}
}
```

### Secreto Directo

```go
service, err := jwtservice.New(
	jwtservice.WithHMACSHA256("my-secret"),
)
if err != nil {
	panic(err)
}
```

### Contexto Y Validadores

```go
service, err := jwtservice.New(
	jwtservice.WithHMACSHA256("my-secret"),
	jwtservice.WithContextTimeout(2*time.Second),
	jwtservice.WithValidator(func(ctx context.Context, token jwtservice.Token) error {
		return nil
	}),
)
if err != nil {
	panic(err)
}

ctx := context.Background()

token, err := service.CreateWithContext(ctx, map[string]any{"user_id": "42"})
if err != nil {
	panic(err)
}

var claims struct {
	UserID string `json:"user_id"`
}

parsedToken, err := service.Decode(ctx, token, &claims)
if err != nil {
	panic(err)
}

_ = parsedToken
```

Usa `ValidateSignatureWithContext(ctx, token)` cuando necesites verificar la
estructura, algoritmo, firma y claims de tiempo registrados del JWT sin
decodificar claims en un destino.

### Claims De Tiempo Registrados

Despues de validar la firma, el servicio valida los claims `exp` y `nbf`
presentes como valores JWT NumericDate numericos. Un valor mal formado devuelve
`ErrInvalidExpirationClaim` o `ErrInvalidNotBeforeClaim`; un token expirado o
prematuro devuelve `ErrTokenExpired` o `ErrTokenNotYetValid`.

El reloj predeterminado es el reloj del sistema y la tolerancia predeterminada
es cero. Los servicios explicitos pueden usar `WithClock` para inyectar un reloj
comprobable y `WithLeeway` para una tolerancia no negativa y acotada:

```go
service, err := jwtservice.New(
	jwtservice.WithHMACSHA256("my-secret"),
	jwtservice.WithLeeway(30*time.Second),
)
```

El paquete no aplica `iss` ni `aud` porque no conoce las expectativas
especificas del caller para esos claims. Validalos con `WithValidator` o con un
validador por llamada cuando tu aplicacion requiera una politica de issuer o
audience.

## Algoritmos Soportados

- `HS256`: HMAC-SHA256
- `RS256`: RSA SHA-256
- `PS256`: RSA-PSS SHA-256
- `EdDSA`: Ed25519

Las llaves RSA y Ed25519 configuradas pueden ser rutas PEM o valores
codificados soportados.

## Middleware Bearer Para Gin

`RequireJWT` lee un bearer token desde el header `Authorization`, lo valida y
guarda el token parseado y los claims en el contexto Gin.

```go
package main

import (
	"context"

	jwtservice "github.com/PointerByte/forge-go/security/auth/jwt"
	"github.com/PointerByte/forge-go/security/middlewares"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

type MyClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

func main() {
	router := gin.New()
	viper.Set(jwtservice.DefaultAlgorithmKey, "HS256")
	viper.Set(jwtservice.DefaultHMACSecretKey, "change-me")

	router.Use(middlewares.RequireJWT(
		middlewares.WithJWTClaimsFactory(func() any { return &MyClaims{} }),
		middlewares.WithJWTValidator(func(ctx context.Context, token jwtservice.Token) error {
			return nil
		}),
	))
}
```

Leer valores desde el contexto Gin:

```go
claimsValue, ok := c.Get(middlewares.JWTClaimsContextKey.String())
if !ok {
	return
}

claims := claimsValue.(*MyClaims)
_ = claims
```

El token parseado se guarda con `middlewares.JWTTokenContextKey.String()`. Sin
claims factory, los claims decodificados se guardan como `map[string]any`.
Personaliza las claves con `WithJWTContextKeys`.

Los fallos abortan con `401` y `{"error": "<mensaje>"}`; reemplaza esa
respuesta con `WithJWTUnauthorizedHandler`. El middleware construye su servicio
una sola vez, al crearse. Si eso falla, por ejemplo porque falta
`jwt.algorithm`, cada request recibe la respuesta unauthorized.

## Interceptores Bearer Para gRPC

`RequireJWTUnaryServerInterceptor` y `RequireJWTStreamServerInterceptor` leen un
bearer token desde metadata gRPC `authorization`, validan el JWT y guardan el
token parseado y los claims en `context.Context`.

```go
server := grpc.NewServer(
	grpc.ChainUnaryInterceptor(
		middlewares.RequireJWTUnaryServerInterceptor(
			middlewares.WithGRPCJWTClaimsFactory(func() any { return &MyClaims{} }),
		),
	),
	grpc.ChainStreamInterceptor(
		middlewares.RequireJWTStreamServerInterceptor(
			middlewares.WithGRPCJWTClaimsFactory(func() any { return &MyClaims{} }),
		),
	),
)
```

Leer valores desde el contexto gRPC:

```go
claimsValue, ok := middlewares.JWTClaimsFromContext(ctx)
if !ok {
	return nil, status.Error(codes.Unauthenticated, "claims not available")
}

claims := claimsValue.(*MyClaims)
_ = claims
```

`JWTTokenFromContext(ctx)` devuelve el token parseado. Todo fallo de
autenticacion devuelve `codes.Unauthenticated`. El servicio se construye desde
viper en la primera llamada; `WithGRPCJWTServiceFactory` reemplaza ese
constructor, por ejemplo para una estrategia custom, y `WithGRPCJWTValidator`
agrega un validador.

Con `config/server/grpc` del modulo raiz, pasa los interceptores mediante
`WithUnaryInterceptors` y `WithStreamInterceptors`.

El cliente debe enviar metadata:

```text
authorization: Bearer <token>
```

## Auth Por Cookies

El paquete `auth/cookies` valida JWTs almacenados en una cookie HTTP.

```go
import (
	cookiesauth "github.com/PointerByte/forge-go/security/auth/cookies"
	jwtservice "github.com/PointerByte/forge-go/security/auth/jwt"
)

hmacSecretKey := jwtservice.DefaultHMACSecretKey

service, err := cookiesauth.NewConfiguredService(cookiesauth.ConfigServiceInput{
	CookieNameKey: cookiesauth.DefaultCookieNameKey,
	JWT: cookiesauth.JWTConfigServiceInput{
		Algorithm:     "HS256",
		HMACSecretKey: &hmacSecretKey,
	},
})
if err != nil {
	panic(err)
}

var claims map[string]any
if err := service.Read(request, &claims); err != nil {
	panic(err)
}
```

`cookiesauth.JWTConfigServiceInput` acepta valores directos en `Algorithm`,
`HMACSecret`, `RSAPrivateKey`, `RSAPublicKey`, `EdDSAPrivateKey` y
`EdDSAPublicKey`, o los nombres de otras claves de viper desde las que copiarlos
mediante los campos puntero `*Key`, ademas de un `Validator` opcional. Un campo
`*Key` cuya clave de viper esta vacia se ignora.

`NewConfiguredService` escribe esos valores en las claves globales de viper del
proceso (`jwt.algorithm`, `jwt.hmac.secret`, `jwt.keys.private_key`,
`jwt.keys.public_key`) antes de construir el servicio JWT, asi que tambien
afectan a cualquier otro servicio configurado desde viper que se construya
despues. Los campos RSA y EdDSA comparten las claves genericas `jwt.keys.*`.

El nombre de la cookie sale de `CookieName`, luego de la clave de viper indicada
por `CookieNameKey` (`jwt.cookie.name` por defecto), y por ultimo usa
`access_token` como fallback.

Middleware Gin con cookies:

```go
router.Use(middlewares.RequireJWTCookie(
	middlewares.WithJWTCookieServiceConfig(cookiesauth.ConfigServiceInput{
		CookieNameKey: cookiesauth.DefaultCookieNameKey,
		JWT: cookiesauth.JWTConfigServiceInput{
			Algorithm:     "HS256",
			HMACSecretKey: &hmacSecretKey,
		},
	}),
	middlewares.WithJWTCookieClaimsFactory(func() any { return &MyClaims{} }),
))
```

El middleware de cookies guarda el token y los claims con las mismas claves de
contexto que `RequireJWT`. `WithJWTCookieValidator`, `WithJWTCookieContextKeys`
y `WithJWTCookieUnauthorizedHandler` replican las opciones del middleware
bearer.

## Estrategias Custom

Usa `WithCustomStrategy` directamente y pasa el servicio al middleware Gin con
`WithJWTService`.

```go
service, err := jwtservice.New(
	jwtservice.WithCustomStrategy("CUSTOM", signFunc, verifyFunc),
)
if err != nil {
	panic(err)
}

router.Use(middlewares.RequireJWT(
	middlewares.WithJWTService(service),
))
```

## Headers De Seguridad

`middlewares.SecurityHeaders()` define estos headers de respuesta:

| Header | Valor |
| --- | --- |
| `X-Frame-Options` | `DENY` |
| `Content-Security-Policy` | `default-src 'self'; connect-src *; font-src *; script-src-elem * 'unsafe-inline'; img-src * data:; style-src * 'unsafe-inline';` |
| `X-XSS-Protection` | `1; mode=block` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `Referrer-Policy` | `strict-origin` |
| `X-Content-Type-Options` | `nosniff` |
| `Permissions-Policy` | `geolocation=(),midi=(),sync-xhr=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=(self),payment=()` |

La Content-Security-Policy permite scripts, estilos, fuentes, imagenes y
conexiones desde cualquier origen. Los servicios que sirven HTML deben
sobrescribirla con una politica mas estricta despues de este middleware.

```go
router.Use(middlewares.SecurityHeaders())
```

El bootstrap Gin del modulo raiz instala este middleware en todas las rutas.

## Relacion Con `encrypt`

`encrypt` es un modulo separado. `security` lo usa internamente, pero la ruta
publica para criptografia es:

```go
github.com/PointerByte/forge-go/encrypt
```

Usa `encrypt` directamente cuando tu aplicacion necesite AES, hashing, RSA/ECC,
KMS o helpers de firma fuera de auth JWT.

## Ejemplo Ejecutable

Este modulo incluye una app de ejemplo en [main.go](./main.go).

```bash
go run .
```

Rutas de ejemplo:

- `GET /health`
- `GET /hmac/health`
- `POST /hmac/login`
- `GET /hmac/api/me`
- `GET /hmac/api/admin`
- `GET /rsa/health`
- `POST /rsa/login`
- `GET /rsa/api/me`
- `GET /rsa/api/admin`
- `GET /custom/health`
- `POST /custom/login`
- `GET /custom/api/me`
- `GET /custom/api/admin`

## Pruebas

Desde el directorio del modulo `security`:

```bash
go test ./...
go test -cover -covermode=atomic -coverprofile=coverage.out ./...
```
