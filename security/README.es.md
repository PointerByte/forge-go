# GoForge Security

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
- `middlewares`: middleware Gin para bearer tokens, cookies y headers de seguridad

## Capacidades

- crear JWTs desde claims arbitrarios
- validar firmas y algoritmos de JWT compactos
- validar claims NumericDate `exp` y `nbf` presentes despues de verificar la firma
- decodificar claims en `map[string]any` o structs tipados
- agregar validadores a nivel servicio y por llamada
- usar contextos de request y timeouts a nivel servicio
- proteger rutas Gin mediante bearer token o cookie JWT
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

- `jwt.enable`: cuando esta explicitamente en `false`, el middleware JWT de Gin deja pasar requests
- `jwt.algorithm`: `HS256`, `RS256`, `PS256` o `EdDSA`; requerido cuando usas `jwt.keys.*`
- `jwt.cookie.name`: nombre de cookie usado por auth con cookies; default `access_token`
- `jwt.hmac.secret`: secreto compartido para `HS256`
- `jwt.keys.private_key`: valor de llave privada asimetrica o ruta a archivo PEM
- `jwt.keys.public_key`: valor de llave publica asimetrica o ruta a archivo PEM
- `jwt.rsa.private_key`, `jwt.rsa.public_key`: rutas legacy para llaves RSA
- `jwt.eddsa.private_key`, `jwt.eddsa.public_key`: rutas legacy para llaves Ed25519

El par generico `jwt.keys.*` se interpreta segun `jwt.algorithm`: usa `EdDSA`
para llaves Ed25519 y `RS256` o `PS256` para llaves RSA. Sin `jwt.algorithm`,
las llaves genericas son ambiguas intencionalmente.

Los archivos `application.yaml` y `application.json` de este modulo son ejemplos
completos: incluyen `hmac`, `keys` y `jwt.algorithm` para documentar las
opciones disponibles.

Los inputs configurados pueden recibir valores directos con `HMACSecret`,
`RSAPrivateKey`, `RSAPublicKey`, `EdDSAPrivateKey` y `EdDSAPublicKey`. Los
campos `*Key` conservan su comportamiento legacy: apuntan a claves de viper,
pero las llaves RSA y EdDSA tambien aceptan rutas PEM o valores DER codificados
en Base64 cuando no existe una clave de viper con ese nombre.

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

service, err := jwtservice.NewConfiguredService(jwtservice.ConfigServiceInput{})
if err != nil {
	panic(err)
}
```

Las rutas legacy especificas por algoritmo, como `jwt.eddsa.*` y `jwt.rsa.*`,
siguen aceptandose por compatibilidad. Cuando una llave privada o publica
generica esta vacia, el constructor configurado de RSA, RSA-PSS o Ed25519 usa
la llave legacy correspondiente. Si configuras varias estrategias, define
`jwt.algorithm` o pasalo en `ConfigServiceInput`:

```go
package main

import (
	jwtservice "github.com/PointerByte/forge-go/security/auth/jwt"
	"github.com/spf13/viper"
)

func main() {
	viper.Set("jwt.algorithm", "HS256")
	viper.Set("jwt.hmac.secret", "my-secret")

	hmacSecretKey := jwtservice.DefaultHMACSecretKey

	service, err := jwtservice.NewConfiguredService(jwtservice.ConfigServiceInput{
		Algorithm:     "HS256",
		HMACSecretKey: &hmacSecretKey,
	})
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
	JWT: jwtservice.ConfigServiceInput{
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

Middleware Gin con cookies:

```go
router.Use(middlewares.RequireJWTCookie(
	middlewares.WithJWTCookieServiceConfig(cookiesauth.ConfigServiceInput{
		CookieNameKey: cookiesauth.DefaultCookieNameKey,
		JWT: jwtservice.ConfigServiceInput{
			Algorithm:     "HS256",
			HMACSecretKey: &hmacSecretKey,
		},
	}),
	middlewares.WithJWTCookieClaimsFactory(func() any { return &MyClaims{} }),
))
```

Lee `jwt.cookie.name` desde viper y usa `access_token` como fallback.

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

`middlewares.SecurityHeaders()` agrega headers comunes como `X-Frame-Options`,
`Content-Security-Policy`, `Strict-Transport-Security`, `Referrer-Policy`,
`X-Content-Type-Options` y `Permissions-Policy`.

```go
router.Use(middlewares.SecurityHeaders())
```

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
- `POST /hmac/login`
- `GET /hmac/api/me`
- `GET /hmac/api/admin`
- `POST /rsa/login`
- `GET /rsa/api/me`
- `GET /rsa/api/admin`
- `POST /custom/login`
- `GET /custom/api/me`
- `GET /custom/api/admin`

## Pruebas

Desde el directorio del modulo `security`:

```bash
go test ./...
go test -cover -covermode=atomic -coverprofile=coverage.out ./...
```
