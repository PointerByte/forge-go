# forge-go Encrypt

`encrypt` es el modulo de criptografia independiente de forge-go. Expone una
API estilo repositorio para cifrado simetrico, hashing, utilidades RSA/ECC y
firmas digitales, con implementaciones intercambiables locales y respaldadas
por proveedores cloud.

## Instalacion

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

- `github.com/PointerByte/forge-go/encrypt`: interfaces compartidas y wrapper de repositorio compuesto
- `github.com/PointerByte/forge-go/encrypt/local`: criptografia en proceso
- `github.com/PointerByte/forge-go/encrypt/aws-kms`: operaciones con AWS KMS y fallbacks locales
- `github.com/PointerByte/forge-go/encrypt/azure-key-vault`: operaciones con Azure Key Vault y fallbacks locales
- `github.com/PointerByte/forge-go/encrypt/gcp-kms`: operaciones con Google Cloud KMS y fallbacks locales
- `github.com/PointerByte/forge-go/encrypt/pkcs11`: operaciones con PKCS#11 (HSM fisico o de red) y fallbacks locales; requiere el build tag `pkcs11`

## Capacidades

- cifrado y descifrado AES-GCM
- generacion HMAC-SHA256
- hashing SHA-256 y BLAKE3
- generacion de llaves RSA y cifrado/descifrado RSA-OAEP
- generacion de llaves ECC y cifrado/descifrado derivado con ECDH
- firma y verificacion Ed25519
- firma y verificacion RSA-PSS y RSA PKCS#1 v1.5 SHA-256
- APIs con `context.Context` para cancelacion y deadlines

## Modelo De Repositorio

El paquete raiz expone interfaces enfocadas:

- `SymmetricRepository`
- `AsymmetricRepository`
- `HashRepository`
- `SignatureRepository`
- `IRepository`, que combina todas las anteriores

Usa `encrypt.NewRepository(...)` cuando quieras un solo valor que exponga todas
las capacidades de un backend:

```go
repository := encrypt.NewRepository(local.NewRepository())
```

Los paquetes backend tambien exponen sus propios constructores
`NewRepository()`:

```go
localRepository := local.NewRepository()
awsRepository := awskms.NewRepository()
azureRepository := azurekeyvault.NewRepository()
gcpRepository := gcpkms.NewRepository()

_, _, _, _ = localRepository, awsRepository, azureRepository, gcpRepository
```

## KeyData

Los metodos de generacion de llaves devuelven `*models.KeyData`:

- `KeyID`: identificador del proveedor; el backend local conserva material de
  llave aqui solo por compatibilidad
- `PublicKey`: llave publica local cuando es exportable
- `KeyRef`: referencia canonica para operaciones: material local o una
  referencia de proveedor como ARN, URL o version
- `Provider`: nombre del backend, por ejemplo `local`, `aws-kms`, `azure-key-vault`, `gcp-kms` o `pkcs11`

Usa `KeyRef` al pasar llaves generadas a operaciones con cualquier backend.
Para llaves asimetricas locales, usa `KeyRef` como llave privada y `PublicKey`
como llave publica. El `KeyID` local permanece igual a `KeyRef` por
compatibilidad, pero ambos campos contienen secretos y nunca deben registrarse.

## Inicio Rapido

```go
package main

import (
	"context"

	"github.com/PointerByte/forge-go/encrypt"
	"github.com/PointerByte/forge-go/encrypt/common"
	"github.com/PointerByte/forge-go/encrypt/local"
	"github.com/PointerByte/forge-go/encrypt/models"
)

func main() {
	ctx := context.Background()
	repository := encrypt.NewRepository(local.NewRepository())

	keyData, err := repository.GenerateSymetrycKeys(ctx, models.GenerateSymmetricKeyRequest{
		UID:  "user-123",
		Size: common.Key256Bits,
	})
	if err != nil {
		panic(err)
	}

	additional := "aad"
	cipherText, err := repository.EncryptAES(ctx, models.EncryptAESRequest{
		UID:        "user-123",
		SecretKey:  keyData.KeyRef,
		Value:      "hola",
		Additional: &additional,
	})
	if err != nil {
		panic(err)
	}

	plainText, err := repository.DecryptAES(ctx, models.DecryptAESRequest{
		UID:         "user-123",
		SecretKey:   keyData.KeyRef,
		CipherValue: cipherText,
		Additional:  &additional,
	})
	if err != nil {
		panic(err)
	}

	_ = plainText
}
```

## Hashing Y HMAC

```go
hmacValue := repository.HMAC(ctx, "secret", "message")
sha256Value := repository.Sha256Hex(ctx, "message")
blake3Value := repository.Blake3(ctx, "message")

_, _, _ = hmacValue, sha256Value, blake3Value
```

## RSA

```go
keys, err := repository.GenerateRSAKeys(ctx, models.GenerateRSAKeyRequest{
	UID:  "user-123",
	Size: common.Key2048Bits,
})
if err != nil {
	panic(err)
}

cipherText, err := repository.RSA_OAEP_Encode(ctx, models.RSAOAEPEncodeRequest{
	UID:       "user-123",
	PublicKey: keys.PublicKey,
	Text:      "hola",
})
if err != nil {
	panic(err)
}

plainText, err := repository.RSA_OAEP_Decode(ctx, models.RSAOAEPDecodeRequest{
	UID:        "user-123",
	PrivateKey: keys.KeyRef,
	CipherText: cipherText,
})
if err != nil {
	panic(err)
}

signature, err := repository.SignRSAPSS(ctx, keys.KeyRef, "payload")
if err != nil {
	panic(err)
}

if err := repository.VerifyRSAPSS(ctx, keys.PublicKey, "payload", signature); err != nil {
	panic(err)
}

_ = plainText
```

## ECC

```go
keys, err := repository.GenerateECDHCurveKeys(ctx, models.GenerateECDHCurveKeyRequest{
	UID:   "user-123",
	Curve: common.CurveP256,
})
if err != nil {
	panic(err)
}

cipherText, err := repository.ECDH_Encode(ctx, models.ECDHEncodeRequest{
	UID:       "user-123",
	PublicKey: keys.PublicKey,
	Text:      "hola",
})
if err != nil {
	panic(err)
}

plainText, err := repository.ECDH_Decode(ctx, models.ECDHDecodeRequest{
	UID:        "user-123",
	PrivateKey: keys.KeyRef,
	CipherText: cipherText,
})
if err != nil {
	panic(err)
}

_ = plainText
```

## Ed25519

```go
keys, err := repository.GenerateEd255Keys(ctx)
if err != nil {
	panic(err)
}

signature, err := repository.SignEd25519(ctx, keys.KeyRef, "payload")
if err != nil {
	panic(err)
}

if err := repository.VerifyEd25519(ctx, keys.PublicKey, "payload", signature); err != nil {
	panic(err)
}
```

## Backends Cloud

Los paquetes cloud implementan el mismo contrato de repositorio y enrutan
operaciones al proveedor cuando la llave recibida parece una referencia del
proveedor. Las llaves locales explicitas usan fallback local donde esta
soportado.

```go
import (
	awskms "github.com/PointerByte/forge-go/encrypt/aws-kms"
	azurekeyvault "github.com/PointerByte/forge-go/encrypt/azure-key-vault"
	gcpkms "github.com/PointerByte/forge-go/encrypt/gcp-kms"
)
```

Claves de configuracion usadas como fallback:

- AWS KMS: `encrypt.vault.aws-kms.arn`
- Azure Key Vault: `encrypt.vault.azure-key-vault.key-id`
- Google Cloud KMS: `encrypt.vault.gcp-kms.key-id`

Azure y GCP tambien conservan compatibilidad con las claves antiguas
`encrypt.azure-key-vault.key-id` y `encrypt.gcp-kms.key-id`.

## Backends Hardware

El paquete `pkcs11` habla con un HSM fisico o de red a traves de la libreria
PKCS#11 del fabricante. A diferencia de los backends cloud necesita cgo y solo
se compila con el build tag `pkcs11`:

```bash
go build -tags pkcs11 ./...
```

Sin el tag se compila un stub y todos los constructores devuelven
`ErrUnavailable`, de modo que las compilaciones con `CGO_ENABLED=0` y la
compilacion cruzada siguen funcionando para quien no necesita soporte de HSM.

Las llaves se referencian con URIs RFC 7512, lo que hace que la decision de
enrutado sea exacta en vez de heuristica:

```go
import "github.com/PointerByte/forge-go/encrypt/pkcs11"

repository := pkcs11.NewRepository(
	pkcs11.WithModulePath("/usr/lib64/softhsm/libsofthsm2.so"),
	pkcs11.WithTokenLabel("forge-hsm"),
	pkcs11.WithPinProvider(func(ctx context.Context) (string, error) {
		return leerPinDeTuAlmacenDeSecretos(ctx)
	}),
)
defer repository.Close()

signature, err := repository.SignRSAPSS(ctx,
	"pkcs11:token=forge-hsm;object=jwt-signing;type=private", payload)
```

Claves de configuracion:

- `encrypt.vault.pkcs11.module-path`
- `encrypt.vault.pkcs11.token-label`
- `encrypt.vault.pkcs11.slot-id`
- `encrypt.vault.pkcs11.key-uri`
- `encrypt.vault.pkcs11.max-sessions`

Deliberadamente **no** existe una clave de configuracion para el PIN. Se
suministra mediante `WithPinProvider`, asi que nunca acaba en `application.yml`,
ni en un volcado del entorno del proceso, ni en un log.

Comportamiento que conviene conocer antes de desplegar:

- Las llaves privadas y secretas generadas se crean con `CKA_SENSITIVE=true` y
  `CKA_EXTRACTABLE=false`; no se pueden extraer del token.
- Cuando el token no anuncia un mecanismo que una operacion necesita, esa
  operacion falla. Nunca cae en silencio a software, lo que anularia la garantia
  de que el trabajo ocurrio en hardware. El fallback a `local` solo sucede
  cuando quien llama pasa material de llave local en vez de una URI.
- `RotateKey` sintetiza la rotacion, porque PKCS#11 no la tiene: genera una
  llave equivalente con un `CKA_ID` nuevo y devuelve un `KeyRef` nuevo. La llave
  anterior sigue usable salvo que se active `WithRotateDisablesPrevious`.
- `DeactivateKey` limpia los atributos de uso del objeto. En la mayoria de
  tokens esto es irreversible, a diferencia del desactivado reversible que
  ofrecen los backends cloud.
- `ECDH_Decode` mantiene el secreto compartido dentro del token cuando este
  implementa `CKM_HKDF_DERIVE`. Si no, el secreto efimero se extrae y la
  derivacion termina localmente, igual que ya hacen los backends de AWS y Azure;
  usa `WithAllowSecretExtraction(false)` para que falle en su lugar.
- `HMAC` necesita una llave `CKK_GENERIC_SECRET` con `CKA_SIGN`.
  `GenerateSymetrycKeys` crea una llave `CKK_AES` para `EncryptAES`, y la mayoria
  de tokens se niegan a calcular un MAC con ella, asi que las llaves de HMAC se
  aprovisionan aparte, igual que el backend de AWS necesita una llave HMAC de KMS
  y no una de cifrado.
- `RSA_OAEP_Decode` esta fijado a SHA-256 con MGF1-SHA256 para que el ciphertext
  siga siendo legible por los demas backends. Un token que solo ofrezca OAEP con
  SHA-1 (SoftHSM2 lo hace) devuelve `ErrOAEPHashUnsupported` en vez de debilitar
  los parametros en silencio.

Verificado contra SoftHSM2 2.7 con `go test -tags 'pkcs11 pkcs11_integration'`;
mira `integration_test.go` para la configuracion.

## Relacion Con `security`

`security` depende internamente de este modulo para firmas JWT y helpers
criptograficos, pero `encrypt` es independiente. Usalo directamente cuando tu
aplicacion necesite primitivas criptograficas fuera del middleware JWT.

## Pruebas

Desde el directorio del modulo `encrypt`:

```bash
go test ./...
go test -cover -covermode=atomic -coverprofile=coverage.out ./...
```
