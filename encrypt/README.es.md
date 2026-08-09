# GoForge Encrypt

`encrypt` es el modulo de criptografia independiente de GoForge. Expone una
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
- `Provider`: nombre del backend, por ejemplo `local`, `aws-kms`, `azure-key-vault` o `gcp-kms`

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
