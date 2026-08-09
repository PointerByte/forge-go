# go-openssl

`go-openssl` es la CLI de GoForge para generar certificados y llaves PEM para
RSA, ECC/ECDSA o Ed25519. Puede crear certificados autofirmados, certificados
CA, certificados firmados por una CA existente y envoltorios PEM cifrados que
luego pueden leerse desde la CLI o desde la API Go.

## Instalacion

```bash
go install github.com/PointerByte/forge-go/cmd/go-openssl@latest
```

Actualizar las dependencias usadas por el modulo actual:

```bash
go get -u ./...
```

## Comandos

Generar archivos PEM:

```bash
go-openssl generate [flags]
```

Leer un archivo PEM plano o cifrado:

```bash
go-openssl read --file ./certs/cert.pem
```

Actualizar el secreto de archivos PEM cifrados existentes:

```bash
go-openssl reencrypt [flags]
```

## Defaults De Generacion

Cuando omites flags, la generacion usa:

- algoritmo: `rsa`
- directorio de salida: `.`
- common name: `localhost`
- DNS SAN: `localhost`
- organizacion: `PointerByte`
- vigencia: `365` dias
- tamano RSA: `2048` bits
- curva ECC: `p256`
- archivos: `cert.pem`, `key.pem`, `public.pem`

Las llaves privadas se escriben con modo `0600`; certificados y llaves publicas
se escriben con modo `0644`. El contenido se prepara junto a su destino y se
reemplaza atomicamente. Un error de generacion o rotacion limpia los temporales
y restaura los destinos reemplazados antes dentro del mismo lote.

## Flags De Generate

| Flag | Short | Descripcion |
| --- | --- | --- |
| `--algorithm` | `-a` | `rsa`, `ecc` o `ed25519` |
| `--dir` | `-d` | directorio de salida |
| `--common-name` | `-n` | common name del certificado |
| `--dns` | | Subject Alternative Name DNS; puede repetirse o ir separado por comas |
| `--organization` | | organizacion del subject del certificado |
| `--days` | | vigencia del certificado en dias |
| `--rsa-bits` | | tamano de llave RSA en bits; minimo `2048` |
| `--ecc-curve` | | `p256`, `p384` o `p521` |
| `--salt` | | entropia adicional opcional mezclada en la generacion |
| `--cert-file` | | nombre del archivo de certificado |
| `--key-file` | | nombre del archivo de llave privada |
| `--public-key-file` | | nombre del archivo de llave publica |
| `--signed-by` | | ruta del certificado CA PEM que firma el nuevo certificado |
| `--ca-key` | | ruta de la llave privada CA usada con `--signed-by` |
| `--ca` | | marca el certificado generado como CA |
| `--encrypt-secret-env` | | variable de entorno que contiene el secreto de los PEM generados |
| `--encrypt-secret-file` | | archivo regular que contiene el secreto de los PEM generados |
| `--signed-by-secret-env` / `--signed-by-secret-file` | | origen de entorno o archivo para el certificado `--signed-by` cifrado |
| `--ca-key-secret-env` / `--ca-key-secret-file` | | origen de entorno o archivo para la llave privada `--ca-key` cifrada |
| `--encrypt-secret`, `--signed-by-secret`, `--ca-key-secret` | | flags de valor literal obsoletos, conservados por compatibilidad |

`--signed-by` y `--ca-key` deben pasarse juntos. Si algun archivo de CA esta
cifrado, pasa el nombre de la variable de entorno o la ruta del archivo de
secreto correspondiente. Los flags literales siguen funcionando, pero avisan
porque otros usuarios y herramientas de monitoreo pueden ver los argumentos
del proceso.

## Flags De Read

| Flag | Short | Descripcion |
| --- | --- | --- |
| `--file` | `-f` | archivo PEM plano o cifrado a leer |
| `--secret-env` | | variable de entorno que contiene el secreto de descifrado |
| `--secret-file` | | archivo regular que contiene el secreto de descifrado |
| `--secret` | `-s` | flag de valor literal obsoleto, conservado por compatibilidad |
| `--out` | `-o` | destino opcional para el PEM descifrado |

Si omites `--out`, el comando escribe el contenido PEM en stdout. Con `--out`,
reemplaza atomicamente un destino de archivo regular con modo `0600`.

## Flags De Reencrypt

| Flag | Descripcion |
| --- | --- |
| `--cert-file` | ruta del certificado PEM cifrado |
| `--key-file` | ruta de la llave privada PEM cifrada |
| `--public-key-file` | ruta de la llave publica PEM cifrada |
| `--encrypt-secret-old-env` / `--encrypt-secret-old-file` | origen de entorno o archivo para el secreto actual |
| `--encrypt-secret-new-env` / `--encrypt-secret-new-file` | origen de entorno o archivo para el secreto nuevo |
| `--encrypt-secret-old`, `--encrypt-secret-new` | flags de valor literal obsoletos, conservados por compatibilidad |

Ambos secretos deben tener al menos 32 bytes. El comando reemplaza atomicamente
los mismos archivos y no genera un certificado ni par de llaves nuevo.

## Ejemplos Basicos

Generar un certificado RSA autofirmado:

```bash
go-openssl generate --algorithm rsa --dir ./certs
```

Generar un certificado ECC:

```bash
go-openssl generate \
  --algorithm ecc \
  --ecc-curve p384 \
  --dir ./certs/ecc \
  --common-name api.default.svc \
  --dns api.default.svc \
  --dns api.default.svc.cluster.local
```

Generar certificado y par de llaves Ed25519:

```bash
go-openssl generate \
  --algorithm ed25519 \
  --dir ./certs/jwt \
  --common-name jwt-signing.default.svc \
  --key-file key.pem \
  --public-key-file public.pem
```

## Ejemplo CA Y mTLS

Crear una CA:

```bash
go-openssl generate \
  --algorithm rsa \
  --rsa-bits 4096 \
  --ca \
  --dir ./certs/ca \
  --common-name internal-ca.example.local \
  --organization "Example Internal CA" \
  --days 3650 \
  --cert-file ca.pem \
  --key-file ca-key.pem \
  --public-key-file ca-public.pem
```

Crear un certificado de servidor firmado por esa CA:

```bash
go-openssl generate \
  --algorithm ecc \
  --ecc-curve p256 \
  --dir ./certs/server \
  --common-name my-api.default.svc \
  --dns my-api.default.svc \
  --dns my-api.default.svc.cluster.local \
  --organization "Example Platform" \
  --days 365 \
  --signed-by ./certs/ca/ca.pem \
  --ca-key ./certs/ca/ca-key.pem
```

Crear un certificado cliente para mTLS:

```bash
go-openssl generate \
  --algorithm ecc \
  --ecc-curve p256 \
  --dir ./certs/client \
  --common-name my-api-client.default.svc \
  --dns my-api-client.default.svc \
  --organization "Example Platform" \
  --days 365 \
  --signed-by ./certs/ca/ca.pem \
  --ca-key ./certs/ca/ca-key.pem
```

## Archivos PEM Cifrados

Las nuevas salidas cifradas usan envoltorios version 2
`GoForge ENCRYPTED PEM`: AES-256-GCM con una llave derivada por Argon2id, una
sal KDF aleatoria de 16 bytes y un nonce aleatorio independiente. La version 2
fija Argon2id en 64 MiB, tres pasadas, dos lanes y una llave de 32 bytes; los
parametros inesperados se rechazan antes de reservar memoria. Los secretos deben
tener al menos 32 bytes. El lector sigue aceptando los envoltorios heredados
version 1; leerlos no los reescribe, mientras que `reencrypt` los actualiza a
version 2.

Prefiere un montaje de gestor de secretos o una variable de entorno. No pongas
el valor del secreto directamente en la linea de comandos:

```bash
go-openssl generate \
  --algorithm rsa \
  --rsa-bits 4096 \
  --dir ./certs/encrypted \
  --common-name api.default.svc \
  --encrypt-secret-file /run/secrets/goforge-pem
```

Leer un PEM cifrado hacia stdout:

```bash
go-openssl read \
  --file ./certs/encrypted/cert.pem \
  --secret-file /run/secrets/goforge-pem
```

Escribir el PEM descifrado en un archivo nuevo:

```bash
go-openssl read \
  --file ./certs/encrypted/key.pem \
  --secret-file /run/secrets/goforge-pem \
  --out ./certs/encrypted/key.decrypted.pem
```

Actualizar archivos PEM cifrados a un secreto nuevo sin regenerar certificados:

```bash
go-openssl reencrypt \
  --cert-file ./certs/encrypted/cert.pem \
  --key-file ./certs/encrypted/key.pem \
  --public-key-file ./certs/encrypted/public.pem \
  --encrypt-secret-old-file /run/secrets/goforge-pem-current \
  --encrypt-secret-new-env GOFORGE_PEM_SECRET_NEW
```

Usar una CA cifrada para firmar otro certificado:

```bash
go-openssl generate \
  --algorithm ecc \
  --ecc-curve p384 \
  --dir ./certs/service \
  --common-name service.default.svc \
  --dns service.default.svc \
  --signed-by ./certs/ca/ca.pem \
  --ca-key ./certs/ca/ca-key.pem \
  --signed-by-secret-file /run/secrets/goforge-ca \
  --ca-key-secret-file /run/secrets/goforge-ca
```

Cada secreto logico acepta exactamente un origen de entorno, archivo o literal
obsoleto. Los archivos de secreto son regulares y de tamano acotado; se elimina
un `LF` o `CRLF` final para funcionar con secretos montados. Los valores nunca
aparecen en el estado ni en los errores del comando.

Las versiones antiguas de `go-openssl` no pueden leer archivos version 2.
Conserva un binario actualizado durante el despliegue. Los errores ordinarios
activan limpieza y rollback, pero ningun formato multiarchivo puede garantizar
una transaccion frente a una caida del host; aplica los controles habituales de
backup y recuperacion al material de llaves.

## Ejemplos Kubernetes

Certificado backend para un servicio detras de un Ingress:

```bash
go-openssl generate \
  --algorithm rsa \
  --rsa-bits 4096 \
  --dir ./certs/my-api \
  --common-name my-api.default.svc \
  --dns my-api.default.svc \
  --dns my-api.default.svc.cluster.local \
  --dns api.example.com \
  --organization "Example Platform" \
  --days 365
```

Certificado interno servicio-a-servicio:

```bash
go-openssl generate \
  --algorithm ecc \
  --ecc-curve p256 \
  --dir ./certs/orders-to-payments \
  --common-name payments.default.svc \
  --dns payments.default.svc \
  --dns payments.default.svc.cluster.local \
  --organization "Example Internal Services" \
  --days 365
```

## API Go

El generador tambien puede usarse directamente desde Go:

```go
package main

import (
	"log"

	goopenssl "github.com/PointerByte/forge-go/cmd/go-openssl/code"
)

func main() {
	result, err := goopenssl.GenerateCertificates(goopenssl.Options{
		Algorithm:    "ecc",
		ECCCurve:     "p256",
		OutputDir:    "./certs",
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		IPAddresses:  []string{"127.0.0.1"},
		Organization: "Example",
		ValidForDays: 365,
	})
	if err != nil {
		log.Fatal(err)
	}

	cert, err := goopenssl.ReadCertificateFile(result.CertificatePath, "")
	if err != nil {
		log.Fatal(err)
	}

	_ = cert
}
```

Para actualizar el secreto de archivos PEM cifrados existentes desde Go:

```go
_, err := goopenssl.UpdateEncryptionSecret(goopenssl.UpdateEncryptionSecretOptions{
	CertificatePath:   "./certs/encrypted/cert.pem",
	PrivateKeyPath:    "./certs/encrypted/key.pem",
	PublicKeyPath:     "./certs/encrypted/public.pem",
	EncryptSecretOld:  oldSecretFromSecretManager,
	EncryptSecretNew:  newSecretFromSecretManager,
})
if err != nil {
	log.Fatal(err)
}
```

`go-openssl generate` corresponde a campos de `goopenssl.Options`:

| Flag CLI | Campo Go |
| --- | --- |
| `--algorithm` | `Algorithm` |
| `--dir` | `OutputDir` |
| `--common-name` | `CommonName` |
| `--dns` | `DNSNames` |
| solo API Go | `IPAddresses` |
| `--organization` | `Organization` |
| `--days` | `ValidForDays` |
| `--rsa-bits` | `RSAKeySize` |
| `--ecc-curve` | `ECCCurve` |
| `--salt` | `Salt` |
| `--cert-file` | `CertFileName` |
| `--key-file` | `KeyFileName` |
| `--public-key-file` | `PublicKeyFileName` |
| `--signed-by` | `SignedBy` |
| `--ca-key` | `CAKeyFile` |
| `--ca` | `IsCA` |
| cualquier origen `--encrypt-secret-*` | `EncryptSecret` |
| cualquier origen `--signed-by-secret-*` | `SignedBySecret` |
| cualquier origen `--ca-key-secret-*` | `CAKeySecret` |

Helpers de lectura:

- `ReadPEMFile(path, secret)`
- `ReadCertificateFile(path, secret)`
- `ReadPrivateKeyFile(path, secret)`
- `ReadPublicKeyFile(path, secret)`
- `UpdateEncryptionSecret(options)`

Los PEM planos pueden leerse con secreto vacio. Los PEM cifrados requieren el
mismo secreto usado durante la generacion. Los consumidores Go deben obtener
los secretos desde su gestor; la API Go nunca requiere argumentos de linea de
comandos.

## Desarrollo

Desde el directorio del modulo `cmd/go-openssl`:

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
