# Núcleo portable de GoForge

Este módulo Go anidado es la fuente de verdad sin dependencias para las reglas
deterministas de GoForge que cruzan los límites de Go nativo, componentes
WebAssembly y Deno. Implementa el paquete de contrato
`pointerbyte:goforge@0.1.0` y el puente JSON estricto `goforge.abi.v1`.

## Contrato

ABI v1 expone ocho operaciones:

| Capacidad | Operaciones |
| --- | --- |
| Normalización | `text.normalize` |
| Validación | `text.validate` |
| SHA-256 | `crypto.sha256` |
| HMAC-SHA256 | `crypto.hmac-sha256` |
| AES-GCM | `crypto.aes-gcm.encrypt`, `crypto.aes-gcm.decrypt` |
| Base64 | `encoding.base64.encode`, `encoding.base64.decode` |

El manifiesto también publica las capacidades observadas por el host
`control.deadline` y `control.cancellation`. Una solicitud que incluya uno de
esos controles falla de forma cerrada si el host no entrega al dispatcher un
estado verificado y coincidente. El paquete nunca consulta un reloj.

```json
{
  "abi": "goforge.abi.v1",
  "id": "request-1",
  "operation": "crypto.sha256",
  "metadata": {
    "required_capabilities": ["crypto.sha256"]
  },
  "payload": {"data": "YWJj"}
}
```

Las respuestas correctas contienen `result`; las fallidas contienen un
`error` tipado del catálogo del manifiesto. Nunca contienen ambos.

Los campos de entrada y resultado de las operaciones son estables:

| Operación | Entrada obligatoria | Resultado correcto |
| --- | --- | --- |
| `text.normalize` | `value`; booleanos opcionales `trim`, `collapse_whitespace`, `lowercase_ascii` | `value` |
| `text.validate` | `value`, `rules` | `valid`, `violations` ordenadas |
| `crypto.sha256` | `data` en Base64 | `digest` en Base64 |
| `crypto.hmac-sha256` | `key` y `data` en Base64 | `mac` en Base64 |
| `crypto.aes-gcm.encrypt` | `key`, `nonce`, `aad`, `plaintext` en Base64 | `ciphertext` en Base64 con el tag de autenticación anexado |
| `crypto.aes-gcm.decrypt` | `key`, `nonce`, `aad`, `ciphertext` en Base64 | `plaintext` en Base64 |
| `encoding.base64.encode` | `text` UTF-8 | `encoded` |
| `encoding.base64.decode` | `encoded` canónico | `text` UTF-8 |

Todos los campos indicados son obligatorios, incluso un `aad` explícitamente
vacío. Las reglas de validación son `required`, `min_bytes`, `max_bytes`,
`min_runes`, `max_runes`, `ascii`, `forbid_control`, `forbid_whitespace`,
`prefix` y `suffix`. Las violaciones siguen ese orden para que todos los
runtimes generen el mismo resultado.

## Serialización y límites

- JSON debe ser UTF-8 y contener un solo objeto.
- Se rechazan campos desconocidos, nombres de objeto duplicados, JSON inválido
  y anidamiento excesivo.
- Los campos binarios usan el alfabeto estándar de RFC 4648 con relleno
  obligatorio. Fallan valores URL-safe, sin relleno, con espacios o no canónicos.
- El manifiesto publica los límites de solicitud, respuesta, binarios, cadenas,
  identificador, token de control, cantidad de capacidades y profundidad JSON;
  el dispatcher los aplica antes de usar los datos.
- Las operaciones Base64 convierten texto UTF-8 intencionalmente. Los binarios
  arbitrarios de las demás operaciones siguen siendo campos Base64 canónicos.

## Seguridad criptográfica

AES-GCM solo acepta claves proporcionadas por el llamador de 128, 192 o 256
bits y nonces proporcionados por el llamador de exactamente 12 bytes. Nunca
genera aleatoriedad ni cambia silenciosamente de algoritmo. El llamador debe
garantizar que cada nonce sea único para cada cifrado con una misma clave. Un
fallo de autenticación solo devuelve el error estable `authentication_failed`,
sin texto plano. Las claves HMAC deben contener al menos 16 bytes.

La implementación solo importa la biblioteca estándar de Go. Los archivos de
producción no acceden al sistema de archivos, red, entorno, logging, SDKs de
nube, relojes ni fuentes aleatorias.

## Verificación

Ejecute este módulo anidado fuera del workspace padre hasta que la integración
lo agregue a `go.work`:

```sh
GOWORK=off GOTOOLCHAIN=go1.25.0 go test ./...
GOWORK=off GOTOOLCHAIN=go1.25.0 go test -coverprofile=coverage.out ./...
GOWORK=off GOTOOLCHAIN=go1.25.0 go vet ./...
GOWORK=off GOTOOLCHAIN=go1.25.12 go test ./...
GOWORK=off GOTOOLCHAIN=go1.25.12 go test -run '^$' -bench . -benchmem ./...
```

`testdata/vectors/v1.json` es el conjunto determinista y neutral al lenguaje.
Cubre todas las operaciones, incluidos los casos AES-128-GCM de NIST y
HMAC-SHA256 de RFC 4231. Las pruebas negativas y fuzz cubren decodificación
estricta, límites, controles de ejecución y fallos criptográficos.

## Límite del artefacto componente

Este módulo no copia deliberadamente un mundo WIT, bindings generados ni un
script de compilación desde un directorio de investigación. Promover el mundo
`pointerbyte:goforge@0.1.0` ya validado a un artefacto de producción requiere la
puerta de integración entre repositorios, controles de deriva de bindings y
validación de paridad en Deno. Mantener esa promoción fuera de este módulo evita
convertir una ruta de investigación en una dependencia de producción no declarada.

Esa promoción existe ahora como el módulo hermano `component/`, que posee el
mundo WIT, los bindings generados versionados y la canalización de compilación.
Este módulo se mantiene libre de ellos para que el núcleo portable no dependa de
la cadena de herramientas de componentes.

```bash
cd component
WASM_TOOLS=/ruta/a/wasm-tools ./scripts/check-generated.sh   # los bindings se reproducen byte a byte
WASM_TOOLS=/ruta/a/wasm-tools ./scripts/check.sh             # tests, race, vet, staticcheck
WASM_TOOLS=/ruta/a/wasm-tools ./scripts/build.sh             # compilar, validar, transpilar, empaquetar
```

`build.sh` produce un paquete de publicación determinista en
`component/artifacts/` (ignorado por git): el componente validado, su WIT
extraído, el glue de host de jco y los módulos core, el manifiesto ABI canónico,
los vectores compartidos, la evidencia de cadena de herramientas y contrato, y
`SHA256SUMS`. Dos compilaciones consecutivas son idénticas byte a byte.

**El componente resultante todavía no es apto para promover.** Su runtime de Go
falla de forma intermitente durante la recolección de basura bajo carga sostenida
de dispatch. La corrección está probada frente a los vectores compartidos; la
resistencia no. Consulta el bloqueador en el registro de migración `../../temp.md`.
