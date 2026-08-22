# Prueba de concepto de componente WASIp2 con TinyGo

Estado: aprobada el 2026-08-01. Este código es investigación aislada, no un
paquete de producción de GoForge.

El PoC implementa el paquete WIT versionado `pointerbyte:goforge-poc@0.1.0` y
prueba escalares `u32`, cadenas UTF-8, `list<u8>`, registros, errores tipados
`result<summary, operation-error>` y la importación explícita `host.annotate`.

La investigación relacionada está en
[tinygo-compatibility.md](../../openspec/changes/tinygo-wasip2-goforge-integration/research/tinygo-compatibility.md),
[wasip2-component-model.md](../../openspec/changes/tinygo-wasip2-goforge-integration/research/wasip2-component-model.md)
y
[wit-bindings.md](../../openspec/changes/tinygo-wasip2-goforge-integration/research/wit-bindings.md).

## Herramientas fijadas

- Directiva del lenguaje Go: `1.25.0`.
- Go para generación y pruebas nativas: `1.25.12`.
- TinyGo: contenedor oficial `tinygo/tinygo:0.41.1`; internamente informa Go
  `1.26.2` y LLVM `20.1.1`.
- `wit-bindgen-go`: `v0.7.0`; biblioteca generada
  `go.bytecodealliance.org/cm@v0.3.0`.
- `wasm-tools`: `1.255.0`; SHA-256 de la distribución
  `a62237f4731c45f665f1115cad39acaeec02963cbc848c9473ab033eed837072`.
- `wkg`: `0.16.0`; SHA-256 de la distribución
  `8ab0f7138e1a84616cb0c87c2bd7b7d00a356b63d458be92bad3fbd463aa3e2a`.

Se usa Go `1.25.12` porque conserva la semántica 1.25 y contiene correcciones de
seguridad ausentes en el compilador `1.25.0`. La versión `1.25.0` es el piso de
compatibilidad, no el binario recomendado para producción.

## Reproducción

```bash
./scripts/fetch-tools.sh
./scripts/build.sh
./scripts/test.sh
```

Salida final esperada:

```text
faae839462c6c80dee2f5062289ea0a7c225170a52f1cbdc30a14c571560db55  artifacts/goforge-poc.component.wasm
494620 artifacts/goforge-poc.component.wasm
```

Dos compilaciones limpias produjeron el mismo hash.
`wasm-tools validate --features component-model` pasó y la inspección WIT
confirmó la importación personalizada y la exportación `operations@0.1.0`.

La ejecución completa en Deno está en el
[PoC del host de DenoForge](../../../forge-deno-private/research/wasip2-host/README.es.md).

## Evidencia importante de versión WASI

El objetivo `wasip2` de TinyGo `0.41.1` exige `wasi:cli/imports@0.2.0`.
`wkg.lock` fija exactamente `0.2.0`, con digest
`sha256:e7e85458e11caf76554b724ebf4f113259decf0f3b1ee2e2930de096f72114a7`, y la
inspección del componente confirma todas sus importaciones WASI en `@0.2.0`.

La publicación actual de WASI 0.2 es `0.2.12`; estas versiones nominales no son
intercambiables al enlazar. La comparación mantenida en
[go-component](../go-component/README.es.md) genera `@0.2.12`, evidencia directa
de que la base integrada en TinyGo está atrasada.

## Validaciones y límites

Las pruebas de Go cubren resultados correctos, ambos errores tipados, UTF-8 y
bytes. El host Deno además verifica los hashes del componente, pegamento
JavaScript y módulos core; todas las formas ABI; 128 llamadas en cuatro
instancias; rechazo de versión; rechazo de hashes; cierre idempotente y rechazo
posterior al cierre.

- La guía oficial indica que las herramientas de componentes para TinyGo no
  reciben mantenimiento y recomienda las herramientas de Go estándar.
- El componente de depuración mide 494,620 bytes; no es una meta de producción.
- Async WIT, cancelación, streams y recursos quedan fuera de este mundo mínimo.
- Las llamadas son síncronas. Cuatro instancias prueban aislamiento, no
  reentrada de una instancia.
- El cierre elimina la referencia JavaScript; la recolección de memoria depende
  del GC.
- Bindings, dependencias WIT, herramientas y binarios son generados e ignorados.
- Adoptar esto en producción exige revisión OpenSpec, clasificación completa de
  APIs y revisión de seguridad.

Las salidas desechables son `artifacts/`, `generated/`, `wit/deps/` y
`wit/pointerbyte-goforge-poc-0.1.0.wasm`. La caché principal está en
`/tmp/goforge-tinygo-wasip2-cache`.
