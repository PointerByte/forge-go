# Comparación con el Modelo de Componentes y Go estándar

Estado: aprobada el 2026-08-01. Es una comparación con la ruta mantenida para el
mismo mundo WIT del PoC de TinyGo.

Usa Go `1.25.12` y `componentize-go@v0.4.0`, que requiere Go `1.25.5` o
posterior. Los bindings generados identifican `wit-bindgen 0.58.0` y
`go.bytecodealliance.org/pkg@v0.2.2`.

## Reproducción

Después de generar el paquete WIT de TinyGo:

```bash
./scripts/build.sh
```

El script regenera bindings para `pointerbyte:goforge-poc@0.1.0`, restaura
`go 1.25.0`, compila con Go `1.25.12`, valida con `wasm-tools 1.255.0` e
inspecciona el WIT resultante.

```text
7247436ce89bdf6e80477a60751980ce1ff83213b25c7d95ad288d27677c5936  artifacts/goforge-standard.component.wasm
2576771 artifacts/goforge-standard.component.wasm
```

Dos compilaciones consecutivas produjeron el mismo hash. El componente es
aproximadamente 5.2 veces mayor que el componente TinyGo de depuración en esta
prueba reducida.

Para probarlo bajo Deno:

```bash
cd ../../../forge-deno-private/research/wasip2-host
./scripts/transpile.sh
DENO_DIR=/tmp/goforge-wasip2-deno-cache deno task standard:smoke
```

La ejecución pasó todas las formas correctas, los errores tipados, los bytes y
la importación del host con Deno `2.9.4` y jco `1.26.1`.

## Resultado principal y límites

Aunque el mundo personalizado de entrada incluye `wasi:cli/imports@0.2.0`,
componentize-go adapta el módulo de Go estándar a WASI `0.2.12` y conserva la
interfaz `pointerbyte@0.1.0`. Esta es la candidata técnica mantenida para
producción.

- El artefacto mide 2,576,771 bytes antes de optimizar y tiene una superficie
  WASI mayor.
- El smoke usa `@bytecodealliance/preview2-shim@0.19.0` con `deno run -A`; esos
  permisos amplios son solo evidencia.
- `go test ./...` nativo no puede enlazar las importaciones WASM del runtime
  generado `v0.2.2`; la conducta se valida mediante el componente y Deno.
- Los bindings y componentes generados están ignorados y se recrean con los
  scripts.

La investigación correspondiente está en
[wasip2-component-model.md](../../openspec/changes/tinygo-wasip2-goforge-integration/research/wasip2-component-model.md).
