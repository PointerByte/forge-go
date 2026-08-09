# Compilación con TinyGo del mundo de componente de producción

Este directorio responde la pregunta que dejó abierta el BLOQUEANTE 1: ¿el fallo durante la
recolección de basura es inherente a compilar el núcleo portable de GoForge a un componente
WebAssembly, o es específico de **componentize-go**?

**Respuesta: es específico de componentize-go.** El mismo código de guest, compilado con TinyGo
0.41.1, ejecuta la misma carga indefinidamente sin fallar y reproduce cada vector compartido byte a
byte.

## Qué se mantiene constante

La única variable bajo prueba es el compilador y su runtime:

- **Misma lógica de guest.** `guest.go` importa el paquete de producción `component/bridge` en lugar
  de reimplementarlo, así que el cableado del despachador es literalmente el código que se publica.
- **Misma superficie exportada.** `scripts/check-world.sh` compara la interfaz `operations` de
  `wit/world.wit` contra `component/wit/world.wit` y falla ante cualquier desviación.
- **Mismo host, misma carga.** Los arneses de soak y paridad en
  `forge-deno-private/research/component-gc-soak/` ejecutan ambos componentes por la misma ruta
  Deno + jco y la misma ruta wasmtime.

Los mundos difieren en una sola forma declarada: el objetivo `wasip2` de TinyGo enlaza WASI 0.2.0, de
modo que el mundo de investigación incluye `wasi:cli/imports@0.2.0` explícitamente donde
componentize-go resuelve WASI 0.2.12 de forma implícita. La interfaz exportada no se ve afectada, y
es la que invocan los arneses.

## Resultados

Resistencia — 20.000 despachos sostenidos de `crypto.sha256` por corrida, cada corrida en un proceso
frío:

| Host | componentize-go 0.4.0 | TinyGo 0.41.1 |
|---|---|---|
| Deno 2.9.4 + jco 1.26.1 | 9 / 10 fallaron | **0 / 10 fallaron** |
| wasmtime 47.0.3 | 2 / 10 fallaron | **0 / 10 fallaron** |

TinyGo también completó 200.000 despachos en cuatro corridas — diez veces el umbral de fallo más
alto observado en componentize-go.

Corrección: los 8 vectores compartidos se reproducen exactamente, y el manifiesto ABI canónico es
idéntico al del componente de componentize-go.

Tamaño: 1.644.550 bytes frente a 3.703.485.

Costo: aproximadamente 2,3–3,5× más lento por despacho. Consulta el
[ADR 0012](../../openspec/changes/tinygo-wasip2-goforge-integration/adr/0012-tinygo-production-component-compiler.md)
para saber por qué ese intercambio sigue valiendo la pena y bajo qué condiciones.

## Reproducir

```bash
./scripts/build.sh       # compilación TinyGo en su imagen oficial, luego validación y extracción WIT
./scripts/transpile.sh   # la misma invocación de jco que usa la compilación de producción

cd ../../../forge-deno-private
deno run -A research/component-gc-soak/tinygo_parity.ts        # 8 vectores + manifiesto
deno run -A research/component-gc-soak/tinygo_soak.ts --runs=10
deno run -A research/component-gc-soak/soak.ts --runs=10        # control con componentize-go
deno run -A research/component-gc-soak/tinygo_throughput.ts     # latencia lado a lado

cd ../forge-go-private/research/component-gc-soak
./venv/bin/python wasmtime_soak.py ../component-tinygo/artifacts/goforge.component.wasm 200000
```

`scripts/build.sh` ejecuta TinyGo mediante la imagen de contenedor `tinygo/tinygo:0.41.1` — no se
instala nada en el host. `wkg`, `wasm-tools` y el árbol de dependencias WASI 0.2.0 se reutilizan de
`research/tinygo-wasip2`, que los descargó con verificación de checksum.

## Estado

Esto es evidencia de investigación que respalda un cambio de toolchain de producción **propuesto**.
No se ha aplicado: `component/scripts/build.sh` y `openspec/metadata/toolchain.yaml` siguen
describiendo la ruta de componentize-go, y no deben cambiar antes de que la puerta de investigación
apruebe el ADR 0012.
