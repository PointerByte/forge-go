# Fallo del componente en la recolección de basura — aislamiento del host

Este directorio responde a una sola pregunta: ¿el componente de GoForge falla bajo carga sostenida
de dispatch por culpa del host jco/Deno, o por el componente mismo?

**Respuesta: por el componente.** El fallo se reproduce en wasmtime, un runtime independiente y sin
JavaScript, sin ninguna intervención de jco.

## Evidencia

Carga de trabajo: una instancia, `crypto.sha256` repetido con
`{"abi":"goforge.abi.v1","id":"soak","operation":"crypto.sha256","payload":{"data":""}}`.
Cada ejecución es un proceso en frío. Componente SHA-256 `4a00bbfd…` (Go 1.25.12 +
componentize-go 0.4.0 + wit-bindgen 0.58.0 + wasm-tools 1.255.0).

| Host | entorno del guest | tasa de fallo | umbrales de ejemplo |
|---|---|---|---|
| Deno 2.9.4 + jco 1.26.1 | GC por defecto | 7 / 10 | 1.168 · 4.431 · 7.544 · 11.023 · 13.756 · 14.506 · 19.672 |
| Deno 2.9.4 + jco 1.26.1 | `GOGC=off` | 0 / 10 | — |
| wasmtime 47.0.3 | GC por defecto | 3 / 10 | 5.249 |
| wasmtime 47.0.3 | `GOGC=off` | 0 / 8 | — |

Una sesión posterior volvió a medir ambos hosts y reprodujo el defecto en 9/10 (Deno) y 2/10
(wasmtime), lo que confirma que sigue vigente y que la tasa varía entre sesiones.

La firma del fallo difiere según el host, pero cae en la misma ruta del guest:

- wasmtime: `WasmtimeError: error while executing at wasm backtrace: 0: <wasm function 32>,
  1: clock_time_get`
- Deno: `RangeError: Maximum call stack size exceeded` con una pila de guest
  `runtime.morestack → runtime.badmorestackg0 → runtime.switchToCrashStack → runtime.usleep`

Ambos fallos ocurren mientras el runtime de Go llama al reloj de WASI. Diferir la recolección
elimina el fallo en los dos hosts, y por eso el disparador es el ritmo periódico del recolector, no
una operación concreta. `GOGC=off` es solo diagnóstico: cambia el fallo por un crecimiento ilimitado
de memoria del guest.

La instrumentación del host lo descarta de forma independiente: en 2.193 dispatches el guest hizo
solo 79 llamadas a `monotonic-clock#now` y ninguna al sistema de archivos, flujos o poll.

## Reproducir

```bash
python3 -m venv venv && ./venv/bin/pip install wasmtime   # aquí se usó wasmtime-py 47.0.1
./venv/bin/python wasmtime_soak.py ../component/artifacts/goforge.component.wasm 20000
./venv/bin/python wasmtime_soak.py ../component/artifacts/goforge.component.wasm 20000 off
```

La parte del experimento en Deno está en
`forge-deno-private/research/component-gc-soak/soak.ts`.

## Dónde corresponde el arreglo

Aguas arriba, en la cadena Go → componente: el adaptador wasip1-a-p2 embebido de componentize-go
0.4.0 o la ruta de reloj/planificador `wasip1` de Go 1.25.12. No es un fallo del host de DenoForge
ni de jco, así que ningún trabajo del lado del host lo resolverá.

## Entonces, ¿qué compilador?

Acotado aún más: el defecto es específico de **componentize-go**, no de compilar GoForge a un
componente. Recompilar el mismo código de guest con TinyGo 0.41.1 da 0/10 fallos en ambos hosts y
200.000 despachos limpios, con los 8 vectores compartidos y el manifiesto ABI idénticos.

TinyGo no incluye el planificador del runtime de Go — el subsistema en cuya ruta de reloj fallan
ambos hosts — lo que es coherente con la desaparición del fallo. La comparación, su costo (2,3–3,5×
más lento por despacho) y el cambio de toolchain propuesto están en
[`share/component-tinygo/`](../component-tinygo/README.es.md) y en el
[ADR 0012](../../openspec/changes/tinygo-wasip2-goforge-integration/adr/0012-tinygo-production-component-compiler.md).

Reproduce la comparación con este mismo arnés:

```bash
./venv/bin/python wasmtime_soak.py ../component-tinygo/artifacts/goforge.component.wasm 200000
```

Consulta [README.md](./README.md) para la versión en inglés.
