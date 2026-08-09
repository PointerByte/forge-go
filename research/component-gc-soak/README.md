# Component garbage-collection trap — host isolation

This directory answers one question: does the GoForge component trap under sustained dispatch load
because of the jco/Deno host, or because of the component itself?

**Answer: the component.** The trap reproduces in wasmtime, a completely independent non-JavaScript
runtime, with no jco involvement.

## Evidence

Workload: one instance, repeated `crypto.sha256` dispatch of
`{"abi":"goforge.abi.v1","id":"soak","operation":"crypto.sha256","payload":{"data":""}}`.
Each run is a cold process. Component SHA-256 `4a00bbfd…` (Go 1.25.12 + componentize-go 0.4.0 +
wit-bindgen 0.58.0 + wasm-tools 1.255.0).

| Host | guest environment | trap rate | example thresholds |
|---|---|---|---|
| Deno 2.9.4 + jco 1.26.1 | default GC | 7 / 10 | 1,168 · 4,431 · 7,544 · 11,023 · 13,756 · 14,506 · 19,672 |
| Deno 2.9.4 + jco 1.26.1 | `GOGC=off` | 0 / 10 | — |
| wasmtime 47.0.3 | default GC | 3 / 10 | 5,249 |
| wasmtime 47.0.3 | `GOGC=off` | 0 / 8 | — |

A later session re-measured both hosts and reproduced the defect at 9/10 (Deno) and 2/10 (wasmtime),
confirming it is still live and that the rate varies between sessions.

The failure signature differs by host but lands on the same guest path:

- wasmtime: `WasmtimeError: error while executing at wasm backtrace: 0: <wasm function 32>,
  1: clock_time_get`
- Deno: `RangeError: Maximum call stack size exceeded` with a guest stack of
  `runtime.morestack → runtime.badmorestackg0 → runtime.switchToCrashStack → runtime.usleep`

Both traps occur while the Go runtime is calling the WASI clock. Deferring collection removes the
trap on both hosts, which is why the collector's periodic pacing — not any single operation — is the
trigger. `GOGC=off` is diagnostic only: it trades the trap for unbounded guest memory growth.

Host instrumentation rules the host out independently: over 2,193 dispatches the guest made only 79
`monotonic-clock#now` calls and no filesystem, stream or poll calls at all.

## Reproduce

```bash
python3 -m venv venv && ./venv/bin/pip install wasmtime   # wasmtime-py 47.0.1 used here
./venv/bin/python wasmtime_soak.py ../../component/artifacts/goforge.component.wasm 20000
./venv/bin/python wasmtime_soak.py ../../component/artifacts/goforge.component.wasm 20000 off
```

The Deno side of the same experiment lives in
`forge-deno-private/research/component-gc-soak/soak.ts`.

## Where the fix belongs

Upstream, in the Go → component toolchain: componentize-go 0.4.0's embedded wasip1-to-p2 adapter or
Go 1.25.12's `wasip1` clock/scheduler path. It is not a DenoForge host bug and not a jco bug, so no
amount of host-side work will resolve it.

## Which compiler, then

Narrowed further: the defect is specific to **componentize-go**, not to compiling GoForge to a
component. Rebuilding the same guest source with TinyGo 0.41.1 gives 0/10 traps on both hosts and
200,000 clean dispatches, with all 8 shared vectors and the ABI manifest identical.

TinyGo does not ship Go's runtime scheduler — the subsystem whose clock path both hosts trap in —
which is consistent with the fault disappearing. The comparison, its cost (2.3–3.5× slower per
dispatch), and the proposed toolchain change live in
[`research/component-tinygo/`](../component-tinygo/README.md) and
[ADR 0012](../../openspec/changes/tinygo-wasip2-goforge-integration/adr/0012-tinygo-production-component-compiler.md).

Reproduce the comparison against this same harness:

```bash
./venv/bin/python wasmtime_soak.py ../component-tinygo/artifacts/goforge.component.wasm 200000
```

See [README.es.md](./README.es.md) for the Spanish version.
