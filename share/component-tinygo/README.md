# TinyGo build of the production component world

This directory answers the question BLOCKER 1 left open: is the garbage-collection trap inherent to
compiling GoForge's portable core to a WebAssembly component, or specific to **componentize-go**?

**Answer: specific to componentize-go.** The same guest source, compiled by TinyGo 0.41.1, runs the
same workload indefinitely without trapping and reproduces every shared vector byte for byte.

## What is held constant

The only variable under test is the compiler and its runtime:

- **Same guest logic.** `guest.go` imports the production `share/component/bridge` package rather than
  re-implementing it, so the dispatcher wiring is literally the shipped code.
- **Same export surface.** `scripts/check-world.sh` diffs the `operations` interface in
  `wit/world.wit` against `share/component/wit/world.wit` and fails on any drift.
- **Same host, same workload.** The soak and parity harnesses in
  `forge-deno-private/research/component-gc-soak/` run both components through the same Deno + jco
  path and the same wasmtime path.

The worlds differ in one declared way: TinyGo's `wasip2` target links WASI 0.2.0, so the research
world includes `wasi:cli/imports@0.2.0` explicitly where componentize-go resolves WASI 0.2.12
implicitly. The exported interface is unaffected, which is what the harnesses call.

## Results

Endurance — 20,000 sustained `crypto.sha256` dispatches per run, each run a cold process:

| Host | componentize-go 0.4.0 | TinyGo 0.41.1 |
|---|---|---|
| Deno 2.9.4 + jco 1.26.1 | 9 / 10 trapped | **0 / 10 trapped** |
| wasmtime 47.0.3 | 2 / 10 trapped | **0 / 10 trapped** |

TinyGo also completed 200,000 dispatches four times over — ten times the largest observed
componentize-go trap threshold.

Correctness: all 8 shared vectors reproduced exactly, and the canonical ABI manifest is identical to
the componentize-go component's.

Size: 1,644,550 bytes versus 3,703,485.

Cost: roughly 2.3–3.5× slower per dispatch. See
[ADR 0012](../../openspec/changes/tinygo-wasip2-goforge-integration/adr/0012-tinygo-production-component-compiler.md)
for why that trade is still worth taking, and for the conditions attached to it.

## Reproduce

```bash
./scripts/build.sh       # TinyGo build in its official image, then wasm-tools validate + WIT extract
./scripts/transpile.sh   # same jco invocation the production build uses

cd ../../../forge-deno-private
deno run -A research/component-gc-soak/tinygo_parity.ts        # 8 vectors + manifest
deno run -A research/component-gc-soak/tinygo_soak.ts --runs=10
deno run -A research/component-gc-soak/soak.ts --runs=10        # componentize-go control
deno run -A research/component-gc-soak/tinygo_throughput.ts     # side-by-side latency

cd ../forge-go-private/share/component-gc-soak
./venv/bin/python wasmtime_soak.py ../component-tinygo/artifacts/goforge.component.wasm 200000
```

`scripts/build.sh` drives TinyGo through the `tinygo/tinygo:0.41.1` container image — nothing is
installed on the host. `wkg`, `wasm-tools` and the WASI 0.2.0 dependency tree are reused from
`share/tinygo-wasip2`, which fetched them under checksum verification.

## Status

This is research evidence supporting a **proposed** production toolchain change. It has not been
applied: `share/component/scripts/build.sh` and `openspec/metadata/toolchain.yaml` still describe the
componentize-go path, and must not change before the research gate approves ADR 0012.
