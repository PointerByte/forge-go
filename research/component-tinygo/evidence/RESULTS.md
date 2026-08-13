# TinyGo production-world comparison — evidence

Captured 2026-08-02 on Linux x86-64 (AMD Ryzen 7 5800X).

```text
tinygo version 0.41.1 linux/amd64 (using go version go1.26.2 and LLVM version 20.1.1)
wasm-tools 1.255.0
wkg 0.16.0
wit-bindgen-go v0.7.0
jco 1.26.1
deno 2.9.4
wasmtime 47.0.3 (wasmtime-py 47.0.1)
```

## Artifact

```text
25dffd2dcaadd91bbe0b47548522fe212ed38bb83acde4dea255c9a2f9eb4d23  artifacts/goforge.component.wasm
1644550 bytes
wasm-tools validate --features component-model: exit 0
export: pointerbyte:goforge/operations@0.1.0
imports: 11 × wasi:*@0.2.0
```

Determinism and reproducibility: the pinned tool binaries and the WASI 0.2.0 dependency tree are both
gitignored, so the build was re-run after deleting them to confirm a fresh clone recovers.
`scripts/generate.sh` re-fetched `wasm-tools` and `wkg` under checksum verification and restored the
deps, and the rebuild produced the **identical digest** `25dffd2dcaadd…`.

The componentize-go component under comparison is
`4a00bbfd710020a28a0479702c5f593ffbf7e30cb248271b314992f10da8fabd`, 3,703,485 bytes, importing
18 × `wasi:*@0.2.12`.

## Endurance

Workload: one instance, repeated `crypto.sha256` dispatch of
`{"abi":"goforge.abi.v1","id":"soak","operation":"crypto.sha256","payload":{"data":""}}`.
Each run is a cold process. Both components measured in the same session.

### Deno 2.9.4 + jco 1.26.1, default GC, 20,000 dispatches × 10 runs

```text
TinyGo           OK ×10                                      trap rate 0/10
componentize-go  TRAP at 1166, 3894, 3905, 7757, 8843,       trap rate 9/10
                 9225, 15563, 16518, 17532; OK ×1
```

### wasmtime 47.0.3, default GC, 20,000 dispatches × 10 runs

```text
TinyGo           OK ×10                                      trap rate 0/10
componentize-go  trapped on runs 1 and 10                    trap rate 2/10
```

### TinyGo long soak, wasmtime, 200,000 dispatches

```text
OK 200000
OK 200000
OK 200000
OK 200000
```

A fifth run was cut off by a 600-second harness timeout rather than a trap; re-run without the cap it
completed. Recorded here because the raw log shows a terminated process.

## Parity

`forge-deno-private/research/component-gc-soak/tinygo_parity.ts`:

```text
  ok    normalize-trim-collapse-ascii-lowercase
  ok    validate-stable-violations
  ok    sha256-abc
  ok    hmac-sha256-rfc4231-case-1
  ok    aes-128-gcm-nist-encrypt
  ok    aes-128-gcm-nist-decrypt
  ok    base64-encode-utf8
  ok    base64-decode-utf8
  ok    manifest identical to the componentize-go component

PARITY OK — 8 shared vectors reproduced exactly by the TinyGo build.
```

The manifest comparison is field by field over operations, capabilities, limits and the ordered error
catalog, with keys sorted so field order cannot mask or invent a difference.

## Cost

`tinygo_throughput.ts`, 2,000 dispatches per operation, 1 KiB payloads, same host and process.
componentize-go runs with `GOGC=off` because it cannot survive the workload otherwise, so these are
its best-case figures:

| Operation | TinyGo | componentize-go (`GOGC=off`) | ratio |
|---|---|---|---|
| `crypto.sha256` | 546.9 µs | 206.6 µs | 2.6× slower |
| `crypto.hmac-sha256` | 546.9 µs | 192.6 µs | 2.8× slower |
| `text.normalize` | 566.2 µs | 187.0 µs | 3.0× slower |
| `encoding.base64.encode` | 541.7 µs | 154.4 µs | 3.5× slower |

A second run of the same harness produced 616.4 / 620.2 / 423.7 / 356.4 µs for TinyGo against
202.7 / 186.0 / 185.6 / 153.4 µs — ratios of 3.0× / 3.3× / 2.3× / 2.3×. componentize-go is stable
between runs; TinyGo varies by up to 35% on the same operation. **The honest summary is 2.3–3.5×
slower, not a single figure**, and a proper `deno bench` treatment belongs in the benchmark suite if
the compiler switch is approved.

For context, the existing three-way benchmark puts the componentize-go component 23–966× slower than
native Deno on the same envelope. The compiler choice does not change the standing guidance that hot
paths use native Deno adapters.

## Interpretation

TinyGo does not ship Go's runtime scheduler, which is the subsystem whose clock path both hosts trap
in (`runtime.usleep` under Deno, `clock_time_get` under wasmtime). The hypothesis recorded in
`temp.md` — that TinyGo "may not exhibit the fault at all" — is confirmed.

This is comparison evidence for a proposed toolchain change, not an applied one. See
[ADR 0012](../../../openspec/changes/tinygo-wasip2-goforge-integration/adr/0012-tinygo-production-component-compiler.md).
