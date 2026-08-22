# Standard-Go Component Model comparison

Status: passed on 2026-08-01. This is a maintained-toolchain comparison for the
same WIT world as the TinyGo PoC.

It uses Go `1.25.12` with `componentize-go@v0.4.0`, which requires Go `1.25.5`
or newer. The generated bindings identify `wit-bindgen 0.58.0` and select
`go.bytecodealliance.org/pkg@v0.2.2`.

## Reproduce

Build the TinyGo WIT package first, then run:

```bash
./scripts/build.sh
```

The script regenerates bindings for `pointerbyte:goforge-poc@0.1.0`, restores
the language directive to `go 1.25.0`, compiles with the exact Go `1.25.12`
binary, validates with `wasm-tools 1.255.0`, and extracts the resolved WIT.

Expected output:

```text
7247436ce89bdf6e80477a60751980ce1ff83213b25c7d95ad288d27677c5936  artifacts/goforge-standard.component.wasm
2576771 artifacts/goforge-standard.component.wasm
```

Two consecutive builds produced the same hash. The resulting component is about
5.2 times the TinyGo debug component size in this narrow experiment.

To exercise it under Deno:

```bash
cd ../../../forge-deno-private/research/wasip2-host
./scripts/transpile.sh
DENO_DIR=/tmp/goforge-wasip2-deno-cache deno task standard:smoke
```

This passed every success shape, typed error propagation, binary data, and the
host import under Deno `2.9.4` with jco `1.26.1`.

## Key result

Although the input custom world includes TinyGo's `wasi:cli/imports@0.2.0`,
componentize-go adapts the standard Go module to WASI `0.2.12`.
`wasm-tools component wit` confirmed every standard-Go WASI import at `@0.2.12`,
while preserving the custom `pointerbyte` import/export at `0.1.0`.

This is the technically viable and maintained production candidate. The TinyGo
path remains useful only as a size/compatibility experiment until its stale
`0.2.0` baseline and maintenance status are resolved.

## Limitations

- The standard artifact is 2,576,771 bytes before production optimization.
- Its WASI import surface is larger than the TinyGo artifact.
- The comparison smoke uses `@bytecodealliance/preview2-shim@0.19.0` and
  `deno run -A`; that broad permission set is evidence only and is not an
  approved production host policy.
- Native `go test ./...` cannot link the generated
  `go.bytecodealliance.org/pkg@v0.2.2` WASM imports on Linux. Runtime behavior
  is therefore tested through the validated component and Deno host. The
  exported pure functions still have a test file ready for a generator/runtime
  that supports host-native stubs.
- Generated binding directories and components are ignored and recreated by the
  scripts.

The corresponding research is in
[wasip2-component-model.md](../../openspec/changes/tinygo-wasip2-goforge-integration/research/wasip2-component-model.md).
