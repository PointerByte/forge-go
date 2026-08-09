# TinyGo WASIp2 component proof of concept

Status: passed on 2026-08-01. This is research code, not a production GoForge
package.

The PoC implements the versioned WIT package `pointerbyte:goforge-poc@0.1.0`.
Its exported interface exercises every boundary required by `metadata.md`:

- scalar `u32` input/output;
- UTF-8 strings;
- `list<u8>` binary data;
- record input and output;
- `result<summary, operation-error>` with payload and payload-free error cases;
- the explicit host import `host.annotate`.

The related decisions and research are in
[tinygo-compatibility.md](../../openspec/changes/tinygo-wasip2-goforge-integration/research/tinygo-compatibility.md),
[wasip2-component-model.md](../../openspec/changes/tinygo-wasip2-goforge-integration/research/wasip2-component-model.md),
and
[wit-bindings.md](../../openspec/changes/tinygo-wasip2-goforge-integration/research/wit-bindings.md).

## Pinned toolchain

- Go language directive: `1.25.0`.
- Go used for generation and native unit tests: `1.25.12`.
- TinyGo: official `tinygo/tinygo:0.41.1` container. The published image reports
  Go `1.26.2` and LLVM `20.1.1` internally.
- `wit-bindgen-go`: `go.bytecodealliance.org/cmd/wit-bindgen-go@v0.7.0`.
- generated Component Model helper: `go.bytecodealliance.org/cm@v0.3.0`.
- `wasm-tools`: `1.255.0`, release SHA-256
  `a62237f4731c45f665f1115cad39acaeec02963cbc848c9473ab033eed837072`.
- `wkg`: `0.16.0`, release SHA-256
  `8ab0f7138e1a84616cb0c87c2bd7b7d00a356b63d458be92bad3fbd463aa3e2a`.

Go `1.25.12` is intentional: it preserves Go 1.25 language semantics and
contains the security fixes absent from the original `1.25.0` compiler. Exact
`1.25.0` is a compatibility floor, not the recommended production compiler
binary.

## Reproduce

From this directory:

```bash
./scripts/fetch-tools.sh
./scripts/build.sh
./scripts/test.sh
```

`fetch-tools.sh` downloads only the pinned x86-64 Linux binaries and verifies
their published hashes. `generate.sh` resolves the WIT dependency graph, encodes
it, and regenerates Go bindings. `build.sh` streams an archive into the official
TinyGo container because Docker Desktop cannot bind-mount this external-media
workspace; it then validates and inspects the returned component.

The expected final build output is:

```text
faae839462c6c80dee2f5062289ea0a7c225170a52f1cbdc30a14c571560db55  artifacts/goforge-poc.component.wasm
494620 artifacts/goforge-poc.component.wasm
```

Two clean rebuilds produced the same component hash.
`wasm-tools validate --features component-model` passed, and
`wasm-tools component wit` showed the custom import and operations export at
`0.1.0`.

The Deno round trip is in
[DenoForge's host PoC](../../../forge-deno-private/research/wasip2-host/README.md).

## Important WASI version evidence

TinyGo `0.41.1`'s `wasip2` target requires `wasi:cli/imports@0.2.0`. `wkg.lock`
resolves `wasi:cli` exactly to `0.2.0`, digest
`sha256:e7e85458e11caf76554b724ebf4f113259decf0f3b1ee2e2930de096f72114a7`.
Inspection of the built component confirms that all of its WASI imports are
`@0.2.0`.

The current WASI 0.2 package release is `0.2.12`. Those interface versions are
nominal and are not interchangeable at link time. The maintained standard-Go
comparison in [go-component](../go-component/README.md) emits `@0.2.12`; this is
direct evidence that TinyGo's bundled baseline is stale even though the custom
`pointerbyte` interface works.

## Test behavior

Native tests cover successful values, both typed error cases, UTF-8, and binary
reversal. The Deno host additionally verifies:

- source component, generated glue, and all core-module SHA-256 values before
  execution;
- all exported ABI shapes and the host import;
- 128 scheduled calls across four independently instantiated components;
- incompatible component-version rejection;
- checksum failure rejection;
- idempotent close and rejection of calls after close.

## Known limitations

- The official Component Model guide says the TinyGo component tooling is not
  currently maintained and recommends the standard-Go tooling.
- The component is a debug research build. Its 494,620-byte size is not a
  production size target.
- WIT async, cancellation, streams, and owned resources are deliberately outside
  this minimal world.
- Calls exported by this component are synchronous. The Deno concurrency test
  schedules requests and uses four instances; it does not prove reentrant calls
  into one instance.
- Close drops the JavaScript reference. This world exports no resources, so
  there is no resource-specific destructor; memory reclamation remains
  garbage-collector controlled.
- Generated bindings, dependency WIT, tools, and binaries are ignored. They must
  be regenerated before building a fresh checkout.
- This code must not be promoted by relocation. Production adoption requires the
  OpenSpec design review, full GoForge API classification, security review, and
  plan tasks.

## Cleanup

The disposable outputs are `artifacts/`, `generated/`, `wit/deps/`, and
`wit/pointerbyte-goforge-poc-0.1.0.wasm`. The task-specific caches are
`/tmp/goforge-tinygo-wasip2-cache`, `/tmp/goforge-wkg-cache`, and
`/tmp/goforge-wasm-tools-1.255.0` when present.
