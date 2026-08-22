# TinyGo PoC evidence

Captured on 2026-08-01 on Linux x86-64.

```text
tinygo version 0.41.1 linux/amd64 (using go version go1.26.2 and LLVM version 20.1.1)
wasm-tools 1.255.0 (76e20611d 2026-07-30)
wkg 0.16.0
go version go1.25.12 linux/amd64
```

Build and validation:

```text
WIT package written to wit/pointerbyte-goforge-poc-0.1.0.wasm
faae839462c6c80dee2f5062289ea0a7c225170a52f1cbdc30a14c571560db55  artifacts/goforge-poc.component.wasm
494620 artifacts/goforge-poc.component.wasm
wasm-tools validate: exit 0
```

The same hash was observed before and after a complete binding regeneration and
repeated Docker build.

Native Go tests passed. The generated packages contained no tests; the root
portable operations package passed in approximately 2 ms.
