# Standard-Go comparison evidence

Captured on 2026-08-01:

```text
Go compiler: 1.25.12
componentize-go: 0.4.0
generated wit-bindgen: 0.58.0
generated runtime: go.bytecodealliance.org/pkg v0.2.2
component SHA-256: 7247436ce89bdf6e80477a60751980ce1ff83213b25c7d95ad288d27677c5936
component bytes: 2576771
wasm-tools validate: exit 0
Deno 2.9.4 + jco 1.26.1 round trip: ok
```

Component inspection resolved the custom package at `0.1.0` and standard WASI
imports at `0.2.12`.
