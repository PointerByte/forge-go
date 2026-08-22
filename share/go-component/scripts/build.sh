#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tinygo_poc=$(cd "${root}/../tinygo-wasip2" && pwd)
cache_root="${TMPDIR:-/tmp}/goforge-componentize-go-cache"
go_root=$(GOTOOLCHAIN=go1.25.12 go env GOROOT)

"${root}/scripts/generate.sh"
mkdir -p "${root}/artifacts"

(
  cd "${root}"
  GOWORK=off \
    GOTOOLCHAIN=go1.25.12 \
    XDG_CACHE_HOME="${cache_root}/xdg" \
    GOCACHE="${cache_root}/go-build" \
    go run github.com/bytecodealliance/componentize-go@v0.4.0 \
      --wit-path "${tinygo_poc}/wit/pointerbyte-goforge-poc-0.1.0.wasm" \
      --world goforge-poc \
      build \
      --output artifacts/goforge-standard.component.wasm \
      --go "${go_root}/bin/go"
)

"${tinygo_poc}/artifacts/tools/wasm-tools" validate --features component-model \
  "${root}/artifacts/goforge-standard.component.wasm"
"${tinygo_poc}/artifacts/tools/wasm-tools" component wit \
  "${root}/artifacts/goforge-standard.component.wasm" \
  > "${root}/artifacts/goforge-standard.component.wit"
sha256sum "${root}/artifacts/goforge-standard.component.wasm"
wc -c "${root}/artifacts/goforge-standard.component.wasm"
