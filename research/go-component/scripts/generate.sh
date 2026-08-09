#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tinygo_poc=$(cd "${root}/../tinygo-wasip2" && pwd)
cache_root="${TMPDIR:-/tmp}/goforge-componentize-go-cache"

if [[ ! -f "${tinygo_poc}/wit/pointerbyte-goforge-poc-0.1.0.wasm" ]]; then
  "${tinygo_poc}/scripts/generate.sh"
fi

(
  cd "${root}"
  GOWORK=off \
    GOTOOLCHAIN=go1.25.12 \
    XDG_CACHE_HOME="${cache_root}/xdg" \
    GOCACHE="${cache_root}/go-build" \
    go run github.com/bytecodealliance/componentize-go@v0.4.0 \
      --wit-path "${tinygo_poc}/wit/pointerbyte-goforge-poc-0.1.0.wasm" \
      --world goforge-poc \
      bindings \
      --format
  GOWORK=off GOTOOLCHAIN=go1.25.12 go mod edit -go=1.25.0
  GOWORK=off GOTOOLCHAIN=go1.25.12 go mod tidy -go=1.25.0
)

