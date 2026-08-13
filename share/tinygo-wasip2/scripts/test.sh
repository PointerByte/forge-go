#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cache_dir="${TMPDIR:-/tmp}/goforge-tinygo-wasip2-cache/go-build"

(
  cd "${root}"
  GOWORK=off GOTOOLCHAIN=go1.25.12 GOCACHE="${cache_dir}" go test ./...
)

"${root}/artifacts/tools/wasm-tools" validate --features component-model \
  "${root}/artifacts/goforge-poc.component.wasm"
