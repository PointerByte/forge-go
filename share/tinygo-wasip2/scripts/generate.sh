#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tools_dir="${root}/artifacts/tools"
cache_dir="${TMPDIR:-/tmp}/goforge-tinygo-wasip2-cache"

if [[ ! -x "${tools_dir}/wasm-tools" || ! -x "${tools_dir}/wkg" ]]; then
  "${root}/scripts/fetch-tools.sh"
fi

mkdir -p "${cache_dir}/go-build" "${cache_dir}/wkg" "${root}/generated"
find "${root}/generated" -mindepth 1 -delete

(
  cd "${root}"
  "${tools_dir}/wkg" fetch --type wit --cache "${cache_dir}/wkg" wit
  "${tools_dir}/wkg" build \
    --cache "${cache_dir}/wkg" \
    --wit-dir wit \
    --output wit/pointerbyte-goforge-poc-0.1.0.wasm
  PATH="${tools_dir}:${PATH}" \
    GOWORK=off \
    GOTOOLCHAIN=go1.25.12 \
    GOCACHE="${cache_dir}/go-build" \
    go run go.bytecodealliance.org/cmd/wit-bindgen-go@v0.7.0 generate \
      --world goforge-poc \
      --out generated \
      --package-root github.com/PointerByte/forge-go/share/tinygo-wasip2/generated \
      wit/pointerbyte-goforge-poc-0.1.0.wasm
)
