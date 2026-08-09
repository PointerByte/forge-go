#!/usr/bin/env bash
# Encodes the WIT package and regenerates the wit-bindgen-go bindings.
#
# The WASI 0.2.0 dependency tree and the pinned `wkg`/`wasm-tools` binaries are reused
# from `research/tinygo-wasip2`, which already fetched them under checksum verification.
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tools_dir="${root}/artifacts/tools"
cache_dir="${TMPDIR:-/tmp}/goforge-component-tinygo-cache"

"${root}/scripts/check-world.sh"

if [[ ! -x "${tools_dir}/wasm-tools" || ! -x "${tools_dir}/wkg" ]]; then
  # Both tool trees are gitignored, so a fresh clone has neither. Fetch them under the checksum
  # verification the sibling PoC already established, then reuse the exact same binaries.
  sibling="${root}/../tinygo-wasip2"
  "${sibling}/scripts/fetch-tools.sh"
  mkdir -p "${tools_dir}"
  install -m 0755 "${sibling}/artifacts/tools/wasm-tools" "${tools_dir}/wasm-tools"
  install -m 0755 "${sibling}/artifacts/tools/wkg" "${tools_dir}/wkg"
fi

if [[ ! -d "${root}/wit/deps" ]]; then
  # The reviewed WASI 0.2.0 dependency tree lives with the sibling PoC for the same reason.
  cp -r "${root}/../tinygo-wasip2/wit/deps" "${root}/wit/deps"
fi

mkdir -p "${cache_dir}/go-build" "${cache_dir}/wkg" "${root}/generated"
find "${root}/generated" -mindepth 1 -delete

(
  cd "${root}"
  "${tools_dir}/wkg" build \
    --cache "${cache_dir}/wkg" \
    --wit-dir wit \
    --output wit/pointerbyte-goforge-0.1.0.wasm
  PATH="${tools_dir}:${PATH}" \
    GOWORK=off \
    GOTOOLCHAIN=go1.25.12 \
    GOCACHE="${cache_dir}/go-build" \
    go run go.bytecodealliance.org/cmd/wit-bindgen-go@v0.7.0 generate \
      --world goforge \
      --out generated \
      --package-root github.com/PointerByte/forge-go/research/component-tinygo/generated \
      wit/pointerbyte-goforge-0.1.0.wasm
)
