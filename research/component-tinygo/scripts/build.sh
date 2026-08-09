#!/usr/bin/env bash
# Builds the production GoForge world with TinyGo 0.41.1 inside its official image.
#
# The tar keeps the repository-relative layout so the `replace` directives in go.mod
# resolve identically inside and outside the container.
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
repo=$(cd "${root}/../.." && pwd)
input_archive=$(mktemp)
output_archive=$(mktemp)
trap 'rm -f "${input_archive}" "${output_archive}"' EXIT

"${root}/scripts/generate.sh"

tar \
  --exclude='./component/artifacts' \
  --exclude='./research/component-tinygo/artifacts/goforge.component.wasm' \
  -cf "${input_archive}" \
  -C "${repo}" \
  ./portable ./component ./research/component-tinygo

docker run --rm -i \
  -e HOME=/tmp/poc-home \
  -e GOWORK=off \
  -e GOCACHE=/tmp/poc-go-cache \
  tinygo/tinygo:0.41.1 \
  sh -c '
    set -eu
    mkdir -p /tmp/src /tmp/poc-home /tmp/poc-go-cache
    tar -xf - -C /tmp/src
    cd /tmp/src/research/component-tinygo
    # stdout is the tar stream back to the host; everything else must go to stderr.
    tinygo version >&2
    PATH=/tmp/src/research/component-tinygo/artifacts/tools:$PATH tinygo build \
      -target=wasip2 \
      -o artifacts/goforge.component.wasm \
      --wit-package wit/pointerbyte-goforge-0.1.0.wasm \
      --wit-world goforge \
      . >&2
    tar -cf - -C /tmp/src/research/component-tinygo artifacts/goforge.component.wasm
  ' < "${input_archive}" > "${output_archive}"

test "$(tar -tf "${output_archive}")" = "artifacts/goforge.component.wasm"
tar -xf "${output_archive}" -C "${root}"

"${root}/artifacts/tools/wasm-tools" validate --features component-model \
  "${root}/artifacts/goforge.component.wasm"
"${root}/artifacts/tools/wasm-tools" component wit \
  "${root}/artifacts/goforge.component.wasm" \
  > "${root}/artifacts/goforge.component.wit"
sha256sum "${root}/artifacts/goforge.component.wasm"
wc -c "${root}/artifacts/goforge.component.wasm"
