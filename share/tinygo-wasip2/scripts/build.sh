#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
input_archive=$(mktemp)
output_archive=$(mktemp)
trap 'rm -f "${input_archive}" "${output_archive}"' EXIT

"${root}/scripts/generate.sh"

tar \
  --exclude='./artifacts/cache' \
  --exclude='./artifacts/goforge-poc.component.wasm' \
  -cf "${input_archive}" \
  -C "${root}" \
  .

docker run --rm -i \
  -e HOME=/tmp/poc-home \
  -e GOWORK=off \
  -e GOCACHE=/tmp/poc-go-cache \
  tinygo/tinygo:0.41.1 \
  sh -c '
    set -eu
    mkdir -p /tmp/src /tmp/poc-home /tmp/poc-go-cache
    tar -xf - -C /tmp/src
    cd /tmp/src
    PATH=/tmp/src/artifacts/tools:$PATH tinygo build \
      -target=wasip2 \
      -o artifacts/goforge-poc.component.wasm \
      --wit-package wit/pointerbyte-goforge-poc-0.1.0.wasm \
      --wit-world goforge-poc \
      .
    tar -cf - artifacts/goforge-poc.component.wasm
  ' < "${input_archive}" > "${output_archive}"

test "$(tar -tf "${output_archive}")" = "artifacts/goforge-poc.component.wasm"
tar -xf "${output_archive}" -C "${root}"

"${root}/artifacts/tools/wasm-tools" validate --features component-model \
  "${root}/artifacts/goforge-poc.component.wasm"
"${root}/artifacts/tools/wasm-tools" component wit \
  "${root}/artifacts/goforge-poc.component.wasm" \
  > "${root}/artifacts/goforge-poc.component.wit"
sha256sum "${root}/artifacts/goforge-poc.component.wasm"
wc -c "${root}/artifacts/goforge-poc.component.wasm"

