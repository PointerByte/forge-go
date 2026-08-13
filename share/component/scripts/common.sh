#!/usr/bin/env bash
set -Eeuo pipefail

component_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
guest_root="${component_root}/guest"
cache_root="${GOFORGE_COMPONENT_CACHE:-${TMPDIR:-/tmp}/goforge-production-component-cache}"
export GOCACHE="${GOCACHE:-${cache_root}/go-build}"
export XDG_CACHE_HOME="${COMPONENTIZE_XDG_CACHE_HOME:-${XDG_CACHE_HOME:-${cache_root}/xdg}}"
export DENO_DIR="${DENO_DIR:-${cache_root}/deno}"
mkdir -p "${GOCACHE}" "${XDG_CACHE_HOME}" "${DENO_DIR}"

go_version=go1.25.12
componentize_version=0.4.0
wit_bindgen_version=0.58.0
wit_runtime_version=0.2.2
wasm_tools_version=1.255.0
jco_version=1.26.1
deno_version=2.9.4

# Production component toolchain, accepted by ADR 0012.
#
# The image is pinned by digest, not by tag: a tag can be repointed at different
# bytes, and the whole point of pinning is that the compiler cannot change
# underneath a reproducible build.
tinygo_version=0.41.1
tinygo_image=tinygo/tinygo@sha256:b216f534ddbf277444407b014a3328b5c1ade403cc397f3ab48a14789bf99d0e
tinygo_image_tag=tinygo/tinygo:0.41.1
wit_bindgen_go_version=v0.7.0
wkg_version=0.16.0
tinygo_wasi_version=0.2.0

# Recorded SHA-256 values for every downloaded tool. Both the archive and the
# extracted binary are checked, so a tampered archive cannot smuggle a different
# executable past the first check.
wasm_tools_archive_sha256=a62237f4731c45f665f1115cad39acaeec02963cbc848c9473ab033eed837072
wasm_tools_binary_sha256=6e431ad26863c697cc30733aae69cbd9248f83811d9e63e4eb01061fc2ece013
wkg_binary_sha256=8ab0f7138e1a84616cb0c87c2bd7b7d00a356b63d458be92bad3fbd463aa3e2a

run_go() {
  GOWORK=off GOTOOLCHAIN="${go_version}" go "$@"
}

run_componentize() {
  (
    cd "${guest_root}"
    GOWORK=off GOTOOLCHAIN="${go_version}" go tool componentize-go "$@"
  )
}

run_jco() {
  (
    cd "${component_root}"
    deno run --cached-only --frozen -A "npm:@bytecodealliance/jco@${jco_version}" "$@"
  )
}

require_toolchain() {
  test "$(GOWORK=off GOTOOLCHAIN="${go_version}" go env GOVERSION)" = "${go_version}"
  test "$(run_componentize --version)" = "componentize-go ${componentize_version}"
  test "$(deno --version | head -n 1)" = "deno ${deno_version} (stable, release, x86_64-unknown-linux-gnu)"
  test "$(run_jco --version)" = "${jco_version}"

  wasm_tools_bin=$(resolve_wasm_tools)
  test "$("${wasm_tools_bin}" --version | awk '{print $2}')" = "${wasm_tools_version}"
}

# resolve_wasm_tools prefers the checksum-verified copy the production build
# fetches, so a different `wasm-tools` on PATH cannot quietly take its place.
resolve_wasm_tools() {
  if [[ -n "${WASM_TOOLS:-}" ]]; then
    echo "${WASM_TOOLS}"
  elif [[ -x "${component_root}/tinygo/tools/wasm-tools" ]]; then
    echo "${component_root}/tinygo/tools/wasm-tools"
  else
    echo wasm-tools
  fi
}

tag_wasip1_main() {
  input=$1
  output=$2
  sed '1i//go:build wasip1\
' "${input}" > "${output}"
}
