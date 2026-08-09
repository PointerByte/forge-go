#!/usr/bin/env bash
# REGRESSION BUILD ONLY — not the production route.
#
# ADR 0012 rejects componentize-go 0.4.0 for production: the component it
# produces intermittently traps during Go garbage collection under sustained
# dispatch load, on both Deno/jco and wasmtime. This script is retained so a
# future componentize-go release can be re-measured against the same harnesses
# without rebuilding the comparison from scratch.
#
# It writes to `artifacts-componentize-go/` so it can never be mistaken for, or
# overwrite, the production bundle in `artifacts/`. Its toolchain evidence is
# recorded with `production: false`.
#
# The production build is `scripts/build.sh`.
set -Eeuo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
"${component_root}/scripts/check-generated.sh"
require_toolchain

artifact_root="${GOFORGE_ARTIFACT_ROOT:-${component_root}/artifacts-componentize-go}"
component_wasm="${artifact_root}/goforge.component.wasm"
component_wit="${artifact_root}/goforge.component.wit"
host_root="${artifact_root}/host"

rm -rf "${artifact_root}"
mkdir -p "${host_root}"

go_root=$(GOWORK=off GOTOOLCHAIN="${go_version}" go env GOROOT)
run_componentize \
  --wit-path "${component_root}/wit" \
  --world goforge \
  build \
  --output "${component_wasm}" \
  --go "${go_root}/bin/go"

"${wasm_tools_bin}" validate --features component-model "${component_wasm}"
"${wasm_tools_bin}" component wit "${component_wasm}" > "${component_wit}"

# Async instantiation keeps every WASI import explicit and host-supplied, so no
# npm preview2 shim is pulled into DenoForge and unauthorized capabilities
# cannot be granted implicitly. This is the shape validated by the WASI 0.2 host
# research PoC.
run_jco transpile \
  "${component_wasm}" \
  --name goforge \
  --out-dir "${host_root}" \
  --instantiation async \
  --no-nodejs-compat \
  --strict

(
  cd "${component_root}"
  GOWORK=off GOTOOLCHAIN="${go_version}" go run ./cmd/release-manifest \
    -artifacts "${artifact_root}" \
    -portable "${component_root}/../portable" \
    -compiler componentize-go
)

sha256sum "${component_wasm}"
wc -c "${component_wasm}"
