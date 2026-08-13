#!/usr/bin/env bash
# PRODUCTION component build — TinyGo 0.41.1, per ADR 0012.
#
# Produces `component/artifacts/`, the bundle DenoForge consumes. The retained
# componentize-go route is `scripts/build-componentize-go.sh`; it is regression
# only and writes elsewhere so the two can never be confused.
#
# Every input is pinned: the TinyGo image by digest, `wasm-tools` and `wkg` by
# SHA-256, the WIT world by a drift check against the canonical contract. The
# build fails closed on any mismatch rather than producing an artifact whose
# recorded provenance would be wrong.
set -Eeuo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

guest_dir="${component_root}/tinygo"
tools_dir="${guest_dir}/tools"
artifact_root="${GOFORGE_ARTIFACT_ROOT:-${component_root}/artifacts}"
component_wasm="${artifact_root}/goforge.component.wasm"
component_wit="${artifact_root}/goforge.component.wit"
host_root="${artifact_root}/host"
wit_package="${guest_dir}/wit/pointerbyte-goforge-0.1.0.wasm"

"${component_root}/scripts/check-world.sh"

# --- pinned tools -----------------------------------------------------------
if [[ ! -x "${tools_dir}/wasm-tools" || ! -x "${tools_dir}/wkg" ]]; then
  "${component_root}/scripts/fetch-tools.sh"
fi
# Re-verify on every build: a tool present from an earlier run is not evidence
# that it is still the tool that was approved.
echo "${wasm_tools_binary_sha256}  ${tools_dir}/wasm-tools" | sha256sum -c - >/dev/null
echo "${wkg_binary_sha256}  ${tools_dir}/wkg" | sha256sum -c - >/dev/null

if [[ ! -d "${guest_dir}/wit/deps" ]]; then
  (cd "${guest_dir}" && "${tools_dir}/wkg" wit fetch)
fi

# --- pinned compiler --------------------------------------------------------
if ! docker image inspect "${tinygo_image}" >/dev/null 2>&1; then
  docker pull "${tinygo_image}" >&2
fi
actual_image=$(docker image inspect "${tinygo_image}" --format '{{.Id}}')
expected_image=${tinygo_image#*@}
if [[ "${actual_image}" != "${expected_image}" ]]; then
  echo "TinyGo image digest mismatch: expected ${expected_image}, got ${actual_image}" >&2
  exit 1
fi

# --- bindings ---------------------------------------------------------------
mkdir -p "${guest_dir}/generated"
find "${guest_dir}/generated" -mindepth 1 -delete
(
  cd "${guest_dir}"
  "${tools_dir}/wkg" build --wit-dir wit --output "${wit_package}" >&2
  PATH="${tools_dir}:${PATH}" GOWORK=off GOTOOLCHAIN="${go_version}" \
    go run "go.bytecodealliance.org/cmd/wit-bindgen-go@${wit_bindgen_go_version}" generate \
      --world goforge \
      --out generated \
      --package-root github.com/PointerByte/forge-go/component/tinygo/generated \
      "${wit_package}" >&2
)

# --- compile ----------------------------------------------------------------
rm -rf "${artifact_root}"
mkdir -p "${host_root}"

input_archive=$(mktemp)
output_archive=$(mktemp)
trap 'rm -f "${input_archive}" "${output_archive}"' EXIT

# The repository-relative layout is preserved inside the container so the go.mod
# `replace` directives resolve identically in both places.
tar --exclude='./component/artifacts' \
    --exclude='./component/artifacts-componentize-go' \
    -cf "${input_archive}" -C "${component_root}/.." ./portable ./component

docker run --rm -i \
  -e HOME=/tmp/build-home \
  -e GOWORK=off \
  -e GOCACHE=/tmp/build-go-cache \
  "${tinygo_image}" \
  sh -c '
    set -eu
    mkdir -p /tmp/src /tmp/build-home /tmp/build-go-cache
    tar -xf - -C /tmp/src
    cd /tmp/src/component/tinygo
    # stdout is the tar stream back to the host; everything else goes to stderr.
    tinygo version >&2
    PATH=/tmp/src/component/tinygo/tools:$PATH tinygo build \
      -target=wasip2 \
      -o /tmp/goforge.component.wasm \
      --wit-package wit/pointerbyte-goforge-0.1.0.wasm \
      --wit-world goforge \
      . >&2
    tar -cf - -C /tmp goforge.component.wasm
  ' < "${input_archive}" > "${output_archive}"

test "$(tar -tf "${output_archive}")" = "goforge.component.wasm"
tar -xf "${output_archive}" -C "${artifact_root}"

# --- validate and transpile -------------------------------------------------
"${tools_dir}/wasm-tools" validate --features component-model "${component_wasm}"
"${tools_dir}/wasm-tools" component wit "${component_wasm}" > "${component_wit}"

grep -q "pointerbyte:goforge/operations@0.1.0" "${component_wit}" || {
  echo "the built component does not export the canonical interface" >&2
  exit 1
}
grep -q "wasi:cli/environment@${tinygo_wasi_version}" "${component_wit}" || {
  echo "the built component does not resolve WASI ${tinygo_wasi_version}" >&2
  exit 1
}

# Async instantiation keeps every WASI import explicit and host-supplied, so no
# npm preview2 shim enters DenoForge and no capability is granted implicitly.
run_jco transpile \
  "${component_wasm}" \
  --name goforge \
  --out-dir "${host_root}" \
  --instantiation async \
  --no-nodejs-compat \
  --strict >&2

# --- release metadata -------------------------------------------------------
(
  cd "${component_root}"
  GOWORK=off GOTOOLCHAIN="${go_version}" go run ./cmd/release-manifest \
    -artifacts "${artifact_root}" \
    -portable "${component_root}/../portable" \
    -compiler tinygo
)

sha256sum "${component_wasm}"
wc -c "${component_wasm}"
