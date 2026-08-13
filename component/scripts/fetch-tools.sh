#!/usr/bin/env bash
# Fetches the pinned build tools into component/tinygo/tools, verifying every
# download against a recorded SHA-256 before it is made executable.
#
# ADR 0012 makes checksum verification a constraint of accepting TinyGo: an
# unverified `wasm-tools` or `wkg` could silently alter the artifact whose digest
# the release manifest then attests.
set -Eeuo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

tools_dir="${component_root}/tinygo/tools"
work_dir=$(mktemp -d)
trap 'rm -rf "${work_dir}"' EXIT

mkdir -p "${tools_dir}"

archive="${work_dir}/wasm-tools.tar.gz"
curl -fsSL \
  "https://github.com/bytecodealliance/wasm-tools/releases/download/v${wasm_tools_version}/wasm-tools-${wasm_tools_version}-x86_64-linux.tar.gz" \
  -o "${archive}"
echo "${wasm_tools_archive_sha256}  ${archive}" | sha256sum -c -
mkdir -p "${work_dir}/wasm-tools"
tar -xzf "${archive}" -C "${work_dir}/wasm-tools" --strip-components=1
echo "${wasm_tools_binary_sha256}  ${work_dir}/wasm-tools/wasm-tools" | sha256sum -c -
install -m 0755 "${work_dir}/wasm-tools/wasm-tools" "${tools_dir}/wasm-tools"

wkg_binary="${work_dir}/wkg"
curl -fsSL \
  "https://github.com/bytecodealliance/wasm-pkg-tools/releases/download/v${wkg_version}/wkg-x86_64-unknown-linux-gnu" \
  -o "${wkg_binary}"
echo "${wkg_binary_sha256}  ${wkg_binary}" | sha256sum -c -
install -m 0755 "${wkg_binary}" "${tools_dir}/wkg"

test "$("${tools_dir}/wasm-tools" --version | awk '{print $2}')" = "${wasm_tools_version}"
test "$("${tools_dir}/wkg" --version | awk '{print $2}')" = "${wkg_version}"
echo "fetch-tools: wasm-tools ${wasm_tools_version} and wkg ${wkg_version} verified."
