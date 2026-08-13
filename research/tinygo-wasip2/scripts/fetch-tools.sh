#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tools_dir="${root}/artifacts/tools"
work_dir=$(mktemp -d)
trap 'rm -rf "${work_dir}"' EXIT

mkdir -p "${tools_dir}"

wasm_tools_archive="${work_dir}/wasm-tools.tar.gz"
curl -fsSL \
  https://github.com/bytecodealliance/wasm-tools/releases/download/v1.255.0/wasm-tools-1.255.0-x86_64-linux.tar.gz \
  -o "${wasm_tools_archive}"
echo "a62237f4731c45f665f1115cad39acaeec02963cbc848c9473ab033eed837072  ${wasm_tools_archive}" | sha256sum -c -
mkdir -p "${work_dir}/wasm-tools"
tar -xzf "${wasm_tools_archive}" -C "${work_dir}/wasm-tools" --strip-components=1
install -m 0755 "${work_dir}/wasm-tools/wasm-tools" "${tools_dir}/wasm-tools"

wkg_binary="${work_dir}/wkg"
curl -fsSL \
  https://github.com/bytecodealliance/wasm-pkg-tools/releases/download/v0.16.0/wkg-x86_64-unknown-linux-gnu \
  -o "${wkg_binary}"
echo "8ab0f7138e1a84616cb0c87c2bd7b7d00a356b63d458be92bad3fbd463aa3e2a  ${wkg_binary}" | sha256sum -c -
install -m 0755 "${wkg_binary}" "${tools_dir}/wkg"

"${tools_dir}/wasm-tools" --version
"${tools_dir}/wkg" --version

