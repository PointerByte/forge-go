#!/usr/bin/env bash
# Transpiles the TinyGo component with the same jco invocation the production build uses,
# so the Deno half of the soak differs from production only by the guest compiler.
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
jco_version=1.26.1
host_root="${root}/artifacts/host"

test -f "${root}/artifacts/goforge.component.wasm" || {
  echo "build the component first: scripts/build.sh" >&2
  exit 1
}

rm -rf "${host_root}"
mkdir -p "${host_root}"

(
  cd "${root}"
  deno run -A "npm:@bytecodealliance/jco@${jco_version}" transpile \
    artifacts/goforge.component.wasm \
    --name goforge \
    --out-dir "${host_root}" \
    --instantiation async \
    --no-nodejs-compat \
    --strict
)

ls -la "${host_root}"
