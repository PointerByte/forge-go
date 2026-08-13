#!/usr/bin/env bash
set -Eeuo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
require_toolchain

stage=$(mktemp -d "${TMPDIR:-/tmp}/goforge-component-bindings-check.XXXXXX")
trap 'find "${stage}" -mindepth 1 -delete; rmdir "${stage}"' EXIT

run_componentize \
  --wit-path "${component_root}/wit" \
  --world goforge \
  bindings \
  --output "${stage}" \
  --format
tag_wasip1_main "${stage}/wit_exports.go" "${stage}/wit_exports.tagged.go"

cmp "${stage}/wit_exports.tagged.go" "${guest_root}/wit_exports.go"
cmp "${stage}/pointerbyte_goforge_operations/wit_bindings.go" \
  "${guest_root}/pointerbyte_goforge_operations/wit_bindings.go"
cmp "${stage}/pointerbyte_goforge_operations/empty.s" \
  "${guest_root}/pointerbyte_goforge_operations/empty.s"

(
  cd "${guest_root}"
  GOWORK=off GOTOOLCHAIN="${go_version}" go mod tidy -diff -go=1.25.0
)
