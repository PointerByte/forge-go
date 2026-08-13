#!/usr/bin/env bash
# Proves the TinyGo build world exports exactly the canonical `operations` interface.
#
# `component/wit/world.wit` is the contract. `component/tinygo/wit/world.wit` is the
# world actually compiled, and it differs by design: TinyGo's wasip2 target needs an
# explicit `wasi:cli/imports@0.2.0` include. Only the exported interface must match,
# and it must match exactly — that is what DenoForge calls and what the shared
# vectors pin.
set -Eeuo pipefail

component_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

extract_interface() {
  awk '/^interface operations \{/ { inside = 1 }
       inside            { print }
       /^\}/             { if (inside) exit }' "$1"
}

if ! diff -u \
  <(extract_interface "${component_root}/wit/world.wit") \
  <(extract_interface "${component_root}/tinygo/wit/world.wit"); then
  echo "the TinyGo build world has drifted from component/wit/world.wit" >&2
  exit 1
fi

echo "check-world: the TinyGo build world exports the canonical operations interface."
