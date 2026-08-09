#!/usr/bin/env bash
# Proves the research world exports exactly the production `operations` interface.
#
# The comparison is only meaningful if the TinyGo guest presents the same surface the
# componentize-go component does. The worlds differ by design (TinyGo links WASI 0.2.0
# and therefore needs an explicit `wasi:cli/imports` include), so the interface — not
# the whole file — is what must stay identical.
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
production="${root}/../../component/wit/world.wit"

extract_interface() {
  awk '/^interface operations \{/ { inside = 1 }
       inside            { print }
       /^\}/             { if (inside) exit }' "$1"
}

if ! diff -u \
  <(extract_interface "${production}") \
  <(extract_interface "${root}/wit/world.wit"); then
  echo "the research world has drifted from component/wit/world.wit" >&2
  exit 1
fi

echo "check-world: the exported operations interface matches production exactly."
