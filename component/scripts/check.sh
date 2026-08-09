#!/usr/bin/env bash
set -Eeuo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
"${component_root}/scripts/check-world.sh"
"${component_root}/scripts/check-generated.sh"

(
  cd "${component_root}"
  GOWORK=off GOTOOLCHAIN="${go_version}" go test ./...
  GOWORK=off GOTOOLCHAIN="${go_version}" go test -race ./...
  GOWORK=off GOTOOLCHAIN="${go_version}" go vet ./...
)

(
  cd "${guest_root}"
  GOWORK=off GOTOOLCHAIN="${go_version}" go test ./...
  GOWORK=off GOTOOLCHAIN="${go_version}" go test -race ./...
  GOWORK=off GOTOOLCHAIN="${go_version}" go vet -unsafeptr=false -composites=false ./...
)

# The production TinyGo guest only builds under the `tinygo` tag and against
# generated bindings, so it gets a vet pass rather than a test run. Its
# behaviour is covered end to end by DenoForge's parity suite against the built
# component, which is the only place the compiled guest can actually be observed.
(
  cd "${component_root}/tinygo"
  if [[ -d generated ]]; then
    GOWORK=off GOTOOLCHAIN="${go_version}" go vet -tags tinygo ./...
  else
    echo "check: skipping the TinyGo guest; run scripts/build.sh to generate its bindings" >&2
  fi
)

if command -v staticcheck >/dev/null 2>&1; then
  (
    cd "${component_root}"
    GOWORK=off GOTOOLCHAIN="${go_version}" staticcheck ./...
  )
  (
    cd "${guest_root}"
    GOWORK=off GOTOOLCHAIN="${go_version}" staticcheck ./...
  )
fi
