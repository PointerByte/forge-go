# GoForge portable core

This nested Go module is the dependency-free source of truth for deterministic
GoForge rules that can cross the native Go, WebAssembly component, and Deno
boundaries. It implements contract package `pointerbyte:goforge@0.1.0` and the
strict JSON bridge `goforge.abi.v1`.

## Contract

ABI v1 exposes eight operations:

| Capability | Operations |
| --- | --- |
| Normalization | `text.normalize` |
| Validation | `text.validate` |
| SHA-256 | `crypto.sha256` |
| HMAC-SHA256 | `crypto.hmac-sha256` |
| AES-GCM | `crypto.aes-gcm.encrypt`, `crypto.aes-gcm.decrypt` |
| Base64 | `encoding.base64.encode`, `encoding.base64.decode` |

The manifest also advertises the host-observed `control.deadline` and
`control.cancellation` capabilities. A request that supplies either control
fails closed unless the host passes matching checked state to the dispatcher.
The package never reads a clock itself.

```json
{
  "abi": "goforge.abi.v1",
  "id": "request-1",
  "operation": "crypto.sha256",
  "metadata": {
    "required_capabilities": ["crypto.sha256"]
  },
  "payload": {"data": "YWJj"}
}
```

Successful responses contain `result`; failed responses contain a typed
`error` from the manifest catalog. They never contain both.

The operation payload and result fields are stable:

| Operation | Required payload | Successful result |
| --- | --- | --- |
| `text.normalize` | `value`; optional `trim`, `collapse_whitespace`, `lowercase_ascii` booleans | `value` |
| `text.validate` | `value`, `rules` | `valid`, ordered `violations` |
| `crypto.sha256` | Base64 `data` | Base64 `digest` |
| `crypto.hmac-sha256` | Base64 `key`, Base64 `data` | Base64 `mac` |
| `crypto.aes-gcm.encrypt` | Base64 `key`, `nonce`, `aad`, `plaintext` | Base64 `ciphertext` with the authentication tag appended |
| `crypto.aes-gcm.decrypt` | Base64 `key`, `nonce`, `aad`, `ciphertext` | Base64 `plaintext` |
| `encoding.base64.encode` | UTF-8 `text` | `encoded` |
| `encoding.base64.decode` | canonical `encoded` | UTF-8 `text` |

Every listed field is required, including an explicitly empty `aad`. Validation
rules are `required`, `min_bytes`, `max_bytes`, `min_runes`, `max_runes`,
`ascii`, `forbid_control`, `forbid_whitespace`, `prefix`, and `suffix`.
Violations follow that rule order so all runtimes produce the same result.

## Serialization and bounds

- JSON must be UTF-8 and contain one object only.
- Unknown fields, duplicate object names, malformed JSON, and excessive nesting
  are rejected.
- Binary fields use RFC 4648's standard alphabet with required padding. URL-safe,
  unpadded, whitespace-containing, and otherwise non-canonical values fail.
- Request, response, binary, string, ID, control-token, capability-count, and
  JSON-depth limits are published by the manifest and enforced before use.
- The Base64 operations intentionally convert UTF-8 text. Arbitrary binary
  values in every other ABI operation remain canonical padded Base64 fields.

## Cryptographic safety

AES-GCM accepts only 128-, 192-, or 256-bit caller-supplied keys and exactly
12-byte caller-supplied nonces. It never generates randomness and never falls
back to another algorithm. Callers must guarantee that a nonce is unique for
every encryption under a given key. Authentication failure returns only the
stable `authentication_failed` error and no plaintext. HMAC keys must contain
at least 16 bytes.

The implementation imports only the Go standard library. Production files do
not access the filesystem, network, environment, logging, cloud SDKs, clocks,
or random sources.

## Verification

Run this nested module outside the parent workspace until integration adds it
to `go.work`:

```sh
GOWORK=off GOTOOLCHAIN=go1.25.0 go test ./...
GOWORK=off GOTOOLCHAIN=go1.25.0 go test -coverprofile=coverage.out ./...
GOWORK=off GOTOOLCHAIN=go1.25.0 go vet ./...
GOWORK=off GOTOOLCHAIN=go1.25.12 go test ./...
GOWORK=off GOTOOLCHAIN=go1.25.12 go test -run '^$' -bench . -benchmem ./...
```

`testdata/vectors/v1.json` is the language-neutral deterministic vector set.
It covers every operation, including the NIST AES-128-GCM and RFC 4231
HMAC-SHA256 cases. Negative and fuzz tests cover strict decoding, bounds,
execution controls, and cryptographic failure behavior.

## Component artifact boundary

This module deliberately does not copy a WIT world, generated bindings, or a
component build script from a research directory. Promoting the already
validated `pointerbyte:goforge@0.1.0` world into a production artifact requires
the cross-repository integration gate, generated-binding drift checks, and Deno
parity validation. Keeping that promotion outside this module prevents a
research path from becoming an undeclared production dependency.

That promotion now exists as the sibling `component/` module, which owns the WIT
world, the checked-in generated bindings and the build pipeline. This module
stays free of them so the portable core has no component-toolchain dependency.

```bash
cd component
WASM_TOOLS=/path/to/wasm-tools ./scripts/check-generated.sh   # bindings reproduce byte for byte
WASM_TOOLS=/path/to/wasm-tools ./scripts/check.sh             # tests, race, vet, staticcheck
WASM_TOOLS=/path/to/wasm-tools ./scripts/build.sh             # build, validate, transpile, package
```

`build.sh` produces a deterministic release bundle under `component/artifacts/`
(gitignored): the validated component, its extracted WIT, the jco host glue and
core modules, the canonical ABI manifest, the shared vectors, toolchain and
contract evidence, and `SHA256SUMS`. Two consecutive rebuilds are byte-identical.

**The resulting component is not yet fit to promote.** Its Go runtime
intermittently traps during garbage collection under sustained dispatch load.
Correctness is proven against the shared vectors; endurance is not. See the
blocker in the migration log at `../../temp.md`.
