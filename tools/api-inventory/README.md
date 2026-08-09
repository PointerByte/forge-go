# GoForge API Inventory

This standard-library-only command generates the Phase 0 declaration catalog used by the
GoForge/DenoForge functional coverage matrix. It scans all six workspace modules while excluding
generated research, OpenSpec, vendor, coverage, and test-data directories.

Run it reproducibly from the GoForge repository root:

```bash
cd tools/api-inventory
SOURCE_DATE_EPOCH=1785628800 GOTOOLCHAIN=go1.25.0 GOWORK=off go run . \
  -root ../.. \
  -json ../../openspec/changes/tinygo-wasip2-goforge-integration/research/evidence/go-api-inventory.json \
  -markdown ../../openspec/changes/tinygo-wasip2-goforge-integration/research/evidence/go-api-inventory.md
```

The inventory is a conservative static audit. A matching identifier in a test is evidence of
exercise, not proof of semantic coverage; host-dependency classification is based on imports and
must be refined by the domain compatibility review. Exported declarations in `package main` are
classified as CLI implementation rather than importable public API. The command is its own nested
module so it cannot alter GoForge's product coverage denominator.

Use the same command with `-check` in CI to fail on public-API drift without changing the committed
catalog.
