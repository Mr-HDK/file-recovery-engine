# Phase 9 Validation Log

## Metadata

- Phase: `9`
- Owner: `Engineering`
- Status: `IN_PROGRESS`

## Validation checklist (current slice)

- [x] `fr-ext` parser/scanner tests passing.
- [x] FFI ext probe/listing tests passing.
- [x] .NET deterministic status tests added and passing.
- [x] UI probe path includes ext between ReFS and FAT.

## Evidence

- `cargo test -p fr-ext` passed (`9` tests, includes inode-type gating, deletion-time sanity, 64-bit size parsing, and multi-group inode-table coverage).
- `cargo test -p fr-ffi` passed (`30` tests, includes ext direct/single/double-indirect recovery success paths and partial fallback when single-indirect metadata is missing).
- `dotnet test ui/windows-app/tests/FileRecovery.WindowsApp.Tests/FileRecovery.WindowsApp.Tests.csproj -c Debug` passed (`36` tests).
- `dotnet build tools/benchmarks/ExtCorpusBench/ExtCorpusBench.csproj -c Release` passed.
- UI recovery flow now executes ext direct/single/double-indirect recovery for supported regular-file candidates and returns status `91` for unsupported candidates.
- ext benchmark corpus scaffolding is in place (`testdata/raw-images/ext-corpus` + benchmark script/tooling).
- ext host/image validation scaffolding is now available via `scripts/run-host-ext-image-validation.ps1` and integrated in profile orchestration/comparison scripts.

## Open items for Phase 9 completion

- Improve ext candidate quality using block-group/inode metadata traversal.
- Expand ext recovery beyond double-indirect (triple-indirect/extents) and non-regular inode semantics.
- Expand ext fixed corpus coverage with additional real-world image fixtures.
