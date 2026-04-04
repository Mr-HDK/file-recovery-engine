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

- `cargo test -p fr-ext` passed (`6` tests, includes multi-group inode-table candidate coverage).
- `cargo test -p fr-ffi` passed (`25` tests, includes ext probe/listing tests).
- `dotnet test ui/windows-app/tests/FileRecovery.WindowsApp.Tests/FileRecovery.WindowsApp.Tests.csproj -c Debug` passed (`35` tests).
- `dotnet build tools/benchmarks/ExtCorpusBench/ExtCorpusBench.csproj -c Release` passed.
- UI recovery flow now gates ext candidates with explicit status `91` ("not implemented") instead of falling through NTFS/FAT recovery paths.
- ext benchmark corpus scaffolding is in place (`testdata/raw-images/ext-corpus` + benchmark script/tooling).

## Open items for Phase 9 completion

- Improve ext candidate quality using block-group/inode metadata traversal.
- Add full ext recovery/export implementation.
- Add fixture corpus and host/image validation profiles for ext images.
