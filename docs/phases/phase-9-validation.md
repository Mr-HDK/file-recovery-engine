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

- `cargo test -p fr-ext` passed (`5` tests, includes deleted inode-table candidate coverage).
- `cargo test -p fr-ffi` passed (`25` tests, includes ext probe/listing tests).
- `dotnet test ui/windows-app/tests/FileRecovery.WindowsApp.Tests/FileRecovery.WindowsApp.Tests.csproj -c Debug` passed (`35` tests).

## Open items for Phase 9 completion

- Improve ext candidate quality using block-group/inode metadata traversal.
- Add ext recovery/export implementation or explicit supported gating.
- Add fixture corpus and host/image validation profiles for ext images.
