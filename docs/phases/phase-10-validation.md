# Phase 10 Validation Log

## Metadata

- Phase: `10`
- Owner: `Engineering`
- Status: `DONE`

## Validation checklist (current slice)

- [x] `fr-apfs` parser/scanner tests passing.
- [x] `fr-hfs` parser/scanner tests passing.
- [x] FFI APFS/HFS+ probe/listing tests passing.
- [x] .NET deterministic status tests added and passing.
- [x] UI probe fallback includes APFS/HFS+ between ext and FAT.

## Evidence

- `cargo test -p fr-apfs` passed (`5` tests).
- `cargo test -p fr-hfs` passed (`5` tests).
- `cargo test -p fr-ffi` passed (`41` tests, includes APFS/HFS+ FFI probe and candidate extraction coverage).
- `dotnet test ui/windows-app/tests/FileRecovery.WindowsApp.Tests/FileRecovery.WindowsApp.Tests.csproj -c Debug` passed (`43` tests).
- UI session flow now attempts APFS container probe/candidate extraction and HFS+ volume probe/candidate extraction before falling back to FAT/exFAT.

## Deferred follow-up (non-blocking)

- Implement APFS/HFS+ recover-to-file data paths beyond metadata candidate surfacing.
