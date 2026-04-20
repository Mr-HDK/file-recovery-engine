# Phase 17 Validation Log

## Metadata

- Phase: `17`
- Owner: `Engineering`
- Status: `DONE`

## Validation checklist

- [x] Phase tracker status moved to `DONE`.
- [x] Windowed carve FFI endpoint added with backward-compatible legacy wrapper.
- [x] UI full-scan carve flow switched from fixed-cap single pass to streaming windows.
- [x] Hard `256 MiB` carve normalization cap removed.
- [x] Rust tests added for window-offset carve behavior and cap normalization behavior.
- [x] Signature-pack versioning surfaced in UI diagnostics.
- [x] Expanded signature coverage batch landed.
- [x] False-positive regression harness fixtures expanded.

## Evidence

- `cargo test -p fr-validator` passed (`16` tests), including a signature regression matrix for false-positive and partial/truncation edges.
- `cargo test -p fr-carving` passed (`8` tests).
- `cargo test -p fr-ffi` passed (`53` tests).
- `dotnet test ui/windows-app/tests/FileRecovery.WindowsApp.Tests/FileRecovery.WindowsApp.Tests.csproj -c Debug` passed (`61` tests).
- `dotnet build ui/windows-app/src/FileRecovery.WindowsApp/FileRecovery.WindowsApp.csproj -c Debug` passed.
