# Phase 8 Retrospective

## Status

Completed on `2026-04-04`.

## What shipped

- New `fr-refs` engine crate with ReFS boot parser and deleted-candidate metadata scanning based on USN-style records.
- New FFI ABI for ReFS boot probe and deleted-candidate listing.
- .NET core interop and deterministic tests for ReFS probe/listing boundaries.
- UI source probe flow now checks ReFS between NTFS and FAT paths.
- UI quick-scan now renders ReFS deleted-candidate results.
- Architecture/pipeline/phase docs updated to reflect ReFS baseline support.

## What did not ship and why

- ReFS recovery/export execution path was not included in Phase 8 scope and is deferred.
- Host-level ReFS fixture/integration validation remains deferred to later phases.

## Test outcomes

- `cargo test -p fr-refs` passed (`5` tests).
- `cargo test -p fr-ffi` passed (`23` tests).
- `dotnet test ui/windows-app/tests/FileRecovery.WindowsApp.Tests/FileRecovery.WindowsApp.Tests.csproj -c Debug` passed (`33` tests).

## Safety/regression notes

- Source access remains read-only.
- Existing NTFS and FAT quick-scan/recovery paths remained green in current test coverage.
- ReFS status codes preserve unsupported-path behavior (`80`) while enabling successful candidate listing on valid ReFS images.

## Follow-up actions for Phase 9

- Start `ext4` engine foundation crate and probe/listing ABI.
- Reuse the ReFS integration pattern (engine -> FFI -> .NET -> UI mapping + deterministic tests).
