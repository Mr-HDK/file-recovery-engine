# Phase 8 Validation Log

## Metadata

- Phase: `8`
- Owner: `Codex agent`
- Status: `DONE`

## Validation checklist

- [x] Engine unit tests updated and passing for `fr-refs`.
- [x] FFI boundary for `ReFS` probe tested.
- [x] .NET probe deterministic status test added and passing.
- [x] UI probe flow confirms `ReFS` detection path.
- [x] No regressions in NTFS/FAT probe paths.

## Evidence

- `cargo test -p fr-refs` passed (`5` tests, includes deleted USN-backed candidate extraction coverage).
- `cargo test -p fr-ffi` passed (`23` tests, includes `ffi_probe_refs_boot_from_session_parses_refs_image` and `ffi_get_refs_deleted_candidates_extracts_usn_deleted_candidate`).
- `dotnet test ui/windows-app/tests/FileRecovery.WindowsApp.Tests/FileRecovery.WindowsApp.Tests.csproj -c Debug` passed (`33` tests).
- ReFS probe is now called in UI session startup flow before FAT fallback.
- ReFS deleted-candidate extraction path is called from UI and rendered into quick-scan candidates.

## Deferred follow-up (outside Phase 8 gate)

- ReFS recovery/export path is not yet implemented.
- ReFS candidate persistence/reporting plumbing remains pending.
