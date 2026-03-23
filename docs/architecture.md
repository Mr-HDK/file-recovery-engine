# Architecture Summary

## Product goals

- Windows-first local desktop recovery tool.
- Safety-first operation: source media read-only, destination must be separate.
- NTFS metadata-first recovery as the core quality path.
- Transparent evidence and confidence model.

## Monorepo structure

- `engine/` Rust workspace for recovery core and FFI.
- `ui/windows-app/` .NET 8 WPF app and UI tests.
- `docs/` architecture, threat, safety, licensing, test strategy.
- `testdata/` sample fixtures and generation scripts.
- `tools/` dependency/license inventory and supporting utilities.
- `scripts/` local bootstrap, test, and fixture generation.

## Engine modules

- `fr-winio`: read-only Windows disk and volume I/O boundary.
- `fr-device-enum`: source discovery abstraction.
- `fr-volume-meta`: partition and volume metadata model.
- `fr-ntfs`: NTFS parsing boundary.
- `fr-fat`: FAT/exFAT parser scaffolding.
- `fr-mft`: MFT record processing.
- `fr-path-recon`: path and directory reconstruction.
- `fr-usn`: USN journal parsing and merge helpers.
- `fr-logfile`: future integration point for `$LogFile` correlation.
- `fr-vss`: shadow-copy discovery and access contracts.
- `fr-carving`: signature-based carving contracts.
- `fr-validator`: recovered-file validation contracts.
- `fr-scoring`: confidence scoring model.
- `fr-session`: resumable scan/session state.
- `fr-ffi`: stable C ABI for UI interop.
- `fr-types`: shared types/evidence model.

## UI architecture

- WPF shell with explicit recovery workflow states:
  1. source selection,
  2. destination validation,
  3. scan mode selection,
  4. session initialization.
- Safety gate runs before session start and blocks same-volume recovery.
- Source discovery surfaces physical disks, logical volumes, and partition entries with filesystem, labels, sector sizes, and mount paths.
- Session state persisted in SQLite (created under `%LocalAppData%\\FileRecovery`).
- Structured session logs written as JSONL plus readable text logs.

## Interop boundary

- Rust exports C ABI symbols from `fr-ffi` as `cdylib`.
- .NET uses a thin P/Invoke probe (`file_recovery_engine.dll`) and degrades safely if the engine is unavailable.
- Contract versioning starts at `0.1.0` and will be semver-gated.
- Read-only source sessions expose open/read/close operations with alignment metadata so UI orchestration can keep chunk reads bounded and cancellation-friendly.
- Engine now includes NTFS boot sector parsing and MFT record parsing (including resident/non-resident attribute decoding and mapping-pairs data-run parsing) as standalone parser primitives for Phase 2 integration.

## Observability

- JSONL event log per session for machine parsing.
- Text log per session for operator readability.
- UI status surface contains warnings and validation reasons.

## Non-goals for this batch

- Full NTFS undelete pipeline implementation.
- VSS browse and restore UI.
- Full carving engine.

These are tracked in `docs/todo-risk-register.md` with concrete follow-up tasks.
