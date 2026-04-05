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
- `fr-ext`: ext superblock/deleted-entry parsing boundary (Phase 9 baseline).
- `fr-refs`: ReFS boot metadata parsing boundary (Phase 8 baseline).
- `fr-fat`: FAT/exFAT boot parsing + deleted-candidate full directory-tree traversal.
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
- Partition discovery fallback now includes a SetupAPI-based disk walk plus partition probing to surface unmounted/offline partition candidates when WMI is unavailable.
- Session state persisted in SQLite (created under `%LocalAppData%\\FileRecovery`).
- Session retention maintenance applies a 30-day window plus maximum recent-session cap and supports explicit compaction (`VACUUM`) from the diagnostics actions.
- Structured session logs written as JSONL plus readable text logs.
- Image acquisition service now supports clone-first capture to raw image files with resume-safe checkpoint logs and SHA-256 verification.
- Session and recovery actions now gate live-media operations behind an explicit image-first recommendation confirmation.

## Interop boundary

- Rust exports C ABI symbols from `fr-ffi` as `cdylib`.
- .NET uses a thin P/Invoke probe (`file_recovery_engine.dll`) and degrades safely if the engine is unavailable.
- Contract versioning starts at `0.1.0` and will be semver-gated.
- Read-only source sessions expose open/read/close operations with alignment metadata so UI orchestration can keep chunk reads bounded and cancellation-friendly.
- Engine now includes NTFS boot sector parsing and MFT record parsing (including resident/non-resident attribute decoding and mapping-pairs data-run parsing) as standalone parser primitives for Phase 2 integration.
- Engine now includes a ReFS boot-sector parser boundary (`fr-refs`) with FFI exposure for source classification/probing in Phase 8.
- Engine now includes an ext superblock parser boundary (`fr-ext`) with FFI/UI candidate-listing wiring in Phase 9.
- Engine now includes concrete USN v2/v3 record parsing (`fr-usn`) and evidence-source propagation flags over the FFI quick-scan candidate boundary.
- Recovery export now includes non-resident NTFS compressed-stream decompression and encrypted-stream raw export with explicit diagnostics/partial signaling through the FFI boundary.

## Observability

- JSONL event log per session for machine parsing.
- Text log per session for operator readability.
- UI status surface contains warnings and validation reasons.

## Non-goals for this batch

- Full NTFS undelete pipeline implementation.
- Cross-snapshot deduplication and historical diffing across multiple VSS snapshots.
- Full carving engine.

These are tracked in `docs/todo-risk-register.md` with concrete follow-up tasks.
