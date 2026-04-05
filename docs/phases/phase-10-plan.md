# Phase 10 Plan: APFS/HFS+ Foundation

## Phase status

- Phase: `10`
- Status: `DONE`
- Owner: `Engineering`
- Start date: `2026-04-05`
- Completion date: `2026-04-05`

## Scope

- Add initial read-only APFS parser crate (`fr-apfs`) with container superblock parsing.
- Add initial read-only HFS+ parser crate (`fr-hfs`) with volume-header parsing.
- Add APFS/HFS+ deleted metadata candidate scanning seams.
- Add FFI ABI for APFS/HFS+ probe and candidate listing.
- Add .NET interop methods for APFS/HFS+ probe/listing.
- Route UI probe fallback flow to APFS and HFS+ between ext and FAT.

## Implemented slice

1. Engine foundation:
- `fr-apfs` container parser boundary (`NXSB`) with metadata-field validation.
- `fr-hfs` volume-header parser boundary (`H+`/`HX`) with metadata-field validation.
- APFS deleted metadata tombstone seam (`APFSDEL`) for image-first candidate extraction.
- HFS+ deleted metadata tombstone seam (`HFSDEL`) for image-first candidate extraction.
- crate-level parser/scanner tests for valid/invalid signatures and candidate extraction behavior.

2. Interop and UI wiring:
- `fr_probe_apfs_container_from_session`.
- `fr_get_apfs_deleted_candidates_from_session`.
- `fr_probe_hfs_volume_header_from_session`.
- `fr_get_hfs_deleted_candidates_from_session`.
- `NativeEngineProbe` APFS/HFS+ structs, wrappers, and status mapping (`100`/`110`).
- UI scan fallback now probes in order: `NTFS -> ReFS -> ext -> APFS -> HFS+ -> FAT`.
- APFS/HFS+ candidate rendering and evidence labeling in quick-scan table.

3. Validation updates:
- Rust unit/integration coverage expanded for APFS/HFS+ crates and FFI paths.
- deterministic .NET status tests expanded for APFS/HFS+ probe and candidate calls.

## Deferred in Phase 10

- APFS/HFS+ file-content recovery/export paths (candidates are metadata-only in this phase).
