# Phase 11 Plan: ext2/ext3, XFS, UFS Compatibility

## Phase status

- Phase: `11`
- Status: `DONE`
- Owner: `Engineering`
- Start date: `2026-04-08`
- Completion date: `2026-04-08`

## Scope

- Extend ext parser classification to distinguish `ext2`, `ext3`, and `ext4`.
- Add initial read-only XFS parser crate (`fr-xfs`) with superblock parsing.
- Add initial read-only UFS parser crate (`fr-ufs`) with superblock parsing.
- Add XFS/UFS deleted metadata candidate scanning seams.
- Add FFI ABI for ext filesystem-kind metadata plus XFS/UFS probe and candidate listing.
- Add .NET interop methods and status mapping for XFS/UFS.
- Expand UI probe fallback flow to include XFS and UFS before APFS/HFS+/FAT.

## Implemented slice

1. Engine foundation:
- `fr-ext` now classifies filesystem kind from feature flags (`ext2`/`ext3`/`ext4`).
- New `fr-xfs` crate with XFS superblock parser boundary (`XFSB`) and deleted tombstone seam (`XFSDEL`).
- New `fr-ufs` crate with UFS superblock parser at canonical offset and deleted tombstone seam (`UFSDEL`).
- crate-level parser/scanner tests for valid/invalid signatures and candidate extraction behavior.

2. Interop and UI wiring:
- `FrExtSuperblockMetadata` now exports filesystem kind code.
- New FFI calls:
- `fr_probe_xfs_superblock_from_session`
- `fr_get_xfs_deleted_candidates_from_session`
- `fr_probe_ufs_superblock_from_session`
- `fr_get_ufs_deleted_candidates_from_session`
- `.NET NativeEngineProbe` now maps ext filesystem kind and adds XFS/UFS structs/wrappers/status mapping (`120`/`130`).
- UI scan fallback order updated to: `NTFS -> ReFS -> ext2/3/4 -> XFS -> UFS -> APFS -> HFS+ -> FAT`.
- UI quick-scan rendering added for XFS/UFS deleted metadata candidates.

3. Validation updates:
- Rust coverage includes `fr-xfs`, `fr-ufs`, ext-kind classification, and FFI XFS/UFS paths.
- deterministic .NET status tests expanded for XFS/UFS probe and candidate calls.

## Deferred in Phase 11

- XFS/UFS file-content recovery/export paths (candidates remain metadata-only in this phase).
