# Phase 11 Compatibility Matrix

## Scope

Compatibility coverage for Phase 11 foundation support (`ext2/ext3/ext4` detection, `XFS`, `UFS`) with metadata candidate seams.

## Matrix

| Filesystem | Probe support | Deleted metadata candidates | Recover-to-file | Status code (parse fail) |
|---|---|---|---|---|
| ext2 | Yes (`fr_probe_ext_superblock_from_session`) | Yes (`fr_get_ext_deleted_candidates_from_session`) | Partial (ext-only implementation from prior phase) | `90` |
| ext3 | Yes (`fr_probe_ext_superblock_from_session`) | Yes (`fr_get_ext_deleted_candidates_from_session`) | Partial (ext-only implementation from prior phase) | `90` |
| ext4 | Yes (`fr_probe_ext_superblock_from_session`) | Yes (`fr_get_ext_deleted_candidates_from_session`) | Partial (ext-only implementation from prior phase) | `90` |
| XFS | Yes (`fr_probe_xfs_superblock_from_session`) | Yes (`fr_get_xfs_deleted_candidates_from_session`) | Metadata-manifest export only (full content deferred) | `120` |
| UFS | Yes (`fr_probe_ufs_superblock_from_session`) | Yes (`fr_get_ufs_deleted_candidates_from_session`) | Metadata-manifest export only (full content deferred) | `130` |

## Notes

- XFS/UFS support in this phase is intentionally metadata-first and read-only.
- UI fallback order now includes `XFS` and `UFS` between ext and APFS/HFS+/FAT.
- ext2/ext3/ext4 are distinguished in metadata and UI evidence labels via filesystem-kind mapping.
