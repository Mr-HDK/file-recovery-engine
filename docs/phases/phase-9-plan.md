# Phase 9 Plan: ext4 Engine Foundation

## Phase status

- Phase: `9`
- Status: `IN_PROGRESS`
- Owner: `Engineering`
- Start date: `2026-04-04`

## Scope

- Add initial read-only ext parser crate (`fr-ext`) with superblock parsing.
- Add ext deleted directory-entry candidate scanning seam.
- Add FFI ABI for ext superblock probe and candidate listing.
- Add .NET interop methods for ext probe/listing.
- Route UI probe flow to ext between ReFS and FAT.

## Implemented slice (items 1 and 2)

1. `fr-ext` scaffold:
- `ExtSuperblock` parser boundary.
- ext deleted directory-entry scanner (`inode=0` metadata candidates).
- ext deleted-inode scanner from first group inode table (`links=0` + `dtime>0`).
- parser/scanner unit tests.

2. Interop/UI wiring:
- `fr_probe_ext_superblock_from_session`.
- `fr_get_ext_deleted_candidates_from_session`.
- `NativeEngineProbe` ext methods, structs, status mapping.
- UI probe path + candidate rendering for ext evidence.
- deterministic .NET tests for ext probe/candidates.

## Deferred in Phase 9

- ext inode-table-backed deleted metadata reconstruction.
- ext recovery/export path implementation.
- fixture corpus expansion and host validation scripts.
