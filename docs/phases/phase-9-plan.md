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
- ext inode-candidate hardening: inode-type gating, deletion-time sanity bounds, and 64-bit inode size parsing.
- parser/scanner unit tests.

2. Interop/UI wiring:
- `fr_probe_ext_superblock_from_session`.
- `fr_get_ext_deleted_candidates_from_session`.
- `NativeEngineProbe` ext methods, structs, status mapping.
- UI probe path + candidate rendering for ext evidence.
- deterministic .NET tests for ext probe/candidates.

3. Fixture/benchmark scaffolding:
- fixed ext corpus manifest and README under `testdata/raw-images/ext-corpus/`.
- `ExtCorpusBench` benchmark tool for ext probe/candidate throughput baselines.
- `scripts/benchmark-ext-corpus.ps1` benchmark runner wrapper.

4. Host/image validation scaffolding:
- `scripts/run-host-ext-image-validation.ps1` to archive ext corpus validation artifacts per run.
- `scripts/run-host-validation-profile.ps1` now orchestrates `ext` validation lane alongside `ntfs`/`vss`.
- `scripts/compare-host-validation-profiles.ps1` now includes `ext` drift summaries per profile.

5. ext recovery baseline:
- `fr_recover_ext_candidate_to_file` now supports regular-file recovery from direct block pointers.
- recovery marks partial when unresolved tail requires indirect blocks or reads fail.

## Deferred in Phase 9

- ext inode-table-backed deleted metadata reconstruction.
- ext recovery/export coverage for indirect block trees, extents, and directory/symlink semantics.
- fixture corpus expansion beyond fixed scaffolding.
