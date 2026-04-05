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
- ext inode-table-backed reconstruction that links deleted directory-entry names to deleted inode metadata when inode references are recoverable.
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
- primary ext corpus manifest now includes expanded real-world case slots (`sparse-extents`, `symlink-heavy`, `inode-linked-names`) alongside baseline scenarios.
- committed synthetic ext mini-corpus manifest/images under `testdata/raw-images/ext-corpus/manifest.synthetic.json` + `synthetic/*.img`.
- `ExtCorpusBench` benchmark tool for ext probe/candidate throughput baselines.
- `scripts/benchmark-ext-corpus.ps1` benchmark runner wrapper.
- `scripts/generate-ext-synthetic-corpus.ps1` deterministic synthetic corpus generator.
- `scripts/benchmark-ext-synthetic-corpus.ps1` synthetic manifest benchmark wrapper.

4. Host/image validation scaffolding:
- `scripts/run-host-ext-image-validation.ps1` to archive ext corpus validation artifacts per run.
- `scripts/run-host-validation-profile.ps1` now orchestrates `ext` validation lane alongside `ntfs`/`vss`.
- `scripts/compare-host-validation-profiles.ps1` now includes `ext` drift summaries per profile.
- host ext validation/profile scripts now support synthetic-corpus mode (`-UseSyntheticCorpus` / `-UseSyntheticExtCorpus`) for deterministic in-repo runs.

5. ext recovery baseline:
- `fr_recover_ext_candidate_to_file` now supports regular-file recovery from direct, single-indirect, double-indirect, and triple-indirect block pointers.
- extents-flagged inodes now route through extent-tree traversal for initialized extent runs.
- sparse gaps and uninitialized extent runs now zero-fill during export.
- inline (fast) symlink inodes now export the stored target bytes.
- non-inline symlink inodes now export through data-block recovery paths.
- directory inodes now export raw directory data bytes.
- recovery marks partial when unresolved pointers/reads prevent full export.

## Deferred in Phase 9

- real-world ext fixture corpus expansion beyond the committed synthetic mini-corpus.
