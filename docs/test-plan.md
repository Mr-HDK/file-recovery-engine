# Test Plan

## Principles

- Validate safety constraints before recovery correctness.
- Prefer deterministic fixtures and golden outputs.
- Separate parser tests, orchestration tests, and UI smoke checks.

## Test layers

1. Core unit tests
- Source/destination safety validator.
- Session persistence create/update/list flows.
- Confidence tier mapping logic (engine).

2. Parser tests (engine)
- NTFS boot sector and MFT golden parsing.
- USN record parsing golden tests.
- FAT/exFAT parser and full-tree deleted traversal tests.

3. Integration tests
- Enumerate sources and enforce separation.
- Session resume from persisted checkpoints.

4. Fuzzing
- NTFS attribute parser fuzz targets.
- USN record parser fuzz targets.

5. UI smoke tests
- App starts and source list loads.
- Destination validation blocks same-volume writes.

## Required fixture coverage roadmap

- Recently deleted NTFS files.
- Deleted directories with nested children.
- Resident and non-resident files.
- Fragmented and partially overwritten files.
- Sparse/compressed files and ADS.
- Raw image input path.
- USN-assisted reconstruction scenarios.

## Current batch coverage

- Unit tests for separation validator.
- Unit tests for SQLite-backed session store.
- Unit tests for native engine probe/session wrapper fallback behavior.
- Unit tests for preview-read scanner deterministic outcomes.
- Rust unit tests for NTFS boot sector parsing.
- Rust unit tests for MFT record parsing with resident and non-resident attributes plus update-sequence-array fixup mismatch detection.
- Rust unit tests for session-level NTFS quick-scan orchestration over synthetic image bytes.
- Rust unit tests for deleted nested-directory reconstruction and quick-scan recent-deleted prioritization ordering.
- Candidate persistence tests for recovery diagnostics/status-code/write-bytes fields in SQLite.
- Candidate persistence tests for quick-scan ADS/compressed/sparse/encrypted flags in SQLite.
- Candidate persistence tests for raw recovery diagnostics flags bitmask in SQLite.
- Session-retention tests for age/max-count pruning plus compaction trigger behavior in SQLite.
- Safety-validator tests for nested mount-path layouts and same-volume rejection when source volume is inferred from source path.
- Enumeration fallback validation for SetupAPI-based partition discovery paths (mounted and unmounted/offline candidates).
- Rust FFI integration tests for quick-scan candidate payloads (confidence tier/reason + status flag bitset).
- Rust FFI integration tests for ADS sidecar recovery behavior (default+named, named-only partial, skipped compressed named stream).
- Rust FFI integration tests for non-resident compressed default-stream decompression export and encrypted default-stream raw export with partial diagnostics.
- Windows host integration test harness (gated by `FR_RUN_HOST_INTEGRATION=1`) that provisions an NTFS VHD fixture and validates compressed+encrypted deleted-file recovery diagnostics end-to-end.
- Host encrypted-file validation auto-degrades on systems where EFS is unavailable for the fixture volume (compressed-path validation still runs).
- Host integration test exits early with explicit notice when native engine runtime (`file_recovery_engine.dll`) is unavailable in the test process.
- `scripts/run-host-ntfs-stream-validation.ps1` to execute host integration coverage in an elevated shell.
- `scripts/compare-host-validation-artifacts.ps1` to compare archived host-validation manifest/TRX outputs across runs and detect drift in counters/outcomes.
- `scripts/run-host-vss-validation.ps1` plus `HostVssSnapshotRecoveryTests` for elevated host VSS enumeration and snapshot-source quick-scan/recovery validation.
- `scripts/run-host-validation-profile.ps1` + `scripts/compare-host-validation-profiles.ps1` for repeatable multi-host profile execution and drift review across real machine/storage layouts.
- `scripts/run-host-ext-image-validation.ps1` for host/image ext corpus validation artifacts, plus profile-matrix integration under `scripts/run-host-validation-profile.ps1`.
- `scripts/run-host-ext-image-validation.ps1 -UseSyntheticCorpus` and `scripts/run-host-validation-profile.ps1 -UseSyntheticExtCorpus` for deterministic in-repo ext validation lanes when large external corpora are unavailable.
- Engine/UI diagnostics mapping now includes named-stream sidecar export vs skipped-stream reporting.
- Session log writer tests for JSON/text log creation and recovery report artifact emission.
- Image-acquisition service tests for clone-first copy flow, resume from checkpoint, hash/prefix mismatch handling, and checkpoint compatibility behavior for prior read-error states.
- Rust unit coverage in `fr-fat` for FAT32/exFAT boot parsing and full-tree deleted-entry extraction (including nested/deleted-directory traversal).
- Rust unit coverage in `fr-ext` for superblock parsing, deleted inode-table extraction, and deleted directory-entry to inode-metadata reconstruction.
- Rust unit coverage in `fr-raid` for metadata detection, manual override validation, and logical offset mapping seams.
- Rust FFI integration coverage for FAT boot probe and deleted-entry candidate enumeration from image-backed source sessions (including nested directory paths).
- Rust FFI integration coverage for RAID metadata probe and logical mapping ABI seams (`fr_probe_raid_layout_from_session`, `fr_map_raid_logical_offset`).
- Rust unit/FFI coverage for virtual RAID assembled-session lifecycle (`fr_open_virtual_raid_session`, `fr_probe_virtual_raid_session`, `fr_close_virtual_raid_session`) including assembled byte-read verification for RAID0/RAID10 fixtures.
- Rust FFI integration coverage for ext direct/single/double/triple-indirect recovery, extent-leaf recovery, sparse/uninitialized extent zero-fill semantics, inline/non-inline symlink export, and directory inode export plus partial/unsupported fallback status handling.

## Benchmarks

- `scripts/new-test-fixture.ps1` generates filesystem fixture trees.
- `scripts/benchmark-ntfs-corpus.ps1` runs the fixed NTFS corpus benchmark defined in `testdata/raw-images/ntfs-corpus/manifest.json`.
- `scripts/benchmark-ext-corpus.ps1` runs the fixed ext corpus benchmark defined in `testdata/raw-images/ext-corpus/manifest.json`.
- `scripts/benchmark-ext-synthetic-corpus.ps1` regenerates and benchmarks the committed synthetic ext mini-corpus defined in `testdata/raw-images/ext-corpus/manifest.synthetic.json`.
- ext primary corpus manifest now includes dedicated slots for sparse-extents, symlink-heavy, and inode-linked-name real-world scenarios.
- Benchmark outputs are written to `tools/benchmark-results/` as JSON + Markdown summaries.
