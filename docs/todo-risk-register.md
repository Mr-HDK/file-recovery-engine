# TODO and Risk Register

## Active TODOs

1. None for Phase 0-7 engineering scope (2026-03-28). Remaining validation breadth is operational host-matrix execution using the scripted workflows below.

## Recently completed

1. Integrated `fr-session` NTFS quick-scan orchestration with real volume/image `ReadSession` sources and migrated `fr-ffi` quick-scan/candidate entry points to consume shared `fr-session` summaries.
2. Added per-candidate recovery diagnostics persistence (SQLite/UI/export) and expanded recovery-case handling for NTFS sparse/compressed/encrypted/ADS metadata with explicit status signaling.
3. Surfaced ADS/compressed/sparse/encrypted metadata flags during quick-scan candidate listing and persisted them through FFI/UI/session storage.
4. Added ADS sidecar export in `fr-ffi` recovery path (`.ads-<stream>` naming), including diagnostics for exported/skipped named streams and no-default-stream partial recovery.
5. Added `scripts/setup-rust-toolchain.ps1` and README/bootstrap wiring for local Rust installation + component setup (`rustfmt`, `clippy`).
6. Persisted per-candidate recovery diagnostics flags (raw bitmask) through SQLite/UI/export alongside diagnostics text.
7. Hardened `scripts/test.ps1` to detect cargo from `%USERPROFILE%\\.cargo\\bin`, fail on real command failures, and emit explicit linker/rustfmt guidance.
8. Added per-session human-readable recovery report generation (`.recovery-report.md`) with candidate-level status/diagnostics details.
9. Added SQLite session retention policy (30-day + max-session cap) with explicit DB compaction (`VACUUM`) support and UI maintenance trigger.
10. Added safety-validator coverage for nested mount-point layouts to verify longest-prefix volume resolution and same-volume blocking.
11. Added SetupAPI-backed partition fallback enumeration that probes discovered disks for mounted and unmounted/offline partition candidates when WMI is unavailable.
12. Added Rust FFI quick-scan integration coverage validating candidate confidence tier/reason payloads and status flags via session-level image scan tests.
13. Added Rust FFI recovery integration tests for ADS sidecar flows (default + named export, named-only partial export, compressed named-stream skip diagnostics).
14. Implemented non-resident NTFS compressed-stream export decompression in `fr-ffi` (LZNT1 decode via Windows `RtlDecompressBufferEx`) with guarded partial fallback.
15. Implemented encrypted-stream-aware export behavior in `fr-ffi`: encrypted data streams now export raw bytes with explicit partial + diagnostics signaling instead of hard failure on default stream.
16. Added Rust FFI integration coverage for compressed non-resident default-stream recovery and encrypted default-stream raw export diagnostics.
17. Added gated Windows host integration test coverage (`HostNtfsStreamRecoveryTests`) that provisions an NTFS VHD fixture and validates compressed+encrypted deleted-file recovery paths through .NET engine probe APIs.
18. Added `scripts/run-host-ntfs-stream-validation.ps1` for elevated, focused execution of host integration stream-recovery validation.
19. Added automatic host-validation artifact archiving (`artifacts/host-validation/<timestamp>`) including TRX output and a JSON manifest with environment + git metadata.
20. Implemented concrete `fr-usn` journal parser support for USN v2/v3 record streams with reason decoding and parser test coverage.
21. Added `fr-session` USN evidence enrichment hook (`apply_usn_evidence`) and threaded candidate evidence-source propagation through `fr-ffi`, .NET probe mapping, and SQLite candidate persistence.
22. Hardened `fr-session` USN enrichment matching to prioritize direct record-number correlation and constrained fallback matching (`name+parent` / mapped path) to reduce same-name false positives.
23. Added USN rename-hint application in `fr-session` so `RENAME_NEW_NAME` / `FILE_CREATE` journal evidence can update candidate name + reconstructed path.
24. Polished quick-scan UI table readability with status-based row highlighting and an explicit confidence-reason column to expose scoring rationale inline.
25. Closed Phase 1 hardening gaps by adding deterministic image-source enumeration tests in `.NET` and canonical/case-insensitive `\\.\PhysicalDriveN` normalization tests in `fr-winio`.
26. Added NTFS `$FILE_NAME` metadata extraction in quick-scan (`data/allocated size`, file attributes, created/modified/MFT-modified/accessed FILETIME values) and threaded it through Rust FFI, .NET probe mapping, SQLite persistence, and UI/export/report surfaces.
27. Added explicit fragmented non-resident recovery coverage in `fr-ffi` (successful multi-run fragmented reassembly + partial status when a later run is unreadable/out-of-bounds).
28. Added USN-aware quick-scan candidate FFI entry point (`fr_get_ntfs_quick_scan_candidates_from_session_with_usn`) and coverage for rename evidence + ghost candidate surfacing.
29. Added `fr-session` USN summary enrichment helpers (`enrich_summary_with_usn_records` / `_bytes`) and ghost-record synthesis metrics (`usn_enriched_records`, `usn_ghost_records`) for end-to-end reporting.
30. Added extensible `$LogFile` correlation seam in `fr-logfile` (`LogfileCorrelator` trait + hint model) and integrated hint application in `fr-session`.
31. Aligned .NET native interop with updated quick-scan ABI (USN summary counters + ghost flag), including UI/session-store/export handling for ghost candidates.
32. Updated UI recovery workflow to block ghost candidates from false-positive recovery attempts with explicit diagnostics messaging.
33. Implemented Phase 4 baseline VSS path: native snapshot enumeration (`fr-vss` + `fr_list_vss_snapshots`), .NET interop mapping, WPF source-list snapshot integration (ID/timestamp surfaced), and VSS evidence tagging for snapshot-derived quick-scan candidates in the unified results model.
34. Closed remaining Phase 2 quick-scan quality gaps by prioritizing recently deleted candidates in session quick-scan ordering and adding explicit nested deleted-directory reconstruction coverage in `fr-session` tests.
35. Completed Phase 4 recovery UX gaps by enabling directory-selection expansion into child-file recovery, formatting snapshot timestamps clearly in source display, and normalizing snapshot volume identity checks for same-volume safety enforcement.
36. Implemented Phase 5 baseline end-to-end carving path: selective family-based carving in `fr-carving` + validator hardening in `fr-validator`, new FFI carve-candidate API, WPF full-scan carve family selection UI, carve candidate persistence in SQLite, and carve-range export recovery in UI with explicit carve evidence labeling.
37. Implemented Phase 6 post-processing quality baseline in .NET UI/core: candidate dedupe + logical clustering (`CandidatePostProcessor`), metadata-aware placeholder naming and carve rename heuristics, export-time timestamp/attribute preservation attempts, and recovery report/CSV enrichment with cluster + dedupe context.
38. Implemented Phase 7 UI batch 1 in WPF: advanced scan/preview settings drawer, richer results filters (file type/status/evidence/confidence), candidate preview pane (summary/text/image/metadata hooks), recovered-path/file-type grid surfacing, resume-latest-session action, and live preview throughput/progress indicators in status bar.
39. Completed Phase 7 UI polish set: confidence score surfacing, extended filters (size + modified/deleted-date proxy windows), explicit diagnostics/safety views in-app, and guided export/recovery confirmation wizard flow before operations.
40. Added `HostVssSnapshotRecoveryTests` (`Category=HostVssIntegration`) to validate host-level VSS snapshot enumeration plus snapshot-source quick scan/recovery probe flow through the .NET engine boundary.
41. Added `scripts/run-host-vss-validation.ps1` to run elevated host VSS validation with artifact archiving and optional `-AllowNoSnapshots` mode.
42. Added `scripts/compare-host-validation-artifacts.ps1` and documentation wiring to compare archived host-validation manifests/TRX counters/outcomes for drift across host/profile runs.
43. Replaced `fr-fat` scaffold with concrete FAT32/exFAT boot parsing and full directory-tree deleted-entry extraction (cluster-chain walk + FAT lookup + nested path reconstruction).
44. Added FAT/exFAT engine ABI surface (`fr_probe_fat_boot_from_session`, `fr_get_fat_deleted_candidates_from_session`) and .NET `NativeEngineProbe` wrappers/tests.
45. Added profile-level host validation orchestration (`scripts/run-host-validation-profile.ps1`) and cross-profile comparison tooling (`scripts/compare-host-validation-profiles.ps1`) for real-machine/storage-layout validation campaigns.
46. Added clone-first image acquisition foundation in `.NET` core (`FileImageAcquisitionService`) with resumable checkpoint logs, resume-prefix validation, and source/destination SHA-256 verification, plus UI trigger wiring and unit coverage.
47. Added image-first UX safeguards in WPF session/recovery flows: live-media operations now require explicit user confirmation to proceed without prior imaging.

## Active risks

1. **R1 - Missing local Rust toolchain in current environment**
- Impact: engine crates cannot be validated locally.
- Mitigation: CI includes Rust setup; local setup script now provisions rustup/toolchain/components and bootstrap links to it.

2. **R2 - Destination safety for complex mount configurations**
- Impact: false negatives on uncommon mount points.
- Mitigation: mount-point-to-volume GUID resolution is implemented in topology lookup; nested mount-layout validator tests are now in place and should be expanded with host-level topology integration coverage.

3. **R3 - Offline/unmounted partition visibility on restricted systems**
- Impact: fallback enumeration covers mounted volumes but may miss unmounted partitions if WMI is blocked.
- Mitigation: SetupAPI disk-interface fallback is now implemented and probes partition device paths to surface mounted/unmounted candidates; continue adding host integration tests for restricted environments.
