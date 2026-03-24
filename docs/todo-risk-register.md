# TODO and Risk Register

## Active TODOs

1. Run the gated host integration harness (`scripts/run-host-ntfs-stream-validation.ps1`) on an elevated Windows host and archive the resulting evidence/logs as baseline validation artifacts.

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
