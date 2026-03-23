# TODO and Risk Register

## Active TODOs

1. Add Rust FFI integration coverage for quick-scan candidate confidence/status payloads once local `cargo` is available.
2. Add Rust recovery integration tests for ADS sidecar export behavior (default stream present/absent, partial skips) once local `cargo` is available.
3. Implement decompression/decryption-aware export paths for compressed/EFS-protected NTFS streams beyond current diagnostics + guarded failure handling.

## Recently completed

1. Integrated `fr-session` NTFS quick-scan orchestration with real volume/image `ReadSession` sources and migrated `fr-ffi` quick-scan/candidate entry points to consume shared `fr-session` summaries.
2. Added per-candidate recovery diagnostics persistence (SQLite/UI/export) and expanded recovery-case handling for NTFS sparse/compressed/encrypted/ADS metadata with explicit status signaling.
3. Surfaced ADS/compressed/sparse/encrypted metadata flags during quick-scan candidate listing and persisted them through FFI/UI/session storage.
4. Added ADS sidecar export in `fr-ffi` recovery path (`.ads-<stream>` naming), including diagnostics for exported/skipped named streams and no-default-stream partial recovery.
5. Added `scripts/setup-rust-toolchain.ps1` and README/bootstrap wiring for local Rust installation + component setup (`rustfmt`, `clippy`).
6. Persisted per-candidate recovery diagnostics flags (raw bitmask) through SQLite/UI/export alongside diagnostics text.
7. Hardened `scripts/test.ps1` to detect cargo from `%USERPROFILE%\\.cargo\\bin`, fail on real command failures, and emit explicit linker/rustfmt guidance.
8. Added per-session human-readable recovery report generation (`.recovery-report.md`) with candidate-level status/diagnostics details.

## Active risks

1. **R1 - Missing local Rust toolchain in current environment**
- Impact: engine crates cannot be validated locally.
- Mitigation: CI includes Rust setup; local setup script now provisions rustup/toolchain/components and bootstrap links to it.

2. **R2 - Destination safety for complex mount configurations**
- Impact: false negatives on uncommon mount points.
- Mitigation: mount-point-to-volume GUID resolution is implemented in topology lookup; add integration tests for uncommon mount layouts.

3. **R3 - Offline/unmounted partition visibility on restricted systems**
- Impact: fallback enumeration covers mounted volumes but may miss unmounted partitions if WMI is blocked.
- Mitigation: add SetupAPI-based disk/partition walk to complement current Win32 mounted-volume fallback.

4. **R4 - Session store growth over long retention**
- Impact: larger local DB and slower queries.
- Mitigation: add retention policy and compaction command in Phase 1.1.
