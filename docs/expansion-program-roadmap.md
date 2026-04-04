# Expansion Program Roadmap (Phase-by-Phase)

## Program intent

This document defines the required expansion scope requested by product leadership:

- Broader file-system support (`ReFS`, `APFS/HFS+`, `ext*`, `XFS`, `UFS`) with cross-OS recovery flows.
- `RAID` reconstruction with auto-parameter detection.
- `NAS` and network recovery workflows.
- Bootable media recovery (`WinPE` mode).
- Disk imaging/clone-first workflows with recovery from image.
- Larger carving/signature database and removal of the current `256 MiB` cap via chunked streaming scan.

## Execution ownership and rule

- Implementation owner: `Codex agent`.
- Approval owner: repository maintainer.
- Rule: only one phase is active at a time.
- Phase transition rule: no move to next phase until current phase acceptance criteria are met.

## Ordered phases

### Phase 8: Broaden file-system engine foundation (`ReFS` first)

- Add initial `fr-refs` crate with read-only boot/metadata probe and deleted-candidate extraction seam.
- Add FFI ABI for `ReFS` probing and candidate listing.
- Add UI source/file-system routing and candidate rendering for `ReFS`.
- Add unit and integration tests for parser boundaries and FFI mapping.

### Phase 9: Broaden file-system engine foundation (`ext4` second)

- Add `fr-ext` crate with `ext4` superblock/inode/deleted-entry baseline.
- Add read-only image-first support for Linux volumes/images.
- Add FFI/UI integration and evidence labeling for `ext4`.
- Add parser corpus tests and host/image validation scripts.

### Phase 10: Broaden file-system engine foundation (`APFS/HFS+` third)

- Add `fr-apfs` and `fr-hfs` crates for metadata-first deleted discovery.
- Add image-first workflows for macOS containers/volumes.
- Add FFI/UI integration for candidate listing and export.
- Add validation fixtures and parser hardening tests.

### Phase 11: Broaden remaining FS compatibility (`ext2/ext3`, `XFS`, `UFS`)

- Extend Linux support from `ext4` to `ext2/ext3`.
- Add read-only probe + candidate extraction seams for `XFS` and `UFS`.
- Add compatibility matrix and graceful unsupported-status handling in UI.

### Phase 12: FAT/exFAT upgrade from root-only to full traversal

- Upgrade `fr-fat` from deleted-root-entry scanning to full directory-tree traversal.
- Reconstruct nested deleted directory paths and child candidates.
- Improve chain handling and fragmented/loop diagnostics.
- Add dedicated fixtures for nested deleted trees and long-file-name cases.

### Phase 13: Disk imaging/clone-first recovery workflow

- Add image acquisition module (`physical disk/partition -> raw image`) with verification hashes.
- Add resume-safe imaging logs and bad-sector handling policy.
- Make image-first recovery the default recommended path in UI workflow.
- Add UX safeguards to prioritize recovery from image over live media.

### Phase 14: RAID virtual assembly and auto-parameter detection

- Add `fr-raid` crate for virtual array assembly.
- Implement software RAID detection first (Windows/Linux metadata families).
- Add auto-detection for stripe size, disk order, offset, and parity rotation heuristics.
- Add manual override UI for expert correction and replay.

### Phase 15: NAS and network recovery workflows

- Add remote source connectors (SMB/NFS and mounted NAS image workflows).
- Add optional remote agent mode for source-side acquisition/scanning.
- Add constrained network I/O strategy and resumable transfer checkpoints.
- Add explicit chain-of-custody and logging for remote operations.

### Phase 16: Bootable recovery mode (`WinPE`)

- Add bootable runtime packaging and startup scripts for offline recovery.
- Add minimal offline UI for source scan, candidate review, and export.
- Add driver/loading checks and storage visibility validation for offline mode.
- Add docs and scripts for ISO/USB generation and verification.

### Phase 17: Carving expansion and streaming full-scan architecture

- Replace fixed scan cap patterns with chunked streaming scan architecture.
- Remove current carve cap behavior and support large-volume scanning.
- Expand signature/validator coverage to hundreds of formats over iterative batches.
- Add signature pack versioning, regression harness, and false-positive controls.

## Non-negotiable program constraints

- All source access remains read-only.
- Destination separation checks remain mandatory before every write.
- Every phase must ship tests, diagnostics mapping, and docs updates.
- No ABI-breaking changes without explicit version gate and migration notes.

