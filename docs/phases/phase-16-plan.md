# Phase 16 Plan: Bootable WinPE Recovery Mode

## Phase status

- Phase: `16`
- Status: `IN_PROGRESS`
- Owner: `Engineering`
- Start date: `2026-04-17`
- Completion date: `TBD`

## Scope

- Add bootable runtime packaging and startup scripts for offline recovery.
- Add minimal offline UI behavior for source scan, candidate review, and export.
- Add driver/loading checks and storage visibility validation for offline mode.
- Add docs and scripts for ISO/USB generation and verification.

## Initial implementation slice (started)

1. Runtime and offline-readiness foundation:
- Added runtime mode/profile models for WinPE detection.
- Added WinPE runtime service and probe interfaces.
- Added offline storage readiness report generation (critical drivers, source visibility, destination visibility).

2. UI integration (minimal offline mode behavior):
- Runtime mode indicator added to UI header.
- WinPE guardrails added:
- VSS enumeration skipped in WinPE mode.
- network source intake disabled in WinPE mode.
- readiness diagnostics appended to validation/session outputs.

3. Bootable packaging scripts:
- Added WinPE media build script:
- `scripts/winpe/build-winpe-media.ps1`
- Added offline startup launcher script:
- `scripts/winpe/start-file-recovery-offline.cmd`

## Remaining items for completion

- End-to-end WinPE boot validation evidence on reference hardware/VM.
- Startup scripts hardening for missing runtimes/dependencies.
- Minimal offline workflow UX pass (remove/disable non-offline controls where needed).
- Phase validation and retrospective documents.
