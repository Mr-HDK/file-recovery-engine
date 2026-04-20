# Phase 17 Plan: Carving Expansion and Streaming Full-Scan

## Phase status

- Phase: `17`
- Status: `DONE`
- Owner: `Engineering`
- Start date: `2026-04-20`
- Completion date: `2026-04-20`

## Scope

- Replace fixed carve cap behavior with chunked streaming scan windows.
- Support large-volume carve scans by iterating source windows instead of loading a single capped prefix.
- Expand carving signature and validator coverage in iterative batches.
- Add signature-pack versioning and regression controls for false-positive tracking.

## Execution slices

1. Streaming scan architecture:
- Add FFI windowed carve API (`start offset` + `window length`).
- Keep legacy carve API as compatibility wrapper.
- Switch UI full-scan carve orchestration to window iteration with overlap and deduplication.

2. Cap removal and large-volume behavior:
- Remove the current `256 MiB` max normalization cap for carve scan requests.
- Keep bounded per-window reads to avoid monolithic allocations.

3. Signature expansion and controls:
- Expand format coverage in multiple batches (images/documents/archives/media).
- Add signature-pack metadata (`version`, `batch`) and expose diagnostics for pack provenance.
- Add regression fixtures focused on false-positive and partial/truncated behavior.
- Current landed batch (`2026.04-b1`): `jpg`, `png`, `gif`, `bmp`, `tiff`, `webp`, `pdf`, `txt`, `zip`, `gz`, `7z`, `rar`, `docx`, `xlsx`, `pptx`, `mp4`, `ogg`, `flac`, `mp3`, `wav`.

4. Validation and rollout:
- Add Rust tests for window-offset carve behavior.
- Add .NET integration coverage for streaming carve orchestration seams.
- Update architecture and recovery pipeline docs as streaming behavior lands.
