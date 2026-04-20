# Phase 17 Retrospective

## Status

Completed (`DONE`) on `2026-04-20`.

## What Was Delivered

- Streaming carve scan architecture across source sessions:
  - new windowed FFI endpoint for carve candidates (`offset` + `window length`)
  - backward-compatible legacy carve endpoint retained as wrapper
  - UI full-scan flow updated to iterate windows with overlap and deduplicate candidates
- Fixed-cap removal for carve scan requests:
  - removed hard `256 MiB` normalization cap
  - retained bounded per-window scanning behavior for memory safety
- Signature and validator expansion batch (`2026.04-b2`) with `23` formats:
  - image: `jpg`, `png`, `gif`, `bmp`, `tiff`, `webp`
  - document/text/office: `pdf`, `txt`, `rtf`, `docx`, `xlsx`, `pptx`
  - archive: `zip`, `gz`, `7z`, `rar`
  - media: `mp4`, `avi`, `mid`, `ogg`, `flac`, `mp3`, `wav`
- Signature-pack provenance plumbing:
  - pack metadata (`name`, `version`, `format count`) exposed over FFI
  - UI/session diagnostics now log active pack provenance
- Regression hardening:
  - extended false-positive and truncated-data validation fixtures
  - added window-offset and cap-removal regression coverage

## Validation Summary

- `cargo test -p fr-validator` passed (`16` tests).
- `cargo test -p fr-carving` passed (`8` tests).
- `cargo test -p fr-ffi` passed (`53` tests).
- `dotnet build ui/windows-app/src/FileRecovery.WindowsApp/FileRecovery.WindowsApp.csproj -c Debug` passed.
- `dotnet test ui/windows-app/tests/FileRecovery.WindowsApp.Tests/FileRecovery.WindowsApp.Tests.csproj -c Debug` passed (`61` tests).

## What Went Well

- Windowed scanning integrated without breaking legacy call paths, reducing migration risk.
- Signature-pack metadata gave deterministic provenance visibility for triage and support.
- Validator-side regression matrix tightened false-positive control while expanding coverage.

## Remaining Gaps (Deferred, Non-Blocking)

- Signature breadth is expanded but still below "hundreds of formats"; additional batches are needed in future phases.
- Carving heuristics remain conservative and can be further tuned for fragmented media edge cases.
