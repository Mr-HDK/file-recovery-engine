# Phase 13 Plan: Disk Imaging / Clone-First Workflow

## Phase status

- Phase: `13`
- Status: `DONE`
- Owner: `Engineering`
- Start date: `2026-04-09`
- Completion date: `2026-04-09`

## Scope

- Provide clone-first raw image acquisition with verification hashes.
- Persist resume-safe acquisition checkpoints/state logs.
- Define and implement a bad-sector/read-error handling policy.
- Keep image-first UX as the default recommendation before live-media scan/recovery.

## Implemented slice

1. Image acquisition service hardening:
- `ImageAcquisitionRequest` now includes explicit read-error policy controls:
- `ReadErrorPolicy` (`FailFast` / `ContinueWithZeroFill`)
- `MaxReadErrorChunks`
- Acquisition loop now supports policy-driven behavior:
- `FailFast`: immediate failure on source read error.
- `ContinueWithZeroFill`: zero-fill unreadable chunks, advance source offset, continue imaging until completion or threshold reached.
- Acquisition result/progress/state now include:
- read-error chunk count,
- zero-filled byte count,
- policy used.

2. Resume-safe checkpoint behavior:
- Resume compatibility now rejects checkpoints that already include read-error chunks/zero-fill bytes.
- This keeps prefix verification deterministic and avoids unsafe mixed-policy resume across partially imaged unreadable regions.

3. UI image-first flow and safeguards:
- WPF imaging flow now runs with explicit `ContinueWithZeroFill` policy and bounded read-error threshold.
- Completion diagnostics now surface read-error/zero-fill counters and policy in session output.
- Existing scan/recovery image-first confirmation guard remains active for live sources.

## Deferred in Phase 13

- No dedicated per-chunk unreadable-range export/report artifact yet (only aggregate counters in logs/state).
