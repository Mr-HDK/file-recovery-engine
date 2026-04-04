# Phase 8 Plan: ReFS Engine Foundation

## Phase status

- Phase: `8`
- Status: `DONE`
- Owner: `Codex agent`
- Start date: `2026-04-04`
- Completion date: `2026-04-04`

## Scope

- Add initial read-only `ReFS` boot metadata parser crate (`fr-refs`).
- Add FFI ABI probe function for `ReFS` boot metadata.
- Add .NET probe wrapper for `ReFS` boot metadata.
- Route UI source probing to detect `ReFS` and log explicit current support boundaries.
- Add deterministic tests for the new probe boundary.

## Initial implementation slice

1. Create `engine/crates/fr-refs` with:
- module descriptor
- `parse_boot_sector`
- parser error model
- basic unit tests

2. Integrate with `fr-ffi`:
- dependency wiring
- `FrRefsBootMetadata` struct
- `fr_probe_refs_boot_from_session` export

3. Integrate with .NET core:
- native interop struct + DllImport
- `EngineRefsBootMetadata` and `EngineRefsBootProbeResult`
- `NativeEngineProbe.ProbeRefsBootFromSession`

4. Integrate UI probe flow:
- detect `ReFS` between NTFS and FAT paths
- render `ReFS` deleted-candidate scan results in the quick-scan table

5. Add tests:
- native probe deterministic status test in `NativeEngineProbeTests`

## Acceptance criteria for this slice

- Build compiles with new crate and interop symbols.
- ReFS probe path is reachable from UI session start flow.
- Unsupported/non-ReFS sources do not regress NTFS/FAT behavior.
- Tests for the new probe method pass (or are updated with deterministic status ranges).

## Deferred follow-up (post-Phase 8)

- ReFS recovery/export implementation.
- ReFS candidate persistence/reporting pipeline.
- Host-level ReFS fixture/integration validation.
