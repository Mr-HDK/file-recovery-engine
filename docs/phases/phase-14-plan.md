# Phase 14 Plan: RAID Virtual Assembly + Auto-Detection

## Phase status

- Phase: `14`
- Status: `DONE`
- Owner: `Engineering`
- Start date: `2026-04-09`
- Completion date: `2026-04-09`

## Scope

- Add `fr-raid` crate for virtual RAID metadata detection and logical assembly mapping.
- Detect software RAID metadata families first (`Linux MD` and `Windows Storage Spaces`).
- Auto-detect stripe size, member order, data offset, and parity rotation from metadata.
- Add manual override path (level/stripe/offset/parity/disk-order) for expert correction.
- Wire RAID probe and override paths through FFI, .NET interop, and UI advanced settings.

## Implemented slice

1. Engine RAID foundation (`fr-raid`):
- Added RAID layout model and error model for detection, manual override, and logical mapping.
- Implemented metadata detection seams:
- Linux MD superblock v1.x parser seam.
- Storage Spaces header/signature seam.
- Implemented logical offset mapping seams for `RAID0`, `RAID1`, `RAID4`, `RAID5`, and `RAID10`.
- Added parser/override/mapping tests for detection and failure boundaries.

2. FFI wiring (`fr-ffi`):
- Added C ABI structs:
- `FrRaidLayout`
- `FrRaidManualOverride`
- `FrRaidLogicalMapping`
- Added C ABI functions:
- `fr_probe_raid_layout_from_session`
- `fr_map_raid_logical_offset`
- `fr_open_virtual_raid_session`
- `fr_probe_virtual_raid_session`
- `fr_close_virtual_raid_session`
- Added RAID status partition:
- `140` no RAID metadata detected.
- `141` RAID metadata/layout unsupported or invalid.
- `142` invalid manual override/layout input.
- Added FFI tests for RAID layout probing, logical offset mapping, and virtual assembled-session open/probe/read/close flows.

3. .NET + UI integration:
- Added `NativeEngineProbe` RAID wrappers and status mapping.
- Added `NativeEngineProbe` virtual RAID session wrappers (`open/probe/close`) for assembled-source orchestration.
- Added WPF advanced settings controls for RAID manual override inputs.
- Session initialization now runs RAID probe preflight and logs resolved layout/mapping details.
- Invalid RAID override input blocks session startup with deterministic diagnostics.

## Deferred in Phase 14

- WPF multi-member source ingestion UX remains deferred (engine/.NET assembled-session path is available).
