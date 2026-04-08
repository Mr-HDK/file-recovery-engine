# Phase 12 Plan: FAT/exFAT Full Tree Traversal

## Phase status

- Phase: `12`
- Status: `DONE`
- Owner: `Engineering`
- Start date: `2026-04-09`
- Completion date: `2026-04-09`

## Scope

- Upgrade `fr-fat` from root-only deleted-entry scanning to full directory-tree traversal.
- Reconstruct nested deleted paths including traversal through deleted directories.
- Improve chain handling and diagnostics for invalid/reserved clusters, loops, and traversal-cap exhaustion.
- Add dedicated fixtures for nested deleted trees and long-file-name cases.

## Implemented slice

1. FAT/exFAT traversal hardening:
- Tree traversal remains breadth-first across directory clusters for FAT32 and exFAT.
- Deleted directory entries are traversed so child deleted candidates can be surfaced under deleted parents.
- FAT chain handling now returns explicit errors for:
- bad cluster marker (`0x0FFF_FFF7`),
- reserved cluster range (`0x0FFF_FFF0..0x0FFF_FFF8`),
- cluster-loop detection,
- traversal-cap exhaustion (`max_directory_clusters`).

2. Path/name reconstruction:
- FAT32 long-file-name (LFN) deleted entry coverage added with multi-entry LFN reconstruction fixture.
- exFAT nested deleted-directory fixture now validates deleted directory candidate plus nested child path reconstruction.

3. FFI and diagnostics validation:
- FFI tests added for deleted LFN reconstruction and explicit scan-status diagnostics:
- `73` cluster loop,
- `71` invalid cluster chain.
- Existing status mapping in UI/core remains aligned (`70-74`).

## Deferred in Phase 12

- No recover-to-file format expansion in this phase beyond existing FAT recovery behavior.
