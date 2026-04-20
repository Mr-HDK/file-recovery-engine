# Expansion Phase Tracker

## Status legend

- `PENDING`: not started.
- `IN_PROGRESS`: actively being implemented.
- `BLOCKED`: waiting on dependency/decision.
- `DONE`: completed and accepted.

## Active program tracker

| Phase | Scope | Status | Acceptance gate |
|---|---|---|---|
| 8 | `ReFS` engine foundation | DONE | ReFS probe + candidate listing + tests + UI mapping |
| 9 | `ext4` engine foundation | DONE | ext4 probe + deleted metadata candidates + tests + UI mapping |
| 10 | `APFS/HFS+` foundation | DONE | APFS/HFS+ image-first candidate extraction + tests + UI mapping |
| 11 | `ext2/ext3`, `XFS`, `UFS` compatibility | DONE | probe/candidate seams + compatibility matrix + tests |
| 12 | FAT/exFAT full tree traversal | DONE | nested path reconstruction + deleted dir traversal + tests |
| 13 | Disk imaging/clone-first workflow | DONE | image acquisition, hash verification, resume, UI-first flow |
| 14 | RAID virtual assembly + auto-detection | DONE | virtual RAID build + auto-params + manual override + tests |
| 15 | NAS/network workflows | DONE | remote source support + resumable operations + audit logs |
| 16 | Bootable `WinPE` mode | IN_PROGRESS | bootable build, offline scan/recovery flow, docs/scripts |
| 17 | Carving expansion + streaming scan | PENDING | remove fixed scan cap, streaming scan engine, larger signatures |

## Phase completion checklist

Mark every item before setting a phase to `DONE`.

- Scope implemented exactly as defined.
- Engine tests added and passing.
- FFI integration tests added and passing.
- UI/core tests added and passing.
- Host/image validation evidence produced where applicable.
- Safety and destination-separation behavior unchanged or improved.
- Docs updated for architecture/pipeline/test impact.
- New status/diagnostic codes documented and surfaced in UI.

## Change control rule

- If scope changes during a phase, update both:
- `docs/expansion-program-roadmap.md`
- `docs/expansion-phase-tracker.md`

No phase may be marked `DONE` if docs and tracker are out of sync.
