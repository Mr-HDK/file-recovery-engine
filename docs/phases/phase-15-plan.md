# Phase 15 Plan: NAS and Network Recovery Workflows

## Phase status

- Phase: `15`
- Status: `DONE`
- Owner: `Engineering`
- Start date: `2026-04-10`
- Completion date: `2026-04-10`

## Scope

- Add network source connectors for `SMB`/`NFS` and mounted NAS image workflows.
- Add optional remote-agent mode controls for source-side operations.
- Add constrained network I/O behavior and resumable checkpoint metadata for network imaging.
- Add explicit chain-of-custody event logging for remote/network acquisition operations.

## Implemented slice

1. Network source model + enumeration wiring:
- Added network source metadata to `SourceCandidate` (`IsNetworkSource`, protocol, endpoint).
- Added network source request models (`NetworkSourceRequest`, `NetworkSourceProtocol`).
- Extended `IDeviceEnumerationService` with `BuildNetworkImageSourceAsync`.
- Implemented network image source construction in `WindowsDeviceEnumerationService`.

2. Network-aware image acquisition:
- Extended acquisition request/result contracts with network/remote-agent/custody settings.
- Added constrained network chunking and optional throughput throttling.
- Added resumable network checkpoint count in persisted acquisition state.
- Added chain-of-custody JSONL append flow with hash-chained records for:
  - acquisition started
  - periodic checkpoint
  - completed/canceled/failed

3. UI workflow integration:
- Added source panel controls for adding network image sources (`SMB`/`NFS`, path, endpoint hint).
- Added source table columns for network protocol and endpoint.
- Added advanced settings for constrained network I/O, throughput cap, remote agent mode/endpoint, and custody log path.
- Wired acquisition flow to pass network options and log network/custody output paths.

## Deferred in Phase 15

- Active remote agent execution is still a control-plane placeholder (mode/endpoint contract + logging), not a distributed execution runtime.
