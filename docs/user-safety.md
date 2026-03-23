# User Safety Model

## Hard safety rules

- Source devices are treated as read-only.
- Recovery destination must be on a different volume or physical disk than source.
- Recovery cannot start if separation checks fail.
- Risky operations require explicit user action.

## Safety checks in this batch

- Volume identity comparison for volume/image sources.
- Physical disk index comparison for physical disk sources.
- Destination existence validation.
- Elevation status warning surfaced before starting a session.
- Engine preflight read-only open and first-chunk read before session continuation when native engine is available.
- Alignment-aware raw source reads to avoid unsafe/misaligned I/O behavior.
- Volume GUID-based topology resolution to validate source/destination separation even for mounted-folder volumes.
- Cancellable long-running operations across source enumeration, session initialization, preview reads, and candidate recovery execution.
- Session status/error propagation persisted for cancellation and failure outcomes.
- Candidate recoverability states persisted and surfaced as `full`, `partial`, `invalid`, and `overwritten-risk`.

## User messaging standards

- Every blocked operation includes a specific reason.
- Warnings are explicit and never silently ignored.
- No claims of guaranteed full recovery.

## Logging and traceability

- Session-level JSON and text logs are always created on session start.
- Validation outcomes are logged and visible in UI.

## Failure handling

- Invalid source/destination states return structured errors.
- Cancellation leaves persisted session state for later resume.
