# Recovery Pipeline

## Pipeline stages

1. Source discovery
- Enumerate physical disks, partitions, logical volumes, and supported image files.
- Tag each source with identity data needed for safety validation.

2. Safety gate
- Validate destination exists and is writable.
- Enforce source/destination separation at volume or disk identity level.
- Require explicit user confirmation for risk-bearing actions.

3. Session initialization
- Allocate session ID.
- Persist scan parameters and source metadata.
- Create structured and human logs.

4. Metadata-first pass (NTFS primary)
- Read boot sector and NTFS metadata.
- Parse MFT entries and identify deleted records.
- Reconstruct paths and collect timestamps/attributes.
- Current implementation includes parser primitives plus a quick-scan orchestration entry that reads boot-sector metadata and iterates parsable MFT records from raw source bytes.
- Quick-scan candidate payloads now surface NTFS ADS/compressed/sparse/encrypted indicators to drive pre-recovery warnings.

5. Artifact-assisted pass
- Parse USN records and merge rename/move evidence.
- Prepare integration seam for `$LogFile` reconstruction.
- Mark supporting evidence per candidate.
- Current implementation now includes a concrete `fr-usn` parser for USN v2/v3 records, `fr-session` enrichment hooks that apply rename/path hints and synthesize ghost deleted candidates, and an extensible `$LogFile` correlator seam (`fr-logfile` + `apply_logfile_correlation`) for future transaction replay integration.

6. Snapshot augmentation
- Enumerate VSS snapshots.
- Extract additional candidates from selected snapshots.
- Merge into unified result set with snapshot provenance.
- Current implementation enumerates accessible snapshots through `fr-vss`, exposes them through the `fr-ffi` C ABI (`fr_list_vss_snapshots`), surfaces snapshot ID/timestamp in the WPF source picker, treats snapshot reads as read-only source sessions, and tags snapshot-derived quick-scan candidates with `VSS` evidence in the shared candidate model.
- Snapshot-folder recovery is implemented in the UI by expanding selected directory rows into child file candidates and recovering those children while preserving per-directory recovery diagnostics.

7. Optional carving pass
- Apply selected signatures by family/type.
- Validate structures to minimize false positives.
- Mark carved outputs with lower default confidence.

8. Candidate consolidation
- Cluster duplicate candidates from different evidence streams.
- Keep best representative and preserve provenance graph.

9. Recovery/export
- Enforce destination separation again before writes.
- Write recovered files.
- Preserve timestamps and attributes where possible.
- Record full/partial/invalid/overwritten-risk outcomes.
- Persist per-candidate write diagnostics (status code, bytes written, partial flag, and engine diagnostics text).
- Persist per-candidate diagnostics flag bitmask for deterministic post-run triage/reporting.
- Export named NTFS streams as sidecar files (`.ads-<stream>`), and surface exported/skipped stream diagnostics explicitly.
- Decompress non-resident NTFS compressed streams during export (with explicit partial/unsupported diagnostics when decode fails).
- Export encrypted streams as raw bytes with explicit "not decrypted" diagnostics and partial recovery signaling.
- Surface ADS-only edge cases explicitly instead of silent fallback.

10. Reporting
- Generate session report with recovered count, failures, partials, and evidence breakdown.
- Current implementation emits a per-session Markdown report in local log storage (`<session-id>.recovery-report.md`).

## Evidence model

Each recovery candidate carries evidence entries from:
- `MFT`
- `DirectoryIndex`
- `USN`
- `VSS`
- `Carve`

Confidence is computed from evidence quality, data integrity checks, and overwrite risk.
Current implementation includes weighted scoring + reason generation in `fr-scoring`, candidate-level evidence propagation over FFI/UI (`MFT`, `USN`, etc.), and persisted evidence summaries in SQLite session candidate records.

## Cancellation/resume model

- All long-running stages use cancellable work units.
- Session state checkpoints are persisted in SQLite.
- Resume picks up from last durable checkpoint.
