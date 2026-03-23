# NTFS Benchmark Corpus

This directory defines the fixed NTFS corpus used by the benchmark harness.

## Canonical manifest

- `manifest.json` is the source of truth for required benchmark cases.
- All file names are fixed and should not be changed without updating the manifest.

## Required images

1. `ntfs-recent-delete.img`
2. `ntfs-deleted-tree.img`
3. `ntfs-fragmented.img`
4. `ntfs-partial-overwrite.img`

## Build guidance

1. Generate fixture trees with `scripts/new-test-fixture.ps1`.
2. Convert fixtures to raw `.img` files using your Windows imaging workflow.
3. Place resulting images in this folder with the exact names from the manifest.
4. Run benchmark harness:
   - `scripts/benchmark-ntfs-corpus.ps1`

## Notes

- Corpus files are intentionally not committed due size.
- For CI-quality benchmark comparisons, keep image generation settings stable over time.
