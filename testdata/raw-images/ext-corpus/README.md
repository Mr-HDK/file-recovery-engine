# ext Corpus

This directory defines the fixed ext corpus used by the ext benchmark harness.

## Canonical manifest

- `manifest.json` is the source of truth for required benchmark cases.
- All file names are fixed and should not be changed without updating the manifest.

## Required images

1. `ext4-recent-delete.img`
2. `ext4-deleted-tree.img`
3. `ext4-journal-rotated.img`
4. `ext4-partial-overwrite.img`

## Build guidance

1. Build ext fixture trees with deterministic file names/timestamps.
2. Convert fixtures to raw `.img` files using your Linux/macOS imaging workflow.
3. Place resulting images in this folder with the exact names from the manifest.
4. Run benchmark harness:
   - `scripts/benchmark-ext-corpus.ps1`

## Notes

- Corpus files are intentionally not committed due size.
- Keep image generation settings stable to keep benchmark comparisons meaningful.
