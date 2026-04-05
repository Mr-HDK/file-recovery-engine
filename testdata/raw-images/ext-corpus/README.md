# ext Corpus

This directory defines the fixed ext corpus used by the ext benchmark harness.

## Canonical manifest

- `manifest.json` is the source of truth for required benchmark cases.
- All file names are fixed and should not be changed without updating the manifest.
- `manifest.synthetic.json` defines a committed deterministic mini-corpus for CI/local smoke runs.

## Required images

1. `ext4-recent-delete.img`
2. `ext4-deleted-tree.img`
3. `ext4-journal-rotated.img`
4. `ext4-partial-overwrite.img`
5. `ext4-sparse-extents.img`
6. `ext4-symlink-heavy.img`
7. `ext4-inode-linked-names.img`

## Build guidance

1. Build ext fixture trees with deterministic file names/timestamps.
2. Convert fixtures to raw `.img` files using your Linux/macOS imaging workflow.
3. Place resulting images in this folder with the exact names from the manifest.
4. Run benchmark harness:
   - `scripts/benchmark-ext-corpus.ps1`

Suggested scenario emphasis for the expanded matrix:
- `ext4-sparse-extents.img`: sparse and uninitialized extents.
- `ext4-symlink-heavy.img`: inline and non-inline symlink targets.
- `ext4-inode-linked-names.img`: deleted directory-entry names that still reference deleted inode metadata.

## Notes

- Corpus files are intentionally not committed due size.
- Keep image generation settings stable to keep benchmark comparisons meaningful.
- Synthetic mini-corpus images are generated/updated with:
  - `scripts/generate-ext-synthetic-corpus.ps1`
- Synthetic benchmark runner:
  - `scripts/benchmark-ext-synthetic-corpus.ps1`
