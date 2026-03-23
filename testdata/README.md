# Test Data

This folder stores deterministic fixture artifacts for parser and recovery tests.

## Convention

- `raw-images/` disk images used by integration tests.
- `golden/` parser expected outputs.
- `fixtures/` source trees used to generate images.
- `raw-images/ntfs-corpus/manifest.json` fixed image set for benchmark runs.

## Initial workflow

1. Generate fixture tree:

```powershell
./scripts/new-test-fixture.ps1 -OutputPath ./testdata/fixtures/ntfs-baseline
```

2. Convert fixture tree into test images with your preferred imaging tooling.
3. Store expected parser outputs under `testdata/golden`.
4. Run NTFS benchmark harness against fixed corpus:

```powershell
./scripts/benchmark-ntfs-corpus.ps1
```
