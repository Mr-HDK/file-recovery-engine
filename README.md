# File Recovery (Windows-First)

Commercial-grade local desktop recovery foundation targeting Windows and NTFS first.

## Scope in this first implementation batch

- Monorepo scaffold for docs, Rust engine, WPF UI, tests, tools, scripts, and CI.
- Required Phase 0 documentation set under `docs/`.
- WPF shell with source/destination workflow, safety validation, and SQLite session persistence.
- SQLite session retention and maintenance controls (automatic retention + manual compaction trigger).
- Rust engine workspace skeleton with modular crates and stable C ABI entry points.
- Baseline automated tests for safety validation and session persistence.

## Assumptions

- This workspace currently has .NET 8 installed.
- Rust toolchain may not be present locally; use `scripts/setup-rust-toolchain.ps1` to install/verify.
- Product development is phased; this commit establishes a runnable foundation and safety guardrails.

## Quick start

```powershell
./scripts/setup-rust-toolchain.ps1 -Install
./scripts/setup-rust-toolchain.ps1 -RunChecks
./scripts/bootstrap.ps1
./scripts/test.ps1
./scripts/benchmark-ntfs-corpus.ps1 -AllowMissing
```

Optional elevated host-integration validation (provisions a temporary NTFS VHD and validates compressed/encrypted deleted-file recovery paths):

```powershell
./scripts/run-host-ntfs-stream-validation.ps1
# or:
./scripts/test.ps1 -IncludeHostIntegration
```

By default, host-validation evidence is archived under `artifacts/host-validation/<timestamp>/` with:
- `host-ntfs-stream-validation.trx`
- `host-validation-manifest.json`

To skip artifact archiving:

```powershell
./scripts/run-host-ntfs-stream-validation.ps1 -NoArchive
```

## Rust toolchain setup (Windows)

```powershell
./scripts/setup-rust-toolchain.ps1 -Install
./scripts/setup-rust-toolchain.ps1
```

If Rust is already installed, run only `./scripts/setup-rust-toolchain.ps1`.

### MSVC linker prerequisite

Rust builds for `x86_64-pc-windows-msvc` require `link.exe` from Visual C++ Build Tools.

```powershell
winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--wait --quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

Then run repo tests from **Developer PowerShell for VS 2022** (or after running `VsDevCmd.bat`) so `link.exe` is on `PATH`.

## Repo layout

- `docs` Architecture, safety, threat, testing, licensing, pipeline.
- `engine` Rust workspace for recovery core.
- `ui/windows-app` WPF desktop app + tests.
- `testdata` Fixtures and generation guidance.
- `tools` Inventory and engineering utilities.
- `scripts` Bootstrap/test/fixture scripts.
- `.github/workflows` CI.
