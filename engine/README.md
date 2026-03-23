# Engine Workspace

Rust recovery core modules with stable C ABI exported through `fr-ffi`.

Build locally (when Rust is installed):

```powershell
cd ..
./scripts/setup-rust-toolchain.ps1
cd engine
cargo test --workspace
```

If `link.exe` is missing, install Visual C++ Build Tools and run from Developer PowerShell:

```powershell
winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--wait --quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```
