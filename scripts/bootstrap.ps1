param()

function Resolve-CargoPath {
  $command = Get-Command cargo -ErrorAction SilentlyContinue
  if ($command) {
    return $command.Source
  }

  $fallback = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
  if (Test-Path $fallback) {
    return $fallback
  }

  return $null
}

$dotnetVersion = dotnet --version
Write-Host "dotnet: $dotnetVersion"

$cargoPath = Resolve-CargoPath
if ($cargoPath) {
  $cargoVersion = & $cargoPath --version
  Write-Host "cargo: $cargoVersion"
} else {
  Write-Warning "cargo is not installed. Rust engine build steps will be skipped locally."
  Write-Host "Run .\scripts\setup-rust-toolchain.ps1 -Install to install and configure Rust."
}

Write-Host "Bootstrap check complete."
