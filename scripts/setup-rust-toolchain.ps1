param(
  [switch]$Install,
  [switch]$RunChecks,
  [ValidateSet('stable', 'beta', 'nightly')]
  [string]$Channel = 'stable'
)

$ErrorActionPreference = 'Stop'

function Resolve-ToolPath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  $command = Get-Command $Name -ErrorAction SilentlyContinue
  if ($command) {
    return $command.Source
  }

  $fallback = Join-Path $env:USERPROFILE ".cargo\bin\$Name.exe"
  if (Test-Path $fallback) {
    return $fallback
  }

  return $null
}

function Ensure-CargoBinOnPath {
  $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
  if (-not (Test-Path $cargoBin)) {
    return
  }

  $pathEntries = $env:Path -split ';'
  if ($pathEntries -contains $cargoBin) {
    return
  }

  $env:Path = "$cargoBin;$env:Path"
}

function Invoke-External {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Description,
    [Parameter(Mandatory = $true)]
    [scriptblock]$Command
  )

  & $Command
  if ($LASTEXITCODE -ne 0) {
    throw "$Description failed with exit code $LASTEXITCODE."
  }
}

function Test-RustfmtAvailable {
  param(
    [string]$RustupPath
  )

  if (-not $RustupPath) {
    return $false
  }

  $previousNative = $null
  if (Get-Variable PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $previousNative = $PSNativeCommandUseErrorActionPreference
    $PSNativeCommandUseErrorActionPreference = $false
  }

  $previousErrorAction = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    & $RustupPath which rustfmt 1>$null 2>$null
    return $LASTEXITCODE -eq 0
  } finally {
    $ErrorActionPreference = $previousErrorAction
    if ($null -ne $previousNative) {
      $PSNativeCommandUseErrorActionPreference = $previousNative
    }
  }
}

function Test-LinkerAvailable {
  $previousNative = $null
  if (Get-Variable PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $previousNative = $PSNativeCommandUseErrorActionPreference
    $PSNativeCommandUseErrorActionPreference = $false
  }

  $previousErrorAction = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    & where.exe link 1>$null 2>$null
    return $LASTEXITCODE -eq 0
  } finally {
    $ErrorActionPreference = $previousErrorAction
    if ($null -ne $previousNative) {
      $PSNativeCommandUseErrorActionPreference = $previousNative
    }
  }
}

function Show-ManualInstallSteps {
  Write-Host ""
  Write-Host "Rust toolchain is not installed yet."
  Write-Host "Step-by-step:"
  Write-Host "1. Install rustup with winget: winget install --id Rustlang.Rustup -e"
  Write-Host "2. Close this terminal and open a new PowerShell window."
  Write-Host "3. From repo root run: .\scripts\setup-rust-toolchain.ps1"
  Write-Host "4. Optional validation run: .\scripts\test.ps1"
  Write-Host ""
}

function Show-LinkerSetupSteps {
  Write-Host ""
  Write-Warning "MSVC linker (link.exe) is not available on PATH."
  Write-Host "To enable Rust builds for the msvc target:"
  Write-Host "1. Install VS Build Tools C++ workload:"
  Write-Host '   winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--wait --quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"'
  Write-Host "2. Open 'Developer PowerShell for VS 2022' (or run VsDevCmd.bat)."
  Write-Host "3. Re-run: .\scripts\test.ps1"
  Write-Host ""
}

Ensure-CargoBinOnPath
$rustupPath = Resolve-ToolPath -Name "rustup"

if (-not $rustupPath) {
  if (-not $Install) {
    Show-ManualInstallSteps
    exit 1
  }

  $wingetPath = Resolve-ToolPath -Name "winget"
  if (-not $wingetPath) {
    throw "winget is not available. Install rustup manually from https://win.rustup.rs/ and re-run this script."
  }

  Write-Host "Installing rustup via winget..."
  Invoke-External -Description "winget rustup install" -Command {
    & $wingetPath install --id Rustlang.Rustup -e --accept-package-agreements --accept-source-agreements
  }

  Ensure-CargoBinOnPath
  $rustupPath = Resolve-ToolPath -Name "rustup"
  if (-not $rustupPath) {
    Write-Warning "Rustup install finished, but rustup is not visible in this shell yet."
    Write-Warning "Open a new terminal and run .\scripts\setup-rust-toolchain.ps1 again."
    exit 1
  }
}

$cargoPath = Resolve-ToolPath -Name "cargo"
if (-not $cargoPath) {
  Ensure-CargoBinOnPath
  $cargoPath = Resolve-ToolPath -Name "cargo"
}

if (-not $cargoPath) {
  throw "cargo was not found. Reopen terminal and run this script again."
}

Write-Host "rustup: $(& $rustupPath --version)"
Write-Host "cargo: $(& $cargoPath --version)"

$toolchainName = "$Channel-x86_64-pc-windows-msvc"
Write-Host "Installing toolchain '$toolchainName' and required components (rustfmt, clippy)..."
Invoke-External -Description "rustup toolchain install" -Command { & $rustupPath toolchain install $toolchainName }
Invoke-External -Description "rustup default" -Command { & $rustupPath default $toolchainName }
Invoke-External -Description "rustup component add rustfmt" -Command { & $rustupPath component add rustfmt --toolchain $toolchainName }
Invoke-External -Description "rustup component add clippy" -Command { & $rustupPath component add clippy --toolchain $toolchainName }
Invoke-External -Description "rustup target add msvc" -Command { & $rustupPath target add x86_64-pc-windows-msvc --toolchain $toolchainName }

$rustcPath = Resolve-ToolPath -Name "rustc"
if ($rustcPath) {
  Write-Host "rustc: $(& $rustcPath --version)"
}
Write-Host "cargo: $(& $cargoPath --version)"

if (-not (Test-RustfmtAvailable -RustupPath $rustupPath)) {
  Write-Warning "rustfmt proxy is unavailable for the active toolchain."
  Write-Warning "Try: rustup toolchain uninstall $toolchainName ; rustup toolchain install $toolchainName"
}

$linkerAvailable = Test-LinkerAvailable
if (-not $linkerAvailable) {
  Show-LinkerSetupSteps
}

if ($RunChecks) {
  Push-Location (Join-Path $PSScriptRoot "..\engine")
  try {
    if (Test-RustfmtAvailable -RustupPath $rustupPath) {
      Invoke-External -Description "cargo fmt" -Command { & $cargoPath fmt --all --check }
    } else {
      Write-Warning "Skipping cargo fmt because rustfmt is unavailable."
    }

    if ($linkerAvailable) {
      Invoke-External -Description "cargo test --no-run" -Command { & $cargoPath test --workspace --no-run }
    } else {
      Write-Warning "Skipping cargo compile checks because link.exe is unavailable in this shell."
    }
  } finally {
    Pop-Location
  }
}

Write-Host "Rust toolchain setup complete."
