param(
  [switch]$IncludeHostIntegration,
  [switch]$IncludeHostVssIntegration,
  [switch]$IncludeExtImageValidation,
  [switch]$AllowNoSnapshots,
  [switch]$AllowMissingExtImages
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

Invoke-External -Description "dotnet restore" -Command { dotnet restore FileRecovery.sln }
Invoke-External -Description "dotnet build" -Command { dotnet build FileRecovery.sln -c Release }
Invoke-External -Description "dotnet test" -Command { dotnet test FileRecovery.sln -c Release --no-build }
Invoke-External -Description "license gate" -Command { & "$PSScriptRoot\license-gate.ps1" -Check }

$cargoPath = Resolve-ToolPath -Name "cargo"
$rustupPath = Resolve-ToolPath -Name "rustup"

if ($cargoPath) {
  Push-Location engine
  try {
    if (Test-RustfmtAvailable -RustupPath $rustupPath) {
      Invoke-External -Description "cargo fmt --all --check" -Command { & $cargoPath fmt --all --check }
    } else {
      Write-Warning "rustfmt is unavailable for the active Rust toolchain; skipping cargo fmt check."
    }

    $linkerAvailable = Test-LinkerAvailable
    if ($linkerAvailable) {
      Invoke-External -Description "cargo test --workspace" -Command { & $cargoPath test --workspace }
    } else {
      Write-Warning "MSVC linker (link.exe) is not on PATH. Skipping Rust build/test checks in this shell."
    }
  } finally {
    Pop-Location
  }
} else {
  Write-Warning "Skipping Rust checks because cargo is not installed."
}

if ($IncludeHostIntegration) {
  Invoke-External -Description "host NTFS stream validation" -Command {
    & "$PSScriptRoot\run-host-ntfs-stream-validation.ps1" -NoBuild
  }
}

if ($IncludeHostVssIntegration) {
  Invoke-External -Description "host VSS validation" -Command {
    $vssArgs = @{
      NoBuild = $true
    }
    if ($AllowNoSnapshots) {
      $vssArgs.AllowNoSnapshots = $true
    }

    & "$PSScriptRoot\run-host-vss-validation.ps1" @vssArgs
  }
}

if ($IncludeExtImageValidation) {
  Invoke-External -Description "host ext image validation" -Command {
    $extArgs = @{
      NoBuild = $true
    }
    if ($AllowMissingExtImages) {
      $extArgs.AllowMissingImages = $true
    }

    & "$PSScriptRoot\run-host-ext-image-validation.ps1" @extArgs
  }
}
