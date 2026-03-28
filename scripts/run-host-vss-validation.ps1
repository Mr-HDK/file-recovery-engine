param(
  [switch]$NoBuild,
  [switch]$NoArchive,
  [string]$ArtifactRoot,
  [switch]$AllowNoSnapshots
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
  $ArtifactRoot = Join-Path $PSScriptRoot "..\artifacts\host-validation-vss"
}

if (-not ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)) {
  throw "This script requires Windows."
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
  IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
  throw "Run this script from an elevated Administrator PowerShell."
}

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

function Sync-EngineRuntimeDll {
  param(
    [Parameter(Mandatory = $true)]
    [string]$SourceDll,
    [Parameter(Mandatory = $true)]
    [string[]]$DestinationPaths
  )

  if (-not (Test-Path $SourceDll)) {
    throw "Engine DLL not found at $SourceDll"
  }

  foreach ($destination in $DestinationPaths) {
    $destinationDir = Split-Path -Parent $destination
    if (-not (Test-Path $destinationDir)) {
      New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
    }

    Copy-Item $SourceDll $destination -Force
  }
}

$previousHostIntegration = [Environment]::GetEnvironmentVariable("FR_RUN_HOST_INTEGRATION", "Process")
$previousRequireSnapshot = [Environment]::GetEnvironmentVariable("FR_REQUIRE_VSS_SNAPSHOT", "Process")
[Environment]::SetEnvironmentVariable("FR_RUN_HOST_INTEGRATION", "1", "Process")
$requireSnapshotValue = "1"
if ($AllowNoSnapshots) {
  $requireSnapshotValue = "0"
}
[Environment]::SetEnvironmentVariable("FR_REQUIRE_VSS_SNAPSHOT", $requireSnapshotValue, "Process")

$archiveEnabled = -not $NoArchive
$timestampUtc = [DateTimeOffset]::UtcNow
$runStamp = $timestampUtc.ToString("yyyyMMdd-HHmmss")
$artifactDirectory = Join-Path $ArtifactRoot $runStamp
$trxFileName = "host-vss-validation.trx"
$gitCommit = $null
$gitBranch = $null
$validationSucceeded = $false
$validationError = $null

try {
  Push-Location "$PSScriptRoot\.."
  try {
    $repoRoot = (Get-Location).Path
    $engineReleaseDll = Join-Path $repoRoot "engine\target\release\fr_ffi.dll"
    $engineDestinations = @(
      (Join-Path $repoRoot "ui\windows-app\tests\FileRecovery.WindowsApp.Tests\bin\Release\net8.0-windows\file_recovery_engine.dll"),
      (Join-Path $repoRoot "ui\windows-app\src\FileRecovery.WindowsApp\bin\Release\net8.0-windows\file_recovery_engine.dll"),
      (Join-Path $repoRoot "ui\windows-app\src\FileRecovery.WindowsApp.Core\bin\Release\net8.0-windows\file_recovery_engine.dll")
    )

    if (-not $NoBuild) {
      $cargoPath = Resolve-ToolPath -Name "cargo"
      if (-not $cargoPath) {
        throw "cargo not found. Install Rust toolchain before running host validation."
      }

      Push-Location (Join-Path $repoRoot "engine")
      try {
        & $cargoPath build -p fr-ffi --release
        if ($LASTEXITCODE -ne 0) {
          throw "cargo build -p fr-ffi --release failed with exit code $LASTEXITCODE."
        }
      }
      finally {
        Pop-Location
      }

      & dotnet build "ui/windows-app/FileRecovery.WindowsApp.sln" -c Release
      if ($LASTEXITCODE -ne 0) {
        throw "Release build failed with exit code $LASTEXITCODE."
      }
    }

    Sync-EngineRuntimeDll -SourceDll $engineReleaseDll -DestinationPaths $engineDestinations

    if ($archiveEnabled) {
      New-Item -ItemType Directory -Path $artifactDirectory -Force | Out-Null
    }

    $gitCommit = & git rev-parse --short HEAD 2>$null
    if ($LASTEXITCODE -ne 0) { $gitCommit = $null }
    $gitBranch = & git rev-parse --abbrev-ref HEAD 2>$null
    if ($LASTEXITCODE -ne 0) { $gitBranch = $null }

    $args = @(
      "test",
      "ui/windows-app/FileRecovery.WindowsApp.sln",
      "-c", "Release",
      "--filter", "Category=HostVssIntegration"
    )
    $args += "--no-build"
    if ($archiveEnabled) {
      $args += "--logger"
      $args += "trx;LogFileName=$trxFileName"
      $args += "--results-directory"
      $args += $artifactDirectory
    }

    & dotnet @args
    if ($LASTEXITCODE -ne 0) {
      throw "Host VSS validation failed with exit code $LASTEXITCODE."
    }

    $validationSucceeded = $true
  }
  catch {
    $validationError = $_.Exception.Message
    throw
  }
  finally {
    if ($archiveEnabled) {
      $trxPath = Join-Path $artifactDirectory $trxFileName
      $manifestPath = Join-Path $artifactDirectory "host-vss-validation-manifest.json"
      $manifest = [ordered]@{
        run_utc = $timestampUtc.ToString("O")
        run_stamp = $runStamp
        succeeded = $validationSucceeded
        error = $validationError
        elevated = $isAdmin
        machine = $env:COMPUTERNAME
        user = $env:USERNAME
        allow_no_snapshots = [bool]$AllowNoSnapshots
        artifact_directory = [System.IO.Path]::GetFullPath($artifactDirectory)
        trx_path = if (Test-Path $trxPath) { [System.IO.Path]::GetFullPath($trxPath) } else { $null }
        git_branch = if ([string]::IsNullOrWhiteSpace($gitBranch)) { $null } else { $gitBranch.Trim() }
        git_commit = if ([string]::IsNullOrWhiteSpace($gitCommit)) { $null } else { $gitCommit.Trim() }
      }

      $manifest | ConvertTo-Json -Depth 4 | Set-Content -Path $manifestPath -Encoding UTF8
      Write-Host "Host VSS validation artifacts: $([System.IO.Path]::GetFullPath($artifactDirectory))"
    }
  }
}
finally {
  try {
    Pop-Location
  }
  catch {
    # best-effort location restore
  }
  [Environment]::SetEnvironmentVariable("FR_RUN_HOST_INTEGRATION", $previousHostIntegration, "Process")
  [Environment]::SetEnvironmentVariable("FR_REQUIRE_VSS_SNAPSHOT", $previousRequireSnapshot, "Process")
}
