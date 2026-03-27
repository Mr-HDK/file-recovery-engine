param(
  [switch]$NoBuild,
  [switch]$NoArchive,
  [string]$ArtifactRoot
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
  $ArtifactRoot = Join-Path $PSScriptRoot "..\artifacts\host-validation"
}

if (-not ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)) {
  throw "This script requires Windows."
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
  IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
  throw "Run this script from an elevated Administrator PowerShell."
}

$previous = [Environment]::GetEnvironmentVariable("FR_RUN_HOST_INTEGRATION", "Process")
[Environment]::SetEnvironmentVariable("FR_RUN_HOST_INTEGRATION", "1", "Process")

$archiveEnabled = -not $NoArchive
$timestampUtc = [DateTimeOffset]::UtcNow
$runStamp = $timestampUtc.ToString("yyyyMMdd-HHmmss")
$artifactDirectory = Join-Path $ArtifactRoot $runStamp
$trxFileName = "host-ntfs-stream-validation.trx"
$gitCommit = $null
$gitBranch = $null
$validationSucceeded = $false
$validationError = $null

try {
  Push-Location "$PSScriptRoot\.."
  try {
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
      "--filter", "Category=HostIntegration"
    )
    if ($NoBuild) {
      $args += "--no-build"
    }
    if ($archiveEnabled) {
      $args += "--logger"
      $args += "trx;LogFileName=$trxFileName"
      $args += "--results-directory"
      $args += $artifactDirectory
    }

    & dotnet @args
    if ($LASTEXITCODE -ne 0) {
      throw "Host NTFS stream validation failed with exit code $LASTEXITCODE."
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
      $manifestPath = Join-Path $artifactDirectory "host-validation-manifest.json"
      $manifest = [ordered]@{
        run_utc = $timestampUtc.ToString("O")
        run_stamp = $runStamp
        succeeded = $validationSucceeded
        error = $validationError
        elevated = $isAdmin
        machine = $env:COMPUTERNAME
        user = $env:USERNAME
        artifact_directory = [System.IO.Path]::GetFullPath($artifactDirectory)
        trx_path = if (Test-Path $trxPath) { [System.IO.Path]::GetFullPath($trxPath) } else { $null }
        git_branch = if ([string]::IsNullOrWhiteSpace($gitBranch)) { $null } else { $gitBranch.Trim() }
        git_commit = if ([string]::IsNullOrWhiteSpace($gitCommit)) { $null } else { $gitCommit.Trim() }
      }

      $manifest | ConvertTo-Json -Depth 4 | Set-Content -Path $manifestPath -Encoding UTF8
      Write-Host "Host validation artifacts: $([System.IO.Path]::GetFullPath($artifactDirectory))"
    }
  }
  finally {
    Pop-Location
  }
}
finally {
  [Environment]::SetEnvironmentVariable("FR_RUN_HOST_INTEGRATION", $previous, "Process")
}
