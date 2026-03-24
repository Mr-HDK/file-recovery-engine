param(
  [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'

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

try {
  Push-Location "$PSScriptRoot\.."
  try {
    $args = @(
      "test",
      "ui/windows-app/FileRecovery.WindowsApp.sln",
      "-c", "Release",
      "--filter", "Category=HostIntegration"
    )
    if ($NoBuild) {
      $args += "--no-build"
    }

    & dotnet @args
    if ($LASTEXITCODE -ne 0) {
      throw "Host NTFS stream validation failed with exit code $LASTEXITCODE."
    }
  }
  finally {
    Pop-Location
  }
}
finally {
  [Environment]::SetEnvironmentVariable("FR_RUN_HOST_INTEGRATION", $previous, "Process")
}

