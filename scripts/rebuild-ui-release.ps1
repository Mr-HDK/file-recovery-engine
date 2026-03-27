param(
  [switch]$SkipEngineBuild,
  [switch]$Launch,
  [switch]$NoAutoStop
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

function Stop-RunningUiProcess {
  param(
    [switch]$NoAutoStop
  )

  $running = Get-Process FileRecovery.WindowsApp -ErrorAction SilentlyContinue
  if (-not $running) {
    return
  }

  if ($NoAutoStop) {
    throw "FileRecovery.WindowsApp is running. Close it first or rerun without -NoAutoStop."
  }

  foreach ($process in $running) {
    try {
      Stop-Process -Id $process.Id -Force -ErrorAction Stop
    } catch {
      throw "Unable to stop FileRecovery.WindowsApp (PID $($process.Id)). Run this script from Administrator PowerShell."
    }
  }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$project = Join-Path $repoRoot "ui\windows-app\src\FileRecovery.WindowsApp\FileRecovery.WindowsApp.csproj"
$releaseOutput = Join-Path $repoRoot "ui\windows-app\src\FileRecovery.WindowsApp\bin\Release\net8.0-windows"
$releaseExe = Join-Path $releaseOutput "FileRecovery.WindowsApp.exe"
$engineReleaseDll = Join-Path $repoRoot "engine\target\release\fr_ffi.dll"
$engineOutputDll = Join-Path $releaseOutput "file_recovery_engine.dll"

Stop-RunningUiProcess -NoAutoStop:$NoAutoStop

if (-not $SkipEngineBuild) {
  $cargoPath = Resolve-ToolPath -Name "cargo"
  if (-not $cargoPath) {
    throw "cargo not found. Install Rust toolchain or rerun with -SkipEngineBuild if engine is already built."
  }

  Push-Location (Join-Path $repoRoot "engine")
  try {
    & $cargoPath build -p fr-ffi --release
    if ($LASTEXITCODE -ne 0) {
      throw "cargo build -p fr-ffi --release failed with exit code $LASTEXITCODE."
    }
  } finally {
    Pop-Location
  }
}

if (-not (Test-Path $engineReleaseDll)) {
  throw "Engine DLL not found at $engineReleaseDll"
}

& dotnet build $project -c Release
if ($LASTEXITCODE -ne 0) {
  throw "Release UI build failed with exit code $LASTEXITCODE."
}

Copy-Item $engineReleaseDll $engineOutputDll -Force

if (-not (Test-Path $releaseExe)) {
  throw "Release executable not found at $releaseExe"
}

Write-Host "Release package is ready:"
Write-Host "  UI: $releaseExe"
Write-Host "  Engine: $engineOutputDll"

if ($Launch) {
  Start-Process -FilePath $releaseExe -WorkingDirectory $releaseOutput
  Write-Host "Launched Release UI."
}
