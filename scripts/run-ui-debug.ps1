param(
  [switch]$NoBuild,
  [switch]$NoAutoStop
)

$ErrorActionPreference = 'Stop'

function Stop-RunningUiProcess {
  param(
    [switch]$NoAutoStop
  )

  $running = Get-Process FileRecovery.WindowsApp -ErrorAction SilentlyContinue
  if (-not $running) {
    return
  }

  if ($NoAutoStop) {
    throw "FileRecovery.WindowsApp is already running. Close it or rerun without -NoAutoStop."
  }

  foreach ($process in $running) {
    try {
      Stop-Process -Id $process.Id -Force -ErrorAction Stop
    } catch {
      throw "Unable to stop FileRecovery.WindowsApp (PID $($process.Id)). Run this script from Administrator PowerShell."
    }
  }
}

function Copy-EngineDllIfAvailable {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RepoRoot,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
  )

  $releaseDll = Join-Path $RepoRoot "engine\target\release\fr_ffi.dll"
  $debugDll = Join-Path $RepoRoot "engine\target\debug\fr_ffi.dll"
  $destination = Join-Path $OutputDirectory "file_recovery_engine.dll"

  if (Test-Path $releaseDll) {
    Copy-Item $releaseDll $destination -Force
    Write-Host "Engine DLL synced from release build."
    return
  }

  if (Test-Path $debugDll) {
    Copy-Item $debugDll $destination -Force
    Write-Host "Engine DLL synced from debug build."
    return
  }

  Write-Warning "Engine DLL not found. App may run in mock mode. Build engine with: cargo build -p fr-ffi --release"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$project = Join-Path $repoRoot "ui\windows-app\src\FileRecovery.WindowsApp\FileRecovery.WindowsApp.csproj"
$outputDirectory = Join-Path $repoRoot "ui\windows-app\src\FileRecovery.WindowsApp\bin\Debug\net8.0-windows"
$exePath = Join-Path $outputDirectory "FileRecovery.WindowsApp.exe"

Stop-RunningUiProcess -NoAutoStop:$NoAutoStop

if (-not $NoBuild) {
  & dotnet build $project -c Debug
  if ($LASTEXITCODE -ne 0) {
    throw "Debug build failed with exit code $LASTEXITCODE."
  }
}

if (-not (Test-Path $outputDirectory)) {
  New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

Copy-EngineDllIfAvailable -RepoRoot $repoRoot -OutputDirectory $outputDirectory

if (-not (Test-Path $exePath)) {
  throw "UI executable not found at $exePath"
}

Start-Process -FilePath $exePath -WorkingDirectory $outputDirectory
Write-Host "Launched Debug UI: $exePath"
