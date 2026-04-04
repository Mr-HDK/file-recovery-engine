param(
  [switch]$NoBuild,
  [switch]$NoArchive,
  [string]$ArtifactRoot,
  [string]$ManifestPath = ".\testdata\raw-images\ext-corpus\manifest.json",
  [switch]$AllowMissingImages,
  [int]$Iterations = 0,
  [uint32]$MaxEntries = 0,
  [switch]$NoWarmup
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
  $ArtifactRoot = Join-Path $PSScriptRoot "..\artifacts\host-validation-ext"
}

$archiveEnabled = -not $NoArchive
$timestampUtc = [DateTimeOffset]::UtcNow
$runStamp = $timestampUtc.ToString("yyyyMMdd-HHmmss")
$artifactDirectory = Join-Path $ArtifactRoot $runStamp
$gitCommit = $null
$gitBranch = $null
$validationSucceeded = $false
$validationError = $null
$benchmarkJsonPath = $null
$benchmarkMarkdownPath = $null
$resolvedManifestPath = $null

try {
  Push-Location "$PSScriptRoot\.."
  try {
    $repoRoot = (Get-Location).Path
    $resolvedManifestPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $ManifestPath))
    if (-not (Test-Path $resolvedManifestPath)) {
      throw "ext corpus manifest not found: $resolvedManifestPath"
    }

    if ($archiveEnabled) {
      New-Item -ItemType Directory -Path $artifactDirectory -Force | Out-Null
      $benchmarkJsonPath = Join-Path $artifactDirectory "ext-corpus-benchmark.json"
    } else {
      $benchmarkJsonPath = Join-Path ([System.IO.Path]::GetTempPath()) "fr-ext-host-validation-$runStamp.json"
    }

    $benchmarkMarkdownPath = [System.IO.Path]::ChangeExtension($benchmarkJsonPath, ".md")

    $gitCommit = & git rev-parse --short HEAD 2>$null
    if ($LASTEXITCODE -ne 0) { $gitCommit = $null }
    $gitBranch = & git rev-parse --abbrev-ref HEAD 2>$null
    if ($LASTEXITCODE -ne 0) { $gitBranch = $null }

    $benchmarkArgs = @{
      ManifestPath = $resolvedManifestPath
      OutputPath = $benchmarkJsonPath
    }
    if ($AllowMissingImages) {
      $benchmarkArgs.AllowMissing = $true
    }
    if ($NoBuild) {
      $benchmarkArgs.NoBuild = $true
    }
    if ($Iterations -gt 0) {
      $benchmarkArgs.Iterations = $Iterations
    }
    if ($MaxEntries -gt 0) {
      $benchmarkArgs.MaxEntries = $MaxEntries
    }
    if ($NoWarmup) {
      $benchmarkArgs.NoWarmup = $true
    }

    & (Join-Path $PSScriptRoot "benchmark-ext-corpus.ps1") @benchmarkArgs
    if ($LASTEXITCODE -ne 0) {
      throw "ext corpus benchmark failed with exit code $LASTEXITCODE."
    }

    $validationSucceeded = $true
  }
  catch {
    $validationError = $_.Exception.Message
    throw
  }
  finally {
    if ($archiveEnabled) {
      $manifestPathOut = Join-Path $artifactDirectory "host-ext-validation-manifest.json"
      $manifest = [ordered]@{
        run_utc = $timestampUtc.ToString("O")
        run_stamp = $runStamp
        succeeded = $validationSucceeded
        error = $validationError
        machine = $env:COMPUTERNAME
        user = $env:USERNAME
        artifact_directory = [System.IO.Path]::GetFullPath($artifactDirectory)
        benchmark_json_path = if (Test-Path $benchmarkJsonPath) { [System.IO.Path]::GetFullPath($benchmarkJsonPath) } else { $null }
        benchmark_markdown_path = if (Test-Path $benchmarkMarkdownPath) { [System.IO.Path]::GetFullPath($benchmarkMarkdownPath) } else { $null }
        manifest_path = if (-not [string]::IsNullOrWhiteSpace($resolvedManifestPath)) { $resolvedManifestPath } else { $null }
        allow_missing_images = [bool]$AllowMissingImages
        no_warmup = [bool]$NoWarmup
        iterations = if ($Iterations -gt 0) { $Iterations } else { $null }
        max_entries = if ($MaxEntries -gt 0) { $MaxEntries } else { $null }
        git_branch = if ([string]::IsNullOrWhiteSpace($gitBranch)) { $null } else { $gitBranch.Trim() }
        git_commit = if ([string]::IsNullOrWhiteSpace($gitCommit)) { $null } else { $gitCommit.Trim() }
      }

      $manifest | ConvertTo-Json -Depth 6 | Set-Content -Path $manifestPathOut -Encoding UTF8
      Write-Host "Host ext validation artifacts: $([System.IO.Path]::GetFullPath($artifactDirectory))"
    } else {
      Write-Host "Host ext validation completed without artifact archiving."
      if (Test-Path $benchmarkJsonPath) {
        Write-Host "Benchmark JSON: $([System.IO.Path]::GetFullPath($benchmarkJsonPath))"
      }
      if (Test-Path $benchmarkMarkdownPath) {
        Write-Host "Benchmark Markdown: $([System.IO.Path]::GetFullPath($benchmarkMarkdownPath))"
      }
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
}
