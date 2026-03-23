param(
  [string]$ManifestPath = ".\testdata\raw-images\ntfs-corpus\manifest.json",
  [string]$OutputPath = "",
  [switch]$AllowMissing,
  [int]$Iterations = 0,
  [uint32]$MaxRecords = 0,
  [switch]$NoWarmup
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$manifestFullPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $ManifestPath))
if (!(Test-Path $manifestFullPath)) {
  throw "Manifest not found: $manifestFullPath"
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $OutputPath = Join-Path $repoRoot "tools\benchmark-results\ntfs-corpus-$stamp.json"
}

$outputFullPath = [System.IO.Path]::GetFullPath($OutputPath)
New-Item -ItemType Directory -Force -Path ([System.IO.Path]::GetDirectoryName($outputFullPath)) | Out-Null

$projectPath = Join-Path $repoRoot "tools\benchmarks\NtfsCorpusBench\NtfsCorpusBench.csproj"

$runnerArgs = @(
  "run",
  "--project", $projectPath,
  "-c", "Release",
  "--",
  "--manifest", $manifestFullPath,
  "--output", $outputFullPath
)

if ($AllowMissing) {
  $runnerArgs += "--allow-missing"
}

if ($Iterations -gt 0) {
  $runnerArgs += @("--iterations", $Iterations.ToString())
}

if ($MaxRecords -gt 0) {
  $runnerArgs += @("--max-records", $MaxRecords.ToString())
}

if ($NoWarmup) {
  $runnerArgs += "--no-warmup"
}

& dotnet $runnerArgs
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}

$report = Get-Content -Path $outputFullPath -Raw | ConvertFrom-Json
$markdownPath = [System.IO.Path]::ChangeExtension($outputFullPath, ".md")

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# NTFS Corpus Benchmark")
$lines.Add("")
$lines.Add("Generated (UTC): $($report.generatedUtc)")
$lines.Add("Engine: $($report.engineVersion)")
$lines.Add("Manifest: $($report.manifestPath)")
$lines.Add("")
$lines.Add("| Case | Status | Mean ms | Best ms | Avg Parsed | Avg Candidates |")
$lines.Add("|---|---|---:|---:|---:|---:|")

foreach ($case in $report.cases) {
  $mean = "{0:N2}" -f [double]$case.meanElapsedMs
  $best = "{0:N2}" -f [double]$case.bestElapsedMs
  $avgParsed = "{0:N0}" -f [double]$case.averageParsedRecords
  $avgCandidates = "{0:N0}" -f [double]$case.averageCandidates
  $lines.Add("| $($case.id) | $($case.status) | $mean | $best | $avgParsed | $avgCandidates |")
}

$lines.Add("")
$lines.Add("Totals: ok=$($report.totals.ok), partial=$($report.totals.partial), missing=$($report.totals.missing), failed=$($report.totals.failed), engine-unavailable=$($report.totals.engineUnavailable)")

Set-Content -Path $markdownPath -Value ($lines -join [Environment]::NewLine)

Write-Host "Benchmark JSON: $outputFullPath"
Write-Host "Benchmark Markdown: $markdownPath"
