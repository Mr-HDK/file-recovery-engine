param(
  [Parameter(Mandatory = $true)]
  [string]$BaselineProfile,
  [Parameter(Mandatory = $true)]
  [string]$CandidateProfile,
  [string]$ArtifactRoot,
  [string]$OutputPath,
  [switch]$AsJson
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
  $ArtifactRoot = Join-Path $PSScriptRoot "..\artifacts\host-matrix"
}

function Resolve-ProfileRoot {
  param(
    [string]$Root,
    [string]$Profile
  )

  $profileRoot = Join-Path $Root $Profile
  if (-not (Test-Path $profileRoot)) {
    throw "Profile root not found: $profileRoot"
  }

  return (Resolve-Path $profileRoot).Path
}

function Invoke-ArtifactCompare {
  param(
    [string]$Root
  )

  if (-not (Test-Path $Root)) {
    return $null
  }

  $runDirs = Get-ChildItem -Path $Root -Directory | Sort-Object Name
  if ($runDirs.Count -lt 2) {
    return $null
  }

  $compareScript = Join-Path $PSScriptRoot "compare-host-validation-artifacts.ps1"
  $json = & $compareScript -ArtifactRoot $Root -AsJson
  if ($LASTEXITCODE -ne 0) {
    throw "Artifact compare failed for $Root with exit code $LASTEXITCODE."
  }

  return ($json | Out-String | ConvertFrom-Json)
}

$baselineRoot = Resolve-ProfileRoot -Root $ArtifactRoot -Profile $BaselineProfile
$candidateRoot = Resolve-ProfileRoot -Root $ArtifactRoot -Profile $CandidateProfile

$baselineManifestPath = Join-Path $baselineRoot "profile-manifest.json"
$candidateManifestPath = Join-Path $candidateRoot "profile-manifest.json"

$baselineManifest = if (Test-Path $baselineManifestPath) {
  Get-Content -Path $baselineManifestPath -Raw | ConvertFrom-Json
} else {
  $null
}

$candidateManifest = if (Test-Path $candidateManifestPath) {
  Get-Content -Path $candidateManifestPath -Raw | ConvertFrom-Json
} else {
  $null
}

$baselineNtfsRoot = Join-Path $baselineRoot "ntfs"
$candidateNtfsRoot = Join-Path $candidateRoot "ntfs"
$baselineVssRoot = Join-Path $baselineRoot "vss"
$candidateVssRoot = Join-Path $candidateRoot "vss"

$report = [ordered]@{
  generated_utc = [DateTimeOffset]::UtcNow.ToString("O")
  artifact_root = (Resolve-Path $ArtifactRoot).Path
  baseline_profile = [ordered]@{
    name = $BaselineProfile
    root = $baselineRoot
    manifest_path = if (Test-Path $baselineManifestPath) { $baselineManifestPath } else { $null }
    machine = $baselineManifest.machine
    windows_version = $baselineManifest.windows_version
  }
  candidate_profile = [ordered]@{
    name = $CandidateProfile
    root = $candidateRoot
    manifest_path = if (Test-Path $candidateManifestPath) { $candidateManifestPath } else { $null }
    machine = $candidateManifest.machine
    windows_version = $candidateManifest.windows_version
  }
  ntfs = [ordered]@{
    baseline_root = if (Test-Path $baselineNtfsRoot) { $baselineNtfsRoot } else { $null }
    candidate_root = if (Test-Path $candidateNtfsRoot) { $candidateNtfsRoot } else { $null }
    baseline_latest_compare = Invoke-ArtifactCompare -Root $baselineNtfsRoot
    candidate_latest_compare = Invoke-ArtifactCompare -Root $candidateNtfsRoot
  }
  vss = [ordered]@{
    baseline_root = if (Test-Path $baselineVssRoot) { $baselineVssRoot } else { $null }
    candidate_root = if (Test-Path $candidateVssRoot) { $candidateVssRoot } else { $null }
    baseline_latest_compare = Invoke-ArtifactCompare -Root $baselineVssRoot
    candidate_latest_compare = Invoke-ArtifactCompare -Root $candidateVssRoot
  }
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
  $outputDirectory = Split-Path -Parent $OutputPath
  if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
  }
  $report | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8
}

if ($AsJson) {
  $report | ConvertTo-Json -Depth 10
  exit 0
}

Write-Host "Host profile comparison summary"
Write-Host "  Baseline : $BaselineProfile ($baselineRoot)"
Write-Host "  Candidate: $CandidateProfile ($candidateRoot)"
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
  Write-Host "  Output   : $([System.IO.Path]::GetFullPath($OutputPath))"
}
