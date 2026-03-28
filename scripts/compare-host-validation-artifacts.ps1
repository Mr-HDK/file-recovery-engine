param(
  [string]$ArtifactRoot,
  [string]$BaselineRun,
  [string]$CandidateRun,
  [string]$OutputPath,
  [switch]$AsJson
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
  $ArtifactRoot = Join-Path $PSScriptRoot "..\artifacts\host-validation"
}

function Resolve-RunDirectory {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Root,
    [string]$Run
  )

  if (-not [string]::IsNullOrWhiteSpace($Run)) {
    if ([System.IO.Path]::IsPathRooted($Run)) {
      if (-not (Test-Path $Run)) {
        throw "Run directory not found: $Run"
      }

      return (Resolve-Path $Run).Path
    }

    $combined = Join-Path $Root $Run
    if (-not (Test-Path $combined)) {
      throw "Run directory not found: $combined"
    }

    return (Resolve-Path $combined).Path
  }

  return $null
}

function Find-ManifestPath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RunDirectory
  )

  $manifest = Get-ChildItem -Path $RunDirectory -File -Filter "*manifest.json" |
    Sort-Object Name |
    Select-Object -First 1
  if (-not $manifest) {
    throw "No manifest JSON file found in $RunDirectory"
  }

  return $manifest.FullName
}

function Find-TrxPath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RunDirectory,
    [Parameter(Mandatory = $true)]
    [object]$Manifest
  )

  if ($Manifest.PSObject.Properties.Name -contains "trx_path" -and
      -not [string]::IsNullOrWhiteSpace($Manifest.trx_path) -and
      (Test-Path $Manifest.trx_path)) {
    return (Resolve-Path $Manifest.trx_path).Path
  }

  $trx = Get-ChildItem -Path $RunDirectory -File -Filter "*.trx" |
    Sort-Object Name |
    Select-Object -First 1
  if (-not $trx) {
    return $null
  }

  return $trx.FullName
}

function Read-TrxSummary {
  param(
    [string]$TrxPath
  )

  if ([string]::IsNullOrWhiteSpace($TrxPath) -or -not (Test-Path $TrxPath)) {
    return [ordered]@{
      path = $TrxPath
      found = $false
      counters = $null
      tests = @()
    }
  }

  [xml]$xml = Get-Content -Path $TrxPath -Raw
  $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
  $ns.AddNamespace("t", "http://microsoft.com/schemas/VisualStudio/TeamTest/2010")

  $counterNode = $xml.SelectSingleNode("/t:TestRun/t:ResultSummary/t:Counters", $ns)
  $counters = if ($counterNode) {
    [ordered]@{
      total = [int]$counterNode.total
      executed = [int]$counterNode.executed
      passed = [int]$counterNode.passed
      failed = [int]$counterNode.failed
      error = [int]$counterNode.error
      timeout = [int]$counterNode.timeout
      aborted = [int]$counterNode.aborted
      inconclusive = [int]$counterNode.inconclusive
      not_executed = [int]$counterNode.notExecuted
      warning = [int]$counterNode.warning
    }
  } else {
    $null
  }

  $resultNodes = $xml.SelectNodes("/t:TestRun/t:Results/t:UnitTestResult", $ns)
  $tests = @()
  foreach ($result in $resultNodes) {
    $tests += [ordered]@{
      name = [string]$result.testName
      outcome = [string]$result.outcome
      duration = [string]$result.duration
    }
  }

  return [ordered]@{
    path = (Resolve-Path $TrxPath).Path
    found = $true
    counters = $counters
    tests = $tests
  }
}

function Build-TestOutcomeMap {
  param(
    [Parameter(Mandatory = $true)]
    [object[]]$Tests
  )

  $map = @{}
  foreach ($test in $Tests) {
    $map[$test.name] = $test.outcome
  }

  return $map
}

if (-not (Test-Path $ArtifactRoot)) {
  throw "Artifact root not found: $ArtifactRoot"
}

$resolvedRoot = (Resolve-Path $ArtifactRoot).Path
$baselineDirectory = Resolve-RunDirectory -Root $resolvedRoot -Run $BaselineRun
$candidateDirectory = Resolve-RunDirectory -Root $resolvedRoot -Run $CandidateRun

if (-not $baselineDirectory -or -not $candidateDirectory) {
  $runDirectories = Get-ChildItem -Path $resolvedRoot -Directory |
    Sort-Object Name
  if ($runDirectories.Count -lt 2) {
    throw "Need at least two run directories under $resolvedRoot to compare."
  }

  if (-not $baselineDirectory) {
    $baselineDirectory = $runDirectories[$runDirectories.Count - 2].FullName
  }
  if (-not $candidateDirectory) {
    $candidateDirectory = $runDirectories[$runDirectories.Count - 1].FullName
  }
}

$baselineManifestPath = Find-ManifestPath -RunDirectory $baselineDirectory
$candidateManifestPath = Find-ManifestPath -RunDirectory $candidateDirectory
$baselineManifest = Get-Content -Path $baselineManifestPath -Raw | ConvertFrom-Json
$candidateManifest = Get-Content -Path $candidateManifestPath -Raw | ConvertFrom-Json

$baselineTrxPath = Find-TrxPath -RunDirectory $baselineDirectory -Manifest $baselineManifest
$candidateTrxPath = Find-TrxPath -RunDirectory $candidateDirectory -Manifest $candidateManifest
$baselineTrx = Read-TrxSummary -TrxPath $baselineTrxPath
$candidateTrx = Read-TrxSummary -TrxPath $candidateTrxPath

$manifestKeys = @("machine", "user", "git_branch", "git_commit", "elevated", "succeeded", "error")
$manifestDifferences = @()
foreach ($key in $manifestKeys) {
  $baselineValue = if ($baselineManifest.PSObject.Properties.Name -contains $key) { $baselineManifest.$key } else { $null }
  $candidateValue = if ($candidateManifest.PSObject.Properties.Name -contains $key) { $candidateManifest.$key } else { $null }
  if ("$baselineValue" -ne "$candidateValue") {
    $manifestDifferences += [ordered]@{
      key = $key
      baseline = $baselineValue
      candidate = $candidateValue
    }
  }
}

$counterDifferences = @()
if ($baselineTrx.found -and $candidateTrx.found -and $baselineTrx.counters -and $candidateTrx.counters) {
  foreach ($key in $baselineTrx.counters.Keys) {
    $baselineValue = [int]$baselineTrx.counters[$key]
    $candidateValue = [int]$candidateTrx.counters[$key]
    if ($baselineValue -ne $candidateValue) {
      $counterDifferences += [ordered]@{
        counter = $key
        baseline = $baselineValue
        candidate = $candidateValue
        delta = $candidateValue - $baselineValue
      }
    }
  }
}

$baselineTests = Build-TestOutcomeMap -Tests $baselineTrx.tests
$candidateTests = Build-TestOutcomeMap -Tests $candidateTrx.tests
$allTestNames = @($baselineTests.Keys + $candidateTests.Keys | Sort-Object -Unique)
$testOutcomeDifferences = @()
foreach ($testName in $allTestNames) {
  $baselineOutcome = if ($baselineTests.ContainsKey($testName)) { $baselineTests[$testName] } else { "<missing>" }
  $candidateOutcome = if ($candidateTests.ContainsKey($testName)) { $candidateTests[$testName] } else { "<missing>" }
  if ($baselineOutcome -ne $candidateOutcome) {
    $testOutcomeDifferences += [ordered]@{
      test = $testName
      baseline = $baselineOutcome
      candidate = $candidateOutcome
    }
  }
}

$report = [ordered]@{
  generated_utc = [DateTimeOffset]::UtcNow.ToString("O")
  artifact_root = $resolvedRoot
  baseline = [ordered]@{
    run_directory = (Resolve-Path $baselineDirectory).Path
    manifest_path = $baselineManifestPath
    trx_path = $baselineTrx.path
    succeeded = [bool]$baselineManifest.succeeded
    git_branch = $baselineManifest.git_branch
    git_commit = $baselineManifest.git_commit
  }
  candidate = [ordered]@{
    run_directory = (Resolve-Path $candidateDirectory).Path
    manifest_path = $candidateManifestPath
    trx_path = $candidateTrx.path
    succeeded = [bool]$candidateManifest.succeeded
    git_branch = $candidateManifest.git_branch
    git_commit = $candidateManifest.git_commit
  }
  manifest_differences = $manifestDifferences
  trx_counter_differences = $counterDifferences
  test_outcome_differences = $testOutcomeDifferences
  no_drift = ($manifestDifferences.Count -eq 0 -and $counterDifferences.Count -eq 0 -and $testOutcomeDifferences.Count -eq 0)
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
  $outputDirectory = Split-Path -Parent $OutputPath
  if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
  }
  $report | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
}

if ($AsJson) {
  $report | ConvertTo-Json -Depth 8
  exit 0
}

Write-Host "Host validation drift report"
Write-Host "  Baseline : $($report.baseline.run_directory)"
Write-Host "  Candidate: $($report.candidate.run_directory)"
Write-Host "  Drift    : $(if ($report.no_drift) { 'none detected' } else { 'detected' })"

if ($manifestDifferences.Count -gt 0) {
  Write-Host ""
  Write-Host "Manifest differences:"
  foreach ($diff in $manifestDifferences) {
    Write-Host "  - $($diff.key): '$($diff.baseline)' -> '$($diff.candidate)'"
  }
}

if ($counterDifferences.Count -gt 0) {
  Write-Host ""
  Write-Host "TRX counter differences:"
  foreach ($diff in $counterDifferences) {
    Write-Host "  - $($diff.counter): $($diff.baseline) -> $($diff.candidate) (delta $($diff.delta))"
  }
}

if ($testOutcomeDifferences.Count -gt 0) {
  Write-Host ""
  Write-Host "Test outcome differences:"
  foreach ($diff in $testOutcomeDifferences) {
    Write-Host "  - $($diff.test): $($diff.baseline) -> $($diff.candidate)"
  }
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
  Write-Host ""
  Write-Host "Report JSON written: $([System.IO.Path]::GetFullPath($OutputPath))"
}
