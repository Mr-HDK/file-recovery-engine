param(
  [string]$OutputPath = "",
  [switch]$NoBuild,
  [int]$Iterations = 0,
  [uint32]$MaxEntries = 0,
  [switch]$NoWarmup
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

& (Join-Path $PSScriptRoot "generate-ext-synthetic-corpus.ps1")

$invokeParams = @{
  ManifestPath = ".\testdata\raw-images\ext-corpus\manifest.synthetic.json"
}

if (![string]::IsNullOrWhiteSpace($OutputPath)) {
  $invokeParams.OutputPath = $OutputPath
}

if ($NoBuild) {
  $invokeParams.NoBuild = $true
}

if ($Iterations -gt 0) {
  $invokeParams.Iterations = $Iterations
}

if ($MaxEntries -gt 0) {
  $invokeParams.MaxEntries = $MaxEntries
}

if ($NoWarmup) {
  $invokeParams.NoWarmup = $true
}

& (Join-Path $PSScriptRoot "benchmark-ext-corpus.ps1") @invokeParams
exit $LASTEXITCODE
