param(
    [string]$OutputRoot = "artifacts/acceptance",
    [switch]$SkipRust,
    [switch]$SkipDotNet,
    [switch]$SkipSignatures
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$outputDir = Join-Path $repoRoot $OutputRoot
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

$results = @()

function Invoke-Check {
    param(
        [string]$Name,
        [string]$Command,
        [string]$Workdir
    )

    Write-Host "[acceptance] $Name"
    $start = Get-Date
    Push-Location $Workdir
    $message = $null
    try {
        $global:LASTEXITCODE = 0
        Invoke-Expression $Command
        if ($LASTEXITCODE -ne 0) {
            throw "Command exited with code $LASTEXITCODE."
        }
        $status = "passed"
    }
    catch {
        $status = "failed"
        $message = $_.Exception.Message
    }
    finally {
        Pop-Location
    }

    $end = Get-Date
    $duration = [Math]::Round(($end - $start).TotalSeconds, 2)
    $item = [ordered]@{
        name = $Name
        command = $Command
        status = $status
        duration_seconds = $duration
        executed_utc = [DateTimeOffset]::UtcNow.ToString("o")
    }
    if ($status -eq "failed") {
        $item.error = $message
    }
    $script:results += [pscustomobject]$item
}

if (-not $SkipRust) {
    Invoke-Check -Name "rust-fr-raid-ffi" -Command "cargo test -p fr-raid -p fr-ffi" -Workdir (Join-Path $repoRoot "engine")
}

if (-not $SkipDotNet) {
    Invoke-Check -Name "dotnet-tests-windows-app" -Command "dotnet test ui/windows-app/tests/FileRecovery.WindowsApp.Tests/FileRecovery.WindowsApp.Tests.csproj -c Release" -Workdir $repoRoot
    Invoke-Check -Name "dotnet-build-windows-app" -Command "dotnet build ui/windows-app/src/FileRecovery.WindowsApp/FileRecovery.WindowsApp.csproj -c Release" -Workdir $repoRoot
}

if (-not $SkipSignatures) {
    Invoke-Check -Name "signature-pack-matrix-export" -Command "powershell -ExecutionPolicy Bypass -File scripts/signatures/export-signature-pack-matrix.ps1 -OutputPath artifacts/acceptance/signature-pack-compatibility-matrix.generated.md" -Workdir $repoRoot
}

$passedCount = (($results | Where-Object { $_.status -eq "passed" }) | Measure-Object).Count
$failedCount = (($results | Where-Object { $_.status -eq "failed" }) | Measure-Object).Count

$summary = [ordered]@{
    plan = "roadmap-commercial-parity-r3"
    generated_utc = [DateTimeOffset]::UtcNow.ToString("o")
    checks = $results
    passed = $passedCount
    failed = $failedCount
}

$jsonPath = Join-Path $outputDir "commercial-parity-r3-acceptance.json"
$summary | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8

$mdPath = Join-Path $outputDir "commercial-parity-r3-acceptance.md"
$lines = @()
$lines += "# Commercial-Parity R3 Acceptance"
$lines += ""
$lines += "- Generated: $($summary.generated_utc)"
$lines += "- Passed: $($summary.passed)"
$lines += "- Failed: $($summary.failed)"
$lines += ""
$lines += "| Check | Status | Duration(s) |"
$lines += "|---|---|---:|"
foreach ($check in $results) {
    $lines += "| $($check.name) | $($check.status) | $($check.duration_seconds) |"
}
$lines += ""
if ($summary.failed -gt 0) {
$lines += "## Failures"
    foreach ($check in $results | Where-Object { $_.status -eq "failed" }) {
        $lines += "- **$($check.name)**: $($check.error)"
    }
}

$lines -join [Environment]::NewLine | Set-Content -Path $mdPath -Encoding UTF8

$bundleDir = Join-Path $outputDir "commercial-parity-r3-bundle"
New-Item -ItemType Directory -Path $bundleDir -Force | Out-Null

$bundleItems = @(
    $jsonPath,
    $mdPath,
    (Join-Path $repoRoot "artifacts/acceptance/signature-pack-compatibility-matrix.generated.md"),
    (Join-Path $repoRoot "docs/signature-pack-compatibility-matrix.md"),
    (Join-Path $repoRoot "artifacts/plan/roadmap-commercial-parity-r3.md"),
    (Join-Path $repoRoot "artifacts/plan/roadmap-commercial-parity-r3-status.md")
)

$copied = @()
foreach ($item in $bundleItems) {
    if (Test-Path -LiteralPath $item) {
        $destination = Join-Path $bundleDir (Split-Path -Path $item -Leaf)
        Copy-Item -LiteralPath $item -Destination $destination -Force
        $copied += $destination
    }
}

$manifestEntries = @()
foreach ($file in $copied) {
    $hash = Get-FileHash -Path $file -Algorithm SHA256
    $info = Get-Item -LiteralPath $file
    $manifestEntries += [pscustomobject]@{
        file = $info.Name
        bytes = $info.Length
        sha256 = $hash.Hash
    }
}

$bundleManifest = [ordered]@{
    plan = "roadmap-commercial-parity-r3"
    generated_utc = [DateTimeOffset]::UtcNow.ToString("o")
    files = $manifestEntries
}

$bundleManifestPath = Join-Path $outputDir "commercial-parity-r3-bundle-manifest.json"
$bundleManifest | ConvertTo-Json -Depth 8 | Set-Content -Path $bundleManifestPath -Encoding UTF8

$bundleSummaryPath = Join-Path $outputDir "commercial-parity-r3-bundle-manifest.md"
$bundleLines = @()
$bundleLines += "# Commercial-Parity R3 Bundle Manifest"
$bundleLines += ""
$bundleLines += "- Generated: $($bundleManifest.generated_utc)"
$bundleLines += "- File count: $($manifestEntries.Count)"
$bundleLines += ""
$bundleLines += "| File | Bytes | SHA256 |"
$bundleLines += "|---|---:|---|"
foreach ($entry in $manifestEntries) {
    $bundleLines += "| $($entry.file) | $($entry.bytes) | `$($entry.sha256)` |"
}
$bundleLines -join [Environment]::NewLine | Set-Content -Path $bundleSummaryPath -Encoding UTF8

Write-Host "[acceptance] wrote $jsonPath"
Write-Host "[acceptance] wrote $mdPath"
Write-Host "[acceptance] wrote $bundleManifestPath"
Write-Host "[acceptance] wrote $bundleSummaryPath"
if ($summary.failed -gt 0) {
    exit 1
}
