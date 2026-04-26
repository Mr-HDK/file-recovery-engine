param(
    [string]$OutputPath = "artifacts/acceptance/signature-pack-compatibility-matrix.generated.md"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$sourcePath = Join-Path $repoRoot "engine\crates\fr-carving\src\lib.rs"
if (-not (Test-Path -LiteralPath $sourcePath)) {
    throw "Missing source file: $sourcePath"
}

$content = Get-Content -Path $sourcePath -Raw

$packNameMatch = [regex]::Match($content, 'SIGNATURE_PACK_NAME:\s*&str\s*=\s*"([^"]+)"')
$packVersionMatch = [regex]::Match($content, 'SIGNATURE_PACK_VERSION:\s*&str\s*=\s*"([^"]+)"')
if (-not $packNameMatch.Success -or -not $packVersionMatch.Success) {
    throw "Unable to parse signature pack metadata constants."
}

$coreBlock = [regex]::Match(
    $content,
    'pub\s+fn\s+signature_pack_formats\(\)\s*->\s*&''static\s*\[FileFormat\]\s*\{\s*&\[(?<body>.*?)\]\s*\}',
    [System.Text.RegularExpressions.RegexOptions]::Singleline)
if (-not $coreBlock.Success) {
    throw "Unable to parse signature_pack_formats block."
}

$coreFormats = [regex]::Matches($coreBlock.Groups["body"].Value, 'FileFormat::([A-Za-z0-9_]+)')
$coreNames = $coreFormats | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique

$extensionBlock = [regex]::Match(
    $content,
    'formats\.extend\(\s*\[(?<body>.*?)\]\s*\.into_iter\(\)',
    [System.Text.RegularExpressions.RegexOptions]::Singleline)
if (-not $extensionBlock.Success) {
    throw "Unable to parse extended signature extension block."
}

$extensionNames = [regex]::Matches($extensionBlock.Groups["body"].Value, '"([a-z0-9]+)"')
$extensionValues = $extensionNames | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique

$syntheticLimitMatch = [regex]::Match($content, 'while\s+formats\.len\(\)\s*<\s*(\d+)')
$syntheticMin = if ($syntheticLimitMatch.Success) { [int]$syntheticLimitMatch.Groups[1].Value } else { 0 }
$totalDeclared = $coreNames.Count + $extensionValues.Count
$projectedCoverage = [Math]::Max($totalDeclared, $syntheticMin)

$outputAbsolute = Join-Path $repoRoot $OutputPath
$outputDir = Split-Path -Path $outputAbsolute -Parent
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

$lines = @()
$lines += "# Signature Pack Compatibility Matrix (Generated)"
$lines += ""
$lines += "- Generated UTC: $([DateTimeOffset]::UtcNow.ToString("o"))"
$lines += "- Pack: ``$($packNameMatch.Groups[1].Value)@$($packVersionMatch.Groups[1].Value)``"
$lines += "- Core validated formats: $($coreNames.Count)"
$lines += "- Extended declared identifiers: $($extensionValues.Count)"
$lines += "- Projected total coverage: >= $projectedCoverage"
$lines += ""
$lines += "## Core Validated Formats"
$lines += [string]::Join(", ", $coreNames)
$lines += ""
$lines += "## Extended Identifier Samples"
$sample = $extensionValues | Select-Object -First 64
$lines += [string]::Join(", ", $sample)
$lines += ""
$lines += "## Notes"
$lines += "1. Coverage floor is enforced by synthetic identifiers in `signature_pack_format_extensions`."
$lines += "2. Core validated formats remain the regression gate for false-positive protection."
$lines += "3. Consumers should treat metadata CSV as variable-length and versioned."

$lines -join [Environment]::NewLine | Set-Content -Path $outputAbsolute -Encoding UTF8
Write-Host "[signatures] wrote $outputAbsolute"
