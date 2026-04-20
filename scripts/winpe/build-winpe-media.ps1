param(
    [ValidateSet("amd64", "arm64")]
    [string]$Architecture = "amd64",
    [string]$WorkDirectory = (Join-Path $PSScriptRoot "..\..\artifacts\winpe"),
    [string]$OutputIsoPath = (Join-Path $PSScriptRoot "..\..\artifacts\winpe\file-recovery-winpe.iso"),
    [string]$UsbDriveLetter = "",
    [switch]$SkipPublish,
    [switch]$SelfContained,
    [switch]$SkipMediaVerification
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must run in an elevated PowerShell session."
    }
}

function Resolve-CommandPath {
    param([string]$CommandName)
    $cmd = Get-Command $CommandName -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        return $cmd.Source
    }

    return $null
}

function Invoke-External {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )
    Write-Host "Running: $FilePath $($Arguments -join ' ')"
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed ($LASTEXITCODE): $FilePath $($Arguments -join ' ')"
    }
}

function Assert-FileExists {
    param(
        [string]$Path,
        [string]$Description
    )

    if (-not (Test-Path $Path)) {
        throw "$Description not found: $Path"
    }
}

if (-not $PSBoundParameters.ContainsKey("SelfContained")) {
    $SelfContained = $true
}

Assert-Admin

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$windowsAppProject = Join-Path $repoRoot "ui\windows-app\src\FileRecovery.WindowsApp\FileRecovery.WindowsApp.csproj"
$publishRoot = Join-Path $WorkDirectory "publish"
$winPeRoot = Join-Path $WorkDirectory $Architecture
$mountDirectory = Join-Path $WorkDirectory "mount"
$bootWimPath = Join-Path $winPeRoot "media\sources\boot.wim"
$offlineScriptPath = Join-Path $PSScriptRoot "start-file-recovery-offline.cmd"
$offlineScriptTarget = Join-Path $mountDirectory "RecoveryApp\start-file-recovery-offline.cmd"
$startnetPath = Join-Path $mountDirectory "Windows\System32\startnet.cmd"
$appExePath = Join-Path $publishRoot "FileRecovery.WindowsApp.exe"
$appDllPath = Join-Path $publishRoot "FileRecovery.WindowsApp.dll"
$dotnetHostPath = Join-Path $publishRoot "dotnet\dotnet.exe"
$verificationScript = Join-Path $PSScriptRoot "verify-winpe-media.ps1"
$verificationReportPath = Join-Path $WorkDirectory "winpe-media-verification.json"
$buildReportPath = Join-Path $WorkDirectory "winpe-build-report.json"

New-Item -Path $WorkDirectory -ItemType Directory -Force | Out-Null
New-Item -Path $publishRoot -ItemType Directory -Force | Out-Null
New-Item -Path $mountDirectory -ItemType Directory -Force | Out-Null

if (-not $SkipPublish) {
    Write-Host "Publishing Windows app for WinPE payload..."
    dotnet publish $windowsAppProject -c Release -r win-x64 --self-contained $SelfContained -o $publishRoot
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish failed."
    }
}

Assert-FileExists -Path $offlineScriptPath -Description "Offline startup script"
Assert-FileExists -Path $publishRoot -Description "Publish output directory"

if (-not (Test-Path $appExePath) -and -not (Test-Path $appDllPath)) {
    throw "Publish output does not include FileRecovery.WindowsApp.exe or FileRecovery.WindowsApp.dll."
}
if (-not $SelfContained -and -not (Test-Path $dotnetHostPath)) {
    Write-Warning "Framework-dependent publish selected and local dotnet host not found under publish output."
    Write-Warning "WinPE startup will require dotnet host injection or self-contained publish."
}

$copype = Resolve-CommandPath "copype.cmd"
$makeWinPeMedia = Resolve-CommandPath "MakeWinPEMedia.cmd"
$dism = Resolve-CommandPath "dism.exe"
if ([string]::IsNullOrWhiteSpace($copype) -or [string]::IsNullOrWhiteSpace($makeWinPeMedia) -or [string]::IsNullOrWhiteSpace($dism)) {
    throw "WinPE tooling not found. Install Windows ADK + WinPE add-on and run from Deployment and Imaging Tools Environment."
}

if (Test-Path $winPeRoot) {
    Remove-Item $winPeRoot -Recurse -Force
}

Invoke-External -FilePath $copype -Arguments @($Architecture, $winPeRoot)
Assert-FileExists -Path $bootWimPath -Description "WinPE boot.wim"

Invoke-External -FilePath $dism -Arguments @(
    "/Mount-Image",
    "/ImageFile:$bootWimPath",
    "/Index:1",
    "/MountDir:$mountDirectory")

try {
    $appTarget = Join-Path $mountDirectory "RecoveryApp"
    if (Test-Path $appTarget) {
        Remove-Item $appTarget -Recurse -Force
    }
    New-Item -Path $appTarget -ItemType Directory -Force | Out-Null

    Copy-Item (Join-Path $publishRoot "*") -Destination $appTarget -Recurse -Force
    Copy-Item $offlineScriptPath -Destination $offlineScriptTarget -Force

    @(
        "@echo off",
        "wpeinit",
        "call X:\RecoveryApp\start-file-recovery-offline.cmd"
    ) | Set-Content -Path $startnetPath -Encoding Ascii
}
finally {
    Invoke-External -FilePath $dism -Arguments @(
        "/Unmount-Image",
        "/MountDir:$mountDirectory",
        "/Commit")
}

New-Item -Path (Split-Path $OutputIsoPath -Parent) -ItemType Directory -Force | Out-Null
Invoke-External -FilePath $makeWinPeMedia -Arguments @(
    "/ISO",
    $winPeRoot,
    $OutputIsoPath)
Assert-FileExists -Path $OutputIsoPath -Description "Generated WinPE ISO"

if (-not [string]::IsNullOrWhiteSpace($UsbDriveLetter)) {
    $normalizedUsb = $UsbDriveLetter.Trim().TrimEnd(":")
    Invoke-External -FilePath $makeWinPeMedia -Arguments @(
        "/UFD",
        $winPeRoot,
        "$normalizedUsb`:")
}

if ((Test-Path $verificationScript) -and -not $SkipMediaVerification) {
    & $verificationScript -WinPeRoot $winPeRoot -ReportPath $verificationReportPath
    if ($LASTEXITCODE -ne 0) {
        throw "WinPE media verification script reported failure."
    }
}

$isoHash = (Get-FileHash -Path $OutputIsoPath -Algorithm SHA256).Hash
$buildReport = [ordered]@{
    generated_utc = [DateTimeOffset]::UtcNow.ToString("o")
    architecture = $Architecture
    self_contained = [bool]$SelfContained
    work_directory = (Resolve-Path $WorkDirectory).Path
    winpe_root = (Resolve-Path $winPeRoot).Path
    output_iso = (Resolve-Path $OutputIsoPath).Path
    output_iso_sha256 = $isoHash
    verification_report = if (Test-Path $verificationReportPath) { (Resolve-Path $verificationReportPath).Path } else { $null }
}
$buildReport | ConvertTo-Json -Depth 5 | Set-Content -Path $buildReportPath -Encoding UTF8

Write-Host "WinPE build complete."
Write-Host "ISO: $OutputIsoPath"
Write-Host "Build report: $buildReportPath"
