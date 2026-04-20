param(
    [ValidateSet("amd64", "arm64")]
    [string]$Architecture = "amd64",
    [string]$WorkDirectory = (Join-Path $PSScriptRoot "..\..\artifacts\winpe"),
    [string]$OutputIsoPath = (Join-Path $PSScriptRoot "..\..\artifacts\winpe\file-recovery-winpe.iso"),
    [string]$UsbDriveLetter = "",
    [switch]$SkipPublish
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

New-Item -Path $WorkDirectory -ItemType Directory -Force | Out-Null
New-Item -Path $publishRoot -ItemType Directory -Force | Out-Null
New-Item -Path $mountDirectory -ItemType Directory -Force | Out-Null

if (-not $SkipPublish) {
    Write-Host "Publishing Windows app for WinPE payload..."
    dotnet publish $windowsAppProject -c Release -r win-x64 --self-contained false -o $publishRoot
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish failed."
    }
}

if (-not (Test-Path $offlineScriptPath)) {
    throw "Offline startup script not found: $offlineScriptPath"
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

if (-not [string]::IsNullOrWhiteSpace($UsbDriveLetter)) {
    $normalizedUsb = $UsbDriveLetter.Trim().TrimEnd(":")
    Invoke-External -FilePath $makeWinPeMedia -Arguments @(
        "/UFD",
        $winPeRoot,
        "$normalizedUsb`:")
}

Write-Host "WinPE build complete."
Write-Host "ISO: $OutputIsoPath"
