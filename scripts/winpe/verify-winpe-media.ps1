param(
    [string]$WinPeRoot = "",
    [string]$ReportPath = (Join-Path $PSScriptRoot "..\..\artifacts\winpe\winpe-media-verification.json"),
    [switch]$ConfigurationOnly
)

$ErrorActionPreference = "Stop"

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

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed ($LASTEXITCODE): $FilePath $($Arguments -join ' ')"
    }
}

$issues = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]
$readinessChecks = [ordered]@{}

if ($ConfigurationOnly) {
    $launcherScript = Join-Path $PSScriptRoot "start-file-recovery-offline.cmd"
    $buildScript = Join-Path $PSScriptRoot "build-winpe-media.ps1"
    $readinessChecks.launcher_script_exists = Test-Path $launcherScript
    $readinessChecks.build_script_exists = Test-Path $buildScript

    if (-not $readinessChecks.launcher_script_exists) {
        $issues.Add("Offline launcher script missing: $launcherScript")
    }
    if (-not $readinessChecks.build_script_exists) {
        $issues.Add("Build script missing: $buildScript")
    }

    if ($readinessChecks.launcher_script_exists) {
        $launcherRaw = Get-Content $launcherScript -Raw
        $readinessChecks.launcher_sets_winpe_mode = $launcherRaw -match "FR_WINPE_MODE=1"
        $readinessChecks.launcher_supports_dll_fallback = $launcherRaw -match "FileRecovery\.WindowsApp\.dll"
        if (-not $readinessChecks.launcher_sets_winpe_mode) {
            $issues.Add("Launcher script does not set FR_WINPE_MODE=1.")
        }
        if (-not $readinessChecks.launcher_supports_dll_fallback) {
            $issues.Add("Launcher script does not include DLL fallback path.")
        }
    }

    if ($readinessChecks.build_script_exists) {
        $buildRaw = Get-Content $buildScript -Raw
        $readinessChecks.build_generates_iso = $buildRaw -match "MakeWinPEMedia\.cmd"
        $readinessChecks.build_has_verification_step = $buildRaw -match "verify-winpe-media\.ps1"
        if (-not $readinessChecks.build_generates_iso) {
            $issues.Add("Build script does not call MakeWinPEMedia.cmd.")
        }
        if (-not $readinessChecks.build_has_verification_step) {
            $issues.Add("Build script does not call verify-winpe-media.ps1.")
        }
    }

    $isReadyConfig = $issues.Count -eq 0
    $configReport = [ordered]@{
        generated_utc = [DateTimeOffset]::UtcNow.ToString("o")
        mode = "configuration_only"
        is_ready = $isReadyConfig
        checks = $readinessChecks
        issues = $issues.ToArray()
        warnings = $warnings.ToArray()
    }
    New-Item -Path (Split-Path $ReportPath -Parent) -ItemType Directory -Force | Out-Null
    $configReport | ConvertTo-Json -Depth 5 | Set-Content -Path $ReportPath -Encoding UTF8
    if (-not $isReadyConfig) {
        Write-Error "WinPE configuration verification failed. See report: $ReportPath"
        exit 1
    }

    Write-Host "WinPE configuration verification passed."
    Write-Host "Report: $ReportPath"
    exit 0
}

if ([string]::IsNullOrWhiteSpace($WinPeRoot)) {
    Write-Error "WinPeRoot is required unless -ConfigurationOnly is specified."
    exit 1
}

try {
    $resolvedRoot = (Resolve-Path $WinPeRoot).Path
}
catch {
    $issues.Add("WinPE root path not found: $WinPeRoot")
    $resolvedRoot = $WinPeRoot
}

$bootWimPath = Join-Path $resolvedRoot "media\sources\boot.wim"
$readinessChecks.winpe_root_exists = Test-Path $resolvedRoot
$readinessChecks.boot_wim_exists = Test-Path $bootWimPath
if (-not $readinessChecks.boot_wim_exists) {
    $issues.Add("boot.wim not found at: $bootWimPath")
}

$dism = Resolve-CommandPath "dism.exe"
if ([string]::IsNullOrWhiteSpace($dism)) {
    $issues.Add("dism.exe not available in PATH.")
}

$mountDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("fr-winpe-verify-" + [Guid]::NewGuid().ToString("N"))
$mounted = $false

if ($issues.Count -eq 0) {
    New-Item -Path $mountDirectory -ItemType Directory -Force | Out-Null
    try {
        Invoke-External -FilePath $dism -Arguments @(
            "/Mount-Image",
            "/ImageFile:$bootWimPath",
            "/Index:1",
            "/MountDir:$mountDirectory",
            "/ReadOnly")
        $mounted = $true

        $startnetPath = Join-Path $mountDirectory "Windows\System32\startnet.cmd"
        $launcherPath = Join-Path $mountDirectory "RecoveryApp\start-file-recovery-offline.cmd"
        $appExePath = Join-Path $mountDirectory "RecoveryApp\FileRecovery.WindowsApp.exe"
        $appDllPath = Join-Path $mountDirectory "RecoveryApp\FileRecovery.WindowsApp.dll"

        $readinessChecks.startnet_exists = Test-Path $startnetPath
        $readinessChecks.launcher_exists = Test-Path $launcherPath
        $readinessChecks.app_exe_exists = Test-Path $appExePath
        $readinessChecks.app_dll_exists = Test-Path $appDllPath

        if (-not $readinessChecks.startnet_exists) {
            $issues.Add("startnet.cmd missing from mounted image.")
        }
        if (-not $readinessChecks.launcher_exists) {
            $issues.Add("Offline launcher script missing from mounted image.")
        }
        if (-not $readinessChecks.app_exe_exists -and -not $readinessChecks.app_dll_exists) {
            $issues.Add("App executable payload missing from mounted image.")
        }

        if ($readinessChecks.startnet_exists) {
            $startnetRaw = Get-Content $startnetPath -Raw
            $readinessChecks.startnet_calls_launcher = $startnetRaw -match "start-file-recovery-offline\.cmd"
            if (-not $readinessChecks.startnet_calls_launcher) {
                $issues.Add("startnet.cmd does not call start-file-recovery-offline.cmd.")
            }
        }

        if ($readinessChecks.launcher_exists) {
            $launcherRaw = Get-Content $launcherPath -Raw
            $readinessChecks.launcher_sets_winpe_mode = $launcherRaw -match "FR_WINPE_MODE=1"
            if (-not $readinessChecks.launcher_sets_winpe_mode) {
                $issues.Add("Offline launcher script does not set FR_WINPE_MODE=1.")
            }
        }
    }
    finally {
        if ($mounted) {
            try {
                Invoke-External -FilePath $dism -Arguments @(
                    "/Unmount-Image",
                    "/MountDir:$mountDirectory",
                    "/Discard")
            }
            catch {
                $warnings.Add("Failed to unmount verification image cleanly: $($_.Exception.Message)")
            }
        }

        if (Test-Path $mountDirectory) {
            try {
                Remove-Item $mountDirectory -Recurse -Force
            }
            catch {
                $warnings.Add("Failed to remove temporary mount directory: $mountDirectory")
            }
        }
    }
}

$isReady = $issues.Count -eq 0
$report = [ordered]@{
    generated_utc = [DateTimeOffset]::UtcNow.ToString("o")
    winpe_root = $resolvedRoot
    is_ready = $isReady
    checks = $readinessChecks
    issues = $issues.ToArray()
    warnings = $warnings.ToArray()
}

New-Item -Path (Split-Path $ReportPath -Parent) -ItemType Directory -Force | Out-Null
$report | ConvertTo-Json -Depth 5 | Set-Content -Path $ReportPath -Encoding UTF8

if (-not $isReady) {
    Write-Error "WinPE media verification failed. See report: $ReportPath"
    exit 1
}

Write-Host "WinPE media verification passed."
Write-Host "Report: $ReportPath"
exit 0
