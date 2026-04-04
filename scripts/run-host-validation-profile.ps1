param(
  [Parameter(Mandatory = $true)]
  [string]$ProfileName,
  [string]$ArtifactRoot,
  [switch]$NoBuild,
  [switch]$NoArchive,
  [switch]$SkipNtfs,
  [switch]$SkipVss,
  [switch]$SkipExt,
  [switch]$AllowNoSnapshots,
  [switch]$AllowMissingExtImages
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
  $ArtifactRoot = Join-Path $PSScriptRoot "..\artifacts\host-matrix"
}

if ($SkipNtfs -and $SkipVss -and $SkipExt) {
  throw "At least one validation target must be enabled (remove -SkipNtfs, -SkipVss, or -SkipExt)."
}

if ([string]::IsNullOrWhiteSpace($ProfileName)) {
  throw "ProfileName cannot be empty."
}

$sanitizedProfile = ($ProfileName -replace '[^\w\.-]', '-').Trim('-')
if ([string]::IsNullOrWhiteSpace($sanitizedProfile)) {
  throw "ProfileName must include at least one alphanumeric character."
}

$profileRoot = Join-Path $ArtifactRoot $sanitizedProfile
$ntfsRoot = Join-Path $profileRoot "ntfs"
$vssRoot = Join-Path $profileRoot "vss"
$extRoot = Join-Path $profileRoot "ext"
New-Item -ItemType Directory -Path $profileRoot -Force | Out-Null

$runUtc = [DateTimeOffset]::UtcNow
$buildAlreadyExecuted = $false

function Get-LatestRunDirectory {
  param(
    [string]$Root
  )

  if (-not (Test-Path $Root)) {
    return $null
  }

  return Get-ChildItem -Path $Root -Directory |
    Sort-Object Name -Descending |
    Select-Object -First 1
}

function Get-LatestRunName {
  param(
    [string]$Root
  )

  $latest = Get-LatestRunDirectory -Root $Root
  if ($null -eq $latest) {
    return $null
  }

  return $latest.Name
}

function Invoke-HostValidationScript {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptPath,
    [Parameter(Mandatory = $true)]
    [string]$TargetRoot,
    [hashtable]$ExtraArgs
  )

  $invokeArgs = @{}
  if ($NoArchive) {
    $invokeArgs.NoArchive = $true
  } else {
    $invokeArgs.ArtifactRoot = $TargetRoot
  }

  if ($NoBuild -or $buildAlreadyExecuted) {
    $invokeArgs.NoBuild = $true
  }

  if ($ExtraArgs) {
    foreach ($key in $ExtraArgs.Keys) {
      $invokeArgs[$key] = $ExtraArgs[$key]
    }
  }

  & $ScriptPath @invokeArgs
  if ($LASTEXITCODE -ne 0) {
    throw "$ScriptPath failed with exit code $LASTEXITCODE."
  }

  $buildAlreadyExecuted = $true
}

if (-not $SkipNtfs) {
  Invoke-HostValidationScript `
    -ScriptPath (Join-Path $PSScriptRoot "run-host-ntfs-stream-validation.ps1") `
    -TargetRoot $ntfsRoot
}

if (-not $SkipVss) {
  $vssArgs = @{}
  if ($AllowNoSnapshots) {
    $vssArgs.AllowNoSnapshots = $true
  }

  Invoke-HostValidationScript `
    -ScriptPath (Join-Path $PSScriptRoot "run-host-vss-validation.ps1") `
    -TargetRoot $vssRoot `
    -ExtraArgs $vssArgs
}

if (-not $SkipExt) {
  $extArgs = @{}
  if ($AllowMissingExtImages) {
    $extArgs.AllowMissingImages = $true
  }

  Invoke-HostValidationScript `
    -ScriptPath (Join-Path $PSScriptRoot "run-host-ext-image-validation.ps1") `
    -TargetRoot $extRoot `
    -ExtraArgs $extArgs
}

$diskProfile = @(
  Get-CimInstance Win32_DiskDrive |
    Select-Object Model, InterfaceType, MediaType, SerialNumber, Size
)

$volumeProfile = @(
  Get-Volume -ErrorAction SilentlyContinue |
    Select-Object DriveLetter, FileSystem, FileSystemLabel, Size, SizeRemaining
)

$manifest = [ordered]@{
  profile_name = $sanitizedProfile
  run_utc = $runUtc.ToString("O")
  machine = $env:COMPUTERNAME
  user = $env:USERNAME
  windows_version = [System.Environment]::OSVersion.VersionString
  powershell_version = $PSVersionTable.PSVersion.ToString()
  ntfs = [ordered]@{
    enabled = -not $SkipNtfs
    artifact_root = if ($NoArchive) { $null } else { [System.IO.Path]::GetFullPath($ntfsRoot) }
    latest_run = if ($NoArchive) { $null } else { Get-LatestRunName -Root $ntfsRoot }
  }
  vss = [ordered]@{
    enabled = -not $SkipVss
    allow_no_snapshots = [bool]$AllowNoSnapshots
    artifact_root = if ($NoArchive) { $null } else { [System.IO.Path]::GetFullPath($vssRoot) }
    latest_run = if ($NoArchive) { $null } else { Get-LatestRunName -Root $vssRoot }
  }
  ext = [ordered]@{
    enabled = -not $SkipExt
    allow_missing_images = [bool]$AllowMissingExtImages
    artifact_root = if ($NoArchive) { $null } else { [System.IO.Path]::GetFullPath($extRoot) }
    latest_run = if ($NoArchive) { $null } else { Get-LatestRunName -Root $extRoot }
  }
  disk_profile = $diskProfile
  volume_profile = $volumeProfile
}

$manifestPath = Join-Path $profileRoot "profile-manifest.json"
$manifest | ConvertTo-Json -Depth 8 | Set-Content -Path $manifestPath -Encoding UTF8
Write-Host "Host profile validation manifest: $([System.IO.Path]::GetFullPath($manifestPath))"
