param(
    [switch]$Check
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$inventoryPath = Join-Path $repoRoot 'tools\dependency-licenses.json'
$noticePath = Join-Path $repoRoot 'docs\third-party-notices.md'

if (!(Test-Path $inventoryPath)) {
    throw "Dependency inventory not found: $inventoryPath"
}

function Get-NuGetDependencies {
    param([string]$Root)

    $packages = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $files = Get-ChildItem -Path $Root -Recurse -File -Filter *.csproj
    foreach ($file in $files) {
        [xml]$xml = Get-Content -Path $file.FullName -Raw
        $refs = @($xml.Project.ItemGroup.PackageReference)
        foreach ($ref in $refs) {
            $name = [string]$ref.Include
            if ([string]::IsNullOrWhiteSpace($name)) {
                continue
            }

            [void]$packages.Add($name.Trim())
        }
    }

    return $packages | Sort-Object | ForEach-Object {
        [PSCustomObject]@{
            Name = $_
            Ecosystem = 'nuget'
        }
    }
}

function Get-CargoDependencies {
    param([string]$Root)

    $packages = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $files = Get-ChildItem -Path (Join-Path $Root 'engine') -Recurse -File -Filter Cargo.toml

    foreach ($file in $files) {
        $inDependencySection = $false
        foreach ($line in Get-Content -Path $file.FullName) {
            $trimmed = $line.Trim()
            if ($trimmed -match '^\[(.+)\]$') {
                $section = $Matches[1]
                $inDependencySection = $section -match '(^|\.)(dependencies|dev-dependencies|build-dependencies)$'
                continue
            }

            if (-not $inDependencySection -or [string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) {
                continue
            }

            if ($trimmed -match '^([A-Za-z0-9_-]+)(?:\.[A-Za-z0-9_-]+)?\s*=\s*(.+)$') {
                $name = $Matches[1]
                $value = $Matches[2]

                if ($name.StartsWith('fr-', [System.StringComparison]::OrdinalIgnoreCase)) {
                    continue
                }

                if ($value -match 'path\s*=') {
                    continue
                }

                [void]$packages.Add($name)
            }
        }
    }

    return $packages | Sort-Object | ForEach-Object {
        [PSCustomObject]@{
            Name = $_
            Ecosystem = 'cargo'
        }
    }
}

function Build-InventoryIndex {
    param([object[]]$Dependencies)

    $index = @{}
    foreach ($dep in $Dependencies) {
        $name = [string]$dep.name
        $ecosystem = [string]$dep.ecosystem
        if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($ecosystem)) {
            throw "Inventory entry missing required fields (name/ecosystem)."
        }

        $key = ($ecosystem.Trim().ToLowerInvariant() + '|' + $name.Trim().ToLowerInvariant())
        if ($index.ContainsKey($key)) {
            throw "Duplicate inventory entry detected for $ecosystem/$name."
        }

        $index[$key] = $dep
    }

    return $index
}

function New-ThirdPartyNoticesContent {
    param([object]$Inventory)

    $entries = @($Inventory.dependencies) | Sort-Object ecosystem, name
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# Third-Party Notices')
    $lines.Add('')
    $lines.Add('Source of truth: `tools/dependency-licenses.json`.')
    $lines.Add('')
    $lines.Add('| Name | Ecosystem | License | Status |')
    $lines.Add('|---|---|---|---|')
    foreach ($entry in $entries) {
        $lines.Add("| $($entry.name) | $($entry.ecosystem) | $($entry.license) | $($entry.status) |")
    }

    return ($lines -join [Environment]::NewLine) + [Environment]::NewLine
}

$inventory = Get-Content -Path $inventoryPath -Raw | ConvertFrom-Json
$inventoryDependencies = @($inventory.dependencies)
$inventoryIndex = Build-InventoryIndex -Dependencies $inventoryDependencies

$discovered = @()
$discovered += Get-NuGetDependencies -Root $repoRoot
$discovered += Get-CargoDependencies -Root $repoRoot

$discoveredUnique = $discovered |
    Group-Object { $_.Ecosystem.ToLowerInvariant() + '|' + $_.Name.ToLowerInvariant() } |
    ForEach-Object { $_.Group[0] } |
    Sort-Object Ecosystem, Name

$errors = New-Object System.Collections.Generic.List[string]

foreach ($dep in $discoveredUnique) {
    $key = ($dep.Ecosystem + '|' + $dep.Name).ToLowerInvariant()
    if (-not $inventoryIndex.ContainsKey($key)) {
        $errors.Add("Missing inventory entry for discovered dependency: $($dep.Ecosystem)/$($dep.Name)")
        continue
    }

    $entry = $inventoryIndex[$key]
    $status = ([string]$entry.status).Trim().ToLowerInvariant()
    if ($status -ne 'approved') {
        $errors.Add("Dependency is not approved: $($dep.Ecosystem)/$($dep.Name) (status: $($entry.status))")
    }

    $license = [string]$entry.license
    if ($license -match '(?i)\b(AGPL|GPL)\b') {
        $errors.Add("Disallowed strong-copyleft license detected: $($dep.Ecosystem)/$($dep.Name) -> $license")
    }
}

$noticeContent = New-ThirdPartyNoticesContent -Inventory $inventory
if ($Check) {
    if (!(Test-Path $noticePath)) {
        $errors.Add("Third-party notices file is missing: $noticePath. Run scripts/license-gate.ps1 to generate it.")
    } else {
        $currentNotice = Get-Content -Path $noticePath -Raw
        if ($currentNotice -ne $noticeContent) {
            $errors.Add("Third-party notices file is out of date: $noticePath. Run scripts/license-gate.ps1 to regenerate.")
        }
    }
} else {
    Set-Content -Path $noticePath -Value $noticeContent -NoNewline
}

if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Host "License policy gate passed ($($discoveredUnique.Count) discovered dependencies)."
