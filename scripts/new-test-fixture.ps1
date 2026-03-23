param(
  [Parameter(Mandatory = $true)]
  [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

$fullPath = [System.IO.Path]::GetFullPath($OutputPath)
New-Item -ItemType Directory -Force -Path $fullPath | Out-Null

$documents = Join-Path $fullPath 'documents'
$images = Join-Path $fullPath 'images'
$archives = Join-Path $fullPath 'archives'
$nested = Join-Path $fullPath 'nested\a\b\c'

$dirs = @($documents, $images, $archives, $nested)
foreach ($d in $dirs) {
  New-Item -ItemType Directory -Force -Path $d | Out-Null
}

"fixture-generated $(Get-Date -Format o)" | Set-Content -Encoding UTF8 (Join-Path $documents 'readme.txt')
"important data" | Set-Content -Encoding UTF8 (Join-Path $nested 'deep-note.txt')

# Create binary sample files.
$binPath = Join-Path $images 'sample.bin'
[byte[]]$data = 0..255
[System.IO.File]::WriteAllBytes($binPath, $data)

# Create sparse candidate file (requires NTFS support).
$sparsePath = Join-Path $documents 'sparse.dat'
fsutil file createnew $sparsePath 104857600 | Out-Null
fsutil sparse setflag $sparsePath | Out-Null

# Alternate data stream sample.
$adsPath = Join-Path $documents 'invoice.txt'
"invoice" | Set-Content -Encoding UTF8 $adsPath
"hidden-stream" | Set-Content -Encoding UTF8 "$adsPath:hidden.meta"

Write-Host "Fixture created at $fullPath"
