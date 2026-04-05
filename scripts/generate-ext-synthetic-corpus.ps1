param(
  [string]$OutputDir = ".\testdata\raw-images\ext-corpus\synthetic"
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$outputRoot = if ([System.IO.Path]::IsPathRooted($OutputDir)) {
  $OutputDir
} else {
  Join-Path $repoRoot $OutputDir
}
$outputRoot = [System.IO.Path]::GetFullPath($outputRoot)
New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null

function Write-U16 {
  param([byte[]]$Buffer, [int]$Offset, [UInt16]$Value)
  [BitConverter]::GetBytes($Value).CopyTo($Buffer, $Offset)
}

function Write-U32 {
  param([byte[]]$Buffer, [int]$Offset, [UInt32]$Value)
  [BitConverter]::GetBytes($Value).CopyTo($Buffer, $Offset)
}

function Align-4 {
  param([int]$Value)
  return ($Value + 3) -band -4
}

function New-BaseExtImage {
  param([int]$SizeBytes = 131072)

  $image = New-Object byte[] $SizeBytes
  # ext superblock + group-descriptor baseline mirrors unit test fixtures.
  Write-U32 $image (1024 + 0x00) 1024
  Write-U32 $image (1024 + 0x04) 8192
  Write-U32 $image (1024 + 0x18) 2
  Write-U32 $image (1024 + 0x20) 32768
  Write-U32 $image (1024 + 0x28) 256
  Write-U16 $image (1024 + 0x38) 0xEF53
  Write-U16 $image (1024 + 0x58) 256
  Write-U32 $image (4096 + 0x08) 10

  return $image
}

function Set-DeletedInode {
  param(
    [byte[]]$Image,
    [UInt32]$InodeNumber,
    [UInt16]$Mode,
    [UInt32]$SizeBytes,
    [UInt32]$DeletionTime
  )

  if ($InodeNumber -lt 1) {
    throw "InodeNumber must be >= 1."
  }

  $inodeIndex = [int]($InodeNumber - 1)
  $inodeOffset = (10 * 4096) + ($inodeIndex * 256)

  Write-U16 $Image ($inodeOffset + 0) $Mode
  Write-U32 $Image ($inodeOffset + 4) $SizeBytes
  Write-U32 $Image ($inodeOffset + 20) $DeletionTime
  Write-U16 $Image ($inodeOffset + 26) 0
}

function Add-DirEntry {
  param(
    [byte[]]$Image,
    [int]$Offset,
    [UInt32]$Inode,
    [string]$Name,
    [byte]$FileType
  )

  $nameBytes = [System.Text.Encoding]::ASCII.GetBytes($Name)
  $recordLength = Align-4 (8 + $nameBytes.Length)
  $entry = New-Object byte[] $recordLength

  Write-U32 $entry 0 $Inode
  Write-U16 $entry 4 ([UInt16]$recordLength)
  $entry[6] = [byte]$nameBytes.Length
  $entry[7] = $FileType
  $nameBytes.CopyTo($entry, 8)

  $entry.CopyTo($Image, $Offset)
  return $recordLength
}

function Save-Image {
  param([byte[]]$Image, [string]$Path)
  [System.IO.File]::WriteAllBytes($Path, $Image)
}

$generated = New-Object System.Collections.Generic.List[string]
$deletedTime = [UInt32]1704067200

# 1) Single deleted file with inode-linked directory metadata.
$image = New-BaseExtImage
Set-DeletedInode -Image $image -InodeNumber 16 -Mode 0x81A4 -SizeBytes 8192 -DeletionTime $deletedTime
[void](Add-DirEntry -Image $image -Offset 8192 -Inode 16 -Name "recent-delete.txt" -FileType 1)
$path = Join-Path $outputRoot "ext4-recent-delete-synth.img"
Save-Image -Image $image -Path $path
$generated.Add($path)

# 2) Deleted tree with directory/file/symlink inode metadata.
$image = New-BaseExtImage
Set-DeletedInode -Image $image -InodeNumber 16 -Mode 0x41ED -SizeBytes 4096 -DeletionTime $deletedTime
Set-DeletedInode -Image $image -InodeNumber 17 -Mode 0x81A4 -SizeBytes 2048 -DeletionTime $deletedTime
Set-DeletedInode -Image $image -InodeNumber 18 -Mode 0xA1FF -SizeBytes 28 -DeletionTime $deletedTime
$cursor = 8192
$cursor += Add-DirEntry -Image $image -Offset $cursor -Inode 16 -Name "projects" -FileType 2
$cursor += Add-DirEntry -Image $image -Offset $cursor -Inode 17 -Name "todo.md" -FileType 1
[void](Add-DirEntry -Image $image -Offset $cursor -Inode 18 -Name "latest" -FileType 7)
$path = Join-Path $outputRoot "ext4-deleted-tree-synth.img"
Save-Image -Image $image -Path $path
$generated.Add($path)

# 3) Deleted inode fallback path (no linked directory metadata).
$image = New-BaseExtImage
Set-DeletedInode -Image $image -InodeNumber 20 -Mode 0x81A4 -SizeBytes 12288 -DeletionTime $deletedTime
$path = Join-Path $outputRoot "ext4-inode-fallback-synth.img"
Save-Image -Image $image -Path $path
$generated.Add($path)

# 4) Mixed partial-overwrite style block with both zero-inode slack and inode-linked entry.
$image = New-BaseExtImage
Set-DeletedInode -Image $image -InodeNumber 21 -Mode 0x81A4 -SizeBytes 4096 -DeletionTime $deletedTime
$image[8192] = 0x01
$image[8193] = 0x02
$image[8194] = 0x03
$image[8195] = 0x04
[void](Add-DirEntry -Image $image -Offset 8224 -Inode 0 -Name "lost.tmp" -FileType 1)
[void](Add-DirEntry -Image $image -Offset 8256 -Inode 21 -Name "restored.bin" -FileType 1)
$path = Join-Path $outputRoot "ext4-partial-overwrite-synth.img"
Save-Image -Image $image -Path $path
$generated.Add($path)

# 5) Symlink-focused synthetic case.
$image = New-BaseExtImage
Set-DeletedInode -Image $image -InodeNumber 40 -Mode 0xA1FF -SizeBytes 52 -DeletionTime $deletedTime
[void](Add-DirEntry -Image $image -Offset 8192 -Inode 40 -Name "current" -FileType 7)
$path = Join-Path $outputRoot "ext4-symlink-synth.img"
Save-Image -Image $image -Path $path
$generated.Add($path)

# 6) Sparse/slack-only metadata seam case.
$image = New-BaseExtImage
[void](Add-DirEntry -Image $image -Offset 8192 -Inode 0 -Name "ghost-seam.dat" -FileType 1)
[void](Add-DirEntry -Image $image -Offset 8224 -Inode 0 -Name "old-dir" -FileType 2)
$path = Join-Path $outputRoot "ext4-slack-only-synth.img"
Save-Image -Image $image -Path $path
$generated.Add($path)

Write-Host "Generated synthetic ext corpus images:"
$generated | ForEach-Object { Write-Host " - $_" }
