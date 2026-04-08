use thiserror::Error;

use fr_types::RecoverySourceKind;

const UFS_SUPERBLOCK_OFFSET: usize = 8192;
const UFS_SUPERBLOCK_SIZE: usize = 4096;
const UFS_MAGIC_OFFSET: usize = UFS_SUPERBLOCK_OFFSET + 0x55C;
const UFS_BLOCK_SIZE_OFFSET: usize = UFS_SUPERBLOCK_OFFSET + 0x30;
const UFS_FRAGMENT_SIZE_OFFSET: usize = UFS_SUPERBLOCK_OFFSET + 0x34;
const UFS_TOTAL_BLOCKS_OFFSET: usize = UFS_SUPERBLOCK_OFFSET + 0x08;

const UFS1_MAGIC: u32 = 0x0001_1954;
const UFS2_MAGIC: u32 = 0x1954_0119;

const UFS_TOMBSTONE_MARKER: &[u8; 8] = b"UFSDEL\0\0";
const UFS_TOMBSTONE_NAME_CAPACITY: usize = 96;
const UFS_TOMBSTONE_PATH_CAPACITY: usize = 192;
const UFS_TOMBSTONE_HEADER_SIZE: usize = 8 + 4 + 8 + 1 + 1 + 1 + 1;
const UFS_TOMBSTONE_RECORD_SIZE: usize =
    UFS_TOMBSTONE_HEADER_SIZE + UFS_TOMBSTONE_NAME_CAPACITY + UFS_TOMBSTONE_PATH_CAPACITY;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDescriptor {
    pub name: &'static str,
    pub purpose: &'static str,
    pub source_kind: RecoverySourceKind,
}

pub fn descriptor() -> ModuleDescriptor {
    ModuleDescriptor {
        name: "fr-ufs",
        purpose: "UFS superblock parser and deleted metadata seam.",
        source_kind: RecoverySourceKind::ImageFile,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UfsSuperblock {
    pub magic: u32,
    pub block_size_bytes: u32,
    pub fragment_size_bytes: u32,
    pub total_blocks: u64,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SuperblockParseError {
    #[error("image buffer too small for UFS superblock: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall { expected: usize, actual: usize },
    #[error("invalid UFS superblock magic: 0x{0:08X}")]
    InvalidMagic(u32),
    #[error("invalid UFS block size: {0}")]
    InvalidBlockSize(u32),
    #[error("invalid UFS fragment size: {0}")]
    InvalidFragmentSize(u32),
    #[error("invalid UFS total block count: {0}")]
    InvalidTotalBlocks(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UfsDeletedCandidate {
    pub inode_number: u32,
    pub size_bytes: u64,
    pub name: String,
    pub path: String,
    pub is_directory: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScanError {
    #[error(transparent)]
    Superblock(#[from] SuperblockParseError),
}

pub fn parse_superblock(image: &[u8]) -> Result<UfsSuperblock, SuperblockParseError> {
    let minimum = UFS_SUPERBLOCK_OFFSET + UFS_SUPERBLOCK_SIZE;
    if image.len() < minimum {
        return Err(SuperblockParseError::BufferTooSmall {
            expected: minimum,
            actual: image.len(),
        });
    }

    let magic = read_u32_le(image, UFS_MAGIC_OFFSET);
    if magic != UFS1_MAGIC && magic != UFS2_MAGIC {
        return Err(SuperblockParseError::InvalidMagic(magic));
    }

    let block_size_bytes = read_u32_le(image, UFS_BLOCK_SIZE_OFFSET);
    if block_size_bytes < 512 || block_size_bytes > 65_536 || !block_size_bytes.is_power_of_two() {
        return Err(SuperblockParseError::InvalidBlockSize(block_size_bytes));
    }

    let fragment_size_bytes = read_u32_le(image, UFS_FRAGMENT_SIZE_OFFSET);
    if fragment_size_bytes == 0 || fragment_size_bytes > block_size_bytes {
        return Err(SuperblockParseError::InvalidFragmentSize(
            fragment_size_bytes,
        ));
    }

    let total_blocks = read_u64_le(image, UFS_TOTAL_BLOCKS_OFFSET);
    if total_blocks == 0 {
        return Err(SuperblockParseError::InvalidTotalBlocks(total_blocks));
    }

    Ok(UfsSuperblock {
        magic,
        block_size_bytes,
        fragment_size_bytes,
        total_blocks,
    })
}

pub fn scan_deleted_candidates(
    image: &[u8],
    max_entries: usize,
) -> Result<(UfsSuperblock, Vec<UfsDeletedCandidate>), ScanError> {
    let superblock = parse_superblock(image)?;
    let entries = scan_deleted_candidates_with_superblock(image, &superblock, max_entries);
    Ok((superblock, entries))
}

pub fn scan_deleted_candidates_with_superblock(
    image: &[u8],
    _superblock: &UfsSuperblock,
    max_entries: usize,
) -> Vec<UfsDeletedCandidate> {
    if max_entries == 0 || image.len() < UFS_TOMBSTONE_RECORD_SIZE {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut offset = 0usize;

    while offset + UFS_TOMBSTONE_RECORD_SIZE <= image.len() && out.len() < max_entries {
        if image[offset..offset + UFS_TOMBSTONE_MARKER.len()] == *UFS_TOMBSTONE_MARKER {
            if let Some(candidate) =
                parse_tombstone_record(&image[offset..offset + UFS_TOMBSTONE_RECORD_SIZE])
            {
                let key = (candidate.inode_number, candidate.path.to_ascii_lowercase());
                if seen.insert(key) {
                    out.push(candidate);
                }
            }

            offset = offset.saturating_add(UFS_TOMBSTONE_RECORD_SIZE);
            continue;
        }

        offset = offset.saturating_add(8);
    }

    out
}

fn parse_tombstone_record(record: &[u8]) -> Option<UfsDeletedCandidate> {
    if record.len() < UFS_TOMBSTONE_RECORD_SIZE {
        return None;
    }

    let inode_number = read_u32_le(record, 8);
    if inode_number == 0 {
        return None;
    }

    let size_bytes = read_u64_le(record, 12);
    let flags = record[20];
    let name_len = record[21] as usize;
    let path_len = record[22] as usize;
    if name_len == 0
        || name_len > UFS_TOMBSTONE_NAME_CAPACITY
        || path_len > UFS_TOMBSTONE_PATH_CAPACITY
    {
        return None;
    }

    let name_start = UFS_TOMBSTONE_HEADER_SIZE;
    let path_start = name_start + UFS_TOMBSTONE_NAME_CAPACITY;

    let name = decode_metadata_text(&record[name_start..name_start + name_len])?;
    let path = if path_len == 0 {
        format!(r".\{}", name)
    } else {
        normalize_candidate_path(&decode_metadata_text(
            &record[path_start..path_start + path_len],
        )?)
    };

    Some(UfsDeletedCandidate {
        inode_number,
        size_bytes,
        name,
        path,
        is_directory: (flags & 0x01) != 0,
    })
}

fn decode_metadata_text(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes)
        .ok()?
        .trim_matches(char::from(0))
        .trim();
    if text.is_empty() {
        return None;
    }

    if text.as_bytes().iter().any(|value| *value < 0x20) {
        return None;
    }

    Some(text.to_string())
}

fn normalize_candidate_path(path: &str) -> String {
    let mut normalized = path.replace('/', "\\");
    if normalized.is_empty() {
        return ".\\".to_string();
    }

    if !normalized.starts_with(".\\") {
        normalized = format!(".\\{}", normalized.trim_start_matches('\\'));
    }

    normalized
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_ufs_superblock() {
        let image = build_test_ufs_image();
        let sb = parse_superblock(&image).expect("parse ufs");
        assert_eq!(sb.magic, UFS2_MAGIC);
        assert_eq!(sb.block_size_bytes, 4096);
        assert_eq!(sb.fragment_size_bytes, 1024);
        assert_eq!(sb.total_blocks, 262_144);
    }

    #[test]
    fn rejects_invalid_magic() {
        let mut image = build_test_ufs_image();
        write_u32_le(&mut image, UFS_MAGIC_OFFSET, 0xDEAD_BEEF);

        let err = parse_superblock(&image).unwrap_err();
        assert!(matches!(
            err,
            SuperblockParseError::InvalidMagic(0xDEAD_BEEF)
        ));
    }

    #[test]
    fn rejects_invalid_fragment_size() {
        let mut image = build_test_ufs_image();
        write_u32_le(&mut image, UFS_FRAGMENT_SIZE_OFFSET, 8192);

        let err = parse_superblock(&image).unwrap_err();
        assert!(matches!(
            err,
            SuperblockParseError::InvalidFragmentSize(8192)
        ));
    }

    #[test]
    fn extracts_deleted_candidate_from_tombstone_record() {
        let mut image = build_test_ufs_image();
        let record = build_tombstone_record(120, 2048, false, "passwd.old", r"etc\passwd.old");
        let offset = 16 * 1024;
        image[offset..offset + record.len()].copy_from_slice(&record);

        let (_, candidates) = scan_deleted_candidates(&image, 8).expect("scan ufs");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].inode_number, 120);
        assert_eq!(candidates[0].name, "passwd.old");
        assert_eq!(candidates[0].path, r".\etc\passwd.old");
    }

    fn build_test_ufs_image() -> Vec<u8> {
        let mut image = vec![0u8; 128 * 1024];
        write_u32_le(&mut image, UFS_MAGIC_OFFSET, UFS2_MAGIC);
        write_u32_le(&mut image, UFS_BLOCK_SIZE_OFFSET, 4096);
        write_u32_le(&mut image, UFS_FRAGMENT_SIZE_OFFSET, 1024);
        write_u64_le(&mut image, UFS_TOTAL_BLOCKS_OFFSET, 262_144);
        image
    }

    fn build_tombstone_record(
        inode_number: u32,
        size_bytes: u64,
        is_directory: bool,
        name: &str,
        path: &str,
    ) -> Vec<u8> {
        let mut record = vec![0u8; UFS_TOMBSTONE_RECORD_SIZE];
        record[..8].copy_from_slice(UFS_TOMBSTONE_MARKER);
        write_u32_le(&mut record, 8, inode_number);
        write_u64_le(&mut record, 12, size_bytes);
        record[20] = if is_directory { 1 } else { 0 };
        record[21] = name.len() as u8;
        record[22] = path.len() as u8;

        let name_start = UFS_TOMBSTONE_HEADER_SIZE;
        let path_start = name_start + UFS_TOMBSTONE_NAME_CAPACITY;
        record[name_start..name_start + name.len()].copy_from_slice(name.as_bytes());
        record[path_start..path_start + path.len()].copy_from_slice(path.as_bytes());

        record
    }

    fn write_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64_le(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
