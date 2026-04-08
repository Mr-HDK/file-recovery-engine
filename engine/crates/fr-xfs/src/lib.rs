use thiserror::Error;

use fr_types::RecoverySourceKind;

const XFS_SUPERBLOCK_SIZE: usize = 512;
const XFS_MAGIC_OFFSET: usize = 0x00;
const XFS_BLOCK_SIZE_OFFSET: usize = 0x04;
const XFS_DATA_BLOCKS_OFFSET: usize = 0x08;
const XFS_AG_COUNT_OFFSET: usize = 0x54;
const XFS_INODE_SIZE_OFFSET: usize = 0x68;

const XFS_TOMBSTONE_MARKER: &[u8; 8] = b"XFSDEL\0\0";
const XFS_TOMBSTONE_NAME_CAPACITY: usize = 96;
const XFS_TOMBSTONE_PATH_CAPACITY: usize = 192;
const XFS_TOMBSTONE_HEADER_SIZE: usize = 8 + 8 + 8 + 1 + 1 + 1 + 1;
const XFS_TOMBSTONE_RECORD_SIZE: usize =
    XFS_TOMBSTONE_HEADER_SIZE + XFS_TOMBSTONE_NAME_CAPACITY + XFS_TOMBSTONE_PATH_CAPACITY;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDescriptor {
    pub name: &'static str,
    pub purpose: &'static str,
    pub source_kind: RecoverySourceKind,
}

pub fn descriptor() -> ModuleDescriptor {
    ModuleDescriptor {
        name: "fr-xfs",
        purpose: "XFS superblock parser and deleted metadata seam.",
        source_kind: RecoverySourceKind::ImageFile,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XfsSuperblock {
    pub block_size_bytes: u32,
    pub data_blocks: u64,
    pub ag_count: u32,
    pub inode_size_bytes: u16,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SuperblockParseError {
    #[error("image buffer too small for XFS superblock: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall { expected: usize, actual: usize },
    #[error("invalid XFS superblock magic: {0:?}")]
    InvalidMagic([u8; 4]),
    #[error("invalid XFS block size: {0}")]
    InvalidBlockSize(u32),
    #[error("invalid XFS inode size: {0}")]
    InvalidInodeSize(u16),
    #[error("invalid XFS AG count: {0}")]
    InvalidAgCount(u32),
    #[error("invalid XFS data block count: {0}")]
    InvalidDataBlocks(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XfsDeletedCandidate {
    pub inode_number: u64,
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

pub fn parse_superblock(image: &[u8]) -> Result<XfsSuperblock, SuperblockParseError> {
    if image.len() < XFS_SUPERBLOCK_SIZE {
        return Err(SuperblockParseError::BufferTooSmall {
            expected: XFS_SUPERBLOCK_SIZE,
            actual: image.len(),
        });
    }

    let mut magic = [0u8; 4];
    magic.copy_from_slice(&image[XFS_MAGIC_OFFSET..XFS_MAGIC_OFFSET + 4]);
    if &magic != b"XFSB" {
        return Err(SuperblockParseError::InvalidMagic(magic));
    }

    let block_size_bytes = read_u32_be(image, XFS_BLOCK_SIZE_OFFSET);
    if block_size_bytes < 512 || block_size_bytes > 65_536 || !block_size_bytes.is_power_of_two() {
        return Err(SuperblockParseError::InvalidBlockSize(block_size_bytes));
    }

    let inode_size_bytes = read_u16_be(image, XFS_INODE_SIZE_OFFSET);
    if inode_size_bytes < 256 || inode_size_bytes > 4096 || !inode_size_bytes.is_power_of_two() {
        return Err(SuperblockParseError::InvalidInodeSize(inode_size_bytes));
    }

    let ag_count = read_u32_be(image, XFS_AG_COUNT_OFFSET);
    if ag_count == 0 {
        return Err(SuperblockParseError::InvalidAgCount(ag_count));
    }

    let data_blocks = read_u64_be(image, XFS_DATA_BLOCKS_OFFSET);
    if data_blocks == 0 {
        return Err(SuperblockParseError::InvalidDataBlocks(data_blocks));
    }

    Ok(XfsSuperblock {
        block_size_bytes,
        data_blocks,
        ag_count,
        inode_size_bytes,
    })
}

pub fn scan_deleted_candidates(
    image: &[u8],
    max_entries: usize,
) -> Result<(XfsSuperblock, Vec<XfsDeletedCandidate>), ScanError> {
    let superblock = parse_superblock(image)?;
    let entries = scan_deleted_candidates_with_superblock(image, &superblock, max_entries);
    Ok((superblock, entries))
}

pub fn scan_deleted_candidates_with_superblock(
    image: &[u8],
    _superblock: &XfsSuperblock,
    max_entries: usize,
) -> Vec<XfsDeletedCandidate> {
    if max_entries == 0 || image.len() < XFS_TOMBSTONE_RECORD_SIZE {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut offset = 0usize;

    while offset + XFS_TOMBSTONE_RECORD_SIZE <= image.len() && out.len() < max_entries {
        if image[offset..offset + XFS_TOMBSTONE_MARKER.len()] == *XFS_TOMBSTONE_MARKER {
            if let Some(candidate) = parse_tombstone_record(&image[offset..offset + XFS_TOMBSTONE_RECORD_SIZE]) {
                let key = (candidate.inode_number, candidate.path.to_ascii_lowercase());
                if seen.insert(key) {
                    out.push(candidate);
                }
            }

            offset = offset.saturating_add(XFS_TOMBSTONE_RECORD_SIZE);
            continue;
        }

        offset = offset.saturating_add(8);
    }

    out
}

fn parse_tombstone_record(record: &[u8]) -> Option<XfsDeletedCandidate> {
    if record.len() < XFS_TOMBSTONE_RECORD_SIZE {
        return None;
    }

    let inode_number = read_u64_le(record, 8);
    if inode_number == 0 {
        return None;
    }

    let size_bytes = read_u64_le(record, 16);
    let flags = record[24];
    let name_len = record[25] as usize;
    let path_len = record[26] as usize;
    if name_len == 0 || name_len > XFS_TOMBSTONE_NAME_CAPACITY || path_len > XFS_TOMBSTONE_PATH_CAPACITY {
        return None;
    }

    let name_start = XFS_TOMBSTONE_HEADER_SIZE;
    let path_start = name_start + XFS_TOMBSTONE_NAME_CAPACITY;

    let name = decode_metadata_text(&record[name_start..name_start + name_len])?;
    let path = if path_len == 0 {
        format!(r".\{}", name)
    } else {
        normalize_candidate_path(&decode_metadata_text(&record[path_start..path_start + path_len])?)
    };

    Some(XfsDeletedCandidate {
        inode_number,
        size_bytes,
        name,
        path,
        is_directory: (flags & 0x01) != 0,
    })
}

fn decode_metadata_text(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?.trim_matches(char::from(0)).trim();
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

fn read_u16_be(bytes: &[u8], offset: usize) -> u16 {
    let mut value = [0u8; 2];
    value.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_be_bytes(value)
}

fn read_u32_be(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_be_bytes(value)
}

fn read_u64_be(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(value)
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
    fn parses_valid_xfs_superblock() {
        let image = build_test_xfs_image();
        let sb = parse_superblock(&image).expect("parse xfs");
        assert_eq!(sb.block_size_bytes, 4096);
        assert_eq!(sb.data_blocks, 1_048_576);
        assert_eq!(sb.ag_count, 4);
        assert_eq!(sb.inode_size_bytes, 512);
    }

    #[test]
    fn rejects_invalid_magic() {
        let mut image = build_test_xfs_image();
        image[0] = b'N';
        let err = parse_superblock(&image).unwrap_err();
        assert!(matches!(err, SuperblockParseError::InvalidMagic(_)));
    }

    #[test]
    fn rejects_invalid_block_size() {
        let mut image = build_test_xfs_image();
        write_u32_be(&mut image, XFS_BLOCK_SIZE_OFFSET, 1234);
        let err = parse_superblock(&image).unwrap_err();
        assert!(matches!(err, SuperblockParseError::InvalidBlockSize(1234)));
    }

    #[test]
    fn extracts_deleted_candidate_from_tombstone_record() {
        let mut image = build_test_xfs_image();
        let record = build_tombstone_record(88, 10_240, false, "audit.log", r"logs\audit.log");
        let offset = 8192usize;
        image[offset..offset + record.len()].copy_from_slice(&record);

        let (_, candidates) = scan_deleted_candidates(&image, 8).expect("scan xfs");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].inode_number, 88);
        assert_eq!(candidates[0].name, "audit.log");
        assert_eq!(candidates[0].path, r".\logs\audit.log");
    }

    fn build_test_xfs_image() -> Vec<u8> {
        let mut image = vec![0u8; 64 * 1024];
        image[0..4].copy_from_slice(b"XFSB");
        write_u32_be(&mut image, XFS_BLOCK_SIZE_OFFSET, 4096);
        write_u64_be(&mut image, XFS_DATA_BLOCKS_OFFSET, 1_048_576);
        write_u32_be(&mut image, XFS_AG_COUNT_OFFSET, 4);
        write_u16_be(&mut image, XFS_INODE_SIZE_OFFSET, 512);
        image
    }

    fn build_tombstone_record(
        inode_number: u64,
        size_bytes: u64,
        is_directory: bool,
        name: &str,
        path: &str,
    ) -> Vec<u8> {
        let mut record = vec![0u8; XFS_TOMBSTONE_RECORD_SIZE];
        record[..8].copy_from_slice(XFS_TOMBSTONE_MARKER);
        write_u64_le(&mut record, 8, inode_number);
        write_u64_le(&mut record, 16, size_bytes);
        record[24] = if is_directory { 1 } else { 0 };
        record[25] = name.len() as u8;
        record[26] = path.len() as u8;

        let name_start = XFS_TOMBSTONE_HEADER_SIZE;
        let path_start = name_start + XFS_TOMBSTONE_NAME_CAPACITY;
        record[name_start..name_start + name.len()].copy_from_slice(name.as_bytes());
        record[path_start..path_start + path.len()].copy_from_slice(path.as_bytes());

        record
    }

    fn write_u16_be(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn write_u32_be(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn write_u64_be(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }

    fn write_u64_le(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
