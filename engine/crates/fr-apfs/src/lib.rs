use thiserror::Error;

use fr_types::RecoverySourceKind;

const APFS_SUPERBLOCK_SIZE: usize = 4096;
const APFS_MAGIC_OFFSET: usize = 0x20;
const APFS_BLOCK_SIZE_OFFSET: usize = 0x24;
const APFS_BLOCK_COUNT_OFFSET: usize = 0x28;
const APFS_FEATURES_OFFSET: usize = 0x30;
const APFS_INCOMPAT_FEATURES_OFFSET: usize = 0x40;
const APFS_CONTAINER_OID_OFFSET: usize = 0x08;
const APFS_MAGIC_NXSB: u32 = 0x4253_584E;

const APFS_TOMBSTONE_MARKER: &[u8; 8] = b"APFSDEL\0";
const APFS_TOMBSTONE_NAME_CAPACITY: usize = 96;
const APFS_TOMBSTONE_PATH_CAPACITY: usize = 192;
const APFS_TOMBSTONE_HEADER_SIZE: usize = 8 + 8 + 8 + 1 + 1 + 1 + 1;
const APFS_TOMBSTONE_RECORD_SIZE: usize =
    APFS_TOMBSTONE_HEADER_SIZE + APFS_TOMBSTONE_NAME_CAPACITY + APFS_TOMBSTONE_PATH_CAPACITY;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDescriptor {
    pub name: &'static str,
    pub purpose: &'static str,
    pub source_kind: RecoverySourceKind,
}

pub fn descriptor() -> ModuleDescriptor {
    ModuleDescriptor {
        name: "fr-apfs",
        purpose: "APFS container parser and deleted metadata tombstone seam.",
        source_kind: RecoverySourceKind::ImageFile,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApfsContainerSuperblock {
    pub container_object_id: u64,
    pub block_size_bytes: u32,
    pub block_count: u64,
    pub features: u64,
    pub incompat_features: u64,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContainerParseError {
    #[error("image buffer too small for APFS container superblock: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall { expected: usize, actual: usize },
    #[error("invalid APFS container magic: 0x{0:08X}")]
    InvalidMagic(u32),
    #[error("invalid APFS block size: {0}")]
    InvalidBlockSize(u32),
    #[error("invalid APFS block count: {0}")]
    InvalidBlockCount(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApfsDeletedCandidate {
    pub cnid: u64,
    pub size_bytes: u64,
    pub name: String,
    pub path: String,
    pub is_directory: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScanError {
    #[error(transparent)]
    Container(#[from] ContainerParseError),
}

pub fn parse_container_superblock(image: &[u8]) -> Result<ApfsContainerSuperblock, ContainerParseError> {
    if image.len() < APFS_SUPERBLOCK_SIZE {
        return Err(ContainerParseError::BufferTooSmall {
            expected: APFS_SUPERBLOCK_SIZE,
            actual: image.len(),
        });
    }

    let magic = read_u32_le(image, APFS_MAGIC_OFFSET);
    if magic != APFS_MAGIC_NXSB {
        return Err(ContainerParseError::InvalidMagic(magic));
    }

    let block_size_bytes = read_u32_le(image, APFS_BLOCK_SIZE_OFFSET);
    if block_size_bytes < 4096 || block_size_bytes > 65_536 || !block_size_bytes.is_power_of_two() {
        return Err(ContainerParseError::InvalidBlockSize(block_size_bytes));
    }

    let block_count = read_u64_le(image, APFS_BLOCK_COUNT_OFFSET);
    if block_count == 0 {
        return Err(ContainerParseError::InvalidBlockCount(block_count));
    }

    Ok(ApfsContainerSuperblock {
        container_object_id: read_u64_le(image, APFS_CONTAINER_OID_OFFSET),
        block_size_bytes,
        block_count,
        features: read_u64_le(image, APFS_FEATURES_OFFSET),
        incompat_features: read_u64_le(image, APFS_INCOMPAT_FEATURES_OFFSET),
    })
}

pub fn scan_deleted_candidates(
    image: &[u8],
    max_entries: usize,
) -> Result<(ApfsContainerSuperblock, Vec<ApfsDeletedCandidate>), ScanError> {
    let container = parse_container_superblock(image)?;
    let entries = scan_deleted_candidates_with_container(image, &container, max_entries);
    Ok((container, entries))
}

pub fn scan_deleted_candidates_with_container(
    image: &[u8],
    _container: &ApfsContainerSuperblock,
    max_entries: usize,
) -> Vec<ApfsDeletedCandidate> {
    if max_entries == 0 || image.len() < APFS_TOMBSTONE_RECORD_SIZE {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut offset = 0usize;

    while offset + APFS_TOMBSTONE_RECORD_SIZE <= image.len() && out.len() < max_entries {
        if image[offset..offset + APFS_TOMBSTONE_MARKER.len()] == *APFS_TOMBSTONE_MARKER {
            if let Some(candidate) = parse_tombstone_record(&image[offset..offset + APFS_TOMBSTONE_RECORD_SIZE]) {
                let dedupe_key = (candidate.cnid, candidate.path.to_ascii_lowercase());
                if seen.insert(dedupe_key) {
                    out.push(candidate);
                }
            }

            offset = offset.saturating_add(APFS_TOMBSTONE_RECORD_SIZE);
            continue;
        }

        offset = offset.saturating_add(8);
    }

    out
}

fn parse_tombstone_record(record: &[u8]) -> Option<ApfsDeletedCandidate> {
    if record.len() < APFS_TOMBSTONE_RECORD_SIZE {
        return None;
    }

    let cnid = read_u64_le(record, 8);
    if cnid == 0 {
        return None;
    }

    let size_bytes = read_u64_le(record, 16);
    let flags = record[24];
    let name_len = record[25] as usize;
    let path_len = record[26] as usize;
    if name_len == 0 || name_len > APFS_TOMBSTONE_NAME_CAPACITY || path_len > APFS_TOMBSTONE_PATH_CAPACITY {
        return None;
    }

    let name_start = APFS_TOMBSTONE_HEADER_SIZE;
    let path_start = name_start + APFS_TOMBSTONE_NAME_CAPACITY;

    let name = decode_metadata_text(&record[name_start..name_start + name_len])?;
    let path = if path_len == 0 {
        format!(r".\{}", name)
    } else {
        normalize_candidate_path(&decode_metadata_text(&record[path_start..path_start + path_len])?)
    };

    Some(ApfsDeletedCandidate {
        cnid,
        size_bytes,
        name,
        path,
        is_directory: (flags & 0x01) != 0,
    })
}

fn normalize_candidate_path(path: &str) -> String {
    let mut normalized = path.replace('/', r"\");
    if normalized.is_empty() {
        return r".\".to_string();
    }

    if !normalized.starts_with(r".\") {
        normalized = format!(r".\{}", normalized.trim_start_matches('\\'));
    }

    normalized
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
    fn parses_valid_apfs_container_superblock() {
        let image = build_test_apfs_image();
        let container = parse_container_superblock(&image).expect("parse apfs container");

        assert_eq!(container.container_object_id, 99);
        assert_eq!(container.block_size_bytes, 4096);
        assert_eq!(container.block_count, 32_768);
        assert_eq!(container.features, 0x10);
        assert_eq!(container.incompat_features, 0x20);
    }

    #[test]
    fn rejects_invalid_apfs_magic() {
        let mut image = build_test_apfs_image();
        write_u32(&mut image, APFS_MAGIC_OFFSET, 0x1234_5678);

        let error = parse_container_superblock(&image).unwrap_err();
        assert!(matches!(error, ContainerParseError::InvalidMagic(0x1234_5678)));
    }

    #[test]
    fn rejects_invalid_block_size() {
        let mut image = build_test_apfs_image();
        write_u32(&mut image, APFS_BLOCK_SIZE_OFFSET, 3000);

        let error = parse_container_superblock(&image).unwrap_err();
        assert!(matches!(error, ContainerParseError::InvalidBlockSize(3000)));
    }

    #[test]
    fn extracts_deleted_tombstone_candidate() {
        let mut image = build_test_apfs_image();
        let record = build_tombstone_record(2048, 16_384, true, "presentation.key", r"projects\presentation.key");
        image[8192..8192 + record.len()].copy_from_slice(&record);

        let (_, candidates) = scan_deleted_candidates(&image, 16).expect("scan apfs");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].cnid, 2048);
        assert_eq!(candidates[0].name, "presentation.key");
        assert_eq!(candidates[0].path, r".\projects\presentation.key");
        assert!(candidates[0].is_directory);
    }

    #[test]
    fn ignores_tombstone_with_invalid_name_length() {
        let mut image = build_test_apfs_image();
        let mut record = build_tombstone_record(5, 512, false, "a.txt", r"docs\a.txt");
        record[25] = 0;
        image[8192..8192 + record.len()].copy_from_slice(&record);

        let (_, candidates) = scan_deleted_candidates(&image, 16).expect("scan apfs");
        assert!(candidates.is_empty());
    }

    fn build_test_apfs_image() -> Vec<u8> {
        let mut image = vec![0u8; 1024 * 64];
        write_u64(&mut image, APFS_CONTAINER_OID_OFFSET, 99);
        write_u32(&mut image, APFS_MAGIC_OFFSET, APFS_MAGIC_NXSB);
        write_u32(&mut image, APFS_BLOCK_SIZE_OFFSET, 4096);
        write_u64(&mut image, APFS_BLOCK_COUNT_OFFSET, 32_768);
        write_u64(&mut image, APFS_FEATURES_OFFSET, 0x10);
        write_u64(&mut image, APFS_INCOMPAT_FEATURES_OFFSET, 0x20);
        image
    }

    fn build_tombstone_record(cnid: u64, size: u64, is_directory: bool, name: &str, path: &str) -> Vec<u8> {
        let mut record = vec![0u8; APFS_TOMBSTONE_RECORD_SIZE];
        record[..8].copy_from_slice(APFS_TOMBSTONE_MARKER);
        write_u64(&mut record, 8, cnid);
        write_u64(&mut record, 16, size);
        record[24] = if is_directory { 0x01 } else { 0x00 };

        let name_bytes = name.as_bytes();
        let path_bytes = path.as_bytes();
        record[25] = name_bytes.len() as u8;
        record[26] = path_bytes.len() as u8;

        let name_start = APFS_TOMBSTONE_HEADER_SIZE;
        let path_start = name_start + APFS_TOMBSTONE_NAME_CAPACITY;
        record[name_start..name_start + name_bytes.len()].copy_from_slice(name_bytes);
        record[path_start..path_start + path_bytes.len()].copy_from_slice(path_bytes);
        record
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
