use thiserror::Error;

use fr_types::RecoverySourceKind;

const HFS_VOLUME_HEADER_OFFSET: usize = 1024;
const HFS_VOLUME_HEADER_SIZE: usize = 512;
const HFS_SIGNATURE_OFFSET: usize = HFS_VOLUME_HEADER_OFFSET;
const HFS_VERSION_OFFSET: usize = HFS_VOLUME_HEADER_OFFSET + 2;
const HFS_FILE_COUNT_OFFSET: usize = HFS_VOLUME_HEADER_OFFSET + 32;
const HFS_FOLDER_COUNT_OFFSET: usize = HFS_VOLUME_HEADER_OFFSET + 36;
const HFS_BLOCK_SIZE_OFFSET: usize = HFS_VOLUME_HEADER_OFFSET + 40;
const HFS_TOTAL_BLOCKS_OFFSET: usize = HFS_VOLUME_HEADER_OFFSET + 44;

const HFS_SIGNATURE_HPLUS: u16 = 0x482B;
const HFS_SIGNATURE_HX: u16 = 0x4858;

const HFS_TOMBSTONE_MARKER: &[u8; 8] = b"HFSDEL\0\0";
const HFS_TOMBSTONE_NAME_CAPACITY: usize = 96;
const HFS_TOMBSTONE_PATH_CAPACITY: usize = 192;
const HFS_TOMBSTONE_HEADER_SIZE: usize = 8 + 4 + 8 + 1 + 1 + 1 + 1;
const HFS_TOMBSTONE_RECORD_SIZE: usize =
    HFS_TOMBSTONE_HEADER_SIZE + HFS_TOMBSTONE_NAME_CAPACITY + HFS_TOMBSTONE_PATH_CAPACITY;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDescriptor {
    pub name: &'static str,
    pub purpose: &'static str,
    pub source_kind: RecoverySourceKind,
}

pub fn descriptor() -> ModuleDescriptor {
    ModuleDescriptor {
        name: "fr-hfs",
        purpose: "HFS+ volume-header parser and deleted metadata tombstone seam.",
        source_kind: RecoverySourceKind::ImageFile,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HfsVolumeHeader {
    pub signature: u16,
    pub version: u16,
    pub block_size_bytes: u32,
    pub total_blocks: u32,
    pub file_count: u32,
    pub folder_count: u32,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VolumeHeaderParseError {
    #[error("image buffer too small for HFS+ volume header: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall { expected: usize, actual: usize },
    #[error("invalid HFS+ signature: 0x{0:04X}")]
    InvalidSignature(u16),
    #[error("invalid HFS+ version: {0}")]
    InvalidVersion(u16),
    #[error("invalid HFS+ block size: {0}")]
    InvalidBlockSize(u32),
    #[error("invalid HFS+ block count: {0}")]
    InvalidBlockCount(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HfsDeletedCandidate {
    pub cnid: u32,
    pub size_bytes: u64,
    pub name: String,
    pub path: String,
    pub is_directory: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScanError {
    #[error(transparent)]
    Header(#[from] VolumeHeaderParseError),
}

pub fn parse_volume_header(image: &[u8]) -> Result<HfsVolumeHeader, VolumeHeaderParseError> {
    let minimum = HFS_VOLUME_HEADER_OFFSET + HFS_VOLUME_HEADER_SIZE;
    if image.len() < minimum {
        return Err(VolumeHeaderParseError::BufferTooSmall {
            expected: minimum,
            actual: image.len(),
        });
    }

    let signature = read_u16_be(image, HFS_SIGNATURE_OFFSET);
    if signature != HFS_SIGNATURE_HPLUS && signature != HFS_SIGNATURE_HX {
        return Err(VolumeHeaderParseError::InvalidSignature(signature));
    }

    let version = read_u16_be(image, HFS_VERSION_OFFSET);
    if version != 4 && version != 5 {
        return Err(VolumeHeaderParseError::InvalidVersion(version));
    }

    let block_size_bytes = read_u32_be(image, HFS_BLOCK_SIZE_OFFSET);
    if block_size_bytes < 512 || !block_size_bytes.is_power_of_two() {
        return Err(VolumeHeaderParseError::InvalidBlockSize(block_size_bytes));
    }

    let total_blocks = read_u32_be(image, HFS_TOTAL_BLOCKS_OFFSET);
    if total_blocks == 0 {
        return Err(VolumeHeaderParseError::InvalidBlockCount(total_blocks));
    }

    Ok(HfsVolumeHeader {
        signature,
        version,
        block_size_bytes,
        total_blocks,
        file_count: read_u32_be(image, HFS_FILE_COUNT_OFFSET),
        folder_count: read_u32_be(image, HFS_FOLDER_COUNT_OFFSET),
    })
}

pub fn scan_deleted_candidates(
    image: &[u8],
    max_entries: usize,
) -> Result<(HfsVolumeHeader, Vec<HfsDeletedCandidate>), ScanError> {
    let header = parse_volume_header(image)?;
    let entries = scan_deleted_candidates_with_header(image, &header, max_entries);
    Ok((header, entries))
}

pub fn scan_deleted_candidates_with_header(
    image: &[u8],
    _header: &HfsVolumeHeader,
    max_entries: usize,
) -> Vec<HfsDeletedCandidate> {
    if max_entries == 0 || image.len() < HFS_TOMBSTONE_RECORD_SIZE {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut offset = 0usize;

    while offset + HFS_TOMBSTONE_RECORD_SIZE <= image.len() && out.len() < max_entries {
        if image[offset..offset + HFS_TOMBSTONE_MARKER.len()] == *HFS_TOMBSTONE_MARKER {
            if let Some(candidate) =
                parse_tombstone_record(&image[offset..offset + HFS_TOMBSTONE_RECORD_SIZE])
            {
                let dedupe_key = (candidate.cnid, candidate.path.to_ascii_lowercase());
                if seen.insert(dedupe_key) {
                    out.push(candidate);
                }
            }

            offset = offset.saturating_add(HFS_TOMBSTONE_RECORD_SIZE);
            continue;
        }

        offset = offset.saturating_add(8);
    }

    out
}

fn parse_tombstone_record(record: &[u8]) -> Option<HfsDeletedCandidate> {
    if record.len() < HFS_TOMBSTONE_RECORD_SIZE {
        return None;
    }

    let cnid = read_u32_le(record, 8);
    if cnid == 0 {
        return None;
    }

    let size_bytes = read_u64_le(record, 12);
    let flags = record[20];
    let name_len = record[21] as usize;
    let path_len = record[22] as usize;
    if name_len == 0
        || name_len > HFS_TOMBSTONE_NAME_CAPACITY
        || path_len > HFS_TOMBSTONE_PATH_CAPACITY
    {
        return None;
    }

    let name_start = HFS_TOMBSTONE_HEADER_SIZE;
    let path_start = name_start + HFS_TOMBSTONE_NAME_CAPACITY;

    let name = decode_metadata_text(&record[name_start..name_start + name_len])?;
    let path = if path_len == 0 {
        format!(r".\{}", name)
    } else {
        normalize_candidate_path(&decode_metadata_text(
            &record[path_start..path_start + path_len],
        )?)
    };

    Some(HfsDeletedCandidate {
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
    fn parses_valid_hfs_volume_header() {
        let image = build_test_hfs_image();
        let header = parse_volume_header(&image).expect("parse hfs header");

        assert_eq!(header.signature, HFS_SIGNATURE_HPLUS);
        assert_eq!(header.version, 4);
        assert_eq!(header.block_size_bytes, 4096);
        assert_eq!(header.total_blocks, 65_536);
        assert_eq!(header.file_count, 200);
        assert_eq!(header.folder_count, 80);
    }

    #[test]
    fn rejects_invalid_hfs_signature() {
        let mut image = build_test_hfs_image();
        write_u16_be(&mut image, HFS_SIGNATURE_OFFSET, 0x4A4A);

        let error = parse_volume_header(&image).unwrap_err();
        assert!(matches!(
            error,
            VolumeHeaderParseError::InvalidSignature(0x4A4A)
        ));
    }

    #[test]
    fn rejects_invalid_hfs_block_size() {
        let mut image = build_test_hfs_image();
        write_u32_be(&mut image, HFS_BLOCK_SIZE_OFFSET, 1234);

        let error = parse_volume_header(&image).unwrap_err();
        assert!(matches!(
            error,
            VolumeHeaderParseError::InvalidBlockSize(1234)
        ));
    }

    #[test]
    fn extracts_deleted_hfs_tombstone_candidate() {
        let mut image = build_test_hfs_image();
        let record =
            build_tombstone_record(77, 12_288, false, "invoice.pages", r"archive\invoice.pages");
        image[4096..4096 + record.len()].copy_from_slice(&record);

        let (_, candidates) = scan_deleted_candidates(&image, 16).expect("scan hfs");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].cnid, 77);
        assert_eq!(candidates[0].name, "invoice.pages");
        assert_eq!(candidates[0].path, r".\archive\invoice.pages");
        assert_eq!(candidates[0].size_bytes, 12_288);
    }

    #[test]
    fn ignores_tombstone_with_empty_name() {
        let mut image = build_test_hfs_image();
        let mut record = build_tombstone_record(88, 100, false, "draft.txt", r"draft.txt");
        record[21] = 0;
        image[4096..4096 + record.len()].copy_from_slice(&record);

        let (_, candidates) = scan_deleted_candidates(&image, 16).expect("scan hfs");
        assert!(candidates.is_empty());
    }

    fn build_test_hfs_image() -> Vec<u8> {
        let mut image = vec![0u8; 1024 * 64];
        write_u16_be(&mut image, HFS_SIGNATURE_OFFSET, HFS_SIGNATURE_HPLUS);
        write_u16_be(&mut image, HFS_VERSION_OFFSET, 4);
        write_u32_be(&mut image, HFS_FILE_COUNT_OFFSET, 200);
        write_u32_be(&mut image, HFS_FOLDER_COUNT_OFFSET, 80);
        write_u32_be(&mut image, HFS_BLOCK_SIZE_OFFSET, 4096);
        write_u32_be(&mut image, HFS_TOTAL_BLOCKS_OFFSET, 65_536);
        image
    }

    fn build_tombstone_record(
        cnid: u32,
        size: u64,
        is_directory: bool,
        name: &str,
        path: &str,
    ) -> Vec<u8> {
        let mut record = vec![0u8; HFS_TOMBSTONE_RECORD_SIZE];
        record[..8].copy_from_slice(HFS_TOMBSTONE_MARKER);
        write_u32_le(&mut record, 8, cnid);
        write_u64_le(&mut record, 12, size);
        record[20] = if is_directory { 0x01 } else { 0x00 };

        let name_bytes = name.as_bytes();
        let path_bytes = path.as_bytes();
        record[21] = name_bytes.len() as u8;
        record[22] = path_bytes.len() as u8;

        let name_start = HFS_TOMBSTONE_HEADER_SIZE;
        let path_start = name_start + HFS_TOMBSTONE_NAME_CAPACITY;
        record[name_start..name_start + name_bytes.len()].copy_from_slice(name_bytes);
        record[path_start..path_start + path_bytes.len()].copy_from_slice(path_bytes);

        record
    }

    fn write_u16_be(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn write_u32_be(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn write_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64_le(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
