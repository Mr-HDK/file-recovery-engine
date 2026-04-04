use thiserror::Error;

use fr_types::RecoverySourceKind;

const EXT_SUPERBLOCK_OFFSET: usize = 1024;
const EXT_SUPERBLOCK_SIZE: usize = 1024;
const EXT_SUPERBLOCK_MAGIC_OFFSET: usize = EXT_SUPERBLOCK_OFFSET + 0x38;
const EXT_SUPERBLOCK_INODE_SIZE_OFFSET: usize = EXT_SUPERBLOCK_OFFSET + 0x58;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDescriptor {
    pub name: &'static str,
    pub purpose: &'static str,
    pub source_kind: RecoverySourceKind,
}

pub fn descriptor() -> ModuleDescriptor {
    ModuleDescriptor {
        name: "fr-ext",
        purpose: "ext superblock parser and deleted directory-entry candidate seam.",
        source_kind: RecoverySourceKind::ImageFile,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtSuperblock {
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub block_size_bytes: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size_bytes: u16,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SuperblockParseError {
    #[error("image buffer too small for ext superblock: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall { expected: usize, actual: usize },
    #[error("invalid ext superblock magic: 0x{0:04X}")]
    InvalidMagic(u16),
    #[error("invalid ext block size shift: {0}")]
    InvalidBlockSizeShift(u32),
    #[error("invalid ext inode size: {0}")]
    InvalidInodeSize(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtDeletedCandidate {
    pub inode_number: u64,
    pub entry_offset_bytes: u64,
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

pub fn parse_superblock(image: &[u8]) -> Result<ExtSuperblock, SuperblockParseError> {
    let min_size = EXT_SUPERBLOCK_OFFSET + EXT_SUPERBLOCK_SIZE;
    if image.len() < min_size {
        return Err(SuperblockParseError::BufferTooSmall {
            expected: min_size,
            actual: image.len(),
        });
    }

    let magic = read_u16_le(image, EXT_SUPERBLOCK_MAGIC_OFFSET);
    if magic != 0xEF53 {
        return Err(SuperblockParseError::InvalidMagic(magic));
    }

    let block_size_shift = read_u32_le(image, EXT_SUPERBLOCK_OFFSET + 0x18);
    if block_size_shift > 6 {
        return Err(SuperblockParseError::InvalidBlockSizeShift(
            block_size_shift,
        ));
    }
    let block_size_bytes = 1024u32 << block_size_shift;

    let inode_size_bytes = read_u16_le(image, EXT_SUPERBLOCK_INODE_SIZE_OFFSET);
    if inode_size_bytes < 128 || inode_size_bytes > 4096 || inode_size_bytes % 4 != 0 {
        return Err(SuperblockParseError::InvalidInodeSize(inode_size_bytes));
    }

    Ok(ExtSuperblock {
        inodes_count: read_u32_le(image, EXT_SUPERBLOCK_OFFSET + 0x00),
        blocks_count: read_u32_le(image, EXT_SUPERBLOCK_OFFSET + 0x04) as u64,
        block_size_bytes,
        blocks_per_group: read_u32_le(image, EXT_SUPERBLOCK_OFFSET + 0x20),
        inodes_per_group: read_u32_le(image, EXT_SUPERBLOCK_OFFSET + 0x28),
        inode_size_bytes,
    })
}

pub fn scan_deleted_candidates(
    image: &[u8],
    max_entries: usize,
) -> Result<(ExtSuperblock, Vec<ExtDeletedCandidate>), ScanError> {
    let superblock = parse_superblock(image)?;
    let entries = scan_deleted_candidates_with_superblock(image, &superblock, max_entries);
    Ok((superblock, entries))
}

pub fn scan_deleted_candidates_with_superblock(
    image: &[u8],
    _superblock: &ExtSuperblock,
    max_entries: usize,
) -> Vec<ExtDeletedCandidate> {
    if max_entries == 0 || image.len() < 8 {
        return Vec::new();
    }

    let mut entries = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut offset = 0usize;
    while offset + 8 <= image.len() && entries.len() < max_entries {
        let inode = read_u32_le(image, offset) as u64;
        let rec_len = read_u16_le(image, offset + 4) as usize;
        let name_len = image[offset + 6] as usize;
        let file_type = image[offset + 7];

        if inode == 0
            && rec_len >= 8
            && rec_len <= 4096
            && rec_len % 4 == 0
            && name_len > 0
            && file_type <= 7
        {
            let end = offset.saturating_add(rec_len);
            let name_end = offset.saturating_add(8 + name_len);
            if end <= image.len() && name_end <= end {
                let name_bytes = &image[offset + 8..name_end];
                if let Some(name) = decode_ext_name(name_bytes) {
                    let key = (offset, name.to_ascii_lowercase());
                    if seen.insert(key) {
                        entries.push(ExtDeletedCandidate {
                            inode_number: inode,
                            entry_offset_bytes: offset as u64,
                            size_bytes: 0,
                            path: format!(r".\{}", name),
                            name,
                            is_directory: file_type == 2,
                        });
                    }
                }

                offset = end;
                continue;
            }
        }

        offset = offset.saturating_add(4);
    }

    entries
}

fn decode_ext_name(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if text.is_empty() || text == "." || text == ".." {
        return None;
    }

    if text
        .as_bytes()
        .iter()
        .any(|value| *value < 0x20 || *value == b'/' || *value == b'\\')
    {
        return None;
    }

    Some(text.to_string())
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    let mut value = [0u8; 2];
    value.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_le_bytes(value)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_ext_superblock() {
        let image = build_test_ext4_image();
        let sb = parse_superblock(&image).expect("parse ext superblock");
        assert_eq!(sb.block_size_bytes, 4096);
        assert_eq!(sb.inodes_count, 1024);
        assert_eq!(sb.blocks_count, 8192);
        assert_eq!(sb.inodes_per_group, 256);
        assert_eq!(sb.inode_size_bytes, 256);
    }

    #[test]
    fn rejects_invalid_superblock_magic() {
        let mut image = build_test_ext4_image();
        write_u16(&mut image, EXT_SUPERBLOCK_MAGIC_OFFSET, 0x1234);
        let error = parse_superblock(&image).unwrap_err();
        assert!(matches!(error, SuperblockParseError::InvalidMagic(0x1234)));
    }

    #[test]
    fn extracts_deleted_candidate_from_directory_entry() {
        let mut image = build_test_ext4_image();
        let offset = 8192usize;
        let entry = build_directory_entry(0, "deleted.log", 1);
        image[offset..offset + entry.len()].copy_from_slice(&entry);

        let (sb, entries) = scan_deleted_candidates(&image, 16).expect("scan ext");
        assert_eq!(sb.block_size_bytes, 4096);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_offset_bytes, offset as u64);
        assert_eq!(entries[0].name, "deleted.log");
    }

    #[test]
    fn ignores_in_use_directory_entry() {
        let mut image = build_test_ext4_image();
        let offset = 8192usize;
        let entry = build_directory_entry(42, "active.log", 1);
        image[offset..offset + entry.len()].copy_from_slice(&entry);

        let (_, entries) = scan_deleted_candidates(&image, 16).expect("scan ext");
        assert!(entries.is_empty());
    }

    fn build_test_ext4_image() -> Vec<u8> {
        let mut image = vec![0u8; 512 * 256];
        write_u32(&mut image, EXT_SUPERBLOCK_OFFSET + 0x00, 1024);
        write_u32(&mut image, EXT_SUPERBLOCK_OFFSET + 0x04, 8192);
        write_u32(&mut image, EXT_SUPERBLOCK_OFFSET + 0x18, 2);
        write_u32(&mut image, EXT_SUPERBLOCK_OFFSET + 0x20, 32768);
        write_u32(&mut image, EXT_SUPERBLOCK_OFFSET + 0x28, 256);
        write_u16(&mut image, EXT_SUPERBLOCK_MAGIC_OFFSET, 0xEF53);
        write_u16(&mut image, EXT_SUPERBLOCK_INODE_SIZE_OFFSET, 256);
        image
    }

    fn build_directory_entry(inode: u32, name: &str, file_type: u8) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let rec_len = align_to_4(8 + name_bytes.len());
        let mut entry = vec![0u8; rec_len];
        write_u32(&mut entry, 0, inode);
        write_u16(&mut entry, 4, rec_len as u16);
        entry[6] = name_bytes.len() as u8;
        entry[7] = file_type;
        entry[8..8 + name_bytes.len()].copy_from_slice(name_bytes);
        entry
    }

    fn align_to_4(value: usize) -> usize {
        (value + 3) & !3
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
