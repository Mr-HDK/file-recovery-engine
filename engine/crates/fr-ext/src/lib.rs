use thiserror::Error;

use fr_types::RecoverySourceKind;

const EXT_SUPERBLOCK_OFFSET: usize = 1024;
const EXT_SUPERBLOCK_SIZE: usize = 1024;
const EXT_SUPERBLOCK_MAGIC_OFFSET: usize = EXT_SUPERBLOCK_OFFSET + 0x38;
const EXT_SUPERBLOCK_INODE_SIZE_OFFSET: usize = EXT_SUPERBLOCK_OFFSET + 0x58;
const EXT_SUPERBLOCK_FEATURE_COMPAT_OFFSET: usize = EXT_SUPERBLOCK_OFFSET + 0x5C;
const EXT_SUPERBLOCK_FEATURE_INCOMPAT_OFFSET: usize = EXT_SUPERBLOCK_OFFSET + 0x60;
const EXT_GROUP_DESCRIPTOR_INODE_TABLE_OFFSET: usize = 0x08;
const EXT_INODE_SIZE_HIGH_OFFSET: usize = 0x6C;
const EXT_MIN_DELETION_UNIX: u32 = 315_532_800; // 1980-01-01
const EXT_MAX_DELETION_UNIX: u32 = 4_102_444_800; // 2100-01-01
const EXT_FEATURE_COMPAT_HAS_JOURNAL: u32 = 0x0004;
const EXT_FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;

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
    pub filesystem_kind: ExtFilesystemKind,
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub first_data_block: u32,
    pub block_size_bytes: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size_bytes: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtFilesystemKind {
    Ext2,
    Ext3,
    Ext4,
}

impl ExtFilesystemKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExtFilesystemKind::Ext2 => "ext2",
            ExtFilesystemKind::Ext3 => "ext3",
            ExtFilesystemKind::Ext4 => "ext4",
        }
    }

    pub fn as_code(&self) -> u32 {
        match self {
            ExtFilesystemKind::Ext2 => 1,
            ExtFilesystemKind::Ext3 => 2,
            ExtFilesystemKind::Ext4 => 3,
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeletedInodeMetadata {
    inode_number: u64,
    inode_offset_bytes: u64,
    size_bytes: u64,
    file_type: ExtInodeFileType,
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

    let features_compat = read_u32_le(image, EXT_SUPERBLOCK_FEATURE_COMPAT_OFFSET);
    let features_incompat = read_u32_le(image, EXT_SUPERBLOCK_FEATURE_INCOMPAT_OFFSET);
    let filesystem_kind = classify_ext_filesystem(features_compat, features_incompat);

    Ok(ExtSuperblock {
        filesystem_kind,
        inodes_count: read_u32_le(image, EXT_SUPERBLOCK_OFFSET + 0x00),
        blocks_count: read_u32_le(image, EXT_SUPERBLOCK_OFFSET + 0x04) as u64,
        first_data_block: read_u32_le(image, EXT_SUPERBLOCK_OFFSET + 0x14),
        block_size_bytes,
        blocks_per_group: read_u32_le(image, EXT_SUPERBLOCK_OFFSET + 0x20),
        inodes_per_group: read_u32_le(image, EXT_SUPERBLOCK_OFFSET + 0x28),
        inode_size_bytes,
    })
}

fn classify_ext_filesystem(features_compat: u32, features_incompat: u32) -> ExtFilesystemKind {
    if (features_incompat & EXT_FEATURE_INCOMPAT_EXTENTS) != 0 {
        ExtFilesystemKind::Ext4
    } else if (features_compat & EXT_FEATURE_COMPAT_HAS_JOURNAL) != 0 {
        ExtFilesystemKind::Ext3
    } else {
        ExtFilesystemKind::Ext2
    }
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
    superblock: &ExtSuperblock,
    max_entries: usize,
) -> Vec<ExtDeletedCandidate> {
    if max_entries == 0 || image.len() < 8 {
        return Vec::new();
    }

    let mut entries = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();
    let deleted_inodes = collect_deleted_inode_metadata(image, superblock);
    let mut matched_inodes = std::collections::HashSet::new();
    scan_deleted_directory_entry_slack(
        image,
        max_entries,
        &deleted_inodes,
        &mut matched_inodes,
        &mut entries,
        &mut seen_keys,
    );
    append_deleted_inode_fallback_candidates(
        max_entries,
        &deleted_inodes,
        &matched_inodes,
        &mut entries,
        &mut seen_keys,
    );

    entries
}

fn scan_deleted_directory_entry_slack(
    image: &[u8],
    max_entries: usize,
    deleted_inodes: &[DeletedInodeMetadata],
    matched_inodes: &mut std::collections::HashSet<u64>,
    out: &mut Vec<ExtDeletedCandidate>,
    seen_keys: &mut std::collections::HashSet<String>,
) {
    let mut offset = 0usize;
    while offset + 8 <= image.len() && out.len() < max_entries {
        let inode = read_u32_le(image, offset) as u64;
        let rec_len = read_u16_le(image, offset + 4) as usize;
        let name_len = image[offset + 6] as usize;
        let file_type = image[offset + 7];

        if rec_len >= 8 && rec_len <= 4096 && rec_len % 4 == 0 && name_len > 0 && file_type <= 7 {
            let end = offset.saturating_add(rec_len);
            let name_end = offset.saturating_add(8 + name_len);
            if end <= image.len() && name_end <= end {
                let name_bytes = &image[offset + 8..name_end];
                if let Some(name) = decode_ext_name(name_bytes) {
                    if inode > 0 {
                        if let Some(metadata) = deleted_inodes
                            .iter()
                            .find(|candidate| candidate.inode_number == inode)
                        {
                            if ext_dir_entry_matches_inode_type(file_type, metadata.file_type) {
                                matched_inodes.insert(inode);
                                let key = format!("inode-linked:{}", inode);
                                push_candidate(
                                    out,
                                    seen_keys,
                                    key,
                                    ExtDeletedCandidate {
                                        inode_number: inode,
                                        entry_offset_bytes: offset as u64,
                                        size_bytes: metadata.size_bytes,
                                        path: format!(r".\{}", name),
                                        name,
                                        is_directory: metadata.file_type
                                            == ExtInodeFileType::Directory,
                                    },
                                );
                            }
                        }
                    } else {
                        let key = format!("dir:{}:{}", offset, name.to_ascii_lowercase());
                        push_candidate(
                            out,
                            seen_keys,
                            key,
                            ExtDeletedCandidate {
                                inode_number: inode,
                                entry_offset_bytes: offset as u64,
                                size_bytes: 0,
                                path: format!(r".\{}", name),
                                name,
                                is_directory: file_type == 2,
                            },
                        );
                    }
                }

                offset = end;
                continue;
            }
        }

        offset = offset.saturating_add(4);
    }
}

fn append_deleted_inode_fallback_candidates(
    max_entries: usize,
    deleted_inodes: &[DeletedInodeMetadata],
    matched_inodes: &std::collections::HashSet<u64>,
    out: &mut Vec<ExtDeletedCandidate>,
    seen_keys: &mut std::collections::HashSet<String>,
) {
    for metadata in deleted_inodes {
        if out.len() >= max_entries {
            break;
        }

        if matched_inodes.contains(&metadata.inode_number) {
            continue;
        }

        let name = format!("inode-{}", metadata.inode_number);
        let key = format!("inode:{}", metadata.inode_number);
        push_candidate(
            out,
            seen_keys,
            key,
            ExtDeletedCandidate {
                inode_number: metadata.inode_number,
                entry_offset_bytes: metadata.inode_offset_bytes,
                size_bytes: metadata.size_bytes,
                name: name.clone(),
                path: format!(r".\{}", name),
                is_directory: metadata.file_type == ExtInodeFileType::Directory,
            },
        );
    }
}

fn collect_deleted_inode_metadata(
    image: &[u8],
    superblock: &ExtSuperblock,
) -> Vec<DeletedInodeMetadata> {
    let mut metadata = Vec::new();
    let block_size = superblock.block_size_bytes as usize;
    if block_size < 1024 {
        return metadata;
    }

    let inode_size = superblock.inode_size_bytes as usize;
    if inode_size < 128 {
        return metadata;
    }

    let group_desc_base = first_group_descriptor_offset(superblock);
    let group_count = compute_group_count(superblock);
    if group_count == 0 {
        return metadata;
    }

    let inodes_per_group = superblock.inodes_per_group as usize;
    if inodes_per_group == 0 {
        return metadata;
    }

    for group_index in 0..group_count {
        let Some(gd_offset) = group_desc_base.checked_add(group_index.saturating_mul(32)) else {
            break;
        };
        if gd_offset + 32 > image.len() {
            break;
        }

        let inode_table_block =
            read_u32_le(image, gd_offset + EXT_GROUP_DESCRIPTOR_INODE_TABLE_OFFSET);
        if inode_table_block == 0 {
            continue;
        }

        let Some(inode_table_offset) = (inode_table_block as usize).checked_mul(block_size) else {
            continue;
        };
        if inode_table_offset >= image.len() {
            continue;
        }

        let inodes_in_this_group = inodes_in_group(superblock, group_index, group_count);
        if inodes_in_this_group == 0 {
            continue;
        }

        for index in 0..inodes_in_this_group {
            let Some(rel_offset) = index.checked_mul(inode_size) else {
                break;
            };
            let Some(inode_offset) = inode_table_offset.checked_add(rel_offset) else {
                break;
            };
            if inode_offset + inode_size > image.len() {
                break;
            }

            let inode_number = (group_index * inodes_per_group + index + 1) as u64;
            if inode_number <= 10 {
                continue;
            }

            let mode = read_u16_le(image, inode_offset);
            let links_count = read_u16_le(image, inode_offset + 26);
            let deletion_time = read_u32_le(image, inode_offset + 20);
            if mode == 0
                || links_count != 0
                || deletion_time < EXT_MIN_DELETION_UNIX
                || deletion_time > EXT_MAX_DELETION_UNIX
            {
                continue;
            }

            let Some(file_type) = decode_inode_file_type(mode) else {
                continue;
            };

            let size_lo = read_u32_le(image, inode_offset + 4) as u64;
            let size_hi = if inode_size >= EXT_INODE_SIZE_HIGH_OFFSET + 4 {
                read_u32_le(image, inode_offset + EXT_INODE_SIZE_HIGH_OFFSET) as u64
            } else {
                0
            };
            let size_bytes = (size_hi << 32) | size_lo;
            metadata.push(DeletedInodeMetadata {
                inode_number,
                inode_offset_bytes: inode_offset as u64,
                size_bytes,
                file_type,
            });
        }
    }

    metadata
}

fn ext_dir_entry_matches_inode_type(dir_file_type: u8, inode_file_type: ExtInodeFileType) -> bool {
    match dir_file_type {
        0 => true,
        1 => inode_file_type == ExtInodeFileType::Regular,
        2 => inode_file_type == ExtInodeFileType::Directory,
        7 => inode_file_type == ExtInodeFileType::Symlink,
        _ => false,
    }
}

fn first_group_descriptor_offset(superblock: &ExtSuperblock) -> usize {
    if superblock.block_size_bytes == 1024 {
        2048
    } else {
        superblock.block_size_bytes as usize
    }
}

fn compute_group_count(superblock: &ExtSuperblock) -> usize {
    let block_groups = if superblock.blocks_per_group == 0 {
        0usize
    } else {
        div_ceil_u64(superblock.blocks_count, superblock.blocks_per_group as u64)
    };
    let inode_groups = if superblock.inodes_per_group == 0 {
        0usize
    } else {
        div_ceil_u64(
            superblock.inodes_count as u64,
            superblock.inodes_per_group as u64,
        )
    };
    block_groups.max(inode_groups)
}

fn inodes_in_group(superblock: &ExtSuperblock, group_index: usize, group_count: usize) -> usize {
    let inodes_per_group = superblock.inodes_per_group as usize;
    if inodes_per_group == 0 || group_index >= group_count {
        return 0;
    }

    let total_inodes = superblock.inodes_count as usize;
    let full_groups = total_inodes / inodes_per_group;
    let remainder = total_inodes % inodes_per_group;

    if group_index < full_groups {
        inodes_per_group
    } else if group_index == full_groups {
        if remainder == 0 {
            inodes_per_group
        } else {
            remainder
        }
    } else {
        0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtInodeFileType {
    Regular,
    Directory,
    Symlink,
}

fn decode_inode_file_type(mode: u16) -> Option<ExtInodeFileType> {
    match mode & 0xF000 {
        0x8000 => Some(ExtInodeFileType::Regular),
        0x4000 => Some(ExtInodeFileType::Directory),
        0xA000 => Some(ExtInodeFileType::Symlink),
        _ => None,
    }
}

fn div_ceil_u64(numerator: u64, denominator: u64) -> usize {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_add(denominator - 1) as usize / denominator as usize
}

fn push_candidate(
    out: &mut Vec<ExtDeletedCandidate>,
    seen_keys: &mut std::collections::HashSet<String>,
    key: String,
    candidate: ExtDeletedCandidate,
) {
    if seen_keys.insert(key) {
        out.push(candidate);
    }
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
        assert_eq!(sb.filesystem_kind, ExtFilesystemKind::Ext4);
        assert_eq!(sb.block_size_bytes, 4096);
        assert_eq!(sb.inodes_count, 1024);
        assert_eq!(sb.blocks_count, 8192);
        assert_eq!(sb.first_data_block, 0);
        assert_eq!(sb.inodes_per_group, 256);
        assert_eq!(sb.inode_size_bytes, 256);
    }

    #[test]
    fn classifies_ext3_when_journal_feature_present_without_extents() {
        let mut image = build_test_ext4_image();
        write_u32(&mut image, EXT_SUPERBLOCK_FEATURE_INCOMPAT_OFFSET, 0);
        write_u32(
            &mut image,
            EXT_SUPERBLOCK_FEATURE_COMPAT_OFFSET,
            EXT_FEATURE_COMPAT_HAS_JOURNAL,
        );

        let sb = parse_superblock(&image).expect("parse ext3-like superblock");
        assert_eq!(sb.filesystem_kind, ExtFilesystemKind::Ext3);
    }

    #[test]
    fn classifies_ext2_when_no_journal_or_extents_features_present() {
        let mut image = build_test_ext4_image();
        write_u32(&mut image, EXT_SUPERBLOCK_FEATURE_INCOMPAT_OFFSET, 0);
        write_u32(&mut image, EXT_SUPERBLOCK_FEATURE_COMPAT_OFFSET, 0);

        let sb = parse_superblock(&image).expect("parse ext2-like superblock");
        assert_eq!(sb.filesystem_kind, ExtFilesystemKind::Ext2);
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
    fn links_deleted_directory_entry_to_deleted_inode_metadata() {
        let mut image = build_test_ext4_image();
        set_deleted_inode(&mut image, 15, 0x81A4, 8192, 1_704_067_200);

        let offset = 8192usize;
        let entry = build_directory_entry(16, "invoice.pdf", 1);
        image[offset..offset + entry.len()].copy_from_slice(&entry);

        let (_, entries) = scan_deleted_candidates(&image, 16).expect("scan ext");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].inode_number, 16);
        assert_eq!(entries[0].entry_offset_bytes, offset as u64);
        assert_eq!(entries[0].name, "invoice.pdf");
        assert_eq!(entries[0].path, r".\invoice.pdf");
        assert_eq!(entries[0].size_bytes, 8192);
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

    #[test]
    fn extracts_deleted_inode_candidate_from_inode_table() {
        let mut image = build_test_ext4_image();
        set_deleted_inode(&mut image, 15, 0x81A4, 8192, 1_704_067_200);

        let (_, entries) = scan_deleted_candidates(&image, 32).expect("scan ext");
        let inode_entry = entries
            .iter()
            .find(|candidate| candidate.inode_number == 16)
            .expect("inode candidate");

        assert_eq!(inode_entry.name, "inode-16");
        assert_eq!(inode_entry.path, r".\inode-16");
        assert_eq!(inode_entry.size_bytes, 8192);
    }

    #[test]
    fn extracts_deleted_inode_from_second_group_inode_table() {
        let mut image = build_test_ext4_image_two_groups();
        set_deleted_inode_for_group(&mut image, 1, 3, 0x81A4, 4096, 1_704_153_600);

        let (_, entries) = scan_deleted_candidates(&image, 64).expect("scan ext");
        let inode_entry = entries
            .iter()
            .find(|candidate| candidate.inode_number == 260)
            .expect("inode candidate from second group");

        assert_eq!(inode_entry.name, "inode-260");
        assert_eq!(inode_entry.path, r".\inode-260");
        assert_eq!(inode_entry.size_bytes, 4096);
    }

    #[test]
    fn ignores_inode_with_unsupported_file_type() {
        let mut image = build_test_ext4_image();
        set_deleted_inode(&mut image, 15, 0x21A4, 4096, 1_704_067_200);

        let (_, entries) = scan_deleted_candidates(&image, 32).expect("scan ext");
        assert!(!entries.iter().any(|candidate| candidate.inode_number == 16));
    }

    #[test]
    fn ignores_inode_with_invalid_deletion_timestamp() {
        let mut image = build_test_ext4_image();
        set_deleted_inode(&mut image, 15, 0x81A4, 4096, 1000);

        let (_, entries) = scan_deleted_candidates(&image, 32).expect("scan ext");
        assert!(!entries.iter().any(|candidate| candidate.inode_number == 16));
    }

    #[test]
    fn reads_high_size_bits_for_large_inode_payloads() {
        let mut image = build_test_ext4_image();
        set_deleted_inode_with_high_size(
            &mut image,
            15,
            0x81A4,
            0x0000_1000,
            0x0000_0002,
            1_704_067_200,
        );

        let (_, entries) = scan_deleted_candidates(&image, 32).expect("scan ext");
        let inode_entry = entries
            .iter()
            .find(|candidate| candidate.inode_number == 16)
            .expect("inode candidate");

        assert_eq!(inode_entry.size_bytes, 0x0000_0002_0000_1000);
    }

    fn build_test_ext4_image() -> Vec<u8> {
        let mut image = vec![0u8; 512 * 256];
        write_u32(&mut image, EXT_SUPERBLOCK_OFFSET + 0x00, 1024);
        write_u32(&mut image, EXT_SUPERBLOCK_OFFSET + 0x04, 8192);
        write_u32(&mut image, EXT_SUPERBLOCK_OFFSET + 0x18, 2);
        write_u32(&mut image, EXT_SUPERBLOCK_OFFSET + 0x20, 32768);
        write_u32(&mut image, EXT_SUPERBLOCK_OFFSET + 0x28, 256);
        write_u32(
            &mut image,
            EXT_SUPERBLOCK_FEATURE_INCOMPAT_OFFSET,
            EXT_FEATURE_INCOMPAT_EXTENTS,
        );
        write_u16(&mut image, EXT_SUPERBLOCK_MAGIC_OFFSET, 0xEF53);
        write_u16(&mut image, EXT_SUPERBLOCK_INODE_SIZE_OFFSET, 256);
        write_u32(
            &mut image,
            4096 + EXT_GROUP_DESCRIPTOR_INODE_TABLE_OFFSET,
            10,
        );
        image
    }

    fn build_test_ext4_image_two_groups() -> Vec<u8> {
        let mut image = vec![0u8; 4096 * 40];
        write_u32(&mut image, EXT_SUPERBLOCK_OFFSET + 0x00, 512);
        write_u32(&mut image, EXT_SUPERBLOCK_OFFSET + 0x04, 65_536);
        write_u32(&mut image, EXT_SUPERBLOCK_OFFSET + 0x18, 2);
        write_u32(&mut image, EXT_SUPERBLOCK_OFFSET + 0x20, 32_768);
        write_u32(&mut image, EXT_SUPERBLOCK_OFFSET + 0x28, 256);
        write_u32(
            &mut image,
            EXT_SUPERBLOCK_FEATURE_INCOMPAT_OFFSET,
            EXT_FEATURE_INCOMPAT_EXTENTS,
        );
        write_u16(&mut image, EXT_SUPERBLOCK_MAGIC_OFFSET, 0xEF53);
        write_u16(&mut image, EXT_SUPERBLOCK_INODE_SIZE_OFFSET, 256);
        write_u32(
            &mut image,
            4096 + EXT_GROUP_DESCRIPTOR_INODE_TABLE_OFFSET,
            10,
        );
        write_u32(
            &mut image,
            4096 + 32 + EXT_GROUP_DESCRIPTOR_INODE_TABLE_OFFSET,
            20,
        );
        image
    }

    fn set_deleted_inode(
        image: &mut [u8],
        inode_index_zero_based: usize,
        mode: u16,
        size_bytes: u32,
        deletion_time: u32,
    ) {
        set_deleted_inode_with_high_size(
            image,
            inode_index_zero_based,
            mode,
            size_bytes,
            0,
            deletion_time,
        );
    }

    fn set_deleted_inode_with_high_size(
        image: &mut [u8],
        inode_index_zero_based: usize,
        mode: u16,
        size_lo_bytes: u32,
        size_hi_bytes: u32,
        deletion_time: u32,
    ) {
        let inode_size = 256usize;
        let inode_table_offset = 10usize * 4096usize;
        let inode_offset = inode_table_offset + inode_index_zero_based * inode_size;
        write_u16(image, inode_offset + 0, mode);
        write_u32(image, inode_offset + 4, size_lo_bytes);
        write_u32(
            image,
            inode_offset + EXT_INODE_SIZE_HIGH_OFFSET,
            size_hi_bytes,
        );
        write_u32(image, inode_offset + 20, deletion_time);
        write_u16(image, inode_offset + 26, 0);
    }

    fn set_deleted_inode_for_group(
        image: &mut [u8],
        group_index: usize,
        inode_index_zero_based: usize,
        mode: u16,
        size_bytes: u32,
        deletion_time: u32,
    ) {
        let inode_size = 256usize;
        let gd_offset = 4096 + (group_index * 32);
        let inode_table_block =
            read_u32_le(image, gd_offset + EXT_GROUP_DESCRIPTOR_INODE_TABLE_OFFSET);
        let inode_table_offset = (inode_table_block as usize) * 4096usize;
        let inode_offset = inode_table_offset + inode_index_zero_based * inode_size;
        write_u16(image, inode_offset + 0, mode);
        write_u32(image, inode_offset + 4, size_bytes);
        write_u32(image, inode_offset + 20, deletion_time);
        write_u16(image, inode_offset + 26, 0);
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
