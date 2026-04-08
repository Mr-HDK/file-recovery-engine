use fr_types::RecoverySourceKind;
use std::collections::{HashSet, VecDeque};
use thiserror::Error;

pub const EXFAT_OEM_ID: &[u8; 8] = b"EXFAT   ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDescriptor {
    pub name: &'static str,
    pub purpose: &'static str,
    pub source_kind: RecoverySourceKind,
}

pub fn descriptor() -> ModuleDescriptor {
    ModuleDescriptor {
        name: "fr-fat",
        purpose: "FAT32/exFAT boot metadata parsing and deleted-entry full-tree scan.",
        source_kind: RecoverySourceKind::Volume,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatFilesystemKind {
    Fat32,
    ExFat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatBootSector {
    pub filesystem: FatFilesystemKind,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub fat_count: u8,
    pub total_sectors: u64,
    pub fat_offset_sectors: u32,
    pub fat_length_sectors: u32,
    pub data_region_offset_sectors: u32,
    pub root_dir_first_cluster: u32,
    pub volume_serial: u32,
}

impl FatBootSector {
    pub fn cluster_size_bytes(&self) -> u32 {
        (self.bytes_per_sector as u32) * (self.sectors_per_cluster as u32)
    }

    pub fn fat_offset_bytes(&self) -> Option<u64> {
        (self.fat_offset_sectors as u64).checked_mul(self.bytes_per_sector as u64)
    }

    pub fn data_region_offset_bytes(&self) -> Option<u64> {
        (self.data_region_offset_sectors as u64).checked_mul(self.bytes_per_sector as u64)
    }

    pub fn cluster_offset_bytes(&self, cluster_number: u32) -> Option<u64> {
        if cluster_number < 2 {
            return None;
        }

        let cluster_index = (cluster_number - 2) as u64;
        let cluster_size = self.cluster_size_bytes() as u64;
        let data_start = self.data_region_offset_bytes()?;
        let cluster_delta = cluster_index.checked_mul(cluster_size)?;
        data_start.checked_add(cluster_delta)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BootSectorParseError {
    #[error("boot sector buffer too small: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall { expected: usize, actual: usize },
    #[error("invalid boot signature: 0x{0:04X}")]
    InvalidBootSignature(u16),
    #[error("unsupported FAT/exFAT boot sector")]
    UnsupportedFilesystem,
    #[error("invalid bytes per sector: {0}")]
    InvalidBytesPerSector(u16),
    #[error("invalid sectors per cluster: {0}")]
    InvalidSectorsPerCluster(u8),
    #[error("invalid FAT count: {0}")]
    InvalidFatCount(u8),
    #[error("invalid root cluster: {0}")]
    InvalidRootCluster(u32),
    #[error("invalid shift value for {field}: {value}")]
    InvalidShiftValue { field: &'static str, value: u8 },
    #[error("arithmetic overflow while parsing {0}")]
    ArithmeticOverflow(&'static str),
}

pub fn parse_boot_sector(bytes: &[u8]) -> Result<FatBootSector, BootSectorParseError> {
    const REQUIRED_SIZE: usize = 512;
    if bytes.len() < REQUIRED_SIZE {
        return Err(BootSectorParseError::BufferTooSmall {
            expected: REQUIRED_SIZE,
            actual: bytes.len(),
        });
    }

    if &bytes[0x03..0x0B] == EXFAT_OEM_ID {
        parse_exfat_boot_sector(bytes)
    } else {
        parse_fat32_boot_sector(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatDeletedEntry {
    pub filesystem: FatFilesystemKind,
    pub name: String,
    pub path: String,
    pub is_directory: bool,
    pub start_cluster: u32,
    pub size_bytes: u64,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScanError {
    #[error(transparent)]
    Boot(#[from] BootSectorParseError),
    #[error("invalid cluster number: {0}")]
    InvalidCluster(u32),
    #[error("arithmetic overflow while scanning {0}")]
    ArithmeticOverflow(&'static str),
    #[error("requested bytes are out of bounds: offset={offset}, length={length}, image_len={image_len}")]
    OutOfBounds {
        offset: usize,
        length: usize,
        image_len: usize,
    },
    #[error("detected loop in cluster chain at cluster {0}")]
    ClusterLoop(u32),
    #[error("directory entry set is truncated")]
    DirectoryEntryTruncated,
}

pub fn quick_scan_deleted_root_entries(
    image: &[u8],
    max_entries: usize,
) -> Result<(FatBootSector, Vec<FatDeletedEntry>), ScanError> {
    let boot = parse_boot_sector(image)?;
    let entries = scan_deleted_entries_with_boot(image, &boot, max_entries, 256)?;
    Ok((boot, entries))
}

pub fn scan_deleted_entries_with_boot(
    image: &[u8],
    boot: &FatBootSector,
    max_entries: usize,
    max_directory_clusters: usize,
) -> Result<Vec<FatDeletedEntry>, ScanError> {
    if max_entries == 0 {
        return Ok(Vec::new());
    }

    match boot.filesystem {
        FatFilesystemKind::Fat32 => {
            scan_fat32_deleted_entries(image, boot, max_entries, max_directory_clusters)
        }
        FatFilesystemKind::ExFat => {
            scan_exfat_deleted_entries(image, boot, max_entries, max_directory_clusters)
        }
    }
}

pub fn scan_deleted_root_entries_with_boot(
    image: &[u8],
    boot: &FatBootSector,
    max_entries: usize,
    max_directory_clusters: usize,
) -> Result<Vec<FatDeletedEntry>, ScanError> {
    scan_deleted_entries_with_boot(image, boot, max_entries, max_directory_clusters)
}

const FAT_CHAIN_BAD_CLUSTER: u32 = 0x0FFF_FFF7;
const FAT_CHAIN_EOC_MIN: u32 = 0x0FFF_FFF8;
const FAT_CHAIN_RESERVED_MIN: u32 = 0x0FFF_FFF0;

fn parse_fat32_boot_sector(bytes: &[u8]) -> Result<FatBootSector, BootSectorParseError> {
    let boot_signature = read_u16_le(bytes, 0x1FE);
    if boot_signature != 0xAA55 {
        return Err(BootSectorParseError::InvalidBootSignature(boot_signature));
    }

    let bytes_per_sector = read_u16_le(bytes, 0x0B);
    if !is_valid_sector_size(bytes_per_sector) {
        return Err(BootSectorParseError::InvalidBytesPerSector(
            bytes_per_sector,
        ));
    }

    let sectors_per_cluster = bytes[0x0D];
    if !is_valid_cluster_factor(sectors_per_cluster) {
        return Err(BootSectorParseError::InvalidSectorsPerCluster(
            sectors_per_cluster,
        ));
    }

    let reserved_sector_count = read_u16_le(bytes, 0x0E);
    let fat_count = bytes[0x10];
    if fat_count == 0 {
        return Err(BootSectorParseError::InvalidFatCount(fat_count));
    }

    let sectors_per_fat_16 = read_u16_le(bytes, 0x16);
    let sectors_per_fat_32 = read_u32_le(bytes, 0x24);
    if sectors_per_fat_16 != 0 || sectors_per_fat_32 == 0 {
        return Err(BootSectorParseError::UnsupportedFilesystem);
    }

    let total_sectors_16 = read_u16_le(bytes, 0x13) as u32;
    let total_sectors_32 = read_u32_le(bytes, 0x20);
    let total_sectors = if total_sectors_16 != 0 {
        total_sectors_16 as u64
    } else {
        total_sectors_32 as u64
    };

    let root_cluster = read_u32_le(bytes, 0x2C);
    if root_cluster < 2 {
        return Err(BootSectorParseError::InvalidRootCluster(root_cluster));
    }

    let fat_region_sectors = (fat_count as u32).checked_mul(sectors_per_fat_32).ok_or(
        BootSectorParseError::ArithmeticOverflow("FAT region sectors"),
    )?;
    let data_region_offset_sectors = (reserved_sector_count as u32)
        .checked_add(fat_region_sectors)
        .ok_or(BootSectorParseError::ArithmeticOverflow(
            "data region offset sectors",
        ))?;

    Ok(FatBootSector {
        filesystem: FatFilesystemKind::Fat32,
        bytes_per_sector,
        sectors_per_cluster,
        fat_count,
        total_sectors,
        fat_offset_sectors: reserved_sector_count as u32,
        fat_length_sectors: sectors_per_fat_32,
        data_region_offset_sectors,
        root_dir_first_cluster: root_cluster,
        volume_serial: read_u32_le(bytes, 0x43),
    })
}

fn parse_exfat_boot_sector(bytes: &[u8]) -> Result<FatBootSector, BootSectorParseError> {
    let boot_signature = read_u16_le(bytes, 0x1FE);
    if boot_signature != 0xAA55 {
        return Err(BootSectorParseError::InvalidBootSignature(boot_signature));
    }

    let bytes_per_sector_shift = bytes[0x6C];
    if !(9..=12).contains(&bytes_per_sector_shift) {
        return Err(BootSectorParseError::InvalidShiftValue {
            field: "bytes_per_sector_shift",
            value: bytes_per_sector_shift,
        });
    }

    let sectors_per_cluster_shift = bytes[0x6D];
    if sectors_per_cluster_shift > 12 {
        return Err(BootSectorParseError::InvalidShiftValue {
            field: "sectors_per_cluster_shift",
            value: sectors_per_cluster_shift,
        });
    }

    let bytes_per_sector = 1u16.checked_shl(bytes_per_sector_shift as u32).ok_or(
        BootSectorParseError::InvalidShiftValue {
            field: "bytes_per_sector_shift",
            value: bytes_per_sector_shift,
        },
    )?;
    let sectors_per_cluster = 1u8.checked_shl(sectors_per_cluster_shift as u32).ok_or(
        BootSectorParseError::InvalidShiftValue {
            field: "sectors_per_cluster_shift",
            value: sectors_per_cluster_shift,
        },
    )?;

    if !is_valid_sector_size(bytes_per_sector) {
        return Err(BootSectorParseError::InvalidBytesPerSector(
            bytes_per_sector,
        ));
    }
    if !is_valid_cluster_factor(sectors_per_cluster) {
        return Err(BootSectorParseError::InvalidSectorsPerCluster(
            sectors_per_cluster,
        ));
    }

    let fat_count = bytes[0x6E];
    if fat_count == 0 {
        return Err(BootSectorParseError::InvalidFatCount(fat_count));
    }

    let root_cluster = read_u32_le(bytes, 0x60);
    if root_cluster < 2 {
        return Err(BootSectorParseError::InvalidRootCluster(root_cluster));
    }

    Ok(FatBootSector {
        filesystem: FatFilesystemKind::ExFat,
        bytes_per_sector,
        sectors_per_cluster,
        fat_count,
        total_sectors: read_u64_le(bytes, 0x48),
        fat_offset_sectors: read_u32_le(bytes, 0x50),
        fat_length_sectors: read_u32_le(bytes, 0x54),
        data_region_offset_sectors: read_u32_le(bytes, 0x58),
        root_dir_first_cluster: root_cluster,
        volume_serial: read_u32_le(bytes, 0x64),
    })
}

fn scan_fat32_deleted_entries(
    image: &[u8],
    boot: &FatBootSector,
    max_entries: usize,
    max_directory_clusters: usize,
) -> Result<Vec<FatDeletedEntry>, ScanError> {
    let mut entries = Vec::new();
    let mut directories = VecDeque::new();
    let mut visited_directories = HashSet::new();
    directories.push_back((boot.root_dir_first_cluster, ".".to_string()));

    while let Some((directory_cluster, directory_path)) = directories.pop_front() {
        if !visited_directories.insert(directory_cluster) {
            continue;
        }

        let chain = collect_cluster_chain(image, boot, directory_cluster, max_directory_clusters)?;
        let mut long_name_parts = Vec::new();
        let mut stop = false;
        for cluster in chain {
            let cluster_bytes = read_cluster(image, boot, cluster)?;
            for entry in cluster_bytes.chunks_exact(32) {
                let first = entry[0];
                if first == 0x00 {
                    stop = true;
                    break;
                }

                let attributes = entry[11];
                if attributes == 0x0F {
                    let part = decode_lfn_part(entry);
                    if !part.is_empty() {
                        long_name_parts.insert(0, part);
                    }
                    continue;
                }

                let deleted = first == 0xE5;
                let is_directory = (attributes & 0x10) != 0;
                let is_volume_label = (attributes & 0x08) != 0;
                let mut name = if !long_name_parts.is_empty() {
                    let joined = long_name_parts.join("");
                    long_name_parts.clear();
                    joined
                } else {
                    decode_short_name(entry)
                };
                name = sanitize_name(name);
                if is_volume_label || name.is_empty() {
                    continue;
                }

                let first_cluster_high = read_u16_le(entry, 20) as u32;
                let first_cluster_low = read_u16_le(entry, 26) as u32;
                let start_cluster = (first_cluster_high << 16) | first_cluster_low;
                let path = join_candidate_path(&directory_path, &name);

                if is_directory && start_cluster >= 2 && !is_dot_entry(&name) {
                    directories.push_back((start_cluster, path.clone()));
                }

                if !deleted {
                    continue;
                }

                let size_bytes = read_u32_le(entry, 28) as u64;
                entries.push(FatDeletedEntry {
                    filesystem: FatFilesystemKind::Fat32,
                    name,
                    path,
                    is_directory,
                    start_cluster,
                    size_bytes,
                });
                if entries.len() >= max_entries {
                    return Ok(entries);
                }
            }

            if stop {
                break;
            }
        }
    }

    Ok(entries)
}

fn scan_exfat_deleted_entries(
    image: &[u8],
    boot: &FatBootSector,
    max_entries: usize,
    max_directory_clusters: usize,
) -> Result<Vec<FatDeletedEntry>, ScanError> {
    let mut entries = Vec::new();
    let mut directories = VecDeque::new();
    let mut visited_directories = HashSet::new();
    directories.push_back((boot.root_dir_first_cluster, ".".to_string()));

    while let Some((directory_cluster, directory_path)) = directories.pop_front() {
        if !visited_directories.insert(directory_cluster) {
            continue;
        }

        let directory_bytes =
            read_directory_bytes(image, boot, directory_cluster, max_directory_clusters)?;

        let mut offset = 0usize;
        while offset + 32 <= directory_bytes.len() {
            let entry = &directory_bytes[offset..offset + 32];
            let entry_type = entry[0];
            if entry_type == 0x00 {
                break;
            }

            if entry_type != 0x05 && entry_type != 0x85 {
                offset = offset
                    .checked_add(32)
                    .ok_or(ScanError::ArithmeticOverflow("exfat entry step"))?;
                continue;
            }

            let deleted = entry_type == 0x05;
            let secondary_count = entry[1] as usize;
            let attributes = read_u16_le(entry, 4);
            let mut stream_entry_seen = false;
            let mut name_length = 0usize;
            let mut start_cluster = 0u32;
            let mut data_length = 0u64;
            let mut name_units = Vec::new();

            for index in 0..secondary_count {
                let secondary_offset =
                    offset
                        .checked_add((index + 1) * 32)
                        .ok_or(ScanError::ArithmeticOverflow(
                            "exfat secondary entry offset",
                        ))?;
                if secondary_offset + 32 > directory_bytes.len() {
                    return Err(ScanError::DirectoryEntryTruncated);
                }

                let secondary = &directory_bytes[secondary_offset..secondary_offset + 32];
                match secondary[0] {
                    0x40 | 0xC0 => {
                        stream_entry_seen = true;
                        name_length = secondary[3] as usize;
                        start_cluster = read_u32_le(secondary, 20);
                        data_length = read_u64_le(secondary, 24);
                    }
                    0x41 | 0xC1 => {
                        for char_index in 0..15usize {
                            let code = read_u16_le(secondary, 2 + char_index * 2);
                            if code == 0x0000 {
                                break;
                            }
                            if code != 0xFFFF {
                                name_units.push(code);
                            }
                        }
                    }
                    _ => {}
                }
            }

            offset = offset
                .checked_add((secondary_count + 1) * 32)
                .ok_or(ScanError::ArithmeticOverflow("exfat entry advance"))?;
            if !stream_entry_seen {
                continue;
            }

            if name_length > 0 && name_units.len() > name_length {
                name_units.truncate(name_length);
            }

            let name = sanitize_name(String::from_utf16_lossy(&name_units));
            if name.is_empty() {
                continue;
            }

            let is_directory = (attributes & 0x10) != 0;
            let path = join_candidate_path(&directory_path, &name);
            if is_directory && start_cluster >= 2 {
                directories.push_back((start_cluster, path.clone()));
            }

            if !deleted {
                continue;
            }

            entries.push(FatDeletedEntry {
                filesystem: FatFilesystemKind::ExFat,
                name,
                path,
                is_directory,
                start_cluster,
                size_bytes: data_length,
            });
            if entries.len() >= max_entries {
                return Ok(entries);
            }
        }
    }

    Ok(entries)
}

fn read_directory_bytes(
    image: &[u8],
    boot: &FatBootSector,
    directory_cluster: u32,
    max_directory_clusters: usize,
) -> Result<Vec<u8>, ScanError> {
    let chain = collect_cluster_chain(image, boot, directory_cluster, max_directory_clusters)?;
    let mut directory_bytes = Vec::new();
    for cluster in chain {
        directory_bytes.extend_from_slice(read_cluster(image, boot, cluster)?);
    }
    Ok(directory_bytes)
}

fn collect_cluster_chain(
    image: &[u8],
    boot: &FatBootSector,
    start_cluster: u32,
    max_clusters: usize,
) -> Result<Vec<u32>, ScanError> {
    if start_cluster < 2 {
        return Err(ScanError::InvalidCluster(start_cluster));
    }
    if max_clusters == 0 {
        return Ok(Vec::new());
    }

    let mut seen = HashSet::new();
    let mut chain = Vec::new();
    let mut current = start_cluster;
    let mut ended = false;
    for _ in 0..max_clusters {
        if !seen.insert(current) {
            return Err(ScanError::ClusterLoop(current));
        }

        chain.push(current);
        let next = read_fat_entry(image, boot, current)?;
        if next == 0 || next >= FAT_CHAIN_EOC_MIN {
            ended = true;
            break;
        }
        if next < 2
            || next == FAT_CHAIN_BAD_CLUSTER
            || (FAT_CHAIN_RESERVED_MIN..FAT_CHAIN_EOC_MIN).contains(&next)
        {
            return Err(ScanError::InvalidCluster(next));
        }
        current = next;
    }

    if !ended {
        return Err(ScanError::ArithmeticOverflow(
            "directory cluster chain exceeded traversal cap",
        ));
    }

    Ok(chain)
}

fn read_fat_entry(image: &[u8], boot: &FatBootSector, cluster: u32) -> Result<u32, ScanError> {
    let fat_offset = boot
        .fat_offset_bytes()
        .ok_or(ScanError::ArithmeticOverflow("fat offset bytes"))?;
    let cluster_offset = (cluster as u64)
        .checked_mul(4)
        .ok_or(ScanError::ArithmeticOverflow("fat cluster offset"))?;
    let entry_offset_u64 = fat_offset
        .checked_add(cluster_offset)
        .ok_or(ScanError::ArithmeticOverflow("fat entry absolute offset"))?;
    let entry_offset = usize::try_from(entry_offset_u64)
        .map_err(|_| ScanError::ArithmeticOverflow("fat entry usize conversion"))?;
    read_slice(image, entry_offset, 4)
        .map(read_u32_le_at_zero)
        .map(|raw| raw & 0x0FFF_FFFF)
}

fn read_cluster<'a>(
    image: &'a [u8],
    boot: &FatBootSector,
    cluster: u32,
) -> Result<&'a [u8], ScanError> {
    let cluster_offset_u64 = boot
        .cluster_offset_bytes(cluster)
        .ok_or(ScanError::InvalidCluster(cluster))?;
    let cluster_offset = usize::try_from(cluster_offset_u64)
        .map_err(|_| ScanError::ArithmeticOverflow("cluster offset usize conversion"))?;
    let cluster_size = boot.cluster_size_bytes() as usize;
    read_slice(image, cluster_offset, cluster_size)
}

fn read_slice(image: &[u8], offset: usize, length: usize) -> Result<&[u8], ScanError> {
    let end = offset
        .checked_add(length)
        .ok_or(ScanError::ArithmeticOverflow("slice bounds"))?;
    if end > image.len() {
        return Err(ScanError::OutOfBounds {
            offset,
            length,
            image_len: image.len(),
        });
    }

    Ok(&image[offset..end])
}

fn decode_lfn_part(entry: &[u8]) -> String {
    let mut chars = Vec::new();
    append_lfn_range(entry, 1, 10, &mut chars);
    append_lfn_range(entry, 14, 25, &mut chars);
    append_lfn_range(entry, 28, 31, &mut chars);
    String::from_utf16_lossy(&chars)
}

fn append_lfn_range(entry: &[u8], start: usize, end: usize, out: &mut Vec<u16>) {
    let mut offset = start;
    while offset < end {
        let code = read_u16_le(entry, offset);
        if code == 0x0000 || code == 0xFFFF {
            break;
        }
        out.push(code);
        offset += 2;
    }
}

fn decode_short_name(entry: &[u8]) -> String {
    let mut base = String::new();
    for (index, value) in entry[0..8].iter().enumerate() {
        if *value == b' ' || *value == 0x00 {
            break;
        }

        if index == 0 && *value == 0xE5 {
            base.push('_');
        } else {
            base.push(decode_ascii_component(*value));
        }
    }

    let mut extension = String::new();
    for value in &entry[8..11] {
        if *value == b' ' || *value == 0x00 {
            break;
        }
        extension.push(decode_ascii_component(*value));
    }

    if extension.is_empty() {
        base
    } else {
        format!("{}.{}", base, extension)
    }
}

fn decode_ascii_component(byte: u8) -> char {
    if (0x20..=0x7E).contains(&byte) {
        byte as char
    } else {
        '_'
    }
}

fn sanitize_name(name: String) -> String {
    name.trim_matches(char::from(0)).trim().to_string()
}

fn join_candidate_path(parent_path: &str, name: &str) -> String {
    if parent_path == "." {
        format!(r".\{}", name)
    } else {
        format!(r"{}\{}", parent_path, name)
    }
}

fn is_dot_entry(name: &str) -> bool {
    name == "." || name == ".."
}

fn is_valid_sector_size(value: u16) -> bool {
    value >= 512 && value <= 4096 && value.is_power_of_two()
}

fn is_valid_cluster_factor(value: u8) -> bool {
    value != 0 && value.is_power_of_two()
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_le_bytes(buf)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(buf)
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(buf)
}

fn read_u32_le_at_zero(bytes: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[0..4]);
    u32::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn parses_valid_fat32_boot_sector() {
        let image = build_fat32_test_image();
        let boot = parse_boot_sector(&image).expect("parse fat32 boot");
        assert_eq!(boot.filesystem, FatFilesystemKind::Fat32);
        assert_eq!(boot.bytes_per_sector, 512);
        assert_eq!(boot.sectors_per_cluster, 1);
        assert_eq!(boot.fat_offset_sectors, 32);
        assert_eq!(boot.data_region_offset_sectors, 33);
        assert_eq!(boot.root_dir_first_cluster, 2);
    }

    #[test]
    fn parses_valid_exfat_boot_sector() {
        let image = build_exfat_test_image();
        let boot = parse_boot_sector(&image).expect("parse exfat boot");
        assert_eq!(boot.filesystem, FatFilesystemKind::ExFat);
        assert_eq!(boot.bytes_per_sector, 512);
        assert_eq!(boot.sectors_per_cluster, 1);
        assert_eq!(boot.fat_offset_sectors, 24);
        assert_eq!(boot.data_region_offset_sectors, 40);
        assert_eq!(boot.root_dir_first_cluster, 2);
    }

    #[test]
    fn scans_deleted_fat32_root_entries() {
        let image = build_fat32_test_image();
        let (boot, entries) = quick_scan_deleted_root_entries(&image, 16).expect("scan fat32");
        assert_eq!(boot.filesystem, FatFilesystemKind::Fat32);
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.name, "_EST.TXT");
        assert_eq!(entry.path, r".\_EST.TXT");
        assert!(!entry.is_directory);
        assert_eq!(entry.start_cluster, 5);
        assert_eq!(entry.size_bytes, 1234);
    }

    #[test]
    fn scans_deleted_exfat_root_entries() {
        let image = build_exfat_test_image();
        let (boot, entries) = quick_scan_deleted_root_entries(&image, 16).expect("scan exfat");
        assert_eq!(boot.filesystem, FatFilesystemKind::ExFat);
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.name, "lost.doc");
        assert_eq!(entry.path, r".\lost.doc");
        assert!(!entry.is_directory);
        assert_eq!(entry.start_cluster, 7);
        assert_eq!(entry.size_bytes, 42);
    }

    #[test]
    fn scans_deleted_fat32_nested_entries() {
        let image = build_fat32_nested_test_image();
        let (_, entries) = quick_scan_deleted_root_entries(&image, 32).expect("scan nested fat32");
        let paths: HashSet<String> = entries.iter().map(|entry| entry.path.clone()).collect();
        assert!(paths.contains(r".\_EST.TXT"));
        assert!(paths.contains(r".\_ELDIR"));
        assert!(paths.contains(r".\SUBDIR\_HILD.TXT"));
        assert!(paths.contains(r".\_ELDIR\_NNER.BIN"));
    }

    #[test]
    fn scans_deleted_exfat_nested_entries() {
        let image = build_exfat_nested_test_image();
        let (_, entries) = quick_scan_deleted_root_entries(&image, 32).expect("scan nested exfat");
        let paths: HashSet<String> = entries.iter().map(|entry| entry.path.clone()).collect();
        assert!(paths.contains(r".\docs"));
        assert!(paths.contains(r".\lost.doc"));
        assert!(paths.contains(r".\docs\notes.txt"));
    }

    #[test]
    fn scans_deleted_fat32_long_file_name_entries() {
        let image = build_fat32_deleted_lfn_test_image();
        let (_, entries) = quick_scan_deleted_root_entries(&image, 16).expect("scan lfn fat32");
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.name, "QuarterlyReport.txt");
        assert_eq!(entry.path, r".\QuarterlyReport.txt");
        assert!(!entry.is_directory);
        assert_eq!(entry.start_cluster, 5);
        assert_eq!(entry.size_bytes, 4321);
    }

    #[test]
    fn returns_cluster_loop_error_for_directory_chain() {
        let image = build_fat32_loop_chain_test_image();
        let err = quick_scan_deleted_root_entries(&image, 16).expect_err("expected cluster loop");
        assert!(matches!(err, ScanError::ClusterLoop(2)));
    }

    #[test]
    fn returns_invalid_cluster_error_for_bad_cluster_marker() {
        let image = build_fat32_bad_cluster_chain_test_image();
        let err =
            quick_scan_deleted_root_entries(&image, 16).expect_err("expected invalid cluster chain");
        assert!(matches!(err, ScanError::InvalidCluster(0x0FFF_FFF7)));
    }

    fn build_fat32_test_image() -> Vec<u8> {
        let mut image = vec![0u8; 512 * 128];
        write_u16(&mut image, 0x0B, 512);
        image[0x0D] = 1;
        write_u16(&mut image, 0x0E, 32);
        image[0x10] = 1;
        write_u16(&mut image, 0x16, 0);
        write_u32(&mut image, 0x20, 128);
        write_u32(&mut image, 0x24, 1);
        write_u32(&mut image, 0x2C, 2);
        write_u16(&mut image, 0x1FE, 0xAA55);
        image[0x52..0x5A].copy_from_slice(b"FAT32   ");

        let fat_sector_offset = 32 * 512;
        write_u32(&mut image, fat_sector_offset, 0x0FFF_FFF8);
        write_u32(&mut image, fat_sector_offset + 4, 0x0FFF_FFFF);
        write_u32(&mut image, fat_sector_offset + 8, 0x0FFF_FFFF);

        let root_sector_offset = 33 * 512;
        image[root_sector_offset] = 0xE5;
        image[root_sector_offset + 1..root_sector_offset + 8].copy_from_slice(b"EST    ");
        image[root_sector_offset + 8..root_sector_offset + 11].copy_from_slice(b"TXT");
        image[root_sector_offset + 11] = 0x20;
        write_u16(&mut image, root_sector_offset + 26, 5);
        write_u32(&mut image, root_sector_offset + 28, 1234);
        image[root_sector_offset + 32] = 0x00;
        image
    }

    fn build_fat32_nested_test_image() -> Vec<u8> {
        let mut image = build_fat32_test_image();

        let fat_sector_offset = 32 * 512;
        write_u32(&mut image, fat_sector_offset + (6 * 4), 0x0FFF_FFFF);
        write_u32(&mut image, fat_sector_offset + (7 * 4), 0x0FFF_FFFF);

        let root_sector_offset = 33 * 512;
        image[root_sector_offset + 32] = b'S';
        image[root_sector_offset + 33..root_sector_offset + 40].copy_from_slice(b"UBDIR  ");
        image[root_sector_offset + 32 + 11] = 0x10;
        write_u16(&mut image, root_sector_offset + 32 + 26, 6);
        write_u32(&mut image, root_sector_offset + 32 + 28, 0);

        image[root_sector_offset + 64] = 0xE5;
        image[root_sector_offset + 65..root_sector_offset + 72].copy_from_slice(b"ELDIR  ");
        image[root_sector_offset + 64 + 11] = 0x10;
        write_u16(&mut image, root_sector_offset + 64 + 26, 7);
        write_u32(&mut image, root_sector_offset + 64 + 28, 0);
        image[root_sector_offset + 96] = 0x00;

        let subdir_sector_offset = 37 * 512;
        image[subdir_sector_offset] = 0xE5;
        image[subdir_sector_offset + 1..subdir_sector_offset + 8].copy_from_slice(b"HILD   ");
        image[subdir_sector_offset + 8..subdir_sector_offset + 11].copy_from_slice(b"TXT");
        image[subdir_sector_offset + 11] = 0x20;
        write_u16(&mut image, subdir_sector_offset + 26, 9);
        write_u32(&mut image, subdir_sector_offset + 28, 55);
        image[subdir_sector_offset + 32] = 0x00;

        let deleted_subdir_sector_offset = 38 * 512;
        image[deleted_subdir_sector_offset] = 0xE5;
        image[deleted_subdir_sector_offset + 1..deleted_subdir_sector_offset + 8]
            .copy_from_slice(b"NNER   ");
        image[deleted_subdir_sector_offset + 8..deleted_subdir_sector_offset + 11]
            .copy_from_slice(b"BIN");
        image[deleted_subdir_sector_offset + 11] = 0x20;
        write_u16(&mut image, deleted_subdir_sector_offset + 26, 10);
        write_u32(&mut image, deleted_subdir_sector_offset + 28, 66);
        image[deleted_subdir_sector_offset + 32] = 0x00;

        image
    }

    fn build_fat32_deleted_lfn_test_image() -> Vec<u8> {
        let mut image = build_fat32_test_image();
        let root_sector_offset = 33 * 512;
        image[root_sector_offset..root_sector_offset + 512].fill(0);

        write_fat32_lfn_entry(&mut image, root_sector_offset, 0x42, "rt.txt");
        write_fat32_lfn_entry(&mut image, root_sector_offset + 32, 0x01, "QuarterlyRepo");

        image[root_sector_offset + 64] = 0xE5;
        image[root_sector_offset + 65..root_sector_offset + 72].copy_from_slice(b"EPORT~1");
        image[root_sector_offset + 72..root_sector_offset + 75].copy_from_slice(b"TXT");
        image[root_sector_offset + 64 + 11] = 0x20;
        write_u16(&mut image, root_sector_offset + 64 + 26, 5);
        write_u32(&mut image, root_sector_offset + 64 + 28, 4321);
        image[root_sector_offset + 96] = 0x00;

        image
    }

    fn build_fat32_loop_chain_test_image() -> Vec<u8> {
        let mut image = build_fat32_test_image();
        let fat_sector_offset = 32 * 512;
        write_u32(&mut image, fat_sector_offset + (2 * 4), 3);
        write_u32(&mut image, fat_sector_offset + (3 * 4), 2);
        image
    }

    fn build_fat32_bad_cluster_chain_test_image() -> Vec<u8> {
        let mut image = build_fat32_test_image();
        let fat_sector_offset = 32 * 512;
        write_u32(&mut image, fat_sector_offset + (2 * 4), 0x0FFF_FFF7);
        image
    }

    fn build_exfat_test_image() -> Vec<u8> {
        let mut image = vec![0u8; 512 * 128];
        image[0x03..0x0B].copy_from_slice(EXFAT_OEM_ID);
        write_u64(&mut image, 0x48, 128);
        write_u32(&mut image, 0x50, 24);
        write_u32(&mut image, 0x54, 1);
        write_u32(&mut image, 0x58, 40);
        write_u32(&mut image, 0x5C, 32);
        write_u32(&mut image, 0x60, 2);
        write_u32(&mut image, 0x64, 0x4433_2211);
        image[0x6C] = 9;
        image[0x6D] = 0;
        image[0x6E] = 1;
        write_u16(&mut image, 0x1FE, 0xAA55);

        let fat_sector_offset = 24 * 512;
        write_u32(&mut image, fat_sector_offset, 0xFFFF_FFF8);
        write_u32(&mut image, fat_sector_offset + 4, 0xFFFF_FFFF);
        write_u32(&mut image, fat_sector_offset + 8, 0xFFFF_FFFF);

        let root_sector_offset = 40 * 512;
        image[root_sector_offset] = 0x05;
        image[root_sector_offset + 1] = 2;
        write_u16(&mut image, root_sector_offset + 4, 0x20);

        image[root_sector_offset + 32] = 0x40;
        image[root_sector_offset + 32 + 3] = 8;
        write_u32(&mut image, root_sector_offset + 32 + 20, 7);
        write_u64(&mut image, root_sector_offset + 32 + 24, 42);

        image[root_sector_offset + 64] = 0x41;
        write_utf16_entry(
            &mut image[root_sector_offset + 64 + 2..root_sector_offset + 64 + 32],
            "lost.doc",
        );
        image[root_sector_offset + 96] = 0x00;
        image
    }

    fn build_exfat_nested_test_image() -> Vec<u8> {
        let mut image = vec![0u8; 512 * 160];
        image[0x03..0x0B].copy_from_slice(EXFAT_OEM_ID);
        write_u64(&mut image, 0x48, 160);
        write_u32(&mut image, 0x50, 24);
        write_u32(&mut image, 0x54, 1);
        write_u32(&mut image, 0x58, 40);
        write_u32(&mut image, 0x5C, 32);
        write_u32(&mut image, 0x60, 2);
        write_u32(&mut image, 0x64, 0x4433_2211);
        image[0x6C] = 9;
        image[0x6D] = 0;
        image[0x6E] = 1;
        write_u16(&mut image, 0x1FE, 0xAA55);

        let fat_sector_offset = 24 * 512;
        write_u32(&mut image, fat_sector_offset, 0xFFFF_FFF8);
        write_u32(&mut image, fat_sector_offset + 4, 0xFFFF_FFFF);
        write_u32(&mut image, fat_sector_offset + 8, 0xFFFF_FFFF);
        write_u32(&mut image, fat_sector_offset + (5 * 4), 0xFFFF_FFFF);

        let root_sector_offset = 40 * 512;
        image[root_sector_offset] = 0x05;
        image[root_sector_offset + 1] = 2;
        write_u16(&mut image, root_sector_offset + 4, 0x10);

        image[root_sector_offset + 32] = 0xC0;
        image[root_sector_offset + 32 + 3] = 4;
        write_u32(&mut image, root_sector_offset + 32 + 20, 5);

        image[root_sector_offset + 64] = 0xC1;
        write_utf16_entry(
            &mut image[root_sector_offset + 64 + 2..root_sector_offset + 64 + 32],
            "docs",
        );

        image[root_sector_offset + 96] = 0x05;
        image[root_sector_offset + 96 + 1] = 2;
        write_u16(&mut image, root_sector_offset + 96 + 4, 0x20);

        image[root_sector_offset + 128] = 0x40;
        image[root_sector_offset + 128 + 3] = 8;
        write_u32(&mut image, root_sector_offset + 128 + 20, 7);
        write_u64(&mut image, root_sector_offset + 128 + 24, 42);

        image[root_sector_offset + 160] = 0x41;
        write_utf16_entry(
            &mut image[root_sector_offset + 160 + 2..root_sector_offset + 160 + 32],
            "lost.doc",
        );
        image[root_sector_offset + 192] = 0x00;

        let docs_sector_offset = 43 * 512;
        image[docs_sector_offset] = 0x05;
        image[docs_sector_offset + 1] = 2;
        write_u16(&mut image, docs_sector_offset + 4, 0x20);

        image[docs_sector_offset + 32] = 0x40;
        image[docs_sector_offset + 32 + 3] = 9;
        write_u32(&mut image, docs_sector_offset + 32 + 20, 8);
        write_u64(&mut image, docs_sector_offset + 32 + 24, 21);

        image[docs_sector_offset + 64] = 0x41;
        write_utf16_entry(
            &mut image[docs_sector_offset + 64 + 2..docs_sector_offset + 64 + 32],
            "notes.txt",
        );
        image[docs_sector_offset + 96] = 0x00;

        image
    }

    fn write_fat32_lfn_entry(image: &mut [u8], offset: usize, order: u8, text: &str) {
        let entry = &mut image[offset..offset + 32];
        entry.fill(0);
        entry[0] = order;
        entry[11] = 0x0F;
        entry[12] = 0x00;
        entry[13] = 0x00;
        write_u16(entry, 26, 0);
        write_lfn_text(entry, text);
    }

    fn write_lfn_text(entry: &mut [u8], text: &str) {
        const CHAR_OFFSETS: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        for offset in CHAR_OFFSETS {
            write_u16(entry, offset, 0xFFFF);
        }

        let units: Vec<u16> = text.encode_utf16().take(13).collect();
        for (index, code_unit) in units.iter().enumerate() {
            write_u16(entry, CHAR_OFFSETS[index], *code_unit);
        }

        if units.len() < CHAR_OFFSETS.len() {
            write_u16(entry, CHAR_OFFSETS[units.len()], 0x0000);
        }
    }

    fn write_utf16_entry(slot: &mut [u8], value: &str) {
        let mut cursor = 0usize;
        for code in value.encode_utf16().take(15) {
            slot[cursor..cursor + 2].copy_from_slice(&code.to_le_bytes());
            cursor += 2;
        }
        while cursor + 1 < slot.len() {
            slot[cursor..cursor + 2].copy_from_slice(&0u16.to_le_bytes());
            cursor += 2;
        }
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
