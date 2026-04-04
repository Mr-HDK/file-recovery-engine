use thiserror::Error;

use fr_types::RecoverySourceKind;
use fr_usn::{
    parse_usn_records, UsnRecord, USN_REASON_FILE_DELETE, USN_REASON_RENAME_OLD_NAME,
};

pub const REFS_OEM_PREFIX: &[u8; 4] = b"ReFS";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDescriptor {
    pub name: &'static str,
    pub purpose: &'static str,
    pub source_kind: RecoverySourceKind,
}

pub fn descriptor() -> ModuleDescriptor {
    ModuleDescriptor {
        name: "fr-refs",
        purpose: "ReFS boot metadata parser boundary for metadata-first recovery orchestration.",
        source_kind: RecoverySourceKind::Volume,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefsBootSector {
    pub oem_id: [u8; 8],
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub total_sectors: u64,
    pub volume_serial: u64,
}

impl RefsBootSector {
    pub fn cluster_size_bytes(&self) -> u32 {
        self.bytes_per_sector as u32 * self.sectors_per_cluster as u32
    }

    pub fn volume_size_bytes(&self) -> Option<u64> {
        self.total_sectors.checked_mul(self.bytes_per_sector as u64)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BootSectorParseError {
    #[error("boot sector buffer too small: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall { expected: usize, actual: usize },
    #[error("invalid ReFS OEM id: {0:?}")]
    InvalidOemId([u8; 8]),
    #[error("invalid bytes per sector: {0}")]
    InvalidBytesPerSector(u16),
    #[error("invalid sectors per cluster: {0}")]
    InvalidSectorsPerCluster(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefsDeletedCandidate {
    pub object_id: u64,
    pub size_bytes: u64,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScanError {
    #[error(transparent)]
    Boot(#[from] BootSectorParseError),
}

pub fn parse_boot_sector(bytes: &[u8]) -> Result<RefsBootSector, BootSectorParseError> {
    const REQUIRED_SIZE: usize = 512;
    if bytes.len() < REQUIRED_SIZE {
        return Err(BootSectorParseError::BufferTooSmall {
            expected: REQUIRED_SIZE,
            actual: bytes.len(),
        });
    }

    let mut oem_id = [0u8; 8];
    oem_id.copy_from_slice(&bytes[0x03..0x0B]);
    if !oem_id[0..4].eq_ignore_ascii_case(REFS_OEM_PREFIX) {
        return Err(BootSectorParseError::InvalidOemId(oem_id));
    }

    let bytes_per_sector = read_u16_le(bytes, 0x0B);
    if bytes_per_sector < 512 || !bytes_per_sector.is_power_of_two() {
        return Err(BootSectorParseError::InvalidBytesPerSector(
            bytes_per_sector,
        ));
    }

    let sectors_per_cluster = bytes[0x0D];
    if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
        return Err(BootSectorParseError::InvalidSectorsPerCluster(
            sectors_per_cluster,
        ));
    }

    Ok(RefsBootSector {
        oem_id,
        bytes_per_sector,
        sectors_per_cluster,
        total_sectors: read_u64_le(bytes, 0x28),
        volume_serial: read_u64_le(bytes, 0x48),
    })
}

pub fn scan_deleted_candidates(
    image: &[u8],
    max_entries: usize,
) -> Result<(RefsBootSector, Vec<RefsDeletedCandidate>), ScanError> {
    let boot = parse_boot_sector(image)?;
    let entries = scan_deleted_candidates_with_boot(image, &boot, max_entries);
    Ok((boot, entries))
}

pub fn scan_deleted_candidates_with_boot(
    image: &[u8],
    _boot: &RefsBootSector,
    max_entries: usize,
) -> Vec<RefsDeletedCandidate> {
    if max_entries == 0 || image.len() < 8 {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut offset = 0usize;

    while offset + 8 <= image.len() && candidates.len() < max_entries {
        let record_length = read_u32_le(image, offset) as usize;

        // USN records are 8-byte aligned and at least v2 minimum size.
        if record_length >= 60 && record_length <= 4096 && record_length % 8 == 0 {
            let end = offset.saturating_add(record_length);
            if end <= image.len() {
                let record_bytes = &image[offset..end];
                if let Some(candidate) = try_extract_deleted_candidate_from_record(record_bytes) {
                    let key = (
                        candidate.object_id,
                        candidate.name.to_ascii_lowercase(),
                        candidate.path.to_ascii_lowercase(),
                    );
                    if seen.insert(key) {
                        candidates.push(candidate);
                    }
                }

                offset = end;
                continue;
            }
        }

        offset = offset.saturating_add(8);
    }

    candidates
}

fn try_extract_deleted_candidate_from_record(record_bytes: &[u8]) -> Option<RefsDeletedCandidate> {
    let parsed = parse_usn_records(record_bytes).ok()?;
    if parsed.len() != 1 {
        return None;
    }

    let record = &parsed[0];
    if !is_deleted_like_reason(record) {
        return None;
    }

    let name = record.file_name.trim().to_string();
    if name.is_empty() {
        return None;
    }

    let object_id = record.file_reference_number & 0x0000_FFFF_FFFF_FFFF;
    if object_id == 0 {
        return None;
    }

    Some(RefsDeletedCandidate {
        object_id,
        size_bytes: 0,
        name: name.clone(),
        path: format!(r".\{}", name),
    })
}

fn is_deleted_like_reason(record: &UsnRecord) -> bool {
    record.reason & USN_REASON_FILE_DELETE != 0 || record.reason & USN_REASON_RENAME_OLD_NAME != 0
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

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_refs_boot_sector() {
        let mut sector = [0u8; 512];
        sector[0x03..0x0B].copy_from_slice(b"ReFS    ");
        sector[0x0B..0x0D].copy_from_slice(&4096u16.to_le_bytes());
        sector[0x0D] = 1;
        sector[0x28..0x30].copy_from_slice(&2_000_000u64.to_le_bytes());
        sector[0x48..0x50].copy_from_slice(&0xA1A2_A3A4_A5A6_A7A8u64.to_le_bytes());

        let parsed = parse_boot_sector(&sector).expect("parse refs boot");
        assert_eq!(parsed.bytes_per_sector, 4096);
        assert_eq!(parsed.sectors_per_cluster, 1);
        assert_eq!(parsed.cluster_size_bytes(), 4096);
        assert_eq!(parsed.total_sectors, 2_000_000);
        assert_eq!(parsed.volume_serial, 0xA1A2_A3A4_A5A6_A7A8);
    }

    #[test]
    fn rejects_non_refs_oem_id() {
        let mut sector = [0u8; 512];
        sector[0x03..0x0B].copy_from_slice(b"NTFS    ");
        sector[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        sector[0x0D] = 8;

        let error = parse_boot_sector(&sector).unwrap_err();
        assert!(matches!(error, BootSectorParseError::InvalidOemId(_)));
    }

    #[test]
    fn rejects_invalid_bytes_per_sector() {
        let mut sector = [0u8; 512];
        sector[0x03..0x0B].copy_from_slice(b"ReFS    ");
        sector[0x0B..0x0D].copy_from_slice(&500u16.to_le_bytes());
        sector[0x0D] = 1;

        let error = parse_boot_sector(&sector).unwrap_err();
        assert!(matches!(
            error,
            BootSectorParseError::InvalidBytesPerSector(500)
        ));
    }

    #[test]
    fn extracts_deleted_candidate_from_embedded_usn_record() {
        let mut image = vec![0u8; 512 * 64];
        image[0x03..0x0B].copy_from_slice(b"ReFS    ");
        image[0x0B..0x0D].copy_from_slice(&4096u16.to_le_bytes());
        image[0x0D] = 1;
        image[0x28..0x30].copy_from_slice(&2_000_000u64.to_le_bytes());
        image[0x48..0x50].copy_from_slice(&0xA1A2_A3A4_A5A6_A7A8u64.to_le_bytes());

        let usn_record = build_usn_v2_record(
            "deleted-report.txt",
            USN_REASON_FILE_DELETE,
            42,
            5,
        );
        let start = 4096usize;
        image[start..start + usn_record.len()].copy_from_slice(&usn_record);

        let (boot, candidates) = scan_deleted_candidates(&image, 16).expect("scan refs");
        assert_eq!(boot.bytes_per_sector, 4096);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].object_id, 42);
        assert_eq!(candidates[0].name, "deleted-report.txt");
    }

    #[test]
    fn ignores_non_deleted_usn_record() {
        let mut image = vec![0u8; 512 * 64];
        image[0x03..0x0B].copy_from_slice(b"ReFS    ");
        image[0x0B..0x0D].copy_from_slice(&4096u16.to_le_bytes());
        image[0x0D] = 1;
        image[0x28..0x30].copy_from_slice(&2_000_000u64.to_le_bytes());
        image[0x48..0x50].copy_from_slice(&0xA1A2_A3A4_A5A6_A7A8u64.to_le_bytes());

        let usn_record = build_usn_v2_record("active-report.txt", 0x0000_0001, 7, 5);
        let start = 4096usize;
        image[start..start + usn_record.len()].copy_from_slice(&usn_record);

        let (_, candidates) = scan_deleted_candidates(&image, 16).expect("scan refs");
        assert!(candidates.is_empty());
    }

    fn build_usn_v2_record(name: &str, reason: u32, file_ref: u64, parent_ref: u64) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_len_bytes = (name_utf16.len() * 2) as u16;
        let header_len = 60usize;
        let record_len = align_to_8(header_len + name_len_bytes as usize);
        let mut record = vec![0u8; record_len];

        write_u32(&mut record, 0, record_len as u32);
        write_u16(&mut record, 4, 2);
        write_u16(&mut record, 6, 0);
        write_u64(&mut record, 8, file_ref);
        write_u64(&mut record, 16, parent_ref);
        write_i64(&mut record, 24, 1001);
        write_i64(&mut record, 32, 132_537_600_400_000_000);
        write_u32(&mut record, 40, reason);
        write_u32(&mut record, 44, 0);
        write_u32(&mut record, 48, 0);
        write_u32(&mut record, 52, 0x20);
        write_u16(&mut record, 56, name_len_bytes);
        write_u16(&mut record, 58, header_len as u16);

        let mut cursor = header_len;
        for code in name_utf16 {
            record[cursor..cursor + 2].copy_from_slice(&code.to_le_bytes());
            cursor += 2;
        }

        record
    }

    fn align_to_8(value: usize) -> usize {
        (value + 7) & !7
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

    fn write_i64(bytes: &mut [u8], offset: usize, value: i64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
