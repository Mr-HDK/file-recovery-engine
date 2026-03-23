use thiserror::Error;

pub const NTFS_OEM_ID: &[u8; 8] = b"NTFS    ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsBootSector {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub total_sectors: u64,
    pub mft_cluster: u64,
    pub mft_mirror_cluster: u64,
    pub file_record_size_bytes: u32,
    pub index_record_size_bytes: u32,
    pub volume_serial: u64,
}

impl NtfsBootSector {
    pub fn cluster_size_bytes(&self) -> u32 {
        self.bytes_per_sector as u32 * self.sectors_per_cluster as u32
    }

    pub fn volume_size_bytes(&self) -> Option<u64> {
        self.total_sectors
            .checked_mul(self.bytes_per_sector as u64)
    }

    pub fn mft_offset_bytes(&self) -> Option<u64> {
        self.mft_cluster
            .checked_mul(self.cluster_size_bytes() as u64)
    }

    pub fn mft_mirror_offset_bytes(&self) -> Option<u64> {
        self.mft_mirror_cluster
            .checked_mul(self.cluster_size_bytes() as u64)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BootSectorParseError {
    #[error("boot sector buffer too small: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall { expected: usize, actual: usize },
    #[error("invalid NTFS boot signature: 0x{0:04X}")]
    InvalidBootSignature(u16),
    #[error("invalid NTFS OEM id: {0:?}")]
    InvalidOemId([u8; 8]),
    #[error("invalid bytes per sector: {0}")]
    InvalidBytesPerSector(u16),
    #[error("invalid sectors per cluster: {0}")]
    InvalidSectorsPerCluster(u8),
    #[error("invalid file record size encoding: {0}")]
    InvalidFileRecordSize(i8),
    #[error("invalid index record size encoding: {0}")]
    InvalidIndexRecordSize(i8),
    #[error("arithmetic overflow while parsing {0}")]
    ArithmeticOverflow(&'static str),
}

pub fn parse_boot_sector(bytes: &[u8]) -> Result<NtfsBootSector, BootSectorParseError> {
    const REQUIRED_SIZE: usize = 512;
    if bytes.len() < REQUIRED_SIZE {
        return Err(BootSectorParseError::BufferTooSmall {
            expected: REQUIRED_SIZE,
            actual: bytes.len(),
        });
    }

    let mut oem_id = [0u8; 8];
    oem_id.copy_from_slice(&bytes[0x03..0x0B]);
    if &oem_id != NTFS_OEM_ID {
        return Err(BootSectorParseError::InvalidOemId(oem_id));
    }

    let boot_signature = read_u16_le(bytes, 0x1FE);
    if boot_signature != 0xAA55 {
        return Err(BootSectorParseError::InvalidBootSignature(boot_signature));
    }

    let bytes_per_sector = read_u16_le(bytes, 0x0B);
    if bytes_per_sector == 0 || !bytes_per_sector.is_power_of_two() {
        return Err(BootSectorParseError::InvalidBytesPerSector(bytes_per_sector));
    }

    let sectors_per_cluster = bytes[0x0D];
    if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
        return Err(BootSectorParseError::InvalidSectorsPerCluster(sectors_per_cluster));
    }

    let cluster_size = (bytes_per_sector as u32)
        .checked_mul(sectors_per_cluster as u32)
        .ok_or(BootSectorParseError::ArithmeticOverflow("cluster size"))?;

    let file_record_size_raw = bytes[0x40] as i8;
    let file_record_size_bytes = decode_record_size(file_record_size_raw, cluster_size)
        .map_err(|_| BootSectorParseError::InvalidFileRecordSize(file_record_size_raw))?;

    let index_record_size_raw = bytes[0x44] as i8;
    let index_record_size_bytes = decode_record_size(index_record_size_raw, cluster_size)
        .map_err(|_| BootSectorParseError::InvalidIndexRecordSize(index_record_size_raw))?;

    Ok(NtfsBootSector {
        bytes_per_sector,
        sectors_per_cluster,
        total_sectors: read_u64_le(bytes, 0x28),
        mft_cluster: read_u64_le(bytes, 0x30),
        mft_mirror_cluster: read_u64_le(bytes, 0x38),
        file_record_size_bytes,
        index_record_size_bytes,
        volume_serial: read_u64_le(bytes, 0x48),
    })
}

fn decode_record_size(raw: i8, cluster_size: u32) -> Result<u32, ()> {
    if raw == 0 {
        return Err(());
    }

    if raw > 0 {
        return cluster_size.checked_mul(raw as u32).ok_or(());
    }

    let shift = raw.unsigned_abs() as u32;
    1u32.checked_shl(shift).ok_or(())
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_le_bytes(buf)
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_ntfs_boot_sector() {
        let mut sector = [0u8; 512];
        sector[0x03..0x0B].copy_from_slice(NTFS_OEM_ID);
        sector[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        sector[0x0D] = 8;
        sector[0x28..0x30].copy_from_slice(&1_000_000u64.to_le_bytes());
        sector[0x30..0x38].copy_from_slice(&786_432u64.to_le_bytes());
        sector[0x38..0x40].copy_from_slice(&2u64.to_le_bytes());
        sector[0x40] = (-10i8) as u8;
        sector[0x44] = 1;
        sector[0x48..0x50].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        sector[0x1FE..0x200].copy_from_slice(&0xAA55u16.to_le_bytes());

        let parsed = parse_boot_sector(&sector).unwrap();

        assert_eq!(parsed.bytes_per_sector, 512);
        assert_eq!(parsed.sectors_per_cluster, 8);
        assert_eq!(parsed.cluster_size_bytes(), 4096);
        assert_eq!(parsed.file_record_size_bytes, 1024);
        assert_eq!(parsed.index_record_size_bytes, 4096);
        assert_eq!(parsed.volume_size_bytes(), Some(512_000_000));
        assert_eq!(parsed.mft_offset_bytes(), Some(3_221_225_472));
    }

    #[test]
    fn rejects_non_ntfs_oem_id() {
        let mut sector = [0u8; 512];
        sector[0x03..0x0B].copy_from_slice(b"NOTNTFS ");
        sector[0x1FE..0x200].copy_from_slice(&0xAA55u16.to_le_bytes());

        let error = parse_boot_sector(&sector).unwrap_err();
        assert!(matches!(error, BootSectorParseError::InvalidOemId(_)));
    }

    #[test]
    fn rejects_invalid_signature() {
        let mut sector = [0u8; 512];
        sector[0x03..0x0B].copy_from_slice(NTFS_OEM_ID);

        let error = parse_boot_sector(&sector).unwrap_err();
        assert!(matches!(error, BootSectorParseError::InvalidBootSignature(_)));
    }

    #[test]
    fn parses_positive_file_record_multiplier() {
        let mut sector = [0u8; 512];
        sector[0x03..0x0B].copy_from_slice(NTFS_OEM_ID);
        sector[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        sector[0x0D] = 8;
        sector[0x40] = 2;
        sector[0x44] = 1;
        sector[0x1FE..0x200].copy_from_slice(&0xAA55u16.to_le_bytes());

        let parsed = parse_boot_sector(&sector).unwrap();
        assert_eq!(parsed.file_record_size_bytes, 8192);
    }
}
