use fr_types::RecoverySourceKind;

pub const USN_REASON_DATA_OVERWRITE: u32 = 0x0000_0001;
pub const USN_REASON_DATA_EXTEND: u32 = 0x0000_0002;
pub const USN_REASON_DATA_TRUNCATION: u32 = 0x0000_0004;
pub const USN_REASON_NAMED_DATA_OVERWRITE: u32 = 0x0000_0010;
pub const USN_REASON_NAMED_DATA_EXTEND: u32 = 0x0000_0020;
pub const USN_REASON_NAMED_DATA_TRUNCATION: u32 = 0x0000_0040;
pub const USN_REASON_FILE_CREATE: u32 = 0x0000_0100;
pub const USN_REASON_FILE_DELETE: u32 = 0x0000_0200;
pub const USN_REASON_EA_CHANGE: u32 = 0x0000_0400;
pub const USN_REASON_SECURITY_CHANGE: u32 = 0x0000_0800;
pub const USN_REASON_RENAME_OLD_NAME: u32 = 0x0000_1000;
pub const USN_REASON_RENAME_NEW_NAME: u32 = 0x0000_2000;
pub const USN_REASON_INDEXABLE_CHANGE: u32 = 0x0000_4000;
pub const USN_REASON_BASIC_INFO_CHANGE: u32 = 0x0000_8000;
pub const USN_REASON_HARD_LINK_CHANGE: u32 = 0x0001_0000;
pub const USN_REASON_COMPRESSION_CHANGE: u32 = 0x0002_0000;
pub const USN_REASON_ENCRYPTION_CHANGE: u32 = 0x0004_0000;
pub const USN_REASON_OBJECT_ID_CHANGE: u32 = 0x0008_0000;
pub const USN_REASON_REPARSE_POINT_CHANGE: u32 = 0x0010_0000;
pub const USN_REASON_STREAM_CHANGE: u32 = 0x0020_0000;
pub const USN_REASON_TRANSACTED_CHANGE: u32 = 0x0040_0000;
pub const USN_REASON_INTEGRITY_CHANGE: u32 = 0x0080_0000;
pub const USN_REASON_CLOSE: u32 = 0x8000_0000;

const USN_RECORD_MIN_V2: usize = 60;
const USN_RECORD_MIN_V3: usize = 76;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDescriptor {
    pub name: &'static str,
    pub purpose: &'static str,
    pub source_kind: RecoverySourceKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnRecord {
    pub major_version: u16,
    pub minor_version: u16,
    pub file_reference_number: u64,
    pub parent_file_reference_number: u64,
    pub usn: i64,
    pub timestamp_100ns: i64,
    pub reason: u32,
    pub source_info: u32,
    pub security_id: u32,
    pub file_attributes: u32,
    pub file_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsnParseError {
    TruncatedRecordHeader {
        offset: usize,
    },
    InvalidRecordLength {
        offset: usize,
        length: u32,
    },
    UnsupportedVersion {
        offset: usize,
        major: u16,
        minor: u16,
    },
    TruncatedRecordBody {
        offset: usize,
        length: u32,
        remaining: usize,
    },
    InvalidFileNameRange {
        offset: usize,
        file_name_offset: u16,
        file_name_length: u16,
        record_length: u32,
    },
    InvalidFileNameEncoding {
        offset: usize,
    },
}

pub fn descriptor() -> ModuleDescriptor {
    ModuleDescriptor {
        name: "fr-usn",
        purpose: "USN journal record parser and reason decoding for evidence enrichment.",
        source_kind: RecoverySourceKind::Volume,
    }
}

pub fn parse_usn_records(bytes: &[u8]) -> Result<Vec<UsnRecord>, UsnParseError> {
    let mut records = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        if remaining.iter().all(|value| *value == 0) {
            break;
        }

        if remaining.len() < 8 {
            return Err(UsnParseError::TruncatedRecordHeader { offset });
        }

        let record_length =
            u32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]);
        if record_length == 0 {
            break;
        }

        let record_length_usize = record_length as usize;
        if record_length_usize < USN_RECORD_MIN_V2 {
            return Err(UsnParseError::InvalidRecordLength {
                offset,
                length: record_length,
            });
        }

        if record_length_usize > remaining.len() {
            return Err(UsnParseError::TruncatedRecordBody {
                offset,
                length: record_length,
                remaining: remaining.len(),
            });
        }

        let major = u16::from_le_bytes([remaining[4], remaining[5]]);
        let minor = u16::from_le_bytes([remaining[6], remaining[7]]);
        let record_slice = &remaining[..record_length_usize];

        let record = match major {
            2 => parse_v2_record(record_slice, offset, major, minor)?,
            3 => parse_v3_record(record_slice, offset, major, minor)?,
            _ => {
                return Err(UsnParseError::UnsupportedVersion {
                    offset,
                    major,
                    minor,
                });
            }
        };

        records.push(record);
        offset = offset.saturating_add(record_length_usize);
    }

    Ok(records)
}

pub fn decode_reason_labels(reason: u32) -> Vec<&'static str> {
    let mut labels = Vec::new();

    for (mask, name) in [
        (USN_REASON_DATA_OVERWRITE, "data-overwrite"),
        (USN_REASON_DATA_EXTEND, "data-extend"),
        (USN_REASON_DATA_TRUNCATION, "data-truncation"),
        (USN_REASON_NAMED_DATA_OVERWRITE, "named-data-overwrite"),
        (USN_REASON_NAMED_DATA_EXTEND, "named-data-extend"),
        (USN_REASON_NAMED_DATA_TRUNCATION, "named-data-truncation"),
        (USN_REASON_FILE_CREATE, "file-create"),
        (USN_REASON_FILE_DELETE, "file-delete"),
        (USN_REASON_EA_CHANGE, "ea-change"),
        (USN_REASON_SECURITY_CHANGE, "security-change"),
        (USN_REASON_RENAME_OLD_NAME, "rename-old-name"),
        (USN_REASON_RENAME_NEW_NAME, "rename-new-name"),
        (USN_REASON_INDEXABLE_CHANGE, "indexable-change"),
        (USN_REASON_BASIC_INFO_CHANGE, "basic-info-change"),
        (USN_REASON_HARD_LINK_CHANGE, "hard-link-change"),
        (USN_REASON_COMPRESSION_CHANGE, "compression-change"),
        (USN_REASON_ENCRYPTION_CHANGE, "encryption-change"),
        (USN_REASON_OBJECT_ID_CHANGE, "object-id-change"),
        (USN_REASON_REPARSE_POINT_CHANGE, "reparse-point-change"),
        (USN_REASON_STREAM_CHANGE, "stream-change"),
        (USN_REASON_TRANSACTED_CHANGE, "transacted-change"),
        (USN_REASON_INTEGRITY_CHANGE, "integrity-change"),
        (USN_REASON_CLOSE, "close"),
    ] {
        if reason & mask != 0 {
            labels.push(name);
        }
    }

    labels
}

fn parse_v2_record(
    record: &[u8],
    offset: usize,
    major: u16,
    minor: u16,
) -> Result<UsnRecord, UsnParseError> {
    if record.len() < USN_RECORD_MIN_V2 {
        return Err(UsnParseError::InvalidRecordLength {
            offset,
            length: record.len() as u32,
        });
    }

    let file_reference_number = read_u64(record, 8);
    let parent_file_reference_number = read_u64(record, 16);
    let usn = read_i64(record, 24);
    let timestamp_100ns = read_i64(record, 32);
    let reason = read_u32(record, 40);
    let source_info = read_u32(record, 44);
    let security_id = read_u32(record, 48);
    let file_attributes = read_u32(record, 52);
    let file_name_length = read_u16(record, 56);
    let file_name_offset = read_u16(record, 58);
    let file_name = parse_utf16_file_name(record, offset, file_name_offset, file_name_length)?;

    Ok(UsnRecord {
        major_version: major,
        minor_version: minor,
        file_reference_number,
        parent_file_reference_number,
        usn,
        timestamp_100ns,
        reason,
        source_info,
        security_id,
        file_attributes,
        file_name,
    })
}

fn parse_v3_record(
    record: &[u8],
    offset: usize,
    major: u16,
    minor: u16,
) -> Result<UsnRecord, UsnParseError> {
    if record.len() < USN_RECORD_MIN_V3 {
        return Err(UsnParseError::InvalidRecordLength {
            offset,
            length: record.len() as u32,
        });
    }

    let file_reference_number = read_u64(record, 8);
    let parent_file_reference_number = read_u64(record, 24);
    let usn = read_i64(record, 40);
    let timestamp_100ns = read_i64(record, 48);
    let reason = read_u32(record, 56);
    let source_info = read_u32(record, 60);
    let security_id = read_u32(record, 64);
    let file_attributes = read_u32(record, 68);
    let file_name_length = read_u16(record, 72);
    let file_name_offset = read_u16(record, 74);
    let file_name = parse_utf16_file_name(record, offset, file_name_offset, file_name_length)?;

    Ok(UsnRecord {
        major_version: major,
        minor_version: minor,
        file_reference_number,
        parent_file_reference_number,
        usn,
        timestamp_100ns,
        reason,
        source_info,
        security_id,
        file_attributes,
        file_name,
    })
}

fn parse_utf16_file_name(
    record: &[u8],
    offset: usize,
    file_name_offset: u16,
    file_name_length: u16,
) -> Result<String, UsnParseError> {
    let name_offset = file_name_offset as usize;
    let name_length = file_name_length as usize;
    if name_length % 2 != 0 {
        return Err(UsnParseError::InvalidFileNameRange {
            offset,
            file_name_offset,
            file_name_length,
            record_length: record.len() as u32,
        });
    }

    let Some(name_end) = name_offset.checked_add(name_length) else {
        return Err(UsnParseError::InvalidFileNameRange {
            offset,
            file_name_offset,
            file_name_length,
            record_length: record.len() as u32,
        });
    };

    if name_end > record.len() || name_offset >= record.len() {
        return Err(UsnParseError::InvalidFileNameRange {
            offset,
            file_name_offset,
            file_name_length,
            record_length: record.len() as u32,
        });
    }

    let name_slice = &record[name_offset..name_end];
    let mut utf16_units = Vec::with_capacity(name_slice.len() / 2);
    let mut index = 0usize;
    while index < name_slice.len() {
        utf16_units.push(u16::from_le_bytes([
            name_slice[index],
            name_slice[index + 1],
        ]));
        index += 2;
    }

    String::from_utf16(&utf16_units).map_err(|_| UsnParseError::InvalidFileNameEncoding { offset })
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v2_record() {
        let record = build_v2_record(
            "report.txt",
            USN_REASON_FILE_DELETE | USN_REASON_CLOSE,
            42,
            7,
        );
        let parsed = parse_usn_records(&record).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].major_version, 2);
        assert_eq!(parsed[0].file_reference_number, 42);
        assert_eq!(parsed[0].parent_file_reference_number, 7);
        assert_eq!(parsed[0].file_name, "report.txt");
        assert_eq!(
            decode_reason_labels(parsed[0].reason),
            vec!["file-delete", "close"]
        );
    }

    #[test]
    fn parses_v3_record() {
        let record = build_v3_record(
            "notes.md",
            USN_REASON_FILE_CREATE | USN_REASON_RENAME_NEW_NAME,
            512,
            64,
        );
        let parsed = parse_usn_records(&record).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].major_version, 3);
        assert_eq!(parsed[0].file_reference_number, 512);
        assert_eq!(parsed[0].parent_file_reference_number, 64);
        assert_eq!(parsed[0].file_name, "notes.md");
    }

    #[test]
    fn parses_multiple_records_with_padding() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&build_v2_record("a.txt", USN_REASON_CLOSE, 1, 0));
        bytes.extend_from_slice(&build_v3_record("b.txt", USN_REASON_FILE_DELETE, 2, 0));
        bytes.extend_from_slice(&[0u8; 64]);

        let parsed = parse_usn_records(&bytes).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].file_name, "a.txt");
        assert_eq!(parsed[1].file_name, "b.txt");
    }

    #[test]
    fn returns_error_on_truncated_record() {
        let mut bytes = build_v2_record("broken.bin", USN_REASON_CLOSE, 9, 1);
        bytes.truncate(bytes.len() - 3);

        let error = parse_usn_records(&bytes).unwrap_err();
        assert!(matches!(error, UsnParseError::TruncatedRecordBody { .. }));
    }

    fn build_v2_record(name: &str, reason: u32, file_ref: u64, parent_ref: u64) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_len_bytes = (name_utf16.len() * 2) as u16;
        let header_len = USN_RECORD_MIN_V2 as u16;
        let record_len = align_to_8((header_len + name_len_bytes) as usize);
        let mut record = vec![0u8; record_len];

        write_u32(&mut record, 0, record_len as u32);
        write_u16(&mut record, 4, 2);
        write_u16(&mut record, 6, 0);
        write_u64(&mut record, 8, file_ref);
        write_u64(&mut record, 16, parent_ref);
        write_i64(&mut record, 24, 1001);
        write_i64(&mut record, 32, 1337);
        write_u32(&mut record, 40, reason);
        write_u32(&mut record, 44, 0);
        write_u32(&mut record, 48, 0);
        write_u32(&mut record, 52, 0);
        write_u16(&mut record, 56, name_len_bytes);
        write_u16(&mut record, 58, header_len);

        write_utf16_name(&mut record, header_len as usize, &name_utf16);
        record
    }

    fn build_v3_record(name: &str, reason: u32, file_ref: u64, parent_ref: u64) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_len_bytes = (name_utf16.len() * 2) as u16;
        let header_len = USN_RECORD_MIN_V3 as u16;
        let record_len = align_to_8((header_len + name_len_bytes) as usize);
        let mut record = vec![0u8; record_len];

        write_u32(&mut record, 0, record_len as u32);
        write_u16(&mut record, 4, 3);
        write_u16(&mut record, 6, 0);
        write_u64(&mut record, 8, file_ref);
        write_u64(&mut record, 24, parent_ref);
        write_i64(&mut record, 40, 2002);
        write_i64(&mut record, 48, 4242);
        write_u32(&mut record, 56, reason);
        write_u32(&mut record, 60, 0);
        write_u32(&mut record, 64, 0);
        write_u32(&mut record, 68, 0);
        write_u16(&mut record, 72, name_len_bytes);
        write_u16(&mut record, 74, header_len);

        write_utf16_name(&mut record, header_len as usize, &name_utf16);
        record
    }

    fn write_utf16_name(record: &mut [u8], offset: usize, utf16: &[u16]) {
        let mut cursor = offset;
        for code in utf16 {
            record[cursor..cursor + 2].copy_from_slice(&code.to_le_bytes());
            cursor += 2;
        }
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
