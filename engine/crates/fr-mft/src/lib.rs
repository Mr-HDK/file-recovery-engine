use thiserror::Error;

pub const ATTRIBUTE_TYPE_STANDARD_INFORMATION: u32 = 0x10;
pub const ATTRIBUTE_TYPE_ATTRIBUTE_LIST: u32 = 0x20;
pub const ATTRIBUTE_TYPE_FILE_NAME: u32 = 0x30;
pub const ATTRIBUTE_TYPE_DATA: u32 = 0x80;
pub const ATTRIBUTE_TYPE_END: u32 = 0xFFFF_FFFF;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MftRecord {
    pub header: MftRecordHeader,
    pub attributes: Vec<AttributeRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MftRecordHeader {
    pub usa_offset: u16,
    pub usa_count: u16,
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub first_attribute_offset: u16,
    pub flags: u16,
    pub bytes_in_use: u32,
    pub bytes_allocated: u32,
    pub base_record_reference: u64,
    pub next_attribute_id: u16,
    pub record_number: u32,
}

impl MftRecordHeader {
    pub fn in_use(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    pub fn is_directory(&self) -> bool {
        self.flags & 0x0002 != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeRecord {
    pub attribute_type: u32,
    pub name: Option<String>,
    pub flags: u16,
    pub attribute_id: u16,
    pub form: AttributeForm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeForm {
    Resident(ResidentAttribute),
    NonResident(NonResidentAttribute),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidentAttribute {
    pub value: Vec<u8>,
    pub resident_flags: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonResidentAttribute {
    pub lowest_vcn: u64,
    pub highest_vcn: u64,
    pub compression_unit_size: u16,
    pub allocated_size: u64,
    pub data_size: u64,
    pub initialized_size: u64,
    pub compressed_size: Option<u64>,
    pub mapping_pairs: Vec<u8>,
    pub data_runs: Vec<DataRun>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRun {
    pub cluster_count: u64,
    pub lcn: Option<i64>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MftParseError {
    #[error("MFT record buffer too small: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall { expected: usize, actual: usize },
    #[error("invalid sector size for fixup: {0}")]
    InvalidSectorSize(usize),
    #[error("invalid MFT record signature: {0:?}")]
    InvalidSignature([u8; 4]),
    #[error("invalid update sequence array bounds: offset={offset} count={count}")]
    InvalidUpdateSequenceArray { offset: u16, count: u16 },
    #[error("MFT fixup mismatch at sector {sector_index}: expected 0x{expected:04X}, got 0x{actual:04X}")]
    FixupMismatch {
        sector_index: usize,
        expected: u16,
        actual: u16,
    },
    #[error("invalid bytes-in-use value: {0}")]
    InvalidBytesInUse(u32),
    #[error("invalid first attribute offset: {0}")]
    InvalidFirstAttributeOffset(u16),
    #[error("invalid attribute length at offset {offset}: {length}")]
    InvalidAttributeLength { offset: usize, length: u32 },
    #[error("attribute at offset {offset} exceeds record bytes-in-use limit {limit}")]
    AttributeOutOfBounds {
        offset: usize,
        length: usize,
        limit: usize,
    },
    #[error("invalid non-resident flag value: {0}")]
    InvalidNonResidentFlag(u8),
    #[error("attribute name out of bounds")]
    InvalidNameBounds,
    #[error("invalid UTF-16 attribute name")]
    InvalidUtf16Name,
    #[error("resident attribute value out of bounds")]
    InvalidResidentValueBounds,
    #[error("invalid mapping-pairs offset: {0}")]
    InvalidMappingPairsOffset(u16),
    #[error("invalid data run header byte: 0x{0:02X}")]
    InvalidDataRunHeader(u8),
    #[error("data run length may not be zero")]
    InvalidDataRunLength,
    #[error("data run exceeds available mapping-pairs buffer")]
    DataRunOutOfBounds,
    #[error("data run LCN overflow")]
    DataRunLcnOverflow,
}

pub fn parse_mft_record(record_bytes: &[u8], bytes_per_sector: usize) -> Result<MftRecord, MftParseError> {
    if record_bytes.len() < 48 {
        return Err(MftParseError::BufferTooSmall {
            expected: 48,
            actual: record_bytes.len(),
        });
    }

    if bytes_per_sector < 2 {
        return Err(MftParseError::InvalidSectorSize(bytes_per_sector));
    }

    let fixed = apply_update_sequence_fixup(record_bytes, bytes_per_sector)?;

    let mut signature = [0u8; 4];
    signature.copy_from_slice(&fixed[0x00..0x04]);
    if &signature != b"FILE" {
        return Err(MftParseError::InvalidSignature(signature));
    }

    let bytes_in_use = read_u32(&fixed, 0x18);
    if bytes_in_use == 0 || bytes_in_use as usize > fixed.len() {
        return Err(MftParseError::InvalidBytesInUse(bytes_in_use));
    }

    let first_attribute_offset = read_u16(&fixed, 0x14);
    if first_attribute_offset as usize >= bytes_in_use as usize {
        return Err(MftParseError::InvalidFirstAttributeOffset(first_attribute_offset));
    }

    let header = MftRecordHeader {
        usa_offset: read_u16(&fixed, 0x04),
        usa_count: read_u16(&fixed, 0x06),
        sequence_number: read_u16(&fixed, 0x10),
        hard_link_count: read_u16(&fixed, 0x12),
        first_attribute_offset,
        flags: read_u16(&fixed, 0x16),
        bytes_in_use,
        bytes_allocated: read_u32(&fixed, 0x1C),
        base_record_reference: read_u64(&fixed, 0x20),
        next_attribute_id: read_u16(&fixed, 0x28),
        record_number: read_u32(&fixed, 0x2C),
    };

    let parse_limit = bytes_in_use as usize;
    let mut cursor = first_attribute_offset as usize;
    let mut attributes = Vec::new();

    while cursor + 4 <= parse_limit {
        let attribute_type = read_u32(&fixed, cursor);
        if attribute_type == ATTRIBUTE_TYPE_END {
            break;
        }

        if cursor + 16 > parse_limit {
            return Err(MftParseError::AttributeOutOfBounds {
                offset: cursor,
                length: 16,
                limit: parse_limit,
            });
        }

        let attribute_length_u32 = read_u32(&fixed, cursor + 4);
        let attribute_length = attribute_length_u32 as usize;
        if attribute_length < 16 {
            return Err(MftParseError::InvalidAttributeLength {
                offset: cursor,
                length: attribute_length_u32,
            });
        }

        let attribute_end = cursor + attribute_length;
        if attribute_end > parse_limit {
            return Err(MftParseError::AttributeOutOfBounds {
                offset: cursor,
                length: attribute_length,
                limit: parse_limit,
            });
        }

        let non_resident_flag = fixed[cursor + 8];
        let name_length = fixed[cursor + 9] as usize;
        let name_offset = read_u16(&fixed, cursor + 10) as usize;
        let flags = read_u16(&fixed, cursor + 12);
        let attribute_id = read_u16(&fixed, cursor + 14);

        let name = parse_attribute_name(&fixed[cursor..attribute_end], name_offset, name_length)?;

        let form = match non_resident_flag {
            0 => parse_resident_attribute(&fixed[cursor..attribute_end])?,
            1 => parse_non_resident_attribute(&fixed[cursor..attribute_end])?,
            other => return Err(MftParseError::InvalidNonResidentFlag(other)),
        };

        attributes.push(AttributeRecord {
            attribute_type,
            name,
            flags,
            attribute_id,
            form,
        });

        cursor = attribute_end;
    }

    Ok(MftRecord { header, attributes })
}

fn apply_update_sequence_fixup(record_bytes: &[u8], bytes_per_sector: usize) -> Result<Vec<u8>, MftParseError> {
    let usa_offset = read_u16(record_bytes, 0x04) as usize;
    let usa_count = read_u16(record_bytes, 0x06) as usize;
    if usa_count == 0 {
        return Err(MftParseError::InvalidUpdateSequenceArray {
            offset: usa_offset as u16,
            count: 0,
        });
    }

    let usa_bytes = usa_count.saturating_mul(2);
    if usa_offset + usa_bytes > record_bytes.len() {
        return Err(MftParseError::InvalidUpdateSequenceArray {
            offset: usa_offset as u16,
            count: usa_count as u16,
        });
    }

    let sequence_number = read_u16(record_bytes, usa_offset);
    let mut fixed = record_bytes.to_vec();

    for sector in 1..usa_count {
        let end_of_sector = sector.saturating_mul(bytes_per_sector);
        if end_of_sector < 2 || end_of_sector > fixed.len() {
            return Err(MftParseError::InvalidUpdateSequenceArray {
                offset: usa_offset as u16,
                count: usa_count as u16,
            });
        }

        let fixup_offset = end_of_sector - 2;
        let current_value = read_u16(&fixed, fixup_offset);
        if current_value != sequence_number {
            return Err(MftParseError::FixupMismatch {
                sector_index: sector - 1,
                expected: sequence_number,
                actual: current_value,
            });
        }

        let replacement = read_u16(record_bytes, usa_offset + (sector * 2));
        fixed[fixup_offset..fixup_offset + 2].copy_from_slice(&replacement.to_le_bytes());
    }

    Ok(fixed)
}

fn parse_attribute_name(
    attribute_bytes: &[u8],
    name_offset: usize,
    name_length: usize,
) -> Result<Option<String>, MftParseError> {
    if name_length == 0 {
        return Ok(None);
    }

    let name_bytes_len = name_length
        .checked_mul(2)
        .ok_or(MftParseError::InvalidNameBounds)?;

    if name_offset + name_bytes_len > attribute_bytes.len() {
        return Err(MftParseError::InvalidNameBounds);
    }

    let name_bytes = &attribute_bytes[name_offset..name_offset + name_bytes_len];
    let mut code_units = Vec::with_capacity(name_length);
    let mut i = 0;
    while i < name_bytes.len() {
        code_units.push(u16::from_le_bytes([name_bytes[i], name_bytes[i + 1]]));
        i += 2;
    }

    let name = String::from_utf16(&code_units).map_err(|_| MftParseError::InvalidUtf16Name)?;
    Ok(Some(name))
}

fn parse_resident_attribute(attribute_bytes: &[u8]) -> Result<AttributeForm, MftParseError> {
    if attribute_bytes.len() < 24 {
        return Err(MftParseError::InvalidAttributeLength {
            offset: 0,
            length: attribute_bytes.len() as u32,
        });
    }

    let value_length = read_u32(attribute_bytes, 0x10) as usize;
    let value_offset = read_u16(attribute_bytes, 0x14) as usize;
    let resident_flags = attribute_bytes[0x16];

    if value_offset + value_length > attribute_bytes.len() {
        return Err(MftParseError::InvalidResidentValueBounds);
    }

    let value = attribute_bytes[value_offset..value_offset + value_length].to_vec();
    Ok(AttributeForm::Resident(ResidentAttribute {
        value,
        resident_flags,
    }))
}

fn parse_non_resident_attribute(attribute_bytes: &[u8]) -> Result<AttributeForm, MftParseError> {
    if attribute_bytes.len() < 64 {
        return Err(MftParseError::InvalidAttributeLength {
            offset: 0,
            length: attribute_bytes.len() as u32,
        });
    }

    let lowest_vcn = read_u64(attribute_bytes, 0x10);
    let highest_vcn = read_u64(attribute_bytes, 0x18);
    let mapping_pairs_offset = read_u16(attribute_bytes, 0x20) as usize;
    let compression_unit_size = read_u16(attribute_bytes, 0x22);
    let allocated_size = read_u64(attribute_bytes, 0x28);
    let data_size = read_u64(attribute_bytes, 0x30);
    let initialized_size = read_u64(attribute_bytes, 0x38);
    let compressed_size = if attribute_bytes.len() >= 72 {
        Some(read_u64(attribute_bytes, 0x40))
    } else {
        None
    };

    if mapping_pairs_offset > attribute_bytes.len() {
        return Err(MftParseError::InvalidMappingPairsOffset(
            mapping_pairs_offset as u16,
        ));
    }

    let mapping_pairs = attribute_bytes[mapping_pairs_offset..].to_vec();
    let data_runs = parse_data_runs(&mapping_pairs)?;

    Ok(AttributeForm::NonResident(NonResidentAttribute {
        lowest_vcn,
        highest_vcn,
        compression_unit_size,
        allocated_size,
        data_size,
        initialized_size,
        compressed_size,
        mapping_pairs,
        data_runs,
    }))
}

fn parse_data_runs(mapping_pairs: &[u8]) -> Result<Vec<DataRun>, MftParseError> {
    let mut cursor = 0usize;
    let mut current_lcn: i64 = 0;
    let mut runs = Vec::new();

    while cursor < mapping_pairs.len() {
        let header = mapping_pairs[cursor];
        cursor += 1;

        if header == 0 {
            break;
        }

        let length_size = (header & 0x0F) as usize;
        let offset_size = (header >> 4) as usize;

        if length_size == 0 || length_size > 8 || offset_size > 8 {
            return Err(MftParseError::InvalidDataRunHeader(header));
        }

        if cursor + length_size + offset_size > mapping_pairs.len() {
            return Err(MftParseError::DataRunOutOfBounds);
        }

        let run_length = parse_unsigned_le(&mapping_pairs[cursor..cursor + length_size]);
        cursor += length_size;

        if run_length == 0 {
            return Err(MftParseError::InvalidDataRunLength);
        }

        let run_offset_slice = &mapping_pairs[cursor..cursor + offset_size];
        cursor += offset_size;

        let lcn = if offset_size == 0 {
            None
        } else {
            let lcn_delta = parse_signed_le(run_offset_slice);
            current_lcn = current_lcn
                .checked_add(lcn_delta)
                .ok_or(MftParseError::DataRunLcnOverflow)?;
            Some(current_lcn)
        };

        runs.push(DataRun {
            cluster_count: run_length,
            lcn,
        });
    }

    Ok(runs)
}

fn parse_unsigned_le(bytes: &[u8]) -> u64 {
    let mut out = [0u8; 8];
    out[..bytes.len()].copy_from_slice(bytes);
    u64::from_le_bytes(out)
}

fn parse_signed_le(bytes: &[u8]) -> i64 {
    let mut out = [0u8; 8];
    out[..bytes.len()].copy_from_slice(bytes);

    if !bytes.is_empty() && bytes[bytes.len() - 1] & 0x80 != 0 {
        for byte in &mut out[bytes.len()..] {
            *byte = 0xFF;
        }
    }

    i64::from_le_bytes(out)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_le_bytes(buf)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(buf)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_record_with_resident_attribute() {
        let mut record = build_base_record(0x70);
        let attr_offset = 0x38;

        write_u32(&mut record, attr_offset, ATTRIBUTE_TYPE_STANDARD_INFORMATION);
        write_u32(&mut record, attr_offset + 4, 0x20);
        record[attr_offset + 8] = 0;
        record[attr_offset + 9] = 0;
        write_u16(&mut record, attr_offset + 10, 0);
        write_u16(&mut record, attr_offset + 12, 0);
        write_u16(&mut record, attr_offset + 14, 1);
        write_u32(&mut record, attr_offset + 16, 4);
        write_u16(&mut record, attr_offset + 20, 0x18);
        record[attr_offset + 24..attr_offset + 28].copy_from_slice(&[1, 2, 3, 4]);

        write_u32(&mut record, attr_offset + 0x20, ATTRIBUTE_TYPE_END);

        let parsed = parse_mft_record(&record, 512).unwrap();
        assert!(parsed.header.in_use());
        assert_eq!(parsed.attributes.len(), 1);

        let attribute = &parsed.attributes[0];
        assert_eq!(attribute.attribute_type, ATTRIBUTE_TYPE_STANDARD_INFORMATION);

        match &attribute.form {
            AttributeForm::Resident(value) => assert_eq!(value.value, vec![1, 2, 3, 4]),
            _ => panic!("expected resident attribute"),
        }
    }

    #[test]
    fn parses_record_with_non_resident_data_runs() {
        let mut record = build_base_record(0xA0);
        let attr_offset = 0x38;

        write_u32(&mut record, attr_offset, ATTRIBUTE_TYPE_DATA);
        write_u32(&mut record, attr_offset + 4, 0x50);
        record[attr_offset + 8] = 1;
        record[attr_offset + 9] = 0;
        write_u16(&mut record, attr_offset + 10, 0);
        write_u16(&mut record, attr_offset + 12, 0);
        write_u16(&mut record, attr_offset + 14, 5);

        write_u64(&mut record, attr_offset + 0x10, 0);
        write_u64(&mut record, attr_offset + 0x18, 9);
        write_u16(&mut record, attr_offset + 0x20, 0x40);
        write_u16(&mut record, attr_offset + 0x22, 0);
        write_u64(&mut record, attr_offset + 0x28, 40960);
        write_u64(&mut record, attr_offset + 0x30, 32768);
        write_u64(&mut record, attr_offset + 0x38, 32768);
        write_u64(&mut record, attr_offset + 0x40, 32768);

        let run_bytes = [0x11, 0x03, 0x0A, 0x11, 0x02, 0xFE, 0x01, 0x05, 0x00];
        record[attr_offset + 0x40..attr_offset + 0x40 + run_bytes.len()].copy_from_slice(&run_bytes);

        write_u32(&mut record, attr_offset + 0x50, ATTRIBUTE_TYPE_END);

        let parsed = parse_mft_record(&record, 512).unwrap();
        assert_eq!(parsed.attributes.len(), 1);

        let attribute = &parsed.attributes[0];
        match &attribute.form {
            AttributeForm::NonResident(value) => {
                assert_eq!(value.data_runs.len(), 3);
                assert_eq!(value.data_runs[0].cluster_count, 3);
                assert_eq!(value.data_runs[0].lcn, Some(10));
                assert_eq!(value.data_runs[1].cluster_count, 2);
                assert_eq!(value.data_runs[1].lcn, Some(8));
                assert_eq!(value.data_runs[2].cluster_count, 5);
                assert_eq!(value.data_runs[2].lcn, None);
            }
            _ => panic!("expected non-resident attribute"),
        }
    }

    #[test]
    fn detects_fixup_mismatch() {
        let mut record = build_base_record(0x70);
        write_u16(&mut record, 510, 0xBBBB);

        let error = parse_mft_record(&record, 512).unwrap_err();
        assert!(matches!(error, MftParseError::FixupMismatch { .. }));
    }

    fn build_base_record(bytes_in_use: u32) -> Vec<u8> {
        let mut record = vec![0u8; 1024];

        record[0x00..0x04].copy_from_slice(b"FILE");
        write_u16(&mut record, 0x04, 0x30);
        write_u16(&mut record, 0x06, 3);
        write_u16(&mut record, 0x10, 1);
        write_u16(&mut record, 0x12, 1);
        write_u16(&mut record, 0x14, 0x38);
        write_u16(&mut record, 0x16, 0x0001);
        write_u32(&mut record, 0x18, bytes_in_use);
        write_u32(&mut record, 0x1C, 1024);
        write_u64(&mut record, 0x20, 0);
        write_u16(&mut record, 0x28, 1);
        write_u32(&mut record, 0x2C, 42);

        write_u16(&mut record, 0x30, 0xAAAA);
        write_u16(&mut record, 0x32, 0x1111);
        write_u16(&mut record, 0x34, 0x2222);

        write_u16(&mut record, 510, 0xAAAA);
        write_u16(&mut record, 1022, 0xAAAA);

        record
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
