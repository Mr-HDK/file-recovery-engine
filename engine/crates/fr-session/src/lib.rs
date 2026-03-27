use chrono::{DateTime, Utc};
use fr_mft::{
    parse_mft_record, AttributeForm, AttributeRecord, MftRecord, ATTRIBUTE_TYPE_DATA,
    ATTRIBUTE_TYPE_FILE_NAME,
};
use fr_ntfs::{parse_boot_sector, BootSectorParseError, NtfsBootSector};
use fr_types::{EvidenceSource, RecoverySourceKind, ScanSessionState};
use fr_usn::UsnRecord;
use fr_winio::{ReadSession, WinIoError};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

const MAX_NTFS_FILE_RECORD_SIZE: usize = 1024 * 1024;
const MAX_CONSECUTIVE_EMPTY_MFT_RECORDS: usize = 16_384;

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub state: ScanSessionState,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session not found: {0}")]
    NotFound(String),
}

#[derive(Default)]
pub struct SessionOrchestrator {
    sessions: HashMap<String, SessionRecord>,
}

impl SessionOrchestrator {
    pub fn start_session(&mut self, session_id: impl Into<String>) -> SessionRecord {
        let id = session_id.into();
        let record = SessionRecord {
            state: ScanSessionState::new(id.clone(), "initialized"),
            updated_at: Utc::now(),
        };
        self.sessions.insert(id, record.clone());
        record
    }

    pub fn checkpoint(
        &mut self,
        session_id: &str,
        checkpoint: impl Into<String>,
    ) -> Result<(), SessionError> {
        let Some(record) = self.sessions.get_mut(session_id) else {
            return Err(SessionError::NotFound(session_id.to_string()));
        };

        record.state.checkpoint = checkpoint.into();
        record.updated_at = Utc::now();
        Ok(())
    }

    pub fn cancel(&mut self, session_id: &str) -> Result<(), SessionError> {
        let Some(record) = self.sessions.get_mut(session_id) else {
            return Err(SessionError::NotFound(session_id.to_string()));
        };

        record.state.canceled = true;
        record.updated_at = Utc::now();
        Ok(())
    }

    pub fn get(&self, session_id: &str) -> Option<&SessionRecord> {
        self.sessions.get(session_id)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct QuickScanConfig {
    pub max_records: usize,
}

impl Default for QuickScanConfig {
    fn default() -> Self {
        Self { max_records: 4_096 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickScanRecordError {
    pub record_index: usize,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickScanCandidate {
    pub record_index: usize,
    pub record_number: u32,
    pub in_use: bool,
    pub deleted: bool,
    pub is_directory: bool,
    pub has_non_resident_data: bool,
    pub has_named_data_streams: bool,
    pub has_compressed_data: bool,
    pub has_sparse_data: bool,
    pub has_encrypted_data: bool,
    pub usn_reason_mask: Option<u32>,
    pub name: Option<String>,
    pub parent_record_number: Option<u64>,
    pub reconstructed_path: Option<String>,
    pub evidence_sources: Vec<EvidenceSource>,
}

const NTFS_ATTRIBUTE_FLAG_COMPRESSED: u16 = 0x0001;
const NTFS_ATTRIBUTE_FLAG_ENCRYPTED: u16 = 0x4000;
const NTFS_ATTRIBUTE_FLAG_SPARSE: u16 = 0x8000;

#[derive(Debug, Clone)]
pub struct QuickScanSummary {
    pub boot_sector: NtfsBootSector,
    pub parsed_records: usize,
    pub parse_failures: usize,
    pub resident_attribute_count: usize,
    pub non_resident_attribute_count: usize,
    pub deleted_records: usize,
    pub directory_records: usize,
    pub named_records: usize,
    pub records_with_non_resident_data: usize,
    pub candidates: Vec<QuickScanCandidate>,
    pub record_errors: Vec<QuickScanRecordError>,
}

#[derive(Debug, Error)]
pub enum QuickScanError {
    #[error("source I/O error: {0}")]
    Io(#[from] WinIoError),
    #[error("source ended before NTFS boot sector could be read")]
    SourceTooSmall,
    #[error("boot sector parse failed: {0}")]
    BootSector(#[from] BootSectorParseError),
    #[error("MFT offset does not fit in memory index")]
    InvalidMftOffset,
    #[error("MFT starts outside source data: offset={0} source_len={1}")]
    MftOutOfBounds(usize, usize),
    #[error("invalid NTFS file record size: {0}")]
    InvalidFileRecordSize(u32),
}

pub fn quick_scan_ntfs_metadata(
    source_bytes: &[u8],
    config: QuickScanConfig,
) -> Result<QuickScanSummary, QuickScanError> {
    let boot_sector = parse_boot_sector(source_bytes)?;

    let mft_offset_u64 = boot_sector
        .mft_offset_bytes()
        .ok_or(QuickScanError::InvalidMftOffset)?;
    let mft_offset =
        usize::try_from(mft_offset_u64).map_err(|_| QuickScanError::InvalidMftOffset)?;

    if mft_offset >= source_bytes.len() {
        return Err(QuickScanError::MftOutOfBounds(
            mft_offset,
            source_bytes.len(),
        ));
    }

    let record_size = boot_sector.file_record_size_bytes as usize;
    if record_size < 256 || record_size > MAX_NTFS_FILE_RECORD_SIZE {
        return Err(QuickScanError::InvalidFileRecordSize(
            boot_sector.file_record_size_bytes,
        ));
    }

    let mut parsed_records = 0usize;
    let mut resident_attribute_count = 0usize;
    let mut non_resident_attribute_count = 0usize;
    let mut deleted_records = 0usize;
    let mut directory_records = 0usize;
    let mut named_records = 0usize;
    let mut records_with_non_resident_data = 0usize;
    let mut candidates = Vec::new();
    let mut record_errors = Vec::new();
    let mut consecutive_empty_records = 0usize;

    for index in 0..config.max_records {
        let Some(offset) = mft_offset.checked_add(index.saturating_mul(record_size)) else {
            break;
        };

        let Some(end) = offset.checked_add(record_size) else {
            break;
        };

        if end > source_bytes.len() {
            break;
        }

        let record_bytes = &source_bytes[offset..end];
        if record_bytes.iter().all(|b| *b == 0) {
            consecutive_empty_records = consecutive_empty_records.saturating_add(1);
            if consecutive_empty_records >= MAX_CONSECUTIVE_EMPTY_MFT_RECORDS {
                break;
            }
            continue;
        }
        consecutive_empty_records = 0;

        match parse_mft_record(record_bytes, boot_sector.bytes_per_sector as usize) {
            Ok(record) => {
                parsed_records += 1;
                for attribute in &record.attributes {
                    match &attribute.form {
                        AttributeForm::Resident(_) => resident_attribute_count += 1,
                        AttributeForm::NonResident(_) => non_resident_attribute_count += 1,
                    }
                }

                let candidate = build_candidate(index, &record);
                if candidate.deleted {
                    deleted_records += 1;
                }
                if candidate.is_directory {
                    directory_records += 1;
                }
                if candidate.name.is_some() {
                    named_records += 1;
                }
                if candidate.has_non_resident_data {
                    records_with_non_resident_data += 1;
                }
                candidates.push(candidate);
            }
            Err(error) => {
                record_errors.push(QuickScanRecordError {
                    record_index: index,
                    reason: error.to_string(),
                });
            }
        }
    }

    reconstruct_paths(&mut candidates);

    Ok(QuickScanSummary {
        boot_sector,
        parsed_records,
        parse_failures: record_errors.len(),
        resident_attribute_count,
        non_resident_attribute_count,
        deleted_records,
        directory_records,
        named_records,
        records_with_non_resident_data,
        candidates,
        record_errors,
    })
}

pub fn quick_scan_ntfs_from_source(
    source_path: &str,
    source_kind: RecoverySourceKind,
    config: QuickScanConfig,
) -> Result<QuickScanSummary, QuickScanError> {
    let mut session = ReadSession::open(source_path, source_kind)?;
    quick_scan_ntfs_from_read_session(&mut session, config)
}

pub fn quick_scan_ntfs_from_read_session(
    session: &mut ReadSession,
    config: QuickScanConfig,
) -> Result<QuickScanSummary, QuickScanError> {
    let max_records = if config.max_records == 0 {
        QuickScanConfig::default().max_records
    } else {
        config.max_records
    };

    let mut sector = [0u8; 512];
    if !read_from_session(session, 0, &mut sector)? {
        return Err(QuickScanError::SourceTooSmall);
    }

    let boot_sector = parse_boot_sector(&sector)?;
    let record_size = boot_sector.file_record_size_bytes as usize;
    if record_size < 256 || record_size > MAX_NTFS_FILE_RECORD_SIZE {
        return Err(QuickScanError::InvalidFileRecordSize(
            boot_sector.file_record_size_bytes,
        ));
    }

    let mut parsed_records = 0usize;
    let mut resident_attribute_count = 0usize;
    let mut non_resident_attribute_count = 0usize;
    let mut deleted_records = 0usize;
    let mut directory_records = 0usize;
    let mut named_records = 0usize;
    let mut records_with_non_resident_data = 0usize;
    let mut candidates = Vec::new();
    let mut record_errors = Vec::new();
    let mut record_buffer = vec![0u8; record_size];
    let mut consecutive_empty_records = 0usize;

    let mft_offset = boot_sector
        .mft_offset_bytes()
        .ok_or(QuickScanError::InvalidMftOffset)?;

    for index in 0..max_records {
        let record_index = index as u64;
        let record_stride = record_size as u64;
        let record_delta = record_index
            .checked_mul(record_stride)
            .ok_or(QuickScanError::InvalidMftOffset)?;
        let record_offset = mft_offset
            .checked_add(record_delta)
            .ok_or(QuickScanError::InvalidMftOffset)?;

        if !read_from_session(session, record_offset, &mut record_buffer)? {
            break;
        }

        if record_buffer.iter().all(|b| *b == 0) {
            consecutive_empty_records = consecutive_empty_records.saturating_add(1);
            if consecutive_empty_records >= MAX_CONSECUTIVE_EMPTY_MFT_RECORDS {
                break;
            }
            continue;
        }
        consecutive_empty_records = 0;

        match parse_mft_record(&record_buffer, boot_sector.bytes_per_sector as usize) {
            Ok(record) => {
                parsed_records += 1;
                for attribute in &record.attributes {
                    match &attribute.form {
                        AttributeForm::Resident(_) => resident_attribute_count += 1,
                        AttributeForm::NonResident(_) => non_resident_attribute_count += 1,
                    }
                }

                let candidate = build_candidate(index, &record);
                if candidate.deleted {
                    deleted_records += 1;
                }
                if candidate.is_directory {
                    directory_records += 1;
                }
                if candidate.name.is_some() {
                    named_records += 1;
                }
                if candidate.has_non_resident_data {
                    records_with_non_resident_data += 1;
                }
                candidates.push(candidate);
            }
            Err(error) => {
                record_errors.push(QuickScanRecordError {
                    record_index: index,
                    reason: error.to_string(),
                });
            }
        }
    }

    reconstruct_paths(&mut candidates);

    Ok(QuickScanSummary {
        boot_sector,
        parsed_records,
        parse_failures: record_errors.len(),
        resident_attribute_count,
        non_resident_attribute_count,
        deleted_records,
        directory_records,
        named_records,
        records_with_non_resident_data,
        candidates,
        record_errors,
    })
}

fn build_candidate(record_index: usize, record: &MftRecord) -> QuickScanCandidate {
    let mut has_non_resident_data = false;
    let mut has_named_data_streams = false;
    let mut has_compressed_data = false;
    let mut has_sparse_data = false;
    let mut has_encrypted_data = false;
    let mut name = None;
    let mut parent_record_number = None;

    for attribute in &record.attributes {
        if attribute.flags & NTFS_ATTRIBUTE_FLAG_COMPRESSED != 0 {
            has_compressed_data = true;
        }
        if attribute.flags & NTFS_ATTRIBUTE_FLAG_SPARSE != 0 {
            has_sparse_data = true;
        }
        if attribute.flags & NTFS_ATTRIBUTE_FLAG_ENCRYPTED != 0 {
            has_encrypted_data = true;
        }

        if attribute.attribute_type == ATTRIBUTE_TYPE_DATA
            && matches!(&attribute.form, AttributeForm::NonResident(_))
        {
            has_non_resident_data = true;
        }

        if attribute.attribute_type == ATTRIBUTE_TYPE_DATA && attribute.name.is_some() {
            has_named_data_streams = true;
        }

        if name.is_some() {
            continue;
        }

        if attribute.attribute_type != ATTRIBUTE_TYPE_FILE_NAME {
            continue;
        }

        if let Some((parent, parsed_name)) = extract_file_name(attribute) {
            name = Some(parsed_name);
            parent_record_number = Some(parent);
        }
    }

    QuickScanCandidate {
        record_index,
        record_number: record.header.record_number,
        in_use: record.header.in_use(),
        deleted: !record.header.in_use(),
        is_directory: record.header.is_directory(),
        has_non_resident_data,
        has_named_data_streams,
        has_compressed_data,
        has_sparse_data,
        has_encrypted_data,
        usn_reason_mask: None,
        name,
        parent_record_number,
        reconstructed_path: None,
        evidence_sources: vec![EvidenceSource::Mft],
    }
}

fn extract_file_name(attribute: &AttributeRecord) -> Option<(u64, String)> {
    let AttributeForm::Resident(resident) = &attribute.form else {
        return None;
    };

    parse_file_name_value(&resident.value)
}

fn parse_file_name_value(value: &[u8]) -> Option<(u64, String)> {
    if value.len() < 0x42 {
        return None;
    }

    let parent_ref = read_u64(value, 0) & 0x0000_FFFF_FFFF_FFFF;
    let name_len = value[0x40] as usize;
    let name_start = 0x42usize;
    let name_len_bytes = name_len.checked_mul(2)?;
    let name_end = name_start.checked_add(name_len_bytes)?;
    if name_end > value.len() {
        return None;
    }

    let mut code_units = Vec::with_capacity(name_len);
    let mut i = name_start;
    while i < name_end {
        code_units.push(u16::from_le_bytes([value[i], value[i + 1]]));
        i += 2;
    }

    let name = String::from_utf16(&code_units).ok()?;
    if name.is_empty() {
        return None;
    }

    Some((parent_ref, name))
}

fn reconstruct_paths(candidates: &mut [QuickScanCandidate]) {
    let mut known_names: HashMap<u64, (Option<u64>, String)> = HashMap::new();
    for candidate in candidates.iter() {
        if let Some(name) = &candidate.name {
            known_names.insert(
                candidate.record_number as u64,
                (candidate.parent_record_number, name.clone()),
            );
        }
    }

    for candidate in candidates.iter_mut() {
        let Some(name) = candidate.name.clone() else {
            continue;
        };

        let mut segments = vec![name];
        let mut parent = candidate.parent_record_number;
        let mut seen = HashSet::new();

        while let Some(parent_record) = parent {
            if !seen.insert(parent_record) {
                break;
            }

            let Some((next_parent, parent_name)) = known_names.get(&parent_record) else {
                break;
            };

            segments.push(parent_name.clone());
            parent = *next_parent;

            if segments.len() >= 32 {
                break;
            }
        }

        segments.reverse();
        candidate.reconstructed_path = Some(segments.join("\\"));
    }
}

pub fn apply_usn_evidence(
    candidates: &mut [QuickScanCandidate],
    usn_records: &[UsnRecord],
) -> usize {
    if candidates.is_empty() || usn_records.is_empty() {
        return 0;
    }

    let mut by_name: HashMap<String, u32> = HashMap::new();
    let mut by_path: HashMap<String, u32> = HashMap::new();
    for record in usn_records {
        let normalized_name = normalize_case_key(&record.file_name);
        let reason_entry = by_name.entry(normalized_name).or_insert(0);
        *reason_entry |= record.reason;
    }

    for candidate in candidates.iter() {
        if let Some(path) = &candidate.reconstructed_path {
            let normalized_path = normalize_case_key(path);
            if let Some(reason) = candidate
                .name
                .as_ref()
                .and_then(|name| by_name.get(&normalize_case_key(name)).copied())
            {
                by_path.entry(normalized_path).or_insert(reason);
            }
        }
    }

    let mut enriched = 0usize;
    for candidate in candidates.iter_mut() {
        let mut matched_reason = 0u32;

        if let Some(path) = &candidate.reconstructed_path {
            if let Some(reason) = by_path.get(&normalize_case_key(path)).copied() {
                matched_reason |= reason;
            }
        }

        if let Some(name) = &candidate.name {
            if let Some(reason) = by_name.get(&normalize_case_key(name)).copied() {
                matched_reason |= reason;
            }
        }

        if matched_reason == 0 {
            continue;
        }

        if !candidate.evidence_sources.contains(&EvidenceSource::Usn) {
            candidate.evidence_sources.push(EvidenceSource::Usn);
        }
        candidate.usn_reason_mask = Some(candidate.usn_reason_mask.unwrap_or(0) | matched_reason);
        enriched = enriched.saturating_add(1);
    }

    enriched
}

fn normalize_case_key(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn read_from_session(
    session: &mut ReadSession,
    offset: u64,
    output: &mut [u8],
) -> Result<bool, WinIoError> {
    if output.is_empty() {
        return Ok(true);
    }

    if session.alignment_enforced() {
        let alignment = session.alignment_bytes().unwrap_or(0) as usize;
        if alignment > 1 {
            return read_with_alignment(session, offset, output, alignment);
        }
    }

    read_exact(session, offset, output)
}

fn read_with_alignment(
    session: &mut ReadSession,
    offset: u64,
    output: &mut [u8],
    alignment: usize,
) -> Result<bool, WinIoError> {
    let alignment_u64 = alignment as u64;
    let aligned_offset = (offset / alignment_u64) * alignment_u64;
    let prefix_len = (offset - aligned_offset) as usize;
    let required_len = prefix_len
        .checked_add(output.len())
        .ok_or(WinIoError::InvalidReadOffset)?;
    let aligned_len = round_up(required_len, alignment).ok_or(WinIoError::InvalidReadOffset)?;

    let mut scratch = vec![0u8; aligned_len];
    if !read_exact(session, aligned_offset, &mut scratch)? {
        return Ok(false);
    }

    output.copy_from_slice(&scratch[prefix_len..prefix_len + output.len()]);
    Ok(true)
}

fn read_exact(
    session: &mut ReadSession,
    offset: u64,
    output: &mut [u8],
) -> Result<bool, WinIoError> {
    let mut total = 0usize;
    while total < output.len() {
        let current_offset = offset
            .checked_add(total as u64)
            .ok_or(WinIoError::InvalidReadOffset)?;
        let read = session.read_at(current_offset, &mut output[total..])?;
        if read == 0 {
            return Ok(false);
        }
        total += read;
    }

    Ok(true)
}

fn round_up(value: usize, alignment: usize) -> Option<usize> {
    let remainder = value % alignment;
    if remainder == 0 {
        return Some(value);
    }

    value.checked_add(alignment - remainder)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use std::fs;

    #[test]
    fn can_checkpoint_and_cancel() {
        let mut orchestrator = SessionOrchestrator::default();
        let session = orchestrator.start_session("abc");
        assert_eq!(session.state.checkpoint, "initialized");

        orchestrator.checkpoint("abc", "mft-pass").unwrap();
        orchestrator.cancel("abc").unwrap();

        let state = orchestrator.get("abc").unwrap();
        assert_eq!(state.state.checkpoint, "mft-pass");
        assert!(state.state.canceled);
    }

    #[test]
    fn quick_scan_parses_single_record() {
        let image = build_test_ntfs_image_with_single_record();

        let summary =
            quick_scan_ntfs_metadata(&image, QuickScanConfig { max_records: 16 }).unwrap();

        assert_eq!(summary.parsed_records, 1);
        assert_eq!(summary.parse_failures, 0);
        assert_eq!(summary.resident_attribute_count, 1);
        assert_eq!(summary.non_resident_attribute_count, 0);
    }

    #[test]
    fn quick_scan_extracts_deleted_named_candidate() {
        let image = build_test_ntfs_image_with_named_records();

        let summary =
            quick_scan_ntfs_metadata(&image, QuickScanConfig { max_records: 16 }).unwrap();

        assert_eq!(summary.parsed_records, 2);
        assert_eq!(summary.deleted_records, 1);
        assert_eq!(summary.named_records, 2);
        assert_eq!(summary.candidates.len(), 2);

        let deleted = summary
            .candidates
            .iter()
            .find(|candidate| candidate.record_number == 6)
            .unwrap();

        assert!(deleted.deleted);
        assert_eq!(deleted.name.as_deref(), Some("report.txt"));
        assert_eq!(deleted.parent_record_number, Some(5));
        assert_eq!(
            deleted.reconstructed_path.as_deref(),
            Some(r"Docs\report.txt")
        );
    }

    #[test]
    fn quick_scan_skips_zero_record_gap_before_later_records() {
        let image = build_test_ntfs_image_with_named_records_at_indexes(0, 20);

        let summary =
            quick_scan_ntfs_metadata(&image, QuickScanConfig { max_records: 64 }).unwrap();

        assert_eq!(summary.parsed_records, 2);
        assert_eq!(summary.deleted_records, 1);
        assert_eq!(summary.named_records, 2);

        let deleted = summary
            .candidates
            .iter()
            .find(|candidate| candidate.record_number == 6)
            .unwrap();
        assert!(deleted.deleted);
        assert_eq!(
            deleted.reconstructed_path.as_deref(),
            Some(r"Docs\report.txt")
        );
    }

    #[test]
    fn apply_usn_evidence_marks_matching_candidate() {
        let image = build_test_ntfs_image_with_named_records();
        let mut summary =
            quick_scan_ntfs_metadata(&image, QuickScanConfig { max_records: 16 }).unwrap();

        let usn_records = vec![UsnRecord {
            major_version: 2,
            minor_version: 0,
            file_reference_number: 6,
            parent_file_reference_number: 5,
            usn: 9,
            timestamp_100ns: 10,
            reason: fr_usn::USN_REASON_FILE_DELETE | fr_usn::USN_REASON_CLOSE,
            source_info: 0,
            security_id: 0,
            file_attributes: 0,
            file_name: "report.txt".to_string(),
        }];

        let enriched = apply_usn_evidence(&mut summary.candidates, &usn_records);
        assert_eq!(enriched, 1);

        let deleted = summary
            .candidates
            .iter()
            .find(|candidate| candidate.record_number == 6)
            .unwrap();
        assert!(deleted.evidence_sources.contains(&EvidenceSource::Mft));
        assert!(deleted.evidence_sources.contains(&EvidenceSource::Usn));
        assert_eq!(
            deleted.usn_reason_mask,
            Some(fr_usn::USN_REASON_FILE_DELETE | fr_usn::USN_REASON_CLOSE)
        );
    }

    #[cfg(windows)]
    #[test]
    fn quick_scan_from_image_source_reads_named_candidates() {
        let image = build_test_ntfs_image_with_named_records();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-session-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("ntfs-image.img");
        fs::write(&image_path, &image).unwrap();

        let summary = quick_scan_ntfs_from_source(
            image_path.to_string_lossy().as_ref(),
            RecoverySourceKind::ImageFile,
            QuickScanConfig { max_records: 16 },
        )
        .unwrap();

        assert_eq!(summary.parsed_records, 2);
        assert_eq!(summary.deleted_records, 1);
        assert_eq!(summary.named_records, 2);
        assert_eq!(summary.candidates.len(), 2);

        let deleted = summary
            .candidates
            .iter()
            .find(|candidate| candidate.record_number == 6)
            .unwrap();
        assert!(deleted.deleted);
        assert_eq!(
            deleted.reconstructed_path.as_deref(),
            Some(r"Docs\report.txt")
        );

        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn quick_scan_reports_mft_bounds_error() {
        let mut image = vec![0u8; 4096];
        image[0x03..0x0B].copy_from_slice(b"NTFS    ");
        write_u16(&mut image, 0x0B, 512);
        image[0x0D] = 1;
        write_u64(&mut image, 0x28, 1000);
        write_u64(&mut image, 0x30, 1_000_000);
        write_u64(&mut image, 0x38, 1);
        image[0x40] = (-10i8) as u8;
        image[0x44] = 1;
        write_u16(&mut image, 0x1FE, 0xAA55);

        let error = quick_scan_ntfs_metadata(&image, QuickScanConfig::default()).unwrap_err();
        assert!(matches!(error, QuickScanError::MftOutOfBounds(_, _)));
    }

    fn build_test_ntfs_image_with_single_record() -> Vec<u8> {
        let mut image = vec![0u8; 8 * 1024];

        image[0x03..0x0B].copy_from_slice(b"NTFS    ");
        write_u16(&mut image, 0x0B, 512);
        image[0x0D] = 1;
        write_u64(&mut image, 0x28, 16_000);
        write_u64(&mut image, 0x30, 4);
        write_u64(&mut image, 0x38, 2);
        image[0x40] = (-10i8) as u8;
        image[0x44] = 1;
        write_u64(&mut image, 0x48, 0xAABBCCDDEEFF0011);
        write_u16(&mut image, 0x1FE, 0xAA55);

        let mft_offset = 4 * 512;
        let record = build_resident_mft_record();
        image[mft_offset..mft_offset + record.len()].copy_from_slice(&record);

        image
    }

    fn build_test_ntfs_image_with_named_records() -> Vec<u8> {
        build_test_ntfs_image_with_named_records_at_indexes(0, 1)
    }

    fn build_test_ntfs_image_with_named_records_at_indexes(
        parent_record_index: usize,
        child_record_index: usize,
    ) -> Vec<u8> {
        let highest_record_index = parent_record_index.max(child_record_index);
        let image_len = (8 + highest_record_index + 1) * 1024;
        let mut image = vec![0u8; image_len];

        image[0x03..0x0B].copy_from_slice(b"NTFS    ");
        write_u16(&mut image, 0x0B, 512);
        image[0x0D] = 1;
        write_u64(&mut image, 0x28, 24_000);
        write_u64(&mut image, 0x30, 4);
        write_u64(&mut image, 0x38, 2);
        image[0x40] = (-10i8) as u8;
        image[0x44] = 1;
        write_u16(&mut image, 0x1FE, 0xAA55);

        let mft_offset = 4 * 512;
        let parent = build_named_record(5, 0x0003, "Docs", 0);
        let child_deleted = build_named_record(6, 0x0000, "report.txt", 5);
        let parent_offset = mft_offset + parent_record_index * 1024;
        let child_offset = mft_offset + child_record_index * 1024;

        image[parent_offset..parent_offset + parent.len()].copy_from_slice(&parent);
        image[child_offset..child_offset + child_deleted.len()].copy_from_slice(&child_deleted);

        image
    }

    fn build_resident_mft_record() -> Vec<u8> {
        let mut record = vec![0u8; 1024];
        record[0x00..0x04].copy_from_slice(b"FILE");
        write_u16(&mut record, 0x04, 0x30);
        write_u16(&mut record, 0x06, 3);
        write_u16(&mut record, 0x10, 1);
        write_u16(&mut record, 0x12, 1);
        write_u16(&mut record, 0x14, 0x38);
        write_u16(&mut record, 0x16, 0x0001);
        write_u32(&mut record, 0x18, 0x70);
        write_u32(&mut record, 0x1C, 1024);

        write_u16(&mut record, 0x30, 0xAAAA);
        write_u16(&mut record, 0x32, 0x1111);
        write_u16(&mut record, 0x34, 0x2222);
        write_u16(&mut record, 510, 0xAAAA);
        write_u16(&mut record, 1022, 0xAAAA);

        let attr_offset = 0x38;
        write_u32(&mut record, attr_offset, 0x10);
        write_u32(&mut record, attr_offset + 4, 0x20);
        record[attr_offset + 8] = 0;
        record[attr_offset + 9] = 0;
        write_u16(&mut record, attr_offset + 10, 0);
        write_u16(&mut record, attr_offset + 12, 0);
        write_u16(&mut record, attr_offset + 14, 1);
        write_u32(&mut record, attr_offset + 16, 4);
        write_u16(&mut record, attr_offset + 20, 0x18);
        record[attr_offset + 24..attr_offset + 28].copy_from_slice(&[1, 2, 3, 4]);
        write_u32(&mut record, attr_offset + 0x20, 0xFFFF_FFFF);

        record
    }

    fn build_named_record(
        record_number: u32,
        flags: u16,
        file_name: &str,
        parent_record: u64,
    ) -> Vec<u8> {
        let mut record = vec![0u8; 1024];
        record[0x00..0x04].copy_from_slice(b"FILE");
        write_u16(&mut record, 0x04, 0x30);
        write_u16(&mut record, 0x06, 3);
        write_u16(&mut record, 0x10, 1);
        write_u16(&mut record, 0x12, 1);
        write_u16(&mut record, 0x14, 0x38);
        write_u16(&mut record, 0x16, flags);
        write_u32(&mut record, 0x1C, 1024);
        write_u32(&mut record, 0x2C, record_number);

        write_u16(&mut record, 0x30, 0xAAAA);
        write_u16(&mut record, 0x32, 0x1111);
        write_u16(&mut record, 0x34, 0x2222);
        write_u16(&mut record, 510, 0xAAAA);
        write_u16(&mut record, 1022, 0xAAAA);

        let attr_offset = 0x38usize;
        let file_name_attr = build_file_name_attribute(file_name, parent_record);
        record[attr_offset..attr_offset + file_name_attr.len()].copy_from_slice(&file_name_attr);

        let end_offset = attr_offset + file_name_attr.len();
        write_u32(&mut record, end_offset, 0xFFFF_FFFF);
        write_u32(&mut record, 0x18, (end_offset + 4) as u32);

        record
    }

    fn build_file_name_attribute(file_name: &str, parent_record: u64) -> Vec<u8> {
        let utf16: Vec<u16> = file_name.encode_utf16().collect();
        let name_len = utf16.len() as u8;
        let value_len = 0x42usize + utf16.len() * 2;
        let attr_len = 0x18usize + value_len;
        let mut attr = vec![0u8; attr_len];

        write_u32(&mut attr, 0x00, 0x30);
        write_u32(&mut attr, 0x04, attr_len as u32);
        attr[0x08] = 0;
        attr[0x09] = 0;
        write_u16(&mut attr, 0x0A, 0);
        write_u16(&mut attr, 0x0C, 0);
        write_u16(&mut attr, 0x0E, 1);
        write_u32(&mut attr, 0x10, value_len as u32);
        write_u16(&mut attr, 0x14, 0x18);

        write_u64(&mut attr, 0x18, parent_record & 0x0000_FFFF_FFFF_FFFF);
        attr[0x18 + 0x40] = name_len;
        attr[0x18 + 0x41] = 1;

        let mut cursor = 0x18 + 0x42;
        for code in utf16 {
            attr[cursor..cursor + 2].copy_from_slice(&code.to_le_bytes());
            cursor += 2;
        }

        attr
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
