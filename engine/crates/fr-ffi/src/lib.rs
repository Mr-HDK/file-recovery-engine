use fr_scoring::score_candidate_with_reasons;
use fr_session::{quick_scan_ntfs_from_read_session, QuickScanConfig, QuickScanError};
use fr_types::{ConfidenceTier, EvidenceSource, RecoveryCandidate, RecoverySourceKind};
use fr_mft::{parse_mft_record, AttributeForm, ATTRIBUTE_TYPE_DATA};
use fr_ntfs::parse_boot_sector;
use std::fs::{self, File};
use std::collections::HashMap;
use std::ffi::{c_char, CStr};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

static ENGINE_VERSION: &[u8] = b"0.1.0\0";
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

fn read_sessions() -> &'static Mutex<HashMap<u64, fr_winio::ReadSession>> {
    static SESSIONS: OnceLock<Mutex<HashMap<u64, fr_winio::ReadSession>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FrNtfsBootMetadata {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub _reserved0: u8,
    pub cluster_size_bytes: u32,
    pub file_record_size_bytes: u32,
    pub index_record_size_bytes: u32,
    pub mft_cluster: u64,
    pub mft_offset_bytes: u64,
    pub volume_size_bytes: u64,
    pub volume_serial: u64,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FrNtfsQuickScanSummary {
    pub parsed_records: u32,
    pub parse_failures: u32,
    pub resident_attribute_count: u32,
    pub non_resident_attribute_count: u32,
    pub deleted_records: u32,
    pub directory_records: u32,
    pub named_records: u32,
    pub records_with_non_resident_data: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FrNtfsQuickScanCandidate {
    pub record_number: u32,
    pub flags: u32,
    pub parent_record_number: u64,
    pub confidence_tier: u32,
    pub name: [u8; 128],
    pub reconstructed_path: [u8; 256],
    pub confidence_reason: [u8; 256],
}

const CANDIDATE_FLAG_IN_USE: u32 = 0x0001;
const CANDIDATE_FLAG_DELETED: u32 = 0x0002;
const CANDIDATE_FLAG_DIRECTORY: u32 = 0x0004;
const CANDIDATE_FLAG_NON_RESIDENT_DATA: u32 = 0x0008;
const CANDIDATE_FLAG_HAS_NAME: u32 = 0x0010;
const CANDIDATE_FLAG_HAS_PATH: u32 = 0x0020;
const CANDIDATE_FLAG_HAS_NAMED_DATA_STREAM: u32 = 0x0040;
const CANDIDATE_FLAG_COMPRESSED: u32 = 0x0080;
const CANDIDATE_FLAG_SPARSE: u32 = 0x0100;
const CANDIDATE_FLAG_ENCRYPTED: u32 = 0x0200;

const NTFS_ATTRIBUTE_FLAG_COMPRESSED: u16 = 0x0001;
const NTFS_ATTRIBUTE_FLAG_ENCRYPTED: u16 = 0x4000;
const NTFS_ATTRIBUTE_FLAG_SPARSE: u16 = 0x8000;

const RECOVERY_DIAG_HAS_NAMED_DATA_STREAM: u32 = 0x0001;
const RECOVERY_DIAG_SKIPPED_NAMED_DATA_STREAMS: u32 = 0x0002;
const RECOVERY_DIAG_COMPRESSED_ATTRIBUTE: u32 = 0x0004;
const RECOVERY_DIAG_SPARSE_ATTRIBUTE: u32 = 0x0008;
const RECOVERY_DIAG_ENCRYPTED_ATTRIBUTE: u32 = 0x0010;
const RECOVERY_DIAG_UNSUPPORTED_COMPRESSED: u32 = 0x0020;
const RECOVERY_DIAG_UNSUPPORTED_ENCRYPTED: u32 = 0x0040;
const RECOVERY_DIAG_SPARSE_ZERO_FILLED: u32 = 0x0080;
const RECOVERY_DIAG_NO_DEFAULT_DATA_STREAM: u32 = 0x0100;
const RECOVERY_DIAG_EXPORTED_NAMED_DATA_STREAMS: u32 = 0x0200;

#[no_mangle]
pub extern "C" fn fr_engine_version() -> *const c_char {
    ENGINE_VERSION.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn fr_health_check() -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn fr_validate_destination_separation(
    source_volume_id: *const c_char,
    destination_volume_id: *const c_char,
) -> i32 {
    if source_volume_id.is_null() || destination_volume_id.is_null() {
        return -1;
    }

    let source = unsafe { CStr::from_ptr(source_volume_id) };
    let destination = unsafe { CStr::from_ptr(destination_volume_id) };

    let Ok(source_str) = source.to_str() else {
        return -2;
    };

    let Ok(destination_str) = destination.to_str() else {
        return -3;
    };

    if source_str.eq_ignore_ascii_case(destination_str) {
        return 1;
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_probe_source_readonly(
    source_path: *const c_char,
    source_kind: i32,
    out_size_bytes: *mut u64,
) -> i32 {
    if source_path.is_null() {
        return -1;
    }

    let source = unsafe { CStr::from_ptr(source_path) };
    let Ok(source_str) = source.to_str() else {
        return -2;
    };

    let Ok(kind) = parse_source_kind(source_kind) else {
        return -3;
    };

    match fr_winio::probe_source_read_only(source_str, kind) {
        Ok(result) => {
            if !out_size_bytes.is_null() {
                unsafe {
                    *out_size_bytes = result.size_bytes.unwrap_or(0);
                }
            }
            0
        }
        Err(err) => map_winio_error(err),
    }
}

#[no_mangle]
pub extern "C" fn fr_open_source_session_readonly(
    source_path: *const c_char,
    source_kind: i32,
    out_session_id: *mut u64,
    out_size_bytes: *mut u64,
) -> i32 {
    if source_path.is_null() || out_session_id.is_null() {
        return -1;
    }

    let source = unsafe { CStr::from_ptr(source_path) };
    let Ok(source_str) = source.to_str() else {
        return -2;
    };

    let Ok(kind) = parse_source_kind(source_kind) else {
        return -3;
    };

    match fr_winio::ReadSession::open(source_str, kind) {
        Ok(session) => {
            let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
            let size = session.size_bytes().unwrap_or(0);

            let Ok(mut map) = read_sessions().lock() else {
                return -200;
            };
            map.insert(session_id, session);

            unsafe {
                *out_session_id = session_id;
            }

            if !out_size_bytes.is_null() {
                unsafe {
                    *out_size_bytes = size;
                }
            }

            0
        }
        Err(err) => map_winio_error(err),
    }
}

#[no_mangle]
pub extern "C" fn fr_read_source_session(
    session_id: u64,
    offset: u64,
    buffer: *mut u8,
    buffer_len: u32,
    out_bytes_read: *mut u32,
) -> i32 {
    if out_bytes_read.is_null() {
        return -1;
    }

    if buffer_len > 0 && buffer.is_null() {
        return -2;
    }

    let Ok(mut map) = read_sessions().lock() else {
        return -200;
    };

    let Some(session) = map.get_mut(&session_id) else {
        return 20;
    };

    let bytes = if buffer_len == 0 {
        0
    } else {
        let slice = unsafe { std::slice::from_raw_parts_mut(buffer, buffer_len as usize) };
        match session.read_at(offset, slice) {
            Ok(read) => read as u32,
            Err(err) => return map_winio_error(err),
        }
    };

    unsafe {
        *out_bytes_read = bytes;
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_get_source_session_alignment(
    session_id: u64,
    out_alignment_bytes: *mut u32,
) -> i32 {
    if out_alignment_bytes.is_null() {
        return -1;
    }

    let Ok(map) = read_sessions().lock() else {
        return -200;
    };

    let Some(session) = map.get(&session_id) else {
        return 20;
    };

    unsafe {
        *out_alignment_bytes = session.alignment_bytes().unwrap_or(0);
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_probe_ntfs_boot_from_session(
    session_id: u64,
    out_boot: *mut FrNtfsBootMetadata,
) -> i32 {
    if out_boot.is_null() {
        return -1;
    }

    let Ok(mut map) = read_sessions().lock() else {
        return -200;
    };

    let Some(session) = map.get_mut(&session_id) else {
        return 20;
    };

    let mut sector = [0u8; 512];
    match read_from_session(session, 0, &mut sector) {
        Ok(true) => {}
        Ok(false) => return 31,
        Err(err) => return map_winio_error(err),
    }

    let Ok(boot) = parse_boot_sector(&sector) else {
        return 30;
    };

    unsafe {
        *out_boot = FrNtfsBootMetadata {
            bytes_per_sector: boot.bytes_per_sector,
            sectors_per_cluster: boot.sectors_per_cluster,
            _reserved0: 0,
            cluster_size_bytes: boot.cluster_size_bytes(),
            file_record_size_bytes: boot.file_record_size_bytes,
            index_record_size_bytes: boot.index_record_size_bytes,
            mft_cluster: boot.mft_cluster,
            mft_offset_bytes: boot.mft_offset_bytes().unwrap_or(0),
            volume_size_bytes: boot.volume_size_bytes().unwrap_or(0),
            volume_serial: boot.volume_serial,
        };
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_quick_scan_ntfs_from_session(
    session_id: u64,
    max_records: u32,
    out_summary: *mut FrNtfsQuickScanSummary,
) -> i32 {
    if out_summary.is_null() {
        return -1;
    }

    let Ok(mut map) = read_sessions().lock() else {
        return -200;
    };

    let Some(session) = map.get_mut(&session_id) else {
        return 20;
    };

    let config = QuickScanConfig {
        max_records: normalize_max_records(max_records),
    };

    match quick_scan_ntfs_from_read_session(session, config) {
        Ok(summary) => {
            unsafe {
                *out_summary = FrNtfsQuickScanSummary {
                    parsed_records: usize_to_u32_saturating(summary.parsed_records),
                    parse_failures: usize_to_u32_saturating(summary.parse_failures),
                    resident_attribute_count: usize_to_u32_saturating(
                        summary.resident_attribute_count,
                    ),
                    non_resident_attribute_count: usize_to_u32_saturating(
                        summary.non_resident_attribute_count,
                    ),
                    deleted_records: usize_to_u32_saturating(summary.deleted_records),
                    directory_records: usize_to_u32_saturating(summary.directory_records),
                    named_records: usize_to_u32_saturating(summary.named_records),
                    records_with_non_resident_data: usize_to_u32_saturating(
                        summary.records_with_non_resident_data,
                    ),
                };
            }

            0
        }
        Err(err) => map_quick_scan_error(err),
    }
}

#[no_mangle]
pub extern "C" fn fr_get_ntfs_quick_scan_candidates_from_session(
    session_id: u64,
    max_records: u32,
    out_candidates: *mut FrNtfsQuickScanCandidate,
    candidate_capacity: u32,
    out_written: *mut u32,
) -> i32 {
    if out_written.is_null() {
        return -1;
    }

    if candidate_capacity > 0 && out_candidates.is_null() {
        return -2;
    }

    unsafe {
        *out_written = 0;
    }

    let Ok(mut map) = read_sessions().lock() else {
        return -200;
    };

    let Some(session) = map.get_mut(&session_id) else {
        return 20;
    };
    let config = QuickScanConfig {
        max_records: normalize_max_records(max_records),
    };
    let summary = match quick_scan_ntfs_from_read_session(session, config) {
        Ok(summary) => summary,
        Err(err) => return map_quick_scan_error(err),
    };

    let mut candidates: Vec<QuickScanCandidateInternal> = summary
        .candidates
        .into_iter()
        .map(build_internal_candidate_from_quick_scan)
        .collect();
    score_internal_candidates(&mut candidates);

    let written = candidates.len().min(candidate_capacity as usize);
    if written > 0 {
        let out_slice = unsafe { std::slice::from_raw_parts_mut(out_candidates, written) };
        for (i, candidate) in candidates.into_iter().take(written).enumerate() {
            out_slice[i] = encode_candidate(candidate);
        }
    }

    unsafe {
        *out_written = written as u32;
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_recover_ntfs_candidate_to_file(
    session_id: u64,
    record_number: u32,
    output_path: *const c_char,
    out_bytes_written: *mut u64,
    out_partial: *mut i32,
) -> i32 {
    fr_recover_ntfs_candidate_to_file_impl(
        session_id,
        record_number,
        output_path,
        out_bytes_written,
        out_partial,
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub extern "C" fn fr_recover_ntfs_candidate_to_file_ex(
    session_id: u64,
    record_number: u32,
    output_path: *const c_char,
    out_bytes_written: *mut u64,
    out_partial: *mut i32,
    out_diagnostics_flags: *mut u32,
) -> i32 {
    fr_recover_ntfs_candidate_to_file_impl(
        session_id,
        record_number,
        output_path,
        out_bytes_written,
        out_partial,
        out_diagnostics_flags,
    )
}

fn fr_recover_ntfs_candidate_to_file_impl(
    session_id: u64,
    record_number: u32,
    output_path: *const c_char,
    out_bytes_written: *mut u64,
    out_partial: *mut i32,
    out_diagnostics_flags: *mut u32,
) -> i32 {
    if output_path.is_null() {
        return -1;
    }

    if !out_bytes_written.is_null() {
        unsafe {
            *out_bytes_written = 0;
        }
    }

    if !out_partial.is_null() {
        unsafe {
            *out_partial = 0;
        }
    }

    if !out_diagnostics_flags.is_null() {
        unsafe {
            *out_diagnostics_flags = 0;
        }
    }

    let output_path_cstr = unsafe { CStr::from_ptr(output_path) };
    let Ok(output_path_str) = output_path_cstr.to_str() else {
        return 43;
    };

    if output_path_str.trim().is_empty() {
        return 43;
    }

    let Ok(mut map) = read_sessions().lock() else {
        return -200;
    };

    let Some(session) = map.get_mut(&session_id) else {
        return 20;
    };

    let mut sector = [0u8; 512];
    match read_from_session(session, 0, &mut sector) {
        Ok(true) => {}
        Ok(false) => return 31,
        Err(err) => return map_winio_error(err),
    }

    let Ok(boot) = parse_boot_sector(&sector) else {
        return 30;
    };

    let record_size = boot.file_record_size_bytes as usize;
    if record_size < 256 || record_size > 1024 * 1024 {
        return 32;
    }

    let Some(mut record_offset) = boot.mft_offset_bytes() else {
        return 33;
    };

    let max_records = 262_144usize;
    let mut record_buffer = vec![0u8; record_size];
    let mut target_record: Option<fr_mft::MftRecord> = None;

    for _ in 0..max_records {
        match read_from_session(session, record_offset, &mut record_buffer) {
            Ok(true) => {}
            Ok(false) => break,
            Err(err) => return map_winio_error(err),
        }

        if record_buffer.iter().all(|b| *b == 0) {
            break;
        }

        if let Ok(record) = parse_mft_record(&record_buffer, boot.bytes_per_sector as usize) {
            if record.header.record_number == record_number {
                target_record = Some(record);
                break;
            }
        }

        let Some(next_offset) = record_offset.checked_add(record_size as u64) else {
            return 33;
        };
        record_offset = next_offset;
    }

    let Some(record) = target_record else {
        return 41;
    };

    let output_path = Path::new(output_path_str);
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() && fs::create_dir_all(parent).is_err() {
            return 44;
        }
    }

    let mut diagnostics_flags = 0u32;
    let mut unnamed_data_attribute: Option<&fr_mft::AttributeRecord> = None;
    let mut named_data_attributes: Vec<&fr_mft::AttributeRecord> = Vec::new();
    for attribute in &record.attributes {
        if attribute.attribute_type != ATTRIBUTE_TYPE_DATA {
            continue;
        }

        if attribute.flags & NTFS_ATTRIBUTE_FLAG_COMPRESSED != 0 {
            diagnostics_flags |= RECOVERY_DIAG_COMPRESSED_ATTRIBUTE;
        }
        if attribute.flags & NTFS_ATTRIBUTE_FLAG_SPARSE != 0 {
            diagnostics_flags |= RECOVERY_DIAG_SPARSE_ATTRIBUTE;
        }
        if attribute.flags & NTFS_ATTRIBUTE_FLAG_ENCRYPTED != 0 {
            diagnostics_flags |= RECOVERY_DIAG_ENCRYPTED_ATTRIBUTE;
        }

        if attribute.name.is_some() {
            named_data_attributes.push(attribute);
            continue;
        }

        if unnamed_data_attribute.is_none() {
            unnamed_data_attribute = Some(attribute);
        }
    }

    if !named_data_attributes.is_empty() {
        diagnostics_flags |= RECOVERY_DIAG_HAS_NAMED_DATA_STREAM;
    }

    let mut total_written = 0u64;
    let mut partial = false;
    let mut exported_data_stream_count = 0usize;
    let mut exported_named_stream_count = 0usize;

    if let Some(data_attribute) = unnamed_data_attribute {
        if data_attribute.flags & NTFS_ATTRIBUTE_FLAG_ENCRYPTED != 0 {
            diagnostics_flags |= RECOVERY_DIAG_UNSUPPORTED_ENCRYPTED;
            write_diagnostics_flags(out_diagnostics_flags, diagnostics_flags);
            return 46;
        }

        if data_attribute.flags & NTFS_ATTRIBUTE_FLAG_COMPRESSED != 0 {
            diagnostics_flags |= RECOVERY_DIAG_UNSUPPORTED_COMPRESSED;
            write_diagnostics_flags(out_diagnostics_flags, diagnostics_flags);
            return 45;
        }

        let Ok(mut output_file) = File::create(output_path) else {
            return 44;
        };

        match recover_data_attribute(
            session,
            &boot,
            data_attribute,
            &mut output_file,
            &mut diagnostics_flags,
        ) {
            Ok((written, is_partial)) => {
                total_written = total_written.saturating_add(written);
                partial |= is_partial;
                exported_data_stream_count = exported_data_stream_count.saturating_add(1);
            }
            Err(status) => return status,
        }
    } else if !named_data_attributes.is_empty() {
        diagnostics_flags |= RECOVERY_DIAG_NO_DEFAULT_DATA_STREAM;
        partial = true;
    } else {
        write_diagnostics_flags(out_diagnostics_flags, diagnostics_flags);
        return 42;
    }

    let mut named_stream_suffixes: HashMap<String, u32> = HashMap::new();
    let mut skipped_named_streams = 0usize;
    for named_attribute in named_data_attributes {
        if named_attribute.flags & NTFS_ATTRIBUTE_FLAG_ENCRYPTED != 0 {
            diagnostics_flags |= RECOVERY_DIAG_UNSUPPORTED_ENCRYPTED;
            skipped_named_streams = skipped_named_streams.saturating_add(1);
            partial = true;
            continue;
        }

        if named_attribute.flags & NTFS_ATTRIBUTE_FLAG_COMPRESSED != 0 {
            diagnostics_flags |= RECOVERY_DIAG_UNSUPPORTED_COMPRESSED;
            skipped_named_streams = skipped_named_streams.saturating_add(1);
            partial = true;
            continue;
        }

        let stream_name = named_attribute.name.as_deref().unwrap_or("stream");
        let sidecar_path =
            build_named_stream_output_path(output_path, stream_name, &mut named_stream_suffixes);

        let Ok(mut sidecar_file) = File::create(&sidecar_path) else {
            skipped_named_streams = skipped_named_streams.saturating_add(1);
            partial = true;
            continue;
        };

        match recover_data_attribute(
            session,
            &boot,
            named_attribute,
            &mut sidecar_file,
            &mut diagnostics_flags,
        ) {
            Ok((written, is_partial)) => {
                total_written = total_written.saturating_add(written);
                partial |= is_partial;
                exported_data_stream_count = exported_data_stream_count.saturating_add(1);
                exported_named_stream_count = exported_named_stream_count.saturating_add(1);
            }
            Err(_) => {
                skipped_named_streams = skipped_named_streams.saturating_add(1);
                partial = true;
            }
        }
    }

    if exported_data_stream_count == 0 {
        diagnostics_flags |= RECOVERY_DIAG_SKIPPED_NAMED_DATA_STREAMS;
        write_diagnostics_flags(out_diagnostics_flags, diagnostics_flags);
        return 47;
    }

    if exported_named_stream_count > 0 {
        diagnostics_flags |= RECOVERY_DIAG_EXPORTED_NAMED_DATA_STREAMS;
    }

    if skipped_named_streams > 0 {
        diagnostics_flags |= RECOVERY_DIAG_SKIPPED_NAMED_DATA_STREAMS;
    }

    if !out_bytes_written.is_null() {
        unsafe {
            *out_bytes_written = total_written;
        }
    }

    if !out_partial.is_null() {
        unsafe {
            *out_partial = if partial { 1 } else { 0 };
        }
    }

    write_diagnostics_flags(out_diagnostics_flags, diagnostics_flags);

    0
}

#[no_mangle]
pub extern "C" fn fr_close_source_session(session_id: u64) -> i32 {
    let Ok(mut map) = read_sessions().lock() else {
        return -200;
    };

    if map.remove(&session_id).is_some() {
        0
    } else {
        20
    }
}

#[derive(Debug, Clone)]
struct QuickScanCandidateInternal {
    record_number: u32,
    in_use: bool,
    deleted: bool,
    is_directory: bool,
    has_non_resident_data: bool,
    has_named_data_streams: bool,
    has_compressed_data: bool,
    has_sparse_data: bool,
    has_encrypted_data: bool,
    parent_record_number: Option<u64>,
    name: Option<String>,
    reconstructed_path: Option<String>,
    confidence_tier: u32,
    confidence_reason: String,
}

fn build_internal_candidate_from_quick_scan(
    candidate: fr_session::QuickScanCandidate,
) -> QuickScanCandidateInternal {
    QuickScanCandidateInternal {
        record_number: candidate.record_number,
        in_use: candidate.in_use,
        deleted: candidate.deleted,
        is_directory: candidate.is_directory,
        has_non_resident_data: candidate.has_non_resident_data,
        has_named_data_streams: candidate.has_named_data_streams,
        has_compressed_data: candidate.has_compressed_data,
        has_sparse_data: candidate.has_sparse_data,
        has_encrypted_data: candidate.has_encrypted_data,
        parent_record_number: candidate.parent_record_number,
        name: candidate.name,
        reconstructed_path: candidate.reconstructed_path,
        confidence_tier: confidence_tier_code(ConfidenceTier::Medium),
        confidence_reason: String::from("Score 0. Confidence pending scoring."),
    }
}

fn score_internal_candidates(candidates: &mut [QuickScanCandidateInternal]) {
    for candidate in candidates.iter_mut() {
        let partial = candidate.name.is_none()
            || candidate.reconstructed_path.is_none()
            || candidate.has_named_data_streams
            || candidate.has_compressed_data
            || candidate.has_encrypted_data;
        let recovery_candidate = RecoveryCandidate {
            id: format!("mft-{}", candidate.record_number),
            original_name: candidate.name.clone(),
            original_path: candidate.reconstructed_path.clone(),
            recovered_path: None,
            size_bytes: 0,
            evidence: vec![EvidenceSource::Mft],
            confidence: ConfidenceTier::Medium,
            partial,
        };

        let scored = score_candidate_with_reasons(&recovery_candidate);
        candidate.confidence_tier = confidence_tier_code(scored.tier);
        candidate.confidence_reason = if scored.reasons.is_empty() {
            format!("Score {}.", scored.score)
        } else {
            format!("Score {}. {}", scored.score, scored.reasons.join("; "))
        };
    }
}

fn confidence_tier_code(tier: ConfidenceTier) -> u32 {
    match tier {
        ConfidenceTier::VeryHigh => 0,
        ConfidenceTier::High => 1,
        ConfidenceTier::Medium => 2,
        ConfidenceTier::Low => 3,
        ConfidenceTier::VeryLow => 4,
    }
}

fn encode_candidate(candidate: QuickScanCandidateInternal) -> FrNtfsQuickScanCandidate {
    let mut flags = 0u32;
    if candidate.in_use {
        flags |= CANDIDATE_FLAG_IN_USE;
    }
    if candidate.deleted {
        flags |= CANDIDATE_FLAG_DELETED;
    }
    if candidate.is_directory {
        flags |= CANDIDATE_FLAG_DIRECTORY;
    }
    if candidate.has_non_resident_data {
        flags |= CANDIDATE_FLAG_NON_RESIDENT_DATA;
    }
    if candidate.name.is_some() {
        flags |= CANDIDATE_FLAG_HAS_NAME;
    }
    if candidate.reconstructed_path.is_some() {
        flags |= CANDIDATE_FLAG_HAS_PATH;
    }
    if candidate.has_named_data_streams {
        flags |= CANDIDATE_FLAG_HAS_NAMED_DATA_STREAM;
    }
    if candidate.has_compressed_data {
        flags |= CANDIDATE_FLAG_COMPRESSED;
    }
    if candidate.has_sparse_data {
        flags |= CANDIDATE_FLAG_SPARSE;
    }
    if candidate.has_encrypted_data {
        flags |= CANDIDATE_FLAG_ENCRYPTED;
    }

    let mut out = FrNtfsQuickScanCandidate {
        record_number: candidate.record_number,
        flags,
        parent_record_number: candidate.parent_record_number.unwrap_or(0),
        confidence_tier: candidate.confidence_tier,
        name: [0u8; 128],
        reconstructed_path: [0u8; 256],
        confidence_reason: [0u8; 256],
    };

    if let Some(name) = &candidate.name {
        write_utf8(name, &mut out.name);
    }

    if let Some(path) = &candidate.reconstructed_path {
        write_utf8(path, &mut out.reconstructed_path);
    }

    write_utf8(&candidate.confidence_reason, &mut out.confidence_reason);

    out
}

fn recover_data_attribute(
    session: &mut fr_winio::ReadSession,
    boot: &fr_ntfs::NtfsBootSector,
    attribute: &fr_mft::AttributeRecord,
    output_file: &mut File,
    diagnostics_flags: &mut u32,
) -> Result<(u64, bool), i32> {
    match &attribute.form {
        AttributeForm::Resident(resident) => {
            if output_file.write_all(&resident.value).is_err() {
                return Err(44);
            }
            Ok((resident.value.len() as u64, false))
        }
        AttributeForm::NonResident(non_resident) => {
            recover_non_resident_data(session, boot, non_resident, output_file, diagnostics_flags)
        }
    }
}

fn build_named_stream_output_path(
    output_path: &Path,
    stream_name: &str,
    seen_names: &mut HashMap<String, u32>,
) -> PathBuf {
    let sanitized_stream_name = sanitize_windows_path_component(stream_name);
    let stream_key = sanitized_stream_name.to_ascii_lowercase();
    let occurrence = seen_names.entry(stream_key).or_insert(0);
    *occurrence = occurrence.saturating_add(1);

    let stream_suffix = if *occurrence == 1 {
        format!(".ads-{}", sanitized_stream_name)
    } else {
        format!(".ads-{}-{}", sanitized_stream_name, *occurrence)
    };

    let output_file_name = output_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| String::from("recovered"));

    output_path.with_file_name(format!("{output_file_name}{stream_suffix}"))
}

fn sanitize_windows_path_component(raw: &str) -> String {
    let mut sanitized = String::with_capacity(raw.len().max(8));
    for ch in raw.chars() {
        let invalid = ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*');
        sanitized.push(if invalid { '_' } else { ch });
    }

    let trimmed = sanitized.trim().trim_matches('.');
    let mut normalized = if trimmed.is_empty() {
        String::from("stream")
    } else {
        trimmed.to_string()
    };

    if is_windows_reserved_name(&normalized) {
        normalized.insert(0, '_');
    }

    normalized
}

fn is_windows_reserved_name(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn recover_non_resident_data(
    session: &mut fr_winio::ReadSession,
    boot: &fr_ntfs::NtfsBootSector,
    non_resident: &fr_mft::NonResidentAttribute,
    output_file: &mut File,
    diagnostics_flags: &mut u32,
) -> Result<(u64, bool), i32> {
    let cluster_size = boot.cluster_size_bytes() as u64;
    if cluster_size == 0 {
        return Err(32);
    }

    let mut bytes_written = 0u64;
    let mut remaining = non_resident.data_size;
    let mut partial = false;
    let mut scratch = vec![0u8; 1024 * 1024];
    let zero_chunk = vec![0u8; 64 * 1024];

    for run in &non_resident.data_runs {
        if remaining == 0 {
            break;
        }

        let run_bytes = match run.cluster_count.checked_mul(cluster_size) {
            Some(v) => v,
            None => return Err(33),
        };

        let to_process = run_bytes.min(remaining);
        if to_process == 0 {
            continue;
        }

        match run.lcn {
            None => {
                *diagnostics_flags |= RECOVERY_DIAG_SPARSE_ZERO_FILLED;
                let mut left = to_process;
                while left > 0 {
                    let chunk = left.min(zero_chunk.len() as u64) as usize;
                    if output_file.write_all(&zero_chunk[..chunk]).is_err() {
                        return Err(44);
                    }
                    bytes_written = bytes_written.saturating_add(chunk as u64);
                    left -= chunk as u64;
                }
            }
            Some(lcn) => {
                if lcn < 0 {
                    partial = true;
                    break;
                }

                let source_offset = match (lcn as u64).checked_mul(cluster_size) {
                    Some(v) => v,
                    None => return Err(33),
                };

                let mut copied = 0u64;
                while copied < to_process {
                    let left = to_process - copied;
                    let chunk_len = left.min(scratch.len() as u64) as usize;
                    let current_offset = match source_offset.checked_add(copied) {
                        Some(v) => v,
                        None => return Err(33),
                    };

                    match read_from_session(session, current_offset, &mut scratch[..chunk_len]) {
                        Ok(true) => {}
                        Ok(false) => {
                            partial = true;
                            break;
                        }
                        Err(_) => {
                            partial = true;
                            break;
                        }
                    }

                    if output_file.write_all(&scratch[..chunk_len]).is_err() {
                        return Err(44);
                    }

                    bytes_written = bytes_written.saturating_add(chunk_len as u64);
                    copied += chunk_len as u64;
                }

                if copied < to_process {
                    break;
                }
            }
        }

        remaining -= to_process;
    }

    if remaining > 0 {
        partial = true;
    }

    Ok((bytes_written, partial))
}

fn write_utf8(value: &str, buffer: &mut [u8]) {
    if buffer.is_empty() {
        return;
    }

    let bytes = value.as_bytes();
    let copy_len = bytes.len().min(buffer.len() - 1);
    buffer[..copy_len].copy_from_slice(&bytes[..copy_len]);
    buffer[copy_len] = 0;
}

fn read_from_session(
    session: &mut fr_winio::ReadSession,
    offset: u64,
    output: &mut [u8],
) -> Result<bool, fr_winio::WinIoError> {
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
    session: &mut fr_winio::ReadSession,
    offset: u64,
    output: &mut [u8],
    alignment: usize,
) -> Result<bool, fr_winio::WinIoError> {
    let alignment_u64 = alignment as u64;
    let aligned_offset = (offset / alignment_u64) * alignment_u64;
    let prefix_len = (offset - aligned_offset) as usize;
    let required_len = prefix_len
        .checked_add(output.len())
        .ok_or(fr_winio::WinIoError::InvalidReadOffset)?;
    let aligned_len = round_up(required_len, alignment)
        .ok_or(fr_winio::WinIoError::InvalidReadOffset)?;

    let mut scratch = vec![0u8; aligned_len];
    if !read_exact(session, aligned_offset, &mut scratch)? {
        return Ok(false);
    }

    output.copy_from_slice(&scratch[prefix_len..prefix_len + output.len()]);
    Ok(true)
}

fn read_exact(
    session: &mut fr_winio::ReadSession,
    offset: u64,
    output: &mut [u8],
) -> Result<bool, fr_winio::WinIoError> {
    let mut total = 0usize;
    while total < output.len() {
        let current_offset = offset
            .checked_add(total as u64)
            .ok_or(fr_winio::WinIoError::InvalidReadOffset)?;
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

fn write_diagnostics_flags(out_diagnostics_flags: *mut u32, diagnostics_flags: u32) {
    if out_diagnostics_flags.is_null() {
        return;
    }

    unsafe {
        *out_diagnostics_flags = diagnostics_flags;
    }
}

fn parse_source_kind(raw: i32) -> Result<RecoverySourceKind, ()> {
    match raw {
        0 => Ok(RecoverySourceKind::PhysicalDisk),
        1 => Ok(RecoverySourceKind::Volume),
        2 => Ok(RecoverySourceKind::ImageFile),
        3 => Ok(RecoverySourceKind::Volume),
        _ => Err(()),
    }
}

fn normalize_max_records(max_records: u32) -> usize {
    if max_records == 0 {
        4_096
    } else {
        max_records as usize
    }
}

fn usize_to_u32_saturating(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn map_quick_scan_error(err: QuickScanError) -> i32 {
    match err {
        QuickScanError::Io(err) => map_winio_error(err),
        QuickScanError::SourceTooSmall => 31,
        QuickScanError::BootSector(_) => 30,
        QuickScanError::InvalidMftOffset => 33,
        QuickScanError::MftOutOfBounds(_, _) => 31,
        QuickScanError::InvalidFileRecordSize(_) => 32,
    }
}

fn map_winio_error(err: fr_winio::WinIoError) -> i32 {
    match err {
        fr_winio::WinIoError::InvalidSourcePath => 10,
        fr_winio::WinIoError::InvalidReadOffset => 15,
        fr_winio::WinIoError::MisalignedRead { .. } => 16,
        fr_winio::WinIoError::UnsupportedPlatform => 11,
        fr_winio::WinIoError::AccessDenied(_) => 12,
        fr_winio::WinIoError::NotFound(_) => 13,
        fr_winio::WinIoError::OsError(_) => 14,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_check_returns_zero() {
        assert_eq!(fr_health_check(), 0);
    }

    #[test]
    fn sanitize_windows_path_component_normalizes_invalid_names() {
        assert_eq!(
            sanitize_windows_path_component("Zone.Identifier"),
            "Zone.Identifier"
        );
        assert_eq!(
            sanitize_windows_path_component("bad:name*with?chars"),
            "bad_name_with_chars"
        );
        assert_eq!(sanitize_windows_path_component("CON"), "_CON");
        assert_eq!(sanitize_windows_path_component("..."), "stream");
    }

    #[test]
    fn build_named_stream_output_path_deduplicates_case_insensitive_names() {
        let output_path = Path::new(r"C:\recovery\file.txt");
        let mut seen_names = HashMap::new();

        let first = build_named_stream_output_path(output_path, "Zone.Identifier", &mut seen_names);
        let second = build_named_stream_output_path(output_path, "zone.identifier", &mut seen_names);

        assert_eq!(
            first.file_name().and_then(|name| name.to_str()),
            Some("file.txt.ads-Zone.Identifier")
        );
        assert_eq!(
            second.file_name().and_then(|name| name.to_str()),
            Some("file.txt.ads-zone.identifier-2")
        );
    }
}
