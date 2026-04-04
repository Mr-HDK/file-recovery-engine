use fr_carving::{carve_bytes, CarvingFamily, CarvingPlan};
use fr_fat::{
    parse_boot_sector as parse_fat_boot_sector, scan_deleted_root_entries_with_boot,
    FatFilesystemKind,
};
use fr_mft::{parse_mft_record, AttributeForm, ATTRIBUTE_TYPE_DATA};
use fr_ntfs::parse_boot_sector as parse_ntfs_boot_sector;
use fr_refs::{
    parse_boot_sector as parse_refs_boot_sector, scan_deleted_candidates_with_boot,
};
use fr_scoring::score_candidate_with_reasons;
use fr_session::{
    enrich_summary_with_usn_journal_bytes, quick_scan_ntfs_from_read_session, QuickScanConfig,
    QuickScanError,
};
use fr_types::{ConfidenceTier, EvidenceSource, RecoveryCandidate, RecoverySourceKind};
use std::collections::HashMap;
use std::ffi::{c_char, CStr};
use std::fs::{self, File};
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
pub struct FrFatBootMetadata {
    pub filesystem_kind: u32,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub fat_count: u8,
    pub cluster_size_bytes: u32,
    pub total_sectors: u64,
    pub root_dir_first_cluster: u32,
    pub _reserved0: u32,
    pub fat_offset_bytes: u64,
    pub data_region_offset_bytes: u64,
    pub volume_serial: u32,
    pub _reserved1: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FrRefsBootMetadata {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub _reserved0: u8,
    pub cluster_size_bytes: u32,
    pub total_sectors: u64,
    pub volume_size_bytes: u64,
    pub volume_serial: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FrRefsDeletedCandidate {
    pub flags: u32,
    pub object_id: u64,
    pub size_bytes: u64,
    pub name: [u8; 128],
    pub reconstructed_path: [u8; 256],
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
    pub usn_enriched_records: u32,
    pub usn_ghost_records: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FrNtfsQuickScanCandidate {
    pub record_number: u32,
    pub flags: u32,
    pub parent_record_number: u64,
    pub confidence_tier: u32,
    pub _reserved0: u32,
    pub data_size_bytes: u64,
    pub allocated_size_bytes: u64,
    pub file_attributes: u32,
    pub _reserved1: u32,
    pub created_filetime_utc: u64,
    pub modified_filetime_utc: u64,
    pub mft_modified_filetime_utc: u64,
    pub accessed_filetime_utc: u64,
    pub name: [u8; 128],
    pub reconstructed_path: [u8; 256],
    pub confidence_reason: [u8; 256],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FrFatDeletedCandidate {
    pub flags: u32,
    pub start_cluster: u32,
    pub size_bytes: u64,
    pub name: [u8; 128],
    pub reconstructed_path: [u8; 256],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FrCarveCandidate {
    pub offset_bytes: u64,
    pub length_bytes: u64,
    pub flags: u32,
    pub confidence_tier: u32,
    pub format: [u8; 16],
    pub suggested_name: [u8; 128],
    pub confidence_reason: [u8; 256],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FrVssSnapshot {
    pub snapshot_id: [u8; 96],
    pub volume_name: [u8; 260],
    pub device_object: [u8; 260],
    pub install_time_utc: [u8; 64],
    pub snapshot_path: [u8; 260],
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
const CANDIDATE_FLAG_EVIDENCE_MFT: u32 = 0x1000;
const CANDIDATE_FLAG_EVIDENCE_DIRECTORY_INDEX: u32 = 0x2000;
const CANDIDATE_FLAG_EVIDENCE_USN: u32 = 0x4000;
const CANDIDATE_FLAG_EVIDENCE_VSS: u32 = 0x8000;
const CANDIDATE_FLAG_EVIDENCE_CARVE: u32 = 0x0001_0000;
const CANDIDATE_FLAG_HAS_FILE_METADATA: u32 = 0x0002_0000;
const CANDIDATE_FLAG_GHOST_RECORD: u32 = 0x0004_0000;
const CARVE_CANDIDATE_FLAG_PARTIAL: u32 = 0x0001;
const REFS_DELETED_CANDIDATE_FLAG_DELETED: u32 = 0x0001;
const FAT_DELETED_CANDIDATE_FLAG_DELETED: u32 = 0x0001;
const FAT_DELETED_CANDIDATE_FLAG_DIRECTORY: u32 = 0x0002;
const FAT_FILESYSTEM_KIND_FAT32: u32 = 1;
const FAT_FILESYSTEM_KIND_EXFAT: u32 = 2;
const FAT_EOC_MIN: u32 = 0x0FFF_FFF8;

const CARVE_FAMILY_IMAGES: u32 = 0x0001;
const CARVE_FAMILY_DOCUMENTS: u32 = 0x0002;
const CARVE_FAMILY_ARCHIVES: u32 = 0x0004;
const CARVE_FAMILY_OFFICE: u32 = 0x0008;
const CARVE_FAMILY_MEDIA: u32 = 0x0010;

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
const NTFS_MAX_REASONABLE_COMPRESSION_UNIT_EXPONENT: u16 = 8;
const NTFS_COMPRESSION_FORMAT_LZNT1: u16 = 0x0002;
const MAX_CONSECUTIVE_EMPTY_MFT_RECORDS: usize = 16_384;

#[cfg(windows)]
#[link(name = "ntdll")]
extern "system" {
    fn RtlGetCompressionWorkSpaceSize(
        compression_format_and_engine: u16,
        compress_buffer_work_space_size: *mut u32,
        compress_fragment_work_space_size: *mut u32,
    ) -> i32;
    fn RtlDecompressBufferEx(
        compression_format: u16,
        uncompressed_buffer: *mut u8,
        uncompressed_buffer_size: u32,
        compressed_buffer: *const u8,
        compressed_buffer_size: u32,
        final_uncompressed_size: *mut u32,
        work_space: *mut core::ffi::c_void,
    ) -> i32;
}

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

    let Ok(boot) = parse_ntfs_boot_sector(&sector) else {
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
pub extern "C" fn fr_probe_refs_boot_from_session(
    session_id: u64,
    out_boot: *mut FrRefsBootMetadata,
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

    let Ok(boot) = parse_refs_boot_sector(&sector) else {
        return 80;
    };

    unsafe {
        *out_boot = FrRefsBootMetadata {
            bytes_per_sector: boot.bytes_per_sector,
            sectors_per_cluster: boot.sectors_per_cluster,
            _reserved0: 0,
            cluster_size_bytes: boot.cluster_size_bytes(),
            total_sectors: boot.total_sectors,
            volume_size_bytes: boot.volume_size_bytes().unwrap_or(0),
            volume_serial: boot.volume_serial,
        };
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_get_refs_deleted_candidates_from_session(
    session_id: u64,
    max_entries: u32,
    out_candidates: *mut FrRefsDeletedCandidate,
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

    let image = match read_prefix_for_refs_scan(session) {
        Ok(bytes) => bytes,
        Err(err) => return map_winio_error(err),
    };

    if image.len() < 512 {
        return 31;
    }

    let Ok(boot) = parse_refs_boot_sector(&image[..512]) else {
        return 80;
    };

    let max_entries = if max_entries == 0 {
        512usize
    } else {
        max_entries as usize
    };
    let candidates = scan_deleted_candidates_with_boot(&image, &boot, max_entries);

    let total = usize_to_u32_saturating(candidates.len());
    let write_count = candidates.len().min(candidate_capacity as usize);
    for (index, candidate) in candidates.iter().take(write_count).enumerate() {
        unsafe {
            *out_candidates.add(index) = encode_refs_deleted_candidate(candidate);
        }
    }

    unsafe {
        *out_written = total;
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_probe_fat_boot_from_session(
    session_id: u64,
    out_boot: *mut FrFatBootMetadata,
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

    let Ok(boot) = parse_fat_boot_sector(&sector) else {
        return 70;
    };

    unsafe {
        *out_boot = FrFatBootMetadata {
            filesystem_kind: encode_fat_filesystem_kind(boot.filesystem),
            bytes_per_sector: boot.bytes_per_sector,
            sectors_per_cluster: boot.sectors_per_cluster,
            fat_count: boot.fat_count,
            cluster_size_bytes: boot.cluster_size_bytes(),
            total_sectors: boot.total_sectors,
            root_dir_first_cluster: boot.root_dir_first_cluster,
            _reserved0: 0,
            fat_offset_bytes: boot.fat_offset_bytes().unwrap_or(0),
            data_region_offset_bytes: boot.data_region_offset_bytes().unwrap_or(0),
            volume_serial: boot.volume_serial,
            _reserved1: 0,
        };
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_get_fat_deleted_candidates_from_session(
    session_id: u64,
    max_entries: u32,
    out_candidates: *mut FrFatDeletedCandidate,
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

    let image = match read_prefix_for_fat_scan(session) {
        Ok(bytes) => bytes,
        Err(err) => return map_winio_error(err),
    };

    if image.len() < 512 {
        return 31;
    }

    let boot = match parse_fat_boot_sector(&image[..512]) {
        Ok(boot) => boot,
        Err(_) => return 70,
    };

    let max_entries = if max_entries == 0 {
        512usize
    } else {
        max_entries as usize
    };
    let candidates = match scan_deleted_root_entries_with_boot(&image, &boot, max_entries, 256) {
        Ok(entries) => entries,
        Err(err) => return map_fat_scan_error(err),
    };

    let total = usize_to_u32_saturating(candidates.len());
    let write_count = candidates.len().min(candidate_capacity as usize);
    for (index, candidate) in candidates.iter().take(write_count).enumerate() {
        unsafe {
            *out_candidates.add(index) = encode_fat_deleted_candidate(candidate);
        }
    }

    unsafe {
        *out_written = total;
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
                    usn_enriched_records: usize_to_u32_saturating(summary.usn_enriched_records),
                    usn_ghost_records: usize_to_u32_saturating(summary.usn_ghost_records),
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

    populate_quick_scan_candidates_buffer(
        session_id,
        max_records,
        out_candidates,
        candidate_capacity,
        out_written,
        None,
    )
}

#[no_mangle]
pub extern "C" fn fr_get_ntfs_quick_scan_candidates_from_session_with_usn(
    session_id: u64,
    max_records: u32,
    out_candidates: *mut FrNtfsQuickScanCandidate,
    candidate_capacity: u32,
    out_written: *mut u32,
    usn_journal_bytes: *const u8,
    usn_journal_len: u32,
) -> i32 {
    if usn_journal_len > 0 && usn_journal_bytes.is_null() {
        return -3;
    }

    let usn_slice = if usn_journal_len == 0 {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(usn_journal_bytes, usn_journal_len as usize) })
    };

    populate_quick_scan_candidates_buffer(
        session_id,
        max_records,
        out_candidates,
        candidate_capacity,
        out_written,
        usn_slice,
    )
}

#[no_mangle]
pub extern "C" fn fr_get_carve_candidates_from_session(
    session_id: u64,
    family_flags: u32,
    max_scan_bytes: u64,
    out_candidates: *mut FrCarveCandidate,
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

    let bytes = match read_prefix_for_carving(session, max_scan_bytes) {
        Ok(data) => data,
        Err(err) => return map_winio_error(err),
    };

    if bytes.is_empty() {
        return 0;
    }

    let plan = build_carving_plan(family_flags, max_scan_bytes);
    let candidates = carve_bytes(&plan, &bytes);
    let written = candidates.len().min(candidate_capacity as usize);
    if written > 0 {
        let out_slice = unsafe { std::slice::from_raw_parts_mut(out_candidates, written) };
        for (index, candidate) in candidates.into_iter().take(written).enumerate() {
            out_slice[index] = encode_carve_candidate(candidate);
        }
    }

    unsafe {
        *out_written = written as u32;
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_list_vss_snapshots(
    out_snapshots: *mut FrVssSnapshot,
    snapshot_capacity: u32,
    out_written: *mut u32,
) -> i32 {
    if out_written.is_null() {
        return -1;
    }

    if snapshot_capacity > 0 && out_snapshots.is_null() {
        return -2;
    }

    unsafe {
        *out_written = 0;
    }

    let snapshots = match fr_vss::list_snapshots() {
        Ok(items) => items,
        Err(err) => return map_vss_error(err),
    };

    let total = usize_to_u32_saturating(snapshots.len());
    let write_count = snapshots.len().min(snapshot_capacity as usize);
    for (index, snapshot) in snapshots.iter().take(write_count).enumerate() {
        unsafe {
            *out_snapshots.add(index) = encode_vss_snapshot(snapshot);
        }
    }

    unsafe {
        *out_written = total;
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

    let Ok(boot) = parse_ntfs_boot_sector(&sector) else {
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
    let mut consecutive_empty_records = 0usize;

    for _ in 0..max_records {
        match read_from_session(session, record_offset, &mut record_buffer) {
            Ok(true) => {}
            Ok(false) => break,
            Err(err) => return map_winio_error(err),
        }

        if record_buffer.iter().all(|b| *b == 0) {
            consecutive_empty_records = consecutive_empty_records.saturating_add(1);
            if consecutive_empty_records >= MAX_CONSECUTIVE_EMPTY_MFT_RECORDS {
                break;
            }
            let Some(next_offset) = record_offset.checked_add(record_size as u64) else {
                return 33;
            };
            record_offset = next_offset;
            continue;
        }
        consecutive_empty_records = 0;

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
                drop(sidecar_file);
                let _ = fs::remove_file(&sidecar_path);
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
pub extern "C" fn fr_recover_fat_candidate_to_file(
    session_id: u64,
    start_cluster: u32,
    size_bytes: u64,
    output_path: *const c_char,
    out_bytes_written: *mut u64,
    out_partial: *mut i32,
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

    if start_cluster < 2 {
        return 75;
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

    let Ok(boot) = parse_fat_boot_sector(&sector) else {
        return 70;
    };

    let output_path = Path::new(output_path_str);
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() && fs::create_dir_all(parent).is_err() {
            return 44;
        }
    }

    let Ok(mut output_file) = File::create(output_path) else {
        return 44;
    };

    let (written, partial) = match recover_fat_candidate_data(
        session,
        &boot,
        start_cluster,
        size_bytes,
        &mut output_file,
    ) {
        Ok(result) => result,
        Err(status) => return status,
    };

    if !out_bytes_written.is_null() {
        unsafe {
            *out_bytes_written = written;
        }
    }

    if !out_partial.is_null() {
        unsafe {
            *out_partial = if partial { 1 } else { 0 };
        }
    }

    if written == 0 && size_bytes > 0 {
        return 76;
    }

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

fn populate_quick_scan_candidates_buffer(
    session_id: u64,
    max_records: u32,
    out_candidates: *mut FrNtfsQuickScanCandidate,
    candidate_capacity: u32,
    out_written: *mut u32,
    usn_journal_bytes: Option<&[u8]>,
) -> i32 {
    let Ok(mut map) = read_sessions().lock() else {
        return -200;
    };

    let Some(session) = map.get_mut(&session_id) else {
        return 20;
    };
    let config = QuickScanConfig {
        max_records: normalize_max_records(max_records),
    };
    let mut summary = match quick_scan_ntfs_from_read_session(session, config) {
        Ok(summary) => summary,
        Err(err) => return map_quick_scan_error(err),
    };

    if let Some(usn_bytes) = usn_journal_bytes {
        if let Err(err) = enrich_summary_with_usn_journal_bytes(&mut summary, usn_bytes) {
            return map_usn_parse_error(err);
        }
    }

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

#[derive(Debug, Clone)]
struct QuickScanCandidateInternal {
    record_number: u32,
    is_ghost_record: bool,
    in_use: bool,
    deleted: bool,
    is_directory: bool,
    has_non_resident_data: bool,
    has_named_data_streams: bool,
    has_compressed_data: bool,
    has_sparse_data: bool,
    has_encrypted_data: bool,
    evidence_sources: Vec<EvidenceSource>,
    parent_record_number: Option<u64>,
    name: Option<String>,
    reconstructed_path: Option<String>,
    data_size_bytes: Option<u64>,
    allocated_size_bytes: Option<u64>,
    file_attributes: Option<u32>,
    created_filetime_utc: Option<u64>,
    modified_filetime_utc: Option<u64>,
    mft_modified_filetime_utc: Option<u64>,
    accessed_filetime_utc: Option<u64>,
    confidence_tier: u32,
    confidence_reason: String,
}

fn build_internal_candidate_from_quick_scan(
    candidate: fr_session::QuickScanCandidate,
) -> QuickScanCandidateInternal {
    QuickScanCandidateInternal {
        record_number: candidate.record_number,
        is_ghost_record: candidate.is_ghost_record,
        in_use: candidate.in_use,
        deleted: candidate.deleted,
        is_directory: candidate.is_directory,
        has_non_resident_data: candidate.has_non_resident_data,
        has_named_data_streams: candidate.has_named_data_streams,
        has_compressed_data: candidate.has_compressed_data,
        has_sparse_data: candidate.has_sparse_data,
        has_encrypted_data: candidate.has_encrypted_data,
        evidence_sources: candidate.evidence_sources,
        parent_record_number: candidate.parent_record_number,
        name: candidate.name,
        reconstructed_path: candidate.reconstructed_path,
        data_size_bytes: candidate.data_size_bytes,
        allocated_size_bytes: candidate.allocated_size_bytes,
        file_attributes: candidate.file_attributes,
        created_filetime_utc: candidate.created_filetime_utc,
        modified_filetime_utc: candidate.modified_filetime_utc,
        mft_modified_filetime_utc: candidate.mft_modified_filetime_utc,
        accessed_filetime_utc: candidate.accessed_filetime_utc,
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
            size_bytes: candidate.data_size_bytes.unwrap_or(0),
            evidence: candidate.evidence_sources.clone(),
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
    if candidate.is_ghost_record {
        flags |= CANDIDATE_FLAG_GHOST_RECORD;
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
    for evidence_source in &candidate.evidence_sources {
        flags |= match evidence_source {
            EvidenceSource::Mft => CANDIDATE_FLAG_EVIDENCE_MFT,
            EvidenceSource::DirectoryIndex => CANDIDATE_FLAG_EVIDENCE_DIRECTORY_INDEX,
            EvidenceSource::Usn => CANDIDATE_FLAG_EVIDENCE_USN,
            EvidenceSource::Vss => CANDIDATE_FLAG_EVIDENCE_VSS,
            EvidenceSource::Carve => CANDIDATE_FLAG_EVIDENCE_CARVE,
        };
    }
    if candidate.data_size_bytes.is_some()
        || candidate.allocated_size_bytes.is_some()
        || candidate.file_attributes.is_some()
        || candidate.created_filetime_utc.is_some()
        || candidate.modified_filetime_utc.is_some()
        || candidate.mft_modified_filetime_utc.is_some()
        || candidate.accessed_filetime_utc.is_some()
    {
        flags |= CANDIDATE_FLAG_HAS_FILE_METADATA;
    }

    let mut out = FrNtfsQuickScanCandidate {
        record_number: candidate.record_number,
        flags,
        parent_record_number: candidate.parent_record_number.unwrap_or(0),
        confidence_tier: candidate.confidence_tier,
        _reserved0: 0,
        data_size_bytes: candidate.data_size_bytes.unwrap_or(0),
        allocated_size_bytes: candidate.allocated_size_bytes.unwrap_or(0),
        file_attributes: candidate.file_attributes.unwrap_or(0),
        _reserved1: 0,
        created_filetime_utc: candidate.created_filetime_utc.unwrap_or(0),
        modified_filetime_utc: candidate.modified_filetime_utc.unwrap_or(0),
        mft_modified_filetime_utc: candidate.mft_modified_filetime_utc.unwrap_or(0),
        accessed_filetime_utc: candidate.accessed_filetime_utc.unwrap_or(0),
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

fn encode_carve_candidate(candidate: fr_carving::CarvedCandidate) -> FrCarveCandidate {
    let mut out = FrCarveCandidate {
        offset_bytes: candidate.offset as u64,
        length_bytes: candidate.length as u64,
        flags: if candidate.partial {
            CARVE_CANDIDATE_FLAG_PARTIAL
        } else {
            0
        },
        confidence_tier: confidence_tier_code(candidate.confidence),
        format: [0u8; 16],
        suggested_name: [0u8; 128],
        confidence_reason: [0u8; 256],
    };

    let extension = candidate.format.default_extension();
    write_utf8(extension, &mut out.format);
    write_utf8(
        &format!("carve_{:016X}.{}", candidate.offset, extension),
        &mut out.suggested_name,
    );

    let reason = if candidate.diagnostics.is_empty() {
        String::from("Signature-based carving candidate.")
    } else {
        candidate.diagnostics.join("; ")
    };
    write_utf8(&reason, &mut out.confidence_reason);

    out
}

fn encode_vss_snapshot(snapshot: &fr_vss::VssSnapshot) -> FrVssSnapshot {
    let mut out = FrVssSnapshot {
        snapshot_id: [0u8; 96],
        volume_name: [0u8; 260],
        device_object: [0u8; 260],
        install_time_utc: [0u8; 64],
        snapshot_path: [0u8; 260],
    };

    write_utf8(&snapshot.snapshot_id, &mut out.snapshot_id);
    if let Some(volume_name) = snapshot.volume_name.as_deref() {
        write_utf8(volume_name, &mut out.volume_name);
    }
    write_utf8(&snapshot.device_object, &mut out.device_object);
    if let Some(install_time) = snapshot.install_time_utc.as_deref() {
        write_utf8(install_time, &mut out.install_time_utc);
    }
    write_utf8(&snapshot.snapshot_path, &mut out.snapshot_path);

    out
}

fn encode_fat_filesystem_kind(filesystem: FatFilesystemKind) -> u32 {
    match filesystem {
        FatFilesystemKind::Fat32 => FAT_FILESYSTEM_KIND_FAT32,
        FatFilesystemKind::ExFat => FAT_FILESYSTEM_KIND_EXFAT,
    }
}

fn encode_refs_deleted_candidate(candidate: &fr_refs::RefsDeletedCandidate) -> FrRefsDeletedCandidate {
    let mut out = FrRefsDeletedCandidate {
        flags: REFS_DELETED_CANDIDATE_FLAG_DELETED,
        object_id: candidate.object_id,
        size_bytes: candidate.size_bytes,
        name: [0u8; 128],
        reconstructed_path: [0u8; 256],
    };
    write_utf8(&candidate.name, &mut out.name);
    write_utf8(&candidate.path, &mut out.reconstructed_path);
    out
}

fn encode_fat_deleted_candidate(candidate: &fr_fat::FatDeletedEntry) -> FrFatDeletedCandidate {
    let mut flags = FAT_DELETED_CANDIDATE_FLAG_DELETED;
    if candidate.is_directory {
        flags |= FAT_DELETED_CANDIDATE_FLAG_DIRECTORY;
    }

    let mut out = FrFatDeletedCandidate {
        flags,
        start_cluster: candidate.start_cluster,
        size_bytes: candidate.size_bytes,
        name: [0u8; 128],
        reconstructed_path: [0u8; 256],
    };
    write_utf8(&candidate.name, &mut out.name);
    write_utf8(&candidate.path, &mut out.reconstructed_path);
    out
}

fn recover_fat_candidate_data(
    session: &mut fr_winio::ReadSession,
    boot: &fr_fat::FatBootSector,
    start_cluster: u32,
    size_bytes: u64,
    output_file: &mut File,
) -> Result<(u64, bool), i32> {
    if size_bytes == 0 {
        return Ok((0, false));
    }

    let cluster_size = boot.cluster_size_bytes() as usize;
    if cluster_size == 0 {
        return Err(72);
    }

    let mut current_cluster = start_cluster;
    let mut remaining = size_bytes;
    let mut bytes_written = 0u64;
    let mut partial = false;
    let mut cluster_buffer = vec![0u8; cluster_size];
    let mut seen_clusters = std::collections::HashSet::new();
    let mut used_contiguous_fallback = false;

    while remaining > 0 {
        if current_cluster < 2 {
            partial = true;
            break;
        }

        if !seen_clusters.insert(current_cluster) {
            partial = true;
            break;
        }

        let Some(cluster_offset) = boot.cluster_offset_bytes(current_cluster) else {
            partial = true;
            break;
        };

        let to_read = (remaining.min(cluster_size as u64)) as usize;
        match read_from_session(session, cluster_offset, &mut cluster_buffer[..to_read]) {
            Ok(true) => {}
            Ok(false) => {
                partial = true;
                break;
            }
            Err(err) => return Err(map_winio_error(err)),
        }

        if output_file.write_all(&cluster_buffer[..to_read]).is_err() {
            return Err(44);
        }

        bytes_written = bytes_written.saturating_add(to_read as u64);
        remaining = remaining.saturating_sub(to_read as u64);

        if remaining == 0 {
            break;
        }

        let next_cluster = read_fat_next_cluster_from_session(session, boot, current_cluster)?;
        if next_cluster >= 2 && next_cluster < FAT_EOC_MIN {
            current_cluster = next_cluster;
            continue;
        }

        if next_cluster == 0 || next_cluster >= FAT_EOC_MIN {
            let (fallback_written, fallback_remaining, fallback_used) =
                recover_fat_contiguous_fallback(
                    session,
                    boot,
                    current_cluster,
                    remaining,
                    &mut cluster_buffer,
                    output_file,
                    &mut seen_clusters,
                )?;
            bytes_written = bytes_written.saturating_add(fallback_written);
            remaining = fallback_remaining;
            used_contiguous_fallback |= fallback_used;
        }

        partial = true;
        break;
    }

    if used_contiguous_fallback {
        // Contiguous recovery after a broken chain is heuristic by definition.
        partial = true;
    }

    if remaining > 0 {
        partial = true;
    }

    Ok((bytes_written, partial))
}

fn recover_fat_contiguous_fallback(
    session: &mut fr_winio::ReadSession,
    boot: &fr_fat::FatBootSector,
    current_cluster: u32,
    mut remaining: u64,
    cluster_buffer: &mut [u8],
    output_file: &mut File,
    seen_clusters: &mut std::collections::HashSet<u32>,
) -> Result<(u64, u64, bool), i32> {
    if remaining == 0 {
        return Ok((0, 0, false));
    }

    let cluster_size = cluster_buffer.len();
    if cluster_size == 0 {
        return Err(72);
    }

    let mut contiguous_cluster = current_cluster;
    let mut bytes_written = 0u64;
    let mut used = false;

    while remaining > 0 {
        let Some(next_contiguous) = contiguous_cluster.checked_add(1) else {
            break;
        };
        contiguous_cluster = next_contiguous;

        if contiguous_cluster < 2 {
            break;
        }

        if !seen_clusters.insert(contiguous_cluster) {
            break;
        }

        let Some(cluster_offset) = boot.cluster_offset_bytes(contiguous_cluster) else {
            break;
        };

        // Deleted FAT/exFAT entries often clear chain values to zero. Continue only while
        // contiguous clusters still look free to reduce cross-file contamination.
        let fat_entry_value =
            read_fat_next_cluster_from_session(session, boot, contiguous_cluster)?;
        if fat_entry_value != 0 {
            break;
        }

        let to_read = (remaining.min(cluster_size as u64)) as usize;
        match read_from_session(session, cluster_offset, &mut cluster_buffer[..to_read]) {
            Ok(true) => {}
            Ok(false) => break,
            Err(err) => return Err(map_winio_error(err)),
        }

        if output_file.write_all(&cluster_buffer[..to_read]).is_err() {
            return Err(44);
        }

        bytes_written = bytes_written.saturating_add(to_read as u64);
        remaining = remaining.saturating_sub(to_read as u64);
        used = true;
    }

    Ok((bytes_written, remaining, used))
}

fn read_fat_next_cluster_from_session(
    session: &mut fr_winio::ReadSession,
    boot: &fr_fat::FatBootSector,
    cluster: u32,
) -> Result<u32, i32> {
    let Some(fat_offset_bytes) = boot.fat_offset_bytes() else {
        return Err(72);
    };
    let Some(entry_delta) = (cluster as u64).checked_mul(4) else {
        return Err(72);
    };
    let Some(entry_offset) = fat_offset_bytes.checked_add(entry_delta) else {
        return Err(72);
    };

    let mut entry = [0u8; 4];
    match read_from_session(session, entry_offset, &mut entry) {
        Ok(true) => {}
        Ok(false) => return Ok(0),
        Err(err) => return Err(map_winio_error(err)),
    }

    Ok(u32::from_le_bytes(entry) & 0x0FFF_FFFF)
}

fn recover_data_attribute(
    session: &mut fr_winio::ReadSession,
    boot: &fr_ntfs::NtfsBootSector,
    attribute: &fr_mft::AttributeRecord,
    output_file: &mut File,
    diagnostics_flags: &mut u32,
) -> Result<(u64, bool), i32> {
    let compressed = attribute.flags & NTFS_ATTRIBUTE_FLAG_COMPRESSED != 0;
    let encrypted = attribute.flags & NTFS_ATTRIBUTE_FLAG_ENCRYPTED != 0;
    if encrypted {
        *diagnostics_flags |= RECOVERY_DIAG_UNSUPPORTED_ENCRYPTED;
    }

    match &attribute.form {
        AttributeForm::Resident(resident) => {
            if compressed {
                *diagnostics_flags |= RECOVERY_DIAG_UNSUPPORTED_COMPRESSED;
                return Err(45);
            }

            if output_file.write_all(&resident.value).is_err() {
                return Err(44);
            }
            Ok((resident.value.len() as u64, encrypted))
        }
        AttributeForm::NonResident(non_resident) if compressed && !encrypted => {
            recover_non_resident_compressed_data(
                session,
                boot,
                non_resident,
                output_file,
                diagnostics_flags,
            )
        }
        AttributeForm::NonResident(non_resident) => {
            recover_non_resident_data(session, boot, non_resident, output_file, diagnostics_flags)
                .map(|(written, partial)| (written, partial || encrypted))
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
        let invalid =
            ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*');
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

#[derive(Debug, Clone, Copy)]
struct CompressedUnitRunSlice {
    lcn: Option<i64>,
    cluster_count: u64,
}

fn recover_non_resident_compressed_data(
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

    let Some(compression_unit_clusters) =
        compression_unit_cluster_count(non_resident.compression_unit_size)
    else {
        *diagnostics_flags |= RECOVERY_DIAG_UNSUPPORTED_COMPRESSED;
        return Err(45);
    };

    let Some(unit_size_bytes) = compression_unit_clusters.checked_mul(cluster_size) else {
        return Err(33);
    };

    let mut bytes_written = 0u64;
    let mut remaining = non_resident.data_size;
    let mut partial = false;
    let mut scratch = vec![0u8; 1024 * 1024];
    let zero_chunk = vec![0u8; 64 * 1024];

    let mut run_index = 0usize;
    let mut run_cluster_offset = 0u64;

    while remaining > 0 {
        let mut unit_slices: Vec<CompressedUnitRunSlice> = Vec::new();
        let mut consumed_clusters = 0u64;

        while consumed_clusters < compression_unit_clusters {
            let Some(run) = non_resident.data_runs.get(run_index) else {
                break;
            };

            if run_cluster_offset >= run.cluster_count {
                run_index = run_index.saturating_add(1);
                run_cluster_offset = 0;
                continue;
            }

            let available_in_run = run.cluster_count - run_cluster_offset;
            let needed = compression_unit_clusters - consumed_clusters;
            let take = available_in_run.min(needed);

            let adjusted_lcn = match run.lcn {
                Some(base_lcn) => {
                    let Ok(offset_i64) = i64::try_from(run_cluster_offset) else {
                        return Err(33);
                    };
                    match base_lcn.checked_add(offset_i64) {
                        Some(v) => Some(v),
                        None => return Err(33),
                    }
                }
                None => None,
            };

            unit_slices.push(CompressedUnitRunSlice {
                lcn: adjusted_lcn,
                cluster_count: take,
            });

            consumed_clusters = consumed_clusters.saturating_add(take);
            run_cluster_offset = run_cluster_offset.saturating_add(take);

            if run_cluster_offset >= run.cluster_count {
                run_index = run_index.saturating_add(1);
                run_cluster_offset = 0;
            }
        }

        if consumed_clusters == 0 {
            partial = true;
            break;
        }

        let target_bytes_for_unit = remaining.min(unit_size_bytes);
        let physical_clusters = unit_slices
            .iter()
            .filter_map(|slice| slice.lcn.map(|_| slice.cluster_count))
            .fold(0u64, |acc, count| acc.saturating_add(count));
        let sparse_clusters = consumed_clusters.saturating_sub(physical_clusters);

        if physical_clusters == 0 {
            *diagnostics_flags |= RECOVERY_DIAG_SPARSE_ZERO_FILLED;
            let mut left = target_bytes_for_unit;
            while left > 0 {
                let chunk = left.min(zero_chunk.len() as u64) as usize;
                if output_file.write_all(&zero_chunk[..chunk]).is_err() {
                    return Err(44);
                }
                bytes_written = bytes_written.saturating_add(chunk as u64);
                left -= chunk as u64;
            }
            remaining -= target_bytes_for_unit;
            continue;
        }

        let raw_unit_possible =
            sparse_clusters == 0 && physical_clusters == compression_unit_clusters;

        let mut compressed_source = Vec::new();
        let Some(raw_source_capacity) = physical_clusters.checked_mul(cluster_size) else {
            return Err(33);
        };
        let Ok(raw_source_capacity_usize) = usize::try_from(raw_source_capacity) else {
            return Err(33);
        };
        compressed_source.reserve(raw_source_capacity_usize);

        let mut unit_read_failed = false;
        for slice in unit_slices {
            let Some(lcn) = slice.lcn else {
                continue;
            };
            if lcn < 0 {
                unit_read_failed = true;
                partial = true;
                break;
            }

            let Some(source_offset) = (lcn as u64).checked_mul(cluster_size) else {
                return Err(33);
            };
            let Some(slice_bytes) = slice.cluster_count.checked_mul(cluster_size) else {
                return Err(33);
            };

            let mut copied = 0u64;
            while copied < slice_bytes {
                let left = slice_bytes - copied;
                let chunk_len = left.min(scratch.len() as u64) as usize;
                let Some(current_offset) = source_offset.checked_add(copied) else {
                    return Err(33);
                };

                match read_from_session(session, current_offset, &mut scratch[..chunk_len]) {
                    Ok(true) => {}
                    Ok(false) => {
                        partial = true;
                        unit_read_failed = true;
                        break;
                    }
                    Err(_) => {
                        partial = true;
                        unit_read_failed = true;
                        break;
                    }
                }

                compressed_source.extend_from_slice(&scratch[..chunk_len]);
                copied += chunk_len as u64;
            }

            if unit_read_failed {
                break;
            }
        }

        if unit_read_failed {
            break;
        }

        if raw_unit_possible {
            let Ok(target_len) = usize::try_from(target_bytes_for_unit) else {
                return Err(33);
            };
            if compressed_source.len() < target_len {
                partial = true;
                break;
            }
            if output_file
                .write_all(&compressed_source[..target_len])
                .is_err()
            {
                return Err(44);
            }
            bytes_written = bytes_written.saturating_add(target_bytes_for_unit);
            remaining -= target_bytes_for_unit;
            continue;
        }

        let decompression_input = trim_lznt1_stream_padding(&compressed_source);
        if decompression_input.is_empty() {
            *diagnostics_flags |= RECOVERY_DIAG_UNSUPPORTED_COMPRESSED;
            partial = true;
            break;
        }

        let Ok(unit_uncompressed_len) = usize::try_from(unit_size_bytes) else {
            return Err(33);
        };
        let Some(mut decompressed) =
            try_decompress_lznt1_unit(decompression_input, unit_uncompressed_len)
        else {
            *diagnostics_flags |= RECOVERY_DIAG_UNSUPPORTED_COMPRESSED;
            partial = true;
            break;
        };

        let Ok(target_len) = usize::try_from(target_bytes_for_unit) else {
            return Err(33);
        };
        if decompressed.len() < target_len {
            partial = true;
            *diagnostics_flags |= RECOVERY_DIAG_UNSUPPORTED_COMPRESSED;
        }

        if decompressed.len() > target_len {
            decompressed.truncate(target_len);
        }

        if output_file.write_all(&decompressed).is_err() {
            return Err(44);
        }

        bytes_written = bytes_written.saturating_add(decompressed.len() as u64);
        remaining = remaining.saturating_sub(decompressed.len() as u64);

        if decompressed.len() < target_len {
            break;
        }
    }

    if remaining > 0 {
        partial = true;
    }

    Ok((bytes_written, partial))
}

fn compression_unit_cluster_count(compression_unit_size: u16) -> Option<u64> {
    if compression_unit_size > NTFS_MAX_REASONABLE_COMPRESSION_UNIT_EXPONENT {
        return None;
    }

    1u64.checked_shl(compression_unit_size as u32)
}

fn trim_lznt1_stream_padding(bytes: &[u8]) -> &[u8] {
    let mut cursor = 0usize;
    while cursor + 2 <= bytes.len() {
        let header = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]);
        if header == 0 {
            break;
        }

        let signature = header & 0x7000;
        if signature != 0x3000 {
            break;
        }

        let chunk_len = ((header & 0x0FFF) as usize).saturating_add(1);
        let Some(next_cursor) = cursor.checked_add(2).and_then(|v| v.checked_add(chunk_len)) else {
            break;
        };
        if next_cursor > bytes.len() {
            break;
        }

        cursor = next_cursor;
    }

    &bytes[..cursor]
}

fn try_decompress_lznt1_unit(compressed: &[u8], expected_output_len: usize) -> Option<Vec<u8>> {
    if expected_output_len == 0 {
        return Some(Vec::new());
    }

    #[cfg(windows)]
    {
        let Ok(expected_output_len_u32) = u32::try_from(expected_output_len) else {
            return None;
        };
        let Ok(compressed_len_u32) = u32::try_from(compressed.len()) else {
            return None;
        };
        if compressed_len_u32 == 0 {
            return None;
        }

        let mut workspace_size = 0u32;
        let mut fragment_workspace_size = 0u32;
        let workspace_status = unsafe {
            RtlGetCompressionWorkSpaceSize(
                NTFS_COMPRESSION_FORMAT_LZNT1,
                &mut workspace_size,
                &mut fragment_workspace_size,
            )
        };
        if workspace_status < 0 {
            return None;
        }

        let mut workspace = vec![0u8; workspace_size as usize];
        let mut output = vec![0u8; expected_output_len];
        let mut final_uncompressed_size = 0u32;

        let status = unsafe {
            RtlDecompressBufferEx(
                NTFS_COMPRESSION_FORMAT_LZNT1,
                output.as_mut_ptr(),
                expected_output_len_u32,
                compressed.as_ptr(),
                compressed_len_u32,
                &mut final_uncompressed_size,
                workspace.as_mut_ptr() as *mut core::ffi::c_void,
            )
        };
        if status < 0 {
            return None;
        }

        let final_size = final_uncompressed_size as usize;
        if final_size > output.len() {
            return None;
        }
        output.truncate(final_size);
        return Some(output);
    }

    #[cfg(not(windows))]
    {
        let _ = compressed;
        None
    }
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
    let aligned_len =
        round_up(required_len, alignment).ok_or(fr_winio::WinIoError::InvalidReadOffset)?;

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

fn build_carving_plan(family_flags: u32, max_scan_bytes: u64) -> CarvingPlan {
    let max_scan_bytes = normalize_max_scan_bytes(max_scan_bytes) as usize;
    if family_flags == 0 {
        return CarvingPlan::default().with_max_scan_bytes(max_scan_bytes);
    }

    let mut plan = CarvingPlan::default()
        .without_family(CarvingFamily::Images)
        .without_family(CarvingFamily::Documents);
    if family_flags & CARVE_FAMILY_IMAGES != 0 {
        plan = plan.with_family(CarvingFamily::Images);
    }
    if family_flags & CARVE_FAMILY_DOCUMENTS != 0 {
        plan = plan.with_family(CarvingFamily::Documents);
    }
    if family_flags & CARVE_FAMILY_ARCHIVES != 0 {
        plan = plan.with_family(CarvingFamily::Archives);
    }
    if family_flags & CARVE_FAMILY_OFFICE != 0 {
        plan = plan.with_family(CarvingFamily::Office);
    }
    if family_flags & CARVE_FAMILY_MEDIA != 0 {
        plan = plan.with_family(CarvingFamily::Media);
    }

    plan.with_max_scan_bytes(max_scan_bytes)
}

fn read_prefix_for_carving(
    session: &mut fr_winio::ReadSession,
    max_scan_bytes: u64,
) -> Result<Vec<u8>, fr_winio::WinIoError> {
    const UNKNOWN_SIZE_FALLBACK_SCAN_BYTES: u64 = 8 * 1024 * 1024;

    let normalized_max = normalize_max_scan_bytes(max_scan_bytes);
    let source_len = session
        .size_bytes()
        .unwrap_or(normalized_max.min(UNKNOWN_SIZE_FALLBACK_SCAN_BYTES));
    let scan_len = source_len.min(normalized_max) as usize;
    if scan_len == 0 {
        return Ok(Vec::new());
    }

    let mut bytes = vec![0u8; scan_len];
    if read_from_session(session, 0, &mut bytes)? {
        Ok(bytes)
    } else {
        Ok(Vec::new())
    }
}

fn read_prefix_for_refs_scan(
    session: &mut fr_winio::ReadSession,
) -> Result<Vec<u8>, fr_winio::WinIoError> {
    const DEFAULT_SCAN_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_SCAN_BYTES: u64 = 256 * 1024 * 1024;

    let source_len = session.size_bytes().unwrap_or(DEFAULT_SCAN_BYTES);
    let scan_len = source_len.min(MAX_SCAN_BYTES) as usize;
    if scan_len == 0 {
        return Ok(Vec::new());
    }

    let mut bytes = vec![0u8; scan_len];
    if read_from_session(session, 0, &mut bytes)? {
        Ok(bytes)
    } else {
        Ok(Vec::new())
    }
}

fn read_prefix_for_fat_scan(
    session: &mut fr_winio::ReadSession,
) -> Result<Vec<u8>, fr_winio::WinIoError> {
    const DEFAULT_SCAN_BYTES: u64 = 32 * 1024 * 1024;
    const MAX_SCAN_BYTES: u64 = 256 * 1024 * 1024;

    let source_len = session.size_bytes().unwrap_or(DEFAULT_SCAN_BYTES);
    let scan_len = source_len.min(MAX_SCAN_BYTES) as usize;
    if scan_len == 0 {
        return Ok(Vec::new());
    }

    let mut bytes = vec![0u8; scan_len];
    if read_from_session(session, 0, &mut bytes)? {
        Ok(bytes)
    } else {
        Ok(Vec::new())
    }
}

fn normalize_max_scan_bytes(max_scan_bytes: u64) -> u64 {
    const DEFAULT_MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_ALLOWED_SCAN_BYTES: u64 = 256 * 1024 * 1024;

    if max_scan_bytes == 0 {
        DEFAULT_MAX_SCAN_BYTES
    } else {
        max_scan_bytes.min(MAX_ALLOWED_SCAN_BYTES)
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

fn map_fat_scan_error(err: fr_fat::ScanError) -> i32 {
    match err {
        fr_fat::ScanError::Boot(_) => 70,
        fr_fat::ScanError::InvalidCluster(_) => 71,
        fr_fat::ScanError::ArithmeticOverflow(_) => 72,
        fr_fat::ScanError::OutOfBounds { .. } => 31,
        fr_fat::ScanError::ClusterLoop(_) => 73,
        fr_fat::ScanError::DirectoryEntryTruncated => 74,
    }
}

fn map_usn_parse_error(err: fr_usn::UsnParseError) -> i32 {
    match err {
        fr_usn::UsnParseError::TruncatedRecordHeader { .. }
        | fr_usn::UsnParseError::TruncatedRecordBody { .. } => 51,
        fr_usn::UsnParseError::InvalidRecordLength { .. }
        | fr_usn::UsnParseError::InvalidFileNameRange { .. }
        | fr_usn::UsnParseError::InvalidFileNameEncoding { .. } => 52,
        fr_usn::UsnParseError::UnsupportedVersion { .. } => 53,
    }
}

fn map_vss_error(err: fr_vss::VssError) -> i32 {
    match err {
        fr_vss::VssError::UnsupportedPlatform => 60,
        fr_vss::VssError::PowerShellUnavailable => 61,
        fr_vss::VssError::QueryFailed { .. } => 62,
        fr_vss::VssError::Parse(_) => 63,
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
    use std::ffi::CString;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn health_check_returns_zero() {
        assert_eq!(fr_health_check(), 0);
    }

    #[test]
    fn ffi_probe_fat_boot_from_session_parses_fat32_image() {
        let image = build_test_fat32_image_with_deleted_entry();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-fat-boot-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("fat32.img");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();
        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                image_path_cstr.as_ptr(),
                2,
                &mut session_id,
                &mut size_bytes
            ),
            0
        );

        let mut boot = FrFatBootMetadata::default();
        let status = fr_probe_fat_boot_from_session(session_id, &mut boot);
        assert_eq!(status, 0);
        assert_eq!(boot.filesystem_kind, FAT_FILESYSTEM_KIND_FAT32);
        assert_eq!(boot.bytes_per_sector, 512);
        assert_eq!(boot.sectors_per_cluster, 1);
        assert_eq!(boot.root_dir_first_cluster, 2);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_probe_refs_boot_from_session_parses_refs_image() {
        let image = build_test_refs_image();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-refs-boot-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("refs.img");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();
        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                image_path_cstr.as_ptr(),
                2,
                &mut session_id,
                &mut size_bytes
            ),
            0
        );

        let mut boot = FrRefsBootMetadata::default();
        assert_eq!(fr_probe_refs_boot_from_session(session_id, &mut boot), 0);
        assert_eq!(boot.bytes_per_sector, 4096);
        assert_eq!(boot.sectors_per_cluster, 1);
        assert_eq!(boot.cluster_size_bytes, 4096);
        assert_eq!(boot.total_sectors, 2_000_000);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_get_refs_deleted_candidates_returns_success_with_no_candidates() {
        let image = build_test_refs_image();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-refs-candidates-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("refs.img");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();
        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                image_path_cstr.as_ptr(),
                2,
                &mut session_id,
                &mut size_bytes
            ),
            0
        );

        let mut candidates = vec![empty_refs_deleted_candidate(); 4];
        let mut written = 99u32;
        let status = fr_get_refs_deleted_candidates_from_session(
            session_id,
            64,
            candidates.as_mut_ptr(),
            candidates.len() as u32,
            &mut written,
        );
        assert_eq!(status, 0);
        assert_eq!(written, 0);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_get_refs_deleted_candidates_extracts_usn_deleted_candidate() {
        let image = build_test_refs_image_with_deleted_usn_record();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-refs-candidates-extract-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("refs-usn.img");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();
        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                image_path_cstr.as_ptr(),
                2,
                &mut session_id,
                &mut size_bytes
            ),
            0
        );

        let mut candidates = vec![empty_refs_deleted_candidate(); 8];
        let mut written = 0u32;
        let status = fr_get_refs_deleted_candidates_from_session(
            session_id,
            128,
            candidates.as_mut_ptr(),
            candidates.len() as u32,
            &mut written,
        );
        assert_eq!(status, 0);
        assert!(written >= 1);
        let first = candidates[0];
        assert_eq!(first.flags & REFS_DELETED_CANDIDATE_FLAG_DELETED, REFS_DELETED_CANDIDATE_FLAG_DELETED);
        assert_eq!(first.object_id, 42);
        assert_eq!(c_string_bytes_to_string(&first.name), "refs-deleted.txt");

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_get_fat_deleted_candidates_from_session_returns_deleted_entry() {
        let image = build_test_fat32_image_with_deleted_entry();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-fat-scan-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("fat32.img");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();
        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                image_path_cstr.as_ptr(),
                2,
                &mut session_id,
                &mut size_bytes
            ),
            0
        );

        let mut candidates = vec![empty_fat_deleted_candidate(); 16];
        let mut written = 0u32;
        let status = fr_get_fat_deleted_candidates_from_session(
            session_id,
            32,
            candidates.as_mut_ptr(),
            candidates.len() as u32,
            &mut written,
        );
        assert_eq!(status, 0);
        assert!(written >= 1);
        assert_eq!(
            c_string_bytes_to_string(&candidates[0].name),
            "_EST.TXT".to_string()
        );
        assert_eq!(
            c_string_bytes_to_string(&candidates[0].reconstructed_path),
            r".\_EST.TXT".to_string()
        );
        assert_eq!(candidates[0].start_cluster, 5);
        assert_eq!(candidates[0].size_bytes, 1234);
        assert_ne!(candidates[0].flags & FAT_DELETED_CANDIDATE_FLAG_DELETED, 0);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_fat_candidate_to_file_writes_expected_bytes() {
        let payload = b"fat-recovery-ok";
        let image = build_test_fat32_image_with_recoverable_file(payload);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-fat-recover-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("fat32.img");
        let output_path = temp_dir.join("recovered.bin");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();
        let output_path_cstr = CString::new(output_path.to_string_lossy().as_bytes()).unwrap();
        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                image_path_cstr.as_ptr(),
                2,
                &mut session_id,
                &mut size_bytes
            ),
            0
        );

        let mut bytes_written = 0u64;
        let mut partial = -1i32;
        let status = fr_recover_fat_candidate_to_file(
            session_id,
            5,
            payload.len() as u64,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );

        assert_eq!(status, 0);
        assert_eq!(bytes_written, payload.len() as u64);
        assert_eq!(partial, 0);
        assert_eq!(fs::read(&output_path).unwrap(), payload);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&output_path).unwrap();
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_fat_candidate_to_file_uses_contiguous_fallback_after_chain_gap() {
        let payload = b"fat-partial";
        let image = build_test_fat32_image_with_recoverable_file(payload);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-fat-recover-partial-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("fat32.img");
        let output_path = temp_dir.join("recovered-partial.bin");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();
        let output_path_cstr = CString::new(output_path.to_string_lossy().as_bytes()).unwrap();
        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                image_path_cstr.as_ptr(),
                2,
                &mut session_id,
                &mut size_bytes
            ),
            0
        );

        let mut bytes_written = 0u64;
        let mut partial = 0i32;
        let status = fr_recover_fat_candidate_to_file(
            session_id,
            5,
            800,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );

        assert_eq!(status, 0);
        assert_eq!(bytes_written, 800);
        assert_eq!(partial, 1);
        let recovered = fs::read(&output_path).unwrap();
        assert_eq!(recovered.len(), 800);
        assert_eq!(&recovered[..payload.len()], payload);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&output_path).unwrap();
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_carve_candidates_from_session_returns_image_candidate() {
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-carve-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("carve.img");
        let bytes = b"prefix\xFF\xD8\xFF\xE0test-jpeg\xFF\xD9suffix";
        fs::write(&image_path, bytes).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();
        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                image_path_cstr.as_ptr(),
                2,
                &mut session_id,
                &mut size_bytes
            ),
            0
        );

        let mut out_written = 0u32;
        let mut carved = vec![empty_carve_candidate(); 4];
        let status = fr_get_carve_candidates_from_session(
            session_id,
            CARVE_FAMILY_IMAGES,
            bytes.len() as u64,
            carved.as_mut_ptr(),
            carved.len() as u32,
            &mut out_written,
        );
        assert_eq!(status, 0);
        assert!(out_written >= 1);

        let first = carved[0];
        assert!(first.length_bytes > 0);
        assert_eq!(c_string_bytes_to_string(&first.format), "jpg");

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn encode_vss_snapshot_maps_all_fields() {
        let snapshot = fr_vss::VssSnapshot {
            snapshot_id: "{11111111-1111-1111-1111-111111111111}".to_string(),
            volume_name: Some(r"\\?\Volume{abc}\".to_string()),
            device_object: r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7".to_string(),
            install_time_utc: Some("2026-03-28T10:10:10+00:00".to_string()),
            snapshot_path: r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7\".to_string(),
        };

        let encoded = encode_vss_snapshot(&snapshot);
        assert_eq!(
            c_string_bytes_to_string(&encoded.snapshot_id),
            snapshot.snapshot_id
        );
        assert_eq!(
            c_string_bytes_to_string(&encoded.volume_name),
            snapshot.volume_name.as_deref().unwrap()
        );
        assert_eq!(
            c_string_bytes_to_string(&encoded.device_object),
            snapshot.device_object
        );
        assert_eq!(
            c_string_bytes_to_string(&encoded.install_time_utc),
            snapshot.install_time_utc.as_deref().unwrap()
        );
        assert_eq!(
            c_string_bytes_to_string(&encoded.snapshot_path),
            snapshot.snapshot_path
        );
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
        let second =
            build_named_stream_output_path(output_path, "zone.identifier", &mut seen_names);

        assert_eq!(
            first.file_name().and_then(|name| name.to_str()),
            Some("file.txt.ads-Zone.Identifier")
        );
        assert_eq!(
            second.file_name().and_then(|name| name.to_str()),
            Some("file.txt.ads-zone.identifier-2")
        );
    }

    #[test]
    fn ffi_quick_scan_candidates_include_confidence_and_flags() {
        let image = build_test_ntfs_image_with_named_records();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("sample.img");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();

        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        let open_status = fr_open_source_session_readonly(
            image_path_cstr.as_ptr(),
            2,
            &mut session_id,
            &mut size_bytes,
        );
        assert_eq!(open_status, 0);
        assert!(session_id > 0);
        assert!(size_bytes >= image.len() as u64);

        let mut out_written = 0u32;
        let mut candidates = vec![
            FrNtfsQuickScanCandidate {
                record_number: 0,
                flags: 0,
                parent_record_number: 0,
                confidence_tier: 0,
                _reserved0: 0,
                data_size_bytes: 0,
                allocated_size_bytes: 0,
                file_attributes: 0,
                _reserved1: 0,
                created_filetime_utc: 0,
                modified_filetime_utc: 0,
                mft_modified_filetime_utc: 0,
                accessed_filetime_utc: 0,
                name: [0u8; 128],
                reconstructed_path: [0u8; 256],
                confidence_reason: [0u8; 256],
            };
            8
        ];

        let scan_status = fr_get_ntfs_quick_scan_candidates_from_session(
            session_id,
            16,
            candidates.as_mut_ptr(),
            candidates.len() as u32,
            &mut out_written,
        );
        assert_eq!(scan_status, 0);
        assert_eq!(out_written, 2);

        let result_slice = &candidates[..out_written as usize];
        let deleted = result_slice
            .iter()
            .find(|candidate| candidate.record_number == 6)
            .expect("deleted record candidate must be present");
        let parent = result_slice
            .iter()
            .find(|candidate| candidate.record_number == 5)
            .expect("parent record candidate must be present");

        assert_ne!(deleted.flags & CANDIDATE_FLAG_DELETED, 0);
        assert_eq!(deleted.flags & CANDIDATE_FLAG_DIRECTORY, 0);
        assert_ne!(deleted.flags & CANDIDATE_FLAG_HAS_NAME, 0);
        assert_ne!(deleted.flags & CANDIDATE_FLAG_HAS_PATH, 0);
        assert_ne!(deleted.flags & CANDIDATE_FLAG_EVIDENCE_MFT, 0);
        assert_ne!(deleted.flags & CANDIDATE_FLAG_HAS_FILE_METADATA, 0);
        assert_eq!(deleted.data_size_bytes, 1234);
        assert_eq!(deleted.allocated_size_bytes, 4096);
        assert_eq!(deleted.file_attributes, 0x0000_0020);
        assert_eq!(deleted.created_filetime_utc, 132_537_600_000_000_000);
        assert_eq!(deleted.modified_filetime_utc, 132_537_600_100_000_000);
        assert_eq!(
            deleted.confidence_tier,
            confidence_tier_code(ConfidenceTier::VeryHigh)
        );
        let deleted_reason = c_string_bytes_to_string(&deleted.confidence_reason);
        assert!(deleted_reason.starts_with("Score "));
        assert!(deleted_reason.contains("MFT metadata present"));

        assert_eq!(parent.flags & CANDIDATE_FLAG_DELETED, 0);
        assert_ne!(parent.flags & CANDIDATE_FLAG_DIRECTORY, 0);
        assert_ne!(parent.flags & CANDIDATE_FLAG_EVIDENCE_MFT, 0);
        assert_eq!(
            parent.confidence_tier,
            confidence_tier_code(ConfidenceTier::VeryHigh)
        );

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_quick_scan_candidates_with_usn_adds_ghost_and_rename_evidence() {
        let image = build_test_ntfs_image_with_named_records();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-usn-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("sample.img");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();

        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        let open_status = fr_open_source_session_readonly(
            image_path_cstr.as_ptr(),
            2,
            &mut session_id,
            &mut size_bytes,
        );
        assert_eq!(open_status, 0);
        assert!(session_id > 0);
        assert!(size_bytes >= image.len() as u64);

        let mut usn_bytes = Vec::new();
        usn_bytes.extend_from_slice(&build_usn_v2_record(
            "report-renamed.txt",
            fr_usn::USN_REASON_RENAME_NEW_NAME,
            6,
            5,
        ));
        usn_bytes.extend_from_slice(&build_usn_v2_record(
            "ghost.txt",
            fr_usn::USN_REASON_FILE_DELETE,
            77,
            5,
        ));

        let mut out_written = 0u32;
        let mut candidates = vec![empty_candidate(); 16];

        let scan_status = fr_get_ntfs_quick_scan_candidates_from_session_with_usn(
            session_id,
            64,
            candidates.as_mut_ptr(),
            candidates.len() as u32,
            &mut out_written,
            usn_bytes.as_ptr(),
            usn_bytes.len() as u32,
        );
        assert_eq!(scan_status, 0);
        assert_eq!(out_written, 3);

        let result_slice = &candidates[..out_written as usize];
        let renamed = result_slice
            .iter()
            .find(|candidate| candidate.record_number == 6)
            .expect("renamed candidate should exist");
        let renamed_name = c_string_bytes_to_string(&renamed.name);
        assert_eq!(renamed_name, "report-renamed.txt");
        assert_ne!(renamed.flags & CANDIDATE_FLAG_EVIDENCE_USN, 0);

        let ghost = result_slice
            .iter()
            .find(|candidate| candidate.record_number == 77)
            .expect("ghost candidate should exist");
        assert_ne!(ghost.flags & CANDIDATE_FLAG_GHOST_RECORD, 0);
        assert_ne!(ghost.flags & CANDIDATE_FLAG_EVIDENCE_USN, 0);
        assert_eq!(ghost.flags & CANDIDATE_FLAG_EVIDENCE_MFT, 0);
        assert_eq!(ghost.flags & CANDIDATE_FLAG_DELETED, CANDIDATE_FLAG_DELETED);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_exports_default_and_named_streams() {
        let record_number = 42u32;
        let default_bytes = b"default-stream".to_vec();
        let named_bytes = b"named-stream".to_vec();

        let record = build_record_with_data_attributes(
            record_number,
            vec![
                build_resident_data_attribute(1, None, 0, &default_bytes),
                build_resident_data_attribute(2, Some("Zone.Identifier"), 0, &named_bytes),
            ],
        );
        let image = build_test_ntfs_image_with_record(&record);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-recover-default-named-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("sample.img");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();
        let output_path = temp_dir.join("recovered.bin");
        let output_path_cstr = CString::new(output_path.to_string_lossy().as_bytes()).unwrap();

        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                image_path_cstr.as_ptr(),
                2,
                &mut session_id,
                &mut size_bytes
            ),
            0
        );

        let mut written = 0u64;
        let mut partial = 0i32;
        let mut diagnostics = 0u32;
        let status = fr_recover_ntfs_candidate_to_file_ex(
            session_id,
            record_number,
            output_path_cstr.as_ptr(),
            &mut written,
            &mut partial,
            &mut diagnostics,
        );

        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(written, (default_bytes.len() + named_bytes.len()) as u64);
        assert_ne!(diagnostics & RECOVERY_DIAG_HAS_NAMED_DATA_STREAM, 0);
        assert_ne!(diagnostics & RECOVERY_DIAG_EXPORTED_NAMED_DATA_STREAMS, 0);
        assert_eq!(diagnostics & RECOVERY_DIAG_NO_DEFAULT_DATA_STREAM, 0);
        assert_eq!(fs::read(&output_path).unwrap(), default_bytes);

        let sidecar_path = output_path.with_file_name("recovered.bin.ads-Zone.Identifier");
        assert_eq!(fs::read(&sidecar_path).unwrap(), named_bytes);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&sidecar_path).unwrap();
        fs::remove_file(&output_path).unwrap();
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_named_only_sets_partial_and_no_default_flag() {
        let record_number = 77u32;
        let named_bytes = b"only-named".to_vec();

        let record = build_record_with_data_attributes(
            record_number,
            vec![build_resident_data_attribute(
                1,
                Some("Zone.Identifier"),
                0,
                &named_bytes,
            )],
        );
        let image = build_test_ntfs_image_with_record(&record);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-recover-named-only-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("sample.img");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();
        let output_path = temp_dir.join("recovered.bin");
        let output_path_cstr = CString::new(output_path.to_string_lossy().as_bytes()).unwrap();

        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                image_path_cstr.as_ptr(),
                2,
                &mut session_id,
                &mut size_bytes
            ),
            0
        );

        let mut written = 0u64;
        let mut partial = 0i32;
        let mut diagnostics = 0u32;
        let status = fr_recover_ntfs_candidate_to_file_ex(
            session_id,
            record_number,
            output_path_cstr.as_ptr(),
            &mut written,
            &mut partial,
            &mut diagnostics,
        );

        assert_eq!(status, 0);
        assert_eq!(partial, 1);
        assert_eq!(written, named_bytes.len() as u64);
        assert_ne!(diagnostics & RECOVERY_DIAG_NO_DEFAULT_DATA_STREAM, 0);
        assert_ne!(diagnostics & RECOVERY_DIAG_HAS_NAMED_DATA_STREAM, 0);
        assert_ne!(diagnostics & RECOVERY_DIAG_EXPORTED_NAMED_DATA_STREAMS, 0);

        let sidecar_path = output_path.with_file_name("recovered.bin.ads-Zone.Identifier");
        assert_eq!(fs::read(&sidecar_path).unwrap(), named_bytes);
        assert!(!output_path.exists());

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&sidecar_path).unwrap();
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_skips_compressed_named_stream_and_marks_partial() {
        let record_number = 88u32;
        let default_bytes = b"default-stream".to_vec();
        let named_bytes = b"named-stream".to_vec();

        let record = build_record_with_data_attributes(
            record_number,
            vec![
                build_resident_data_attribute(1, None, 0, &default_bytes),
                build_resident_data_attribute(
                    2,
                    Some("Zone.Identifier"),
                    NTFS_ATTRIBUTE_FLAG_COMPRESSED,
                    &named_bytes,
                ),
            ],
        );
        let image = build_test_ntfs_image_with_record(&record);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-recover-named-skip-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("sample.img");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();
        let output_path = temp_dir.join("recovered.bin");
        let output_path_cstr = CString::new(output_path.to_string_lossy().as_bytes()).unwrap();

        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                image_path_cstr.as_ptr(),
                2,
                &mut session_id,
                &mut size_bytes
            ),
            0
        );

        let mut written = 0u64;
        let mut partial = 0i32;
        let mut diagnostics = 0u32;
        let status = fr_recover_ntfs_candidate_to_file_ex(
            session_id,
            record_number,
            output_path_cstr.as_ptr(),
            &mut written,
            &mut partial,
            &mut diagnostics,
        );

        assert_eq!(status, 0);
        assert_eq!(partial, 1);
        assert_eq!(written, default_bytes.len() as u64);
        assert_ne!(diagnostics & RECOVERY_DIAG_HAS_NAMED_DATA_STREAM, 0);
        assert_ne!(diagnostics & RECOVERY_DIAG_COMPRESSED_ATTRIBUTE, 0);
        assert_ne!(diagnostics & RECOVERY_DIAG_UNSUPPORTED_COMPRESSED, 0);
        assert_ne!(diagnostics & RECOVERY_DIAG_SKIPPED_NAMED_DATA_STREAMS, 0);
        assert_eq!(diagnostics & RECOVERY_DIAG_EXPORTED_NAMED_DATA_STREAMS, 0);
        assert_eq!(fs::read(&output_path).unwrap(), default_bytes);

        let sidecar_path = output_path.with_file_name("recovered.bin.ads-Zone.Identifier");
        assert!(!sidecar_path.exists());

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&output_path).unwrap();
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_decompresses_non_resident_compressed_default_stream() {
        let record_number = 89u32;
        let default_bytes = b"compressed-default-stream".to_vec();

        let mut compressed_cluster = vec![0u8; 512];
        let header = 0x3000u16 | ((default_bytes.len() as u16).saturating_sub(1));
        compressed_cluster[..2].copy_from_slice(&header.to_le_bytes());
        compressed_cluster[2..2 + default_bytes.len()].copy_from_slice(&default_bytes);

        let compressed_attribute = build_non_resident_data_attribute(
            1,
            None,
            NTFS_ATTRIBUTE_FLAG_COMPRESSED,
            4,
            default_bytes.len() as u64,
            &[(1, Some(8)), (15, None)],
            512,
            None,
        );

        let record = build_record_with_data_attributes(record_number, vec![compressed_attribute]);
        let mut image = build_test_ntfs_image_with_record(&record);
        let cluster_offset = 8usize * 512usize;
        image[cluster_offset..cluster_offset + compressed_cluster.len()]
            .copy_from_slice(&compressed_cluster);

        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-recover-compressed-default-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("sample.img");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();
        let output_path = temp_dir.join("recovered.bin");
        let output_path_cstr = CString::new(output_path.to_string_lossy().as_bytes()).unwrap();

        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                image_path_cstr.as_ptr(),
                2,
                &mut session_id,
                &mut size_bytes
            ),
            0
        );

        let mut written = 0u64;
        let mut partial = 0i32;
        let mut diagnostics = 0u32;
        let status = fr_recover_ntfs_candidate_to_file_ex(
            session_id,
            record_number,
            output_path_cstr.as_ptr(),
            &mut written,
            &mut partial,
            &mut diagnostics,
        );

        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(written, default_bytes.len() as u64);
        assert_eq!(fs::read(&output_path).unwrap(), default_bytes);
        assert_ne!(diagnostics & RECOVERY_DIAG_COMPRESSED_ATTRIBUTE, 0);
        assert_eq!(diagnostics & RECOVERY_DIAG_UNSUPPORTED_COMPRESSED, 0);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&output_path).unwrap();
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_decompresses_non_resident_compressed_named_stream() {
        let record_number = 91u32;
        let default_bytes = b"default-stream".to_vec();
        let named_bytes = b"compressed-named-stream".to_vec();

        let mut compressed_cluster = vec![0u8; 512];
        let header = 0x3000u16 | ((named_bytes.len() as u16).saturating_sub(1));
        compressed_cluster[..2].copy_from_slice(&header.to_le_bytes());
        compressed_cluster[2..2 + named_bytes.len()].copy_from_slice(&named_bytes);

        let compressed_named_attribute = build_non_resident_data_attribute(
            2,
            Some("Zone.Identifier"),
            NTFS_ATTRIBUTE_FLAG_COMPRESSED,
            4,
            named_bytes.len() as u64,
            &[(1, Some(8)), (15, None)],
            512,
            None,
        );

        let record = build_record_with_data_attributes(
            record_number,
            vec![
                build_resident_data_attribute(1, None, 0, &default_bytes),
                compressed_named_attribute,
            ],
        );
        let mut image = build_test_ntfs_image_with_record(&record);
        let cluster_offset = 8usize * 512usize;
        image[cluster_offset..cluster_offset + compressed_cluster.len()]
            .copy_from_slice(&compressed_cluster);

        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-recover-compressed-named-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("sample.img");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();
        let output_path = temp_dir.join("recovered.bin");
        let output_path_cstr = CString::new(output_path.to_string_lossy().as_bytes()).unwrap();

        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                image_path_cstr.as_ptr(),
                2,
                &mut session_id,
                &mut size_bytes
            ),
            0
        );

        let mut written = 0u64;
        let mut partial = 0i32;
        let mut diagnostics = 0u32;
        let status = fr_recover_ntfs_candidate_to_file_ex(
            session_id,
            record_number,
            output_path_cstr.as_ptr(),
            &mut written,
            &mut partial,
            &mut diagnostics,
        );

        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(written, (default_bytes.len() + named_bytes.len()) as u64);
        assert_eq!(fs::read(&output_path).unwrap(), default_bytes);

        let sidecar_path = output_path.with_file_name("recovered.bin.ads-Zone.Identifier");
        assert_eq!(fs::read(&sidecar_path).unwrap(), named_bytes);
        assert_ne!(diagnostics & RECOVERY_DIAG_HAS_NAMED_DATA_STREAM, 0);
        assert_ne!(diagnostics & RECOVERY_DIAG_EXPORTED_NAMED_DATA_STREAMS, 0);
        assert_ne!(diagnostics & RECOVERY_DIAG_COMPRESSED_ATTRIBUTE, 0);
        assert_eq!(diagnostics & RECOVERY_DIAG_UNSUPPORTED_COMPRESSED, 0);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&sidecar_path).unwrap();
        fs::remove_file(&output_path).unwrap();
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_exports_encrypted_default_stream_as_partial_raw_data() {
        let record_number = 90u32;
        let encrypted_bytes = b"encrypted-bytes".to_vec();

        let record = build_record_with_data_attributes(
            record_number,
            vec![build_resident_data_attribute(
                1,
                None,
                NTFS_ATTRIBUTE_FLAG_ENCRYPTED,
                &encrypted_bytes,
            )],
        );
        let image = build_test_ntfs_image_with_record(&record);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-recover-encrypted-default-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("sample.img");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();
        let output_path = temp_dir.join("recovered.bin");
        let output_path_cstr = CString::new(output_path.to_string_lossy().as_bytes()).unwrap();

        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                image_path_cstr.as_ptr(),
                2,
                &mut session_id,
                &mut size_bytes
            ),
            0
        );

        let mut written = 0u64;
        let mut partial = 0i32;
        let mut diagnostics = 0u32;
        let status = fr_recover_ntfs_candidate_to_file_ex(
            session_id,
            record_number,
            output_path_cstr.as_ptr(),
            &mut written,
            &mut partial,
            &mut diagnostics,
        );

        assert_eq!(status, 0);
        assert_eq!(partial, 1);
        assert_eq!(written, encrypted_bytes.len() as u64);
        assert_eq!(fs::read(&output_path).unwrap(), encrypted_bytes);
        assert_ne!(diagnostics & RECOVERY_DIAG_ENCRYPTED_ATTRIBUTE, 0);
        assert_ne!(diagnostics & RECOVERY_DIAG_UNSUPPORTED_ENCRYPTED, 0);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&output_path).unwrap();
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_handles_fragmented_non_resident_default_stream() {
        let record_number = 124u32;
        let cluster_size = 512u64;
        let part_a = vec![0x41u8; cluster_size as usize];
        let part_b = vec![0x42u8; cluster_size as usize];

        let fragmented_attribute = build_non_resident_data_attribute(
            1,
            None,
            0,
            0,
            cluster_size * 2,
            &[(1, Some(8)), (1, Some(12))],
            cluster_size,
            None,
        );

        let record = build_record_with_data_attributes(record_number, vec![fragmented_attribute]);
        let mut image = build_test_ntfs_image_with_record(&record);
        image[(8 * cluster_size) as usize..(9 * cluster_size) as usize].copy_from_slice(&part_a);
        image[(12 * cluster_size) as usize..(13 * cluster_size) as usize].copy_from_slice(&part_b);

        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-recover-fragmented-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("sample.img");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();
        let output_path = temp_dir.join("recovered.bin");
        let output_path_cstr = CString::new(output_path.to_string_lossy().as_bytes()).unwrap();

        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                image_path_cstr.as_ptr(),
                2,
                &mut session_id,
                &mut size_bytes
            ),
            0
        );

        let mut written = 0u64;
        let mut partial = 0i32;
        let mut diagnostics = 0u32;
        let status = fr_recover_ntfs_candidate_to_file_ex(
            session_id,
            record_number,
            output_path_cstr.as_ptr(),
            &mut written,
            &mut partial,
            &mut diagnostics,
        );

        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(written, cluster_size * 2);
        let mut expected = part_a;
        expected.extend_from_slice(&part_b);
        assert_eq!(fs::read(&output_path).unwrap(), expected);
        assert_eq!(diagnostics & RECOVERY_DIAG_SPARSE_ZERO_FILLED, 0);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&output_path).unwrap();
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_marks_partial_when_non_resident_run_unreadable() {
        let record_number = 125u32;
        let cluster_size = 512u64;
        let part_a = vec![0x43u8; cluster_size as usize];

        let fragmented_attribute = build_non_resident_data_attribute(
            1,
            None,
            0,
            0,
            cluster_size * 2,
            &[(1, Some(8)), (1, Some(40))],
            cluster_size,
            None,
        );

        let record = build_record_with_data_attributes(record_number, vec![fragmented_attribute]);
        let mut image = build_test_ntfs_image_with_record(&record);
        image[(8 * cluster_size) as usize..(9 * cluster_size) as usize].copy_from_slice(&part_a);

        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-recover-partial-fragmented-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("sample.img");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();
        let output_path = temp_dir.join("recovered.bin");
        let output_path_cstr = CString::new(output_path.to_string_lossy().as_bytes()).unwrap();

        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                image_path_cstr.as_ptr(),
                2,
                &mut session_id,
                &mut size_bytes
            ),
            0
        );

        let mut written = 0u64;
        let mut partial = 0i32;
        let mut diagnostics = 0u32;
        let status = fr_recover_ntfs_candidate_to_file_ex(
            session_id,
            record_number,
            output_path_cstr.as_ptr(),
            &mut written,
            &mut partial,
            &mut diagnostics,
        );

        assert_eq!(status, 0);
        assert_eq!(partial, 1);
        assert_eq!(written, cluster_size);
        assert_eq!(fs::read(&output_path).unwrap(), part_a);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&output_path).unwrap();
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_finds_record_after_zero_gap() {
        let record_number = 123u32;
        let payload = b"gap-test-payload".to_vec();

        let record = build_record_with_data_attributes(
            record_number,
            vec![build_resident_data_attribute(1, None, 0, &payload)],
        );
        let image = build_test_ntfs_image_with_record_at_index(&record, 24);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-recover-gap-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("sample.img");
        fs::write(&image_path, &image).unwrap();

        let image_path_cstr = CString::new(image_path.to_string_lossy().as_bytes()).unwrap();
        let output_path = temp_dir.join("recovered.bin");
        let output_path_cstr = CString::new(output_path.to_string_lossy().as_bytes()).unwrap();

        let mut session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                image_path_cstr.as_ptr(),
                2,
                &mut session_id,
                &mut size_bytes
            ),
            0
        );

        let mut written = 0u64;
        let mut partial = 0i32;
        let mut diagnostics = 0u32;
        let status = fr_recover_ntfs_candidate_to_file_ex(
            session_id,
            record_number,
            output_path_cstr.as_ptr(),
            &mut written,
            &mut partial,
            &mut diagnostics,
        );

        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(written, payload.len() as u64);
        assert_eq!(fs::read(&output_path).unwrap(), payload);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&output_path).unwrap();
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    fn c_string_bytes_to_string(bytes: &[u8]) -> String {
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    }

    fn build_test_ntfs_image_with_named_records() -> Vec<u8> {
        let mut image = vec![0u8; 12 * 1024];

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

        image[mft_offset..mft_offset + parent.len()].copy_from_slice(&parent);
        image[mft_offset + 1024..mft_offset + 1024 + child_deleted.len()]
            .copy_from_slice(&child_deleted);

        image
    }

    fn build_test_ntfs_image_with_record(record: &[u8]) -> Vec<u8> {
        build_test_ntfs_image_with_record_at_index(record, 0)
    }

    fn build_test_ntfs_image_with_record_at_index(record: &[u8], record_index: usize) -> Vec<u8> {
        let image_len = (8 + record_index + 1) * 1024;
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
        let record_offset = mft_offset + record_index * 1024;
        image[record_offset..record_offset + record.len()].copy_from_slice(record);
        image
    }

    fn build_record_with_data_attributes(record_number: u32, attributes: Vec<Vec<u8>>) -> Vec<u8> {
        let mut record = vec![0u8; 1024];
        record[0x00..0x04].copy_from_slice(b"FILE");
        write_u16(&mut record, 0x04, 0x30);
        write_u16(&mut record, 0x06, 3);
        write_u16(&mut record, 0x10, 1);
        write_u16(&mut record, 0x12, 1);
        write_u16(&mut record, 0x14, 0x38);
        write_u16(&mut record, 0x16, 0x0001);
        write_u32(&mut record, 0x1C, 1024);
        write_u32(&mut record, 0x2C, record_number);

        write_u16(&mut record, 0x30, 0xAAAA);
        write_u16(&mut record, 0x32, 0x1111);
        write_u16(&mut record, 0x34, 0x2222);
        write_u16(&mut record, 510, 0xAAAA);
        write_u16(&mut record, 1022, 0xAAAA);

        let mut cursor = 0x38usize;
        for attribute in attributes {
            record[cursor..cursor + attribute.len()].copy_from_slice(&attribute);
            cursor += attribute.len();
        }

        write_u32(&mut record, cursor, 0xFFFF_FFFF);
        write_u32(&mut record, 0x18, (cursor + 4) as u32);
        record
    }

    fn build_resident_data_attribute(
        attribute_id: u16,
        name: Option<&str>,
        flags: u16,
        value: &[u8],
    ) -> Vec<u8> {
        let name_utf16 = name.map(|n| n.encode_utf16().collect::<Vec<u16>>());
        let name_bytes_len = name_utf16
            .as_ref()
            .map(|units| units.len() * 2)
            .unwrap_or(0);
        let name_len_chars = name_utf16.as_ref().map(|units| units.len()).unwrap_or(0);

        let name_offset = if name_bytes_len == 0 { 0 } else { 0x18 };
        let value_offset = 0x18 + name_bytes_len;
        let attr_len = (value_offset + value.len() + 7) & !7;
        let mut attr = vec![0u8; attr_len];

        write_u32(&mut attr, 0x00, ATTRIBUTE_TYPE_DATA);
        write_u32(&mut attr, 0x04, attr_len as u32);
        attr[0x08] = 0;
        attr[0x09] = name_len_chars as u8;
        write_u16(&mut attr, 0x0A, name_offset as u16);
        write_u16(&mut attr, 0x0C, flags);
        write_u16(&mut attr, 0x0E, attribute_id);
        write_u32(&mut attr, 0x10, value.len() as u32);
        write_u16(&mut attr, 0x14, value_offset as u16);
        attr[0x16] = 0;
        attr[0x17] = 0;

        if let Some(name_utf16) = name_utf16 {
            let mut cursor = name_offset;
            for code in name_utf16 {
                attr[cursor..cursor + 2].copy_from_slice(&code.to_le_bytes());
                cursor += 2;
            }
        }

        attr[value_offset..value_offset + value.len()].copy_from_slice(value);
        attr
    }

    fn build_non_resident_data_attribute(
        attribute_id: u16,
        name: Option<&str>,
        flags: u16,
        compression_unit_size: u16,
        data_size: u64,
        runs: &[(u64, Option<i64>)],
        cluster_size: u64,
        compressed_size: Option<u64>,
    ) -> Vec<u8> {
        let name_utf16 = name.map(|n| n.encode_utf16().collect::<Vec<u16>>());
        let name_bytes_len = name_utf16
            .as_ref()
            .map(|units| units.len() * 2)
            .unwrap_or(0);
        let name_len_chars = name_utf16.as_ref().map(|units| units.len()).unwrap_or(0);

        let mut mapping_pairs = encode_mapping_pairs(runs);
        mapping_pairs.push(0);

        let header_len = 0x48usize;
        let name_offset = if name_bytes_len == 0 {
            0
        } else {
            header_len as u16
        };
        let mapping_pairs_offset = header_len + name_bytes_len;
        let attr_len = (mapping_pairs_offset + mapping_pairs.len() + 7) & !7;
        let mut attr = vec![0u8; attr_len];

        write_u32(&mut attr, 0x00, ATTRIBUTE_TYPE_DATA);
        write_u32(&mut attr, 0x04, attr_len as u32);
        attr[0x08] = 1;
        attr[0x09] = name_len_chars as u8;
        write_u16(&mut attr, 0x0A, name_offset);
        write_u16(&mut attr, 0x0C, flags);
        write_u16(&mut attr, 0x0E, attribute_id);

        let total_clusters = runs
            .iter()
            .map(|(cluster_count, _)| *cluster_count)
            .fold(0u64, |acc, cluster_count| acc.saturating_add(cluster_count));
        let highest_vcn = total_clusters.saturating_sub(1);
        write_u64(&mut attr, 0x10, 0);
        write_u64(&mut attr, 0x18, highest_vcn);
        write_u16(&mut attr, 0x20, mapping_pairs_offset as u16);
        write_u16(&mut attr, 0x22, compression_unit_size);
        write_u32(&mut attr, 0x24, 0);
        let allocated_size = total_clusters.saturating_mul(cluster_size);
        write_u64(&mut attr, 0x28, allocated_size);
        write_u64(&mut attr, 0x30, data_size);
        write_u64(&mut attr, 0x38, data_size);
        write_u64(
            &mut attr,
            0x40,
            compressed_size.unwrap_or(allocated_size.min(data_size.max(1))),
        );

        if let Some(name_utf16) = name_utf16 {
            let mut cursor = header_len;
            for code in name_utf16 {
                attr[cursor..cursor + 2].copy_from_slice(&code.to_le_bytes());
                cursor += 2;
            }
        }

        attr[mapping_pairs_offset..mapping_pairs_offset + mapping_pairs.len()]
            .copy_from_slice(&mapping_pairs);
        attr
    }

    fn encode_mapping_pairs(runs: &[(u64, Option<i64>)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut current_lcn = 0i64;

        for (cluster_count, maybe_lcn) in runs {
            let length_bytes = encode_unsigned_le(*cluster_count);
            let (offset_bytes, next_lcn) = match maybe_lcn {
                Some(target_lcn) => {
                    let delta = target_lcn.saturating_sub(current_lcn);
                    let encoded = encode_signed_le(delta);
                    (encoded, *target_lcn)
                }
                None => (Vec::new(), current_lcn),
            };

            let header = ((offset_bytes.len() as u8) << 4) | (length_bytes.len() as u8);
            bytes.push(header);
            bytes.extend_from_slice(&length_bytes);
            bytes.extend_from_slice(&offset_bytes);
            current_lcn = next_lcn;
        }

        bytes
    }

    fn encode_unsigned_le(value: u64) -> Vec<u8> {
        let mut encoded = value.to_le_bytes().to_vec();
        while encoded.len() > 1 && encoded.last() == Some(&0) {
            encoded.pop();
        }
        encoded
    }

    fn encode_signed_le(value: i64) -> Vec<u8> {
        let bytes = value.to_le_bytes();
        let mut length = 8usize;
        while length > 1 {
            let last = bytes[length - 1];
            let next = bytes[length - 2];
            let can_shrink_positive = last == 0x00 && (next & 0x80) == 0;
            let can_shrink_negative = last == 0xFF && (next & 0x80) != 0;
            if can_shrink_positive || can_shrink_negative {
                length -= 1;
                continue;
            }
            break;
        }
        bytes[..length].to_vec()
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
        let attr_len = (attr_len + 7) & !7;

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
        write_u64(&mut attr, 0x20, 132_537_600_000_000_000);
        write_u64(&mut attr, 0x28, 132_537_600_100_000_000);
        write_u64(&mut attr, 0x30, 132_537_600_200_000_000);
        write_u64(&mut attr, 0x38, 132_537_600_300_000_000);
        write_u64(&mut attr, 0x40, 4096);
        write_u64(&mut attr, 0x48, 1234);
        write_u32(&mut attr, 0x50, 0x0000_0020);
        attr[0x18 + 0x40] = name_len;
        attr[0x18 + 0x41] = 1;

        let mut cursor = 0x18 + 0x42;
        for code in utf16 {
            attr[cursor..cursor + 2].copy_from_slice(&code.to_le_bytes());
            cursor += 2;
        }

        attr
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

    fn empty_candidate() -> FrNtfsQuickScanCandidate {
        FrNtfsQuickScanCandidate {
            record_number: 0,
            flags: 0,
            parent_record_number: 0,
            confidence_tier: 0,
            _reserved0: 0,
            data_size_bytes: 0,
            allocated_size_bytes: 0,
            file_attributes: 0,
            _reserved1: 0,
            created_filetime_utc: 0,
            modified_filetime_utc: 0,
            mft_modified_filetime_utc: 0,
            accessed_filetime_utc: 0,
            name: [0u8; 128],
            reconstructed_path: [0u8; 256],
            confidence_reason: [0u8; 256],
        }
    }

    fn empty_carve_candidate() -> FrCarveCandidate {
        FrCarveCandidate {
            offset_bytes: 0,
            length_bytes: 0,
            flags: 0,
            confidence_tier: 0,
            format: [0u8; 16],
            suggested_name: [0u8; 128],
            confidence_reason: [0u8; 256],
        }
    }

    fn empty_refs_deleted_candidate() -> FrRefsDeletedCandidate {
        FrRefsDeletedCandidate {
            flags: 0,
            object_id: 0,
            size_bytes: 0,
            name: [0u8; 128],
            reconstructed_path: [0u8; 256],
        }
    }

    fn empty_fat_deleted_candidate() -> FrFatDeletedCandidate {
        FrFatDeletedCandidate {
            flags: 0,
            start_cluster: 0,
            size_bytes: 0,
            name: [0u8; 128],
            reconstructed_path: [0u8; 256],
        }
    }

    fn build_test_refs_image() -> Vec<u8> {
        let mut image = vec![0u8; 512 * 128];
        image[0x03..0x0B].copy_from_slice(b"ReFS    ");
        write_u16(&mut image, 0x0B, 4096);
        image[0x0D] = 1;
        write_u64(&mut image, 0x28, 2_000_000);
        write_u64(&mut image, 0x48, 0xA1A2_A3A4_A5A6_A7A8);
        image
    }

    fn build_test_refs_image_with_deleted_usn_record() -> Vec<u8> {
        let mut image = build_test_refs_image();
        let usn_record = build_usn_v2_record("refs-deleted.txt", 0x0000_0200, 42, 5);
        let start = 4096usize;
        image[start..start + usn_record.len()].copy_from_slice(&usn_record);
        image
    }

    fn build_test_fat32_image_with_deleted_entry() -> Vec<u8> {
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

    fn build_test_fat32_image_with_recoverable_file(payload: &[u8]) -> Vec<u8> {
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
        write_u32(&mut image, fat_sector_offset + (5 * 4), 0x0FFF_FFFF);

        let root_sector_offset = 33 * 512;
        image[root_sector_offset] = 0xE5;
        image[root_sector_offset + 1..root_sector_offset + 8].copy_from_slice(b"ILE    ");
        image[root_sector_offset + 8..root_sector_offset + 11].copy_from_slice(b"BIN");
        image[root_sector_offset + 11] = 0x20;
        write_u16(&mut image, root_sector_offset + 26, 5);
        write_u32(&mut image, root_sector_offset + 28, payload.len() as u32);
        image[root_sector_offset + 32] = 0x00;

        let file_cluster_sector_offset = 36 * 512;
        image[file_cluster_sector_offset..file_cluster_sector_offset + payload.len()]
            .copy_from_slice(payload);

        image
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
