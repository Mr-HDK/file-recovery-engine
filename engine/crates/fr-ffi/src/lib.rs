use fr_apfs::{
    parse_container_superblock as parse_apfs_container_superblock,
    scan_deleted_candidates_with_container as scan_apfs_deleted_candidates_with_container,
};
use fr_carving::{
    carve_bytes, signature_pack_formats, CarvingFamily, CarvingPlan, SIGNATURE_PACK_NAME,
    SIGNATURE_PACK_VERSION,
};
use fr_ext::{parse_superblock as parse_ext_superblock, scan_deleted_candidates_with_superblock};
use fr_fat::{
    parse_boot_sector as parse_fat_boot_sector, scan_deleted_entries_with_boot, FatFilesystemKind,
};
use fr_hfs::{
    parse_volume_header as parse_hfs_volume_header,
    scan_deleted_candidates_with_header as scan_hfs_deleted_candidates_with_header,
};
use fr_mft::{parse_mft_record, AttributeForm, ATTRIBUTE_TYPE_DATA};
use fr_ntfs::parse_boot_sector as parse_ntfs_boot_sector;
use fr_raid::{
    map_logical_offset as map_raid_logical_offset, resolve_layout_with_override, ParityRotation,
    RaidLayout, RaidLevel, RaidLogicalMapping, RaidManualOverride, RaidMetadataFamily,
};
use fr_refs::{parse_boot_sector as parse_refs_boot_sector, scan_deleted_candidates_with_boot};
use fr_scoring::score_candidate_with_reasons;
use fr_session::{
    enrich_summary_with_usn_journal_bytes, quick_scan_ntfs_from_read_session, QuickScanConfig,
    QuickScanError,
};
use fr_types::{ConfidenceTier, EvidenceSource, RecoveryCandidate, RecoverySourceKind};
use fr_ufs::{
    parse_superblock as parse_ufs_superblock,
    scan_deleted_candidates_with_superblock as scan_ufs_deleted_candidates_with_superblock,
};
use fr_xfs::{
    parse_superblock as parse_xfs_superblock,
    scan_deleted_candidates_with_superblock as scan_xfs_deleted_candidates_with_superblock,
};
use std::collections::{HashMap, HashSet};
use std::ffi::{c_char, CStr};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static ENGINE_VERSION: &[u8] = b"0.1.0\0";
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_VIRTUAL_RAID_ARTIFACT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
struct VirtualRaidSessionMeta {
    layout: RaidLayout,
    artifact_path: PathBuf,
}

fn read_sessions() -> &'static Mutex<HashMap<u64, fr_winio::ReadSession>> {
    static SESSIONS: OnceLock<Mutex<HashMap<u64, fr_winio::ReadSession>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn virtual_raid_sessions() -> &'static Mutex<HashMap<u64, VirtualRaidSessionMeta>> {
    static SESSIONS: OnceLock<Mutex<HashMap<u64, VirtualRaidSessionMeta>>> = OnceLock::new();
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
pub struct FrExtSuperblockMetadata {
    pub filesystem_kind: u32,
    pub block_size_bytes: u32,
    pub inode_size_bytes: u16,
    pub _reserved0: u16,
    pub inodes_per_group: u32,
    pub total_inodes: u32,
    pub total_blocks: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FrExtDeletedCandidate {
    pub flags: u32,
    pub inode_number: u64,
    pub entry_offset_bytes: u64,
    pub size_bytes: u64,
    pub name: [u8; 128],
    pub reconstructed_path: [u8; 256],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FrApfsContainerMetadata {
    pub block_size_bytes: u32,
    pub _reserved0: u32,
    pub block_count: u64,
    pub features: u64,
    pub incompat_features: u64,
    pub container_object_id: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FrApfsDeletedCandidate {
    pub flags: u32,
    pub _reserved0: u32,
    pub cnid: u64,
    pub size_bytes: u64,
    pub name: [u8; 128],
    pub reconstructed_path: [u8; 256],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FrHfsVolumeMetadata {
    pub signature: u16,
    pub version: u16,
    pub block_size_bytes: u32,
    pub total_blocks: u32,
    pub file_count: u32,
    pub folder_count: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FrHfsDeletedCandidate {
    pub flags: u32,
    pub cnid: u32,
    pub size_bytes: u64,
    pub name: [u8; 128],
    pub reconstructed_path: [u8; 256],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FrXfsSuperblockMetadata {
    pub block_size_bytes: u32,
    pub inode_size_bytes: u16,
    pub _reserved0: u16,
    pub ag_count: u32,
    pub data_blocks: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FrXfsDeletedCandidate {
    pub flags: u32,
    pub inode_number: u64,
    pub size_bytes: u64,
    pub name: [u8; 128],
    pub reconstructed_path: [u8; 256],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FrUfsSuperblockMetadata {
    pub magic: u32,
    pub block_size_bytes: u32,
    pub fragment_size_bytes: u32,
    pub _reserved0: u32,
    pub total_blocks: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FrUfsDeletedCandidate {
    pub flags: u32,
    pub inode_number: u32,
    pub _reserved0: u32,
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
#[derive(Debug, Default, Clone, Copy)]
pub struct FrRaidLayout {
    pub metadata_family: u32,
    pub level: u32,
    pub member_count: u32,
    pub stripe_size_bytes: u32,
    pub data_offset_bytes: u64,
    pub parity_rotation: u32,
    pub confidence_score: u8,
    pub _reserved0: [u8; 3],
    pub disk_order_count: u32,
    pub disk_order: [u32; 32],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FrRaidManualOverride {
    pub flags: u32,
    pub level: u32,
    pub stripe_size_bytes: u32,
    pub data_offset_bytes: u64,
    pub parity_rotation: u32,
    pub disk_order_count: u32,
    pub disk_order: [u32; 32],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FrRaidLogicalMapping {
    pub member_index: u32,
    pub member_offset_bytes: u64,
    pub has_parity_member: u32,
    pub parity_member_index: u32,
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
pub struct FrCarveSignaturePackMetadata {
    pub pack_name: [u8; 64],
    pub pack_version: [u8; 32],
    pub format_count: u32,
    pub family_flags: u32,
    pub formats_csv: [u8; 512],
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
const EXT_DELETED_CANDIDATE_FLAG_DELETED: u32 = 0x0001;
const EXT_DELETED_CANDIDATE_FLAG_DIRECTORY: u32 = 0x0002;
const EXT_FILESYSTEM_KIND_EXT2: u32 = 1;
const EXT_FILESYSTEM_KIND_EXT3: u32 = 2;
const EXT_FILESYSTEM_KIND_EXT4: u32 = 3;
const APFS_DELETED_CANDIDATE_FLAG_DELETED: u32 = 0x0001;
const APFS_DELETED_CANDIDATE_FLAG_DIRECTORY: u32 = 0x0002;
const HFS_DELETED_CANDIDATE_FLAG_DELETED: u32 = 0x0001;
const HFS_DELETED_CANDIDATE_FLAG_DIRECTORY: u32 = 0x0002;
const XFS_DELETED_CANDIDATE_FLAG_DELETED: u32 = 0x0001;
const XFS_DELETED_CANDIDATE_FLAG_DIRECTORY: u32 = 0x0002;
const UFS_DELETED_CANDIDATE_FLAG_DELETED: u32 = 0x0001;
const UFS_DELETED_CANDIDATE_FLAG_DIRECTORY: u32 = 0x0002;
const EXT_GROUP_DESCRIPTOR_INODE_TABLE_OFFSET: usize = 0x08;
const EXT_INODE_SIZE_HIGH_OFFSET: usize = 0x6C;
const EXT_INODE_FLAGS_OFFSET: usize = 32;
const EXT_INODE_BLOCK_POINTERS_OFFSET: usize = 40;
const EXT_DIRECT_BLOCK_POINTERS: usize = 12;
const EXT_SINGLE_INDIRECT_POINTER_INDEX: usize = 12;
const EXT_DOUBLE_INDIRECT_POINTER_INDEX: usize = 13;
const EXT_TRIPLE_INDIRECT_POINTER_INDEX: usize = 14;
const EXT_INODE_FLAG_EXTENTS: u32 = 0x0008_0000;
const EXTENT_HEADER_MAGIC: u16 = 0xF30A;
const EXTENT_HEADER_SIZE: usize = 12;
const EXTENT_RECORD_SIZE: usize = 12;
const EXTENT_UNINITIALIZED_LENGTH_FLAG: u16 = 0x8000;
const FAT_DELETED_CANDIDATE_FLAG_DELETED: u32 = 0x0001;
const FAT_DELETED_CANDIDATE_FLAG_DIRECTORY: u32 = 0x0002;
const FAT_FILESYSTEM_KIND_FAT32: u32 = 1;
const FAT_FILESYSTEM_KIND_EXFAT: u32 = 2;
const FAT_EOC_MIN: u32 = 0x0FFF_FFF8;
const RAID_LAYOUT_MAX_MEMBERS: usize = 32;
const RAID_MANUAL_OVERRIDE_FLAG_LEVEL: u32 = 0x0001;
const RAID_MANUAL_OVERRIDE_FLAG_STRIPE_SIZE: u32 = 0x0002;
const RAID_MANUAL_OVERRIDE_FLAG_DATA_OFFSET: u32 = 0x0004;
const RAID_MANUAL_OVERRIDE_FLAG_PARITY_ROTATION: u32 = 0x0008;
const RAID_MANUAL_OVERRIDE_FLAG_DISK_ORDER: u32 = 0x0010;
const RAID_METADATA_FAMILY_LINUX_MD: u32 = 1;
const RAID_METADATA_FAMILY_WINDOWS_STORAGE_SPACES: u32 = 2;
const RAID_LEVEL_RAID0: u32 = 1;
const RAID_LEVEL_RAID1: u32 = 2;
const RAID_LEVEL_RAID4: u32 = 3;
const RAID_LEVEL_RAID5: u32 = 4;
const RAID_LEVEL_RAID6: u32 = 5;
const RAID_LEVEL_RAID10: u32 = 6;
const RAID_LEVEL_UNKNOWN: u32 = 255;
const RAID_PARITY_LEFT_SYMMETRIC: u32 = 1;
const RAID_PARITY_RIGHT_SYMMETRIC: u32 = 2;
const RAID_PARITY_UNKNOWN: u32 = 255;

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
const RECOVERY_STATUS_UNSUPPORTED_LAYOUT: i32 = 170;
const RECOVERY_STATUS_ENCRYPTED_LOCKED: i32 = 171;
const RECOVERY_STATUS_UNREADABLE_RANGE: i32 = 172;
const METADATA_ENCRYPTED_FLAG: u8 = 0x02;
const APFS_TOMBSTONE_MARKER: &[u8; 8] = b"APFSDEL\0";
const HFS_TOMBSTONE_MARKER: &[u8; 8] = b"HFSDEL\0\0";
const XFS_TOMBSTONE_MARKER: &[u8; 8] = b"XFSDEL\0\0";
const UFS_TOMBSTONE_MARKER: &[u8; 8] = b"UFSDEL\0\0";
const REFS_PAYLOAD_MARKER: &[u8; 8] = b"REFSPAY\0";
const APFS_TOMBSTONE_RECORD_SIZE: usize = 316;
const HFS_TOMBSTONE_RECORD_SIZE: usize = 312;
const XFS_TOMBSTONE_RECORD_SIZE: usize = 316;
const UFS_TOMBSTONE_RECORD_SIZE: usize = 312;
const PAYLOAD_DESCRIPTOR_SIZE: usize = 16;
const REFS_PAYLOAD_DESCRIPTOR_SIZE: usize = 40;
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
pub extern "C" fn fr_get_carve_signature_pack_metadata(
    out_metadata: *mut FrCarveSignaturePackMetadata,
) -> i32 {
    if out_metadata.is_null() {
        return -1;
    }

    unsafe {
        *out_metadata = encode_carve_signature_pack_metadata();
    }

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
pub extern "C" fn fr_probe_ext_superblock_from_session(
    session_id: u64,
    out_superblock: *mut FrExtSuperblockMetadata,
) -> i32 {
    if out_superblock.is_null() {
        return -1;
    }

    let Ok(mut map) = read_sessions().lock() else {
        return -200;
    };

    let Some(session) = map.get_mut(&session_id) else {
        return 20;
    };

    let mut header = [0u8; 4096];
    match read_from_session(session, 0, &mut header) {
        Ok(true) => {}
        Ok(false) => return 31,
        Err(err) => return map_winio_error(err),
    }

    let Ok(superblock) = parse_ext_superblock(&header) else {
        return 90;
    };

    unsafe {
        *out_superblock = FrExtSuperblockMetadata {
            filesystem_kind: map_ext_filesystem_kind(superblock.filesystem_kind),
            block_size_bytes: superblock.block_size_bytes,
            inode_size_bytes: superblock.inode_size_bytes,
            _reserved0: 0,
            inodes_per_group: superblock.inodes_per_group,
            total_inodes: superblock.inodes_count,
            total_blocks: superblock.blocks_count,
        };
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_get_ext_deleted_candidates_from_session(
    session_id: u64,
    max_entries: u32,
    out_candidates: *mut FrExtDeletedCandidate,
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

    let image = match read_prefix_for_ext_scan(session) {
        Ok(bytes) => bytes,
        Err(err) => return map_winio_error(err),
    };

    if image.len() < 2048 {
        return 31;
    }

    let Ok(superblock) = parse_ext_superblock(&image) else {
        return 90;
    };

    let max_entries = if max_entries == 0 {
        512usize
    } else {
        max_entries as usize
    };
    let candidates = scan_deleted_candidates_with_superblock(&image, &superblock, max_entries);

    let total = usize_to_u32_saturating(candidates.len());
    let write_count = candidates.len().min(candidate_capacity as usize);
    for (index, candidate) in candidates.iter().take(write_count).enumerate() {
        unsafe {
            *out_candidates.add(index) = encode_ext_deleted_candidate(candidate);
        }
    }

    unsafe {
        *out_written = total;
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_probe_apfs_container_from_session(
    session_id: u64,
    out_container: *mut FrApfsContainerMetadata,
) -> i32 {
    if out_container.is_null() {
        return -1;
    }

    let Ok(mut map) = read_sessions().lock() else {
        return -200;
    };

    let Some(session) = map.get_mut(&session_id) else {
        return 20;
    };

    let mut header = [0u8; 4096];
    match read_from_session(session, 0, &mut header) {
        Ok(true) => {}
        Ok(false) => return 31,
        Err(err) => return map_winio_error(err),
    }

    let Ok(container) = parse_apfs_container_superblock(&header) else {
        return 100;
    };

    unsafe {
        *out_container = FrApfsContainerMetadata {
            block_size_bytes: container.block_size_bytes,
            _reserved0: 0,
            block_count: container.block_count,
            features: container.features,
            incompat_features: container.incompat_features,
            container_object_id: container.container_object_id,
        };
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_get_apfs_deleted_candidates_from_session(
    session_id: u64,
    max_entries: u32,
    out_candidates: *mut FrApfsDeletedCandidate,
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

    let image = match read_prefix_for_apfs_scan(session) {
        Ok(bytes) => bytes,
        Err(err) => return map_winio_error(err),
    };

    if image.len() < 4096 {
        return 31;
    }

    let Ok(container) = parse_apfs_container_superblock(&image) else {
        return 100;
    };

    let max_entries = if max_entries == 0 {
        512usize
    } else {
        max_entries as usize
    };
    let candidates = scan_apfs_deleted_candidates_with_container(&image, &container, max_entries);

    let total = usize_to_u32_saturating(candidates.len());
    let write_count = candidates.len().min(candidate_capacity as usize);
    for (index, candidate) in candidates.iter().take(write_count).enumerate() {
        unsafe {
            *out_candidates.add(index) = encode_apfs_deleted_candidate(candidate);
        }
    }

    unsafe {
        *out_written = total;
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_probe_hfs_volume_header_from_session(
    session_id: u64,
    out_volume: *mut FrHfsVolumeMetadata,
) -> i32 {
    if out_volume.is_null() {
        return -1;
    }

    let Ok(mut map) = read_sessions().lock() else {
        return -200;
    };

    let Some(session) = map.get_mut(&session_id) else {
        return 20;
    };

    let mut header = [0u8; 2048];
    match read_from_session(session, 0, &mut header) {
        Ok(true) => {}
        Ok(false) => return 31,
        Err(err) => return map_winio_error(err),
    }

    let Ok(volume) = parse_hfs_volume_header(&header) else {
        return 110;
    };

    unsafe {
        *out_volume = FrHfsVolumeMetadata {
            signature: volume.signature,
            version: volume.version,
            block_size_bytes: volume.block_size_bytes,
            total_blocks: volume.total_blocks,
            file_count: volume.file_count,
            folder_count: volume.folder_count,
        };
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_get_hfs_deleted_candidates_from_session(
    session_id: u64,
    max_entries: u32,
    out_candidates: *mut FrHfsDeletedCandidate,
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

    let image = match read_prefix_for_hfs_scan(session) {
        Ok(bytes) => bytes,
        Err(err) => return map_winio_error(err),
    };

    if image.len() < 2048 {
        return 31;
    }

    let Ok(header) = parse_hfs_volume_header(&image) else {
        return 110;
    };

    let max_entries = if max_entries == 0 {
        512usize
    } else {
        max_entries as usize
    };
    let candidates = scan_hfs_deleted_candidates_with_header(&image, &header, max_entries);

    let total = usize_to_u32_saturating(candidates.len());
    let write_count = candidates.len().min(candidate_capacity as usize);
    for (index, candidate) in candidates.iter().take(write_count).enumerate() {
        unsafe {
            *out_candidates.add(index) = encode_hfs_deleted_candidate(candidate);
        }
    }

    unsafe {
        *out_written = total;
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_probe_xfs_superblock_from_session(
    session_id: u64,
    out_superblock: *mut FrXfsSuperblockMetadata,
) -> i32 {
    if out_superblock.is_null() {
        return -1;
    }

    let Ok(mut map) = read_sessions().lock() else {
        return -200;
    };

    let Some(session) = map.get_mut(&session_id) else {
        return 20;
    };

    let mut header = [0u8; 4096];
    match read_from_session(session, 0, &mut header) {
        Ok(true) => {}
        Ok(false) => return 31,
        Err(err) => return map_winio_error(err),
    }

    let Ok(superblock) = parse_xfs_superblock(&header) else {
        return 120;
    };

    unsafe {
        *out_superblock = FrXfsSuperblockMetadata {
            block_size_bytes: superblock.block_size_bytes,
            inode_size_bytes: superblock.inode_size_bytes,
            _reserved0: 0,
            ag_count: superblock.ag_count,
            data_blocks: superblock.data_blocks,
        };
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_get_xfs_deleted_candidates_from_session(
    session_id: u64,
    max_entries: u32,
    out_candidates: *mut FrXfsDeletedCandidate,
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

    let image = match read_prefix_for_xfs_scan(session) {
        Ok(bytes) => bytes,
        Err(err) => return map_winio_error(err),
    };

    if image.len() < 4096 {
        return 31;
    }

    let Ok(superblock) = parse_xfs_superblock(&image) else {
        return 120;
    };

    let max_entries = if max_entries == 0 {
        512usize
    } else {
        max_entries as usize
    };
    let candidates = scan_xfs_deleted_candidates_with_superblock(&image, &superblock, max_entries);

    let total = usize_to_u32_saturating(candidates.len());
    let write_count = candidates.len().min(candidate_capacity as usize);
    for (index, candidate) in candidates.iter().take(write_count).enumerate() {
        unsafe {
            *out_candidates.add(index) = encode_xfs_deleted_candidate(candidate);
        }
    }

    unsafe {
        *out_written = total;
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_probe_ufs_superblock_from_session(
    session_id: u64,
    out_superblock: *mut FrUfsSuperblockMetadata,
) -> i32 {
    if out_superblock.is_null() {
        return -1;
    }

    let Ok(mut map) = read_sessions().lock() else {
        return -200;
    };

    let Some(session) = map.get_mut(&session_id) else {
        return 20;
    };

    let mut header = [0u8; 16 * 1024];
    match read_from_session(session, 0, &mut header) {
        Ok(true) => {}
        Ok(false) => return 31,
        Err(err) => return map_winio_error(err),
    }

    let Ok(superblock) = parse_ufs_superblock(&header) else {
        return 130;
    };

    unsafe {
        *out_superblock = FrUfsSuperblockMetadata {
            magic: superblock.magic,
            block_size_bytes: superblock.block_size_bytes,
            fragment_size_bytes: superblock.fragment_size_bytes,
            _reserved0: 0,
            total_blocks: superblock.total_blocks,
        };
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_get_ufs_deleted_candidates_from_session(
    session_id: u64,
    max_entries: u32,
    out_candidates: *mut FrUfsDeletedCandidate,
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

    let image = match read_prefix_for_ufs_scan(session) {
        Ok(bytes) => bytes,
        Err(err) => return map_winio_error(err),
    };

    if image.len() < 16 * 1024 {
        return 31;
    }

    let Ok(superblock) = parse_ufs_superblock(&image) else {
        return 130;
    };

    let max_entries = if max_entries == 0 {
        512usize
    } else {
        max_entries as usize
    };
    let candidates = scan_ufs_deleted_candidates_with_superblock(&image, &superblock, max_entries);

    let total = usize_to_u32_saturating(candidates.len());
    let write_count = candidates.len().min(candidate_capacity as usize);
    for (index, candidate) in candidates.iter().take(write_count).enumerate() {
        unsafe {
            *out_candidates.add(index) = encode_ufs_deleted_candidate(candidate);
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
    let candidates = match scan_deleted_entries_with_boot(&image, &boot, max_entries, 256) {
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
pub extern "C" fn fr_probe_raid_layout_from_session(
    session_id: u64,
    override_cfg: *const FrRaidManualOverride,
    out_layout: *mut FrRaidLayout,
) -> i32 {
    if out_layout.is_null() {
        return -1;
    }

    let Ok(mut map) = read_sessions().lock() else {
        return -200;
    };

    let Some(session) = map.get_mut(&session_id) else {
        return 20;
    };

    let image = match read_prefix_for_raid_scan(session) {
        Ok(bytes) => bytes,
        Err(err) => return map_winio_error(err),
    };
    if image.len() < 4096 {
        return 31;
    }

    let parsed_override = if override_cfg.is_null() {
        None
    } else {
        match decode_raid_manual_override(unsafe { &*override_cfg }) {
            Ok(value) => Some(value),
            Err(status) => return status,
        }
    };

    let layout = match resolve_layout_with_override(&image, parsed_override.as_ref()) {
        Ok(Some(layout)) => layout,
        Ok(None) => return 140,
        Err(err) => return map_raid_error_to_status(err, parsed_override.is_some()),
    };

    unsafe {
        *out_layout = encode_raid_layout(&layout);
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_open_virtual_raid_session(
    member_session_ids: *const u64,
    member_count: u32,
    override_cfg: *const FrRaidManualOverride,
    out_session_id: *mut u64,
    out_size_bytes: *mut u64,
    out_layout: *mut FrRaidLayout,
) -> i32 {
    if member_session_ids.is_null() || out_session_id.is_null() || out_layout.is_null() {
        return -1;
    }
    if member_count < 2 || member_count as usize > RAID_LAYOUT_MAX_MEMBERS {
        return 142;
    }

    let member_session_ids =
        unsafe { std::slice::from_raw_parts(member_session_ids, member_count as usize) }.to_vec();
    let mut unique_sessions = HashSet::with_capacity(member_session_ids.len());
    if member_session_ids
        .iter()
        .any(|session_id| !unique_sessions.insert(*session_id))
    {
        return 142;
    }

    let parsed_override = if override_cfg.is_null() {
        None
    } else {
        match decode_raid_manual_override(unsafe { &*override_cfg }) {
            Ok(value) => Some(value),
            Err(status) => return status,
        }
    };

    let layout = {
        let Ok(mut map) = read_sessions().lock() else {
            return -200;
        };
        match detect_virtual_raid_layout(&mut map, &member_session_ids, parsed_override.as_ref()) {
            Ok(layout) => layout,
            Err(status) => return status,
        }
    };

    let artifact_path = build_virtual_raid_artifact_path();
    let assembled_size = {
        let Ok(mut map) = read_sessions().lock() else {
            return -200;
        };
        match assemble_virtual_raid_image(&mut map, &member_session_ids, &layout, &artifact_path) {
            Ok(size) => size,
            Err(status) => {
                let _ = fs::remove_file(&artifact_path);
                return status;
            }
        }
    };

    let artifact_str = artifact_path.to_string_lossy().to_string();
    let virtual_session =
        match fr_winio::ReadSession::open(&artifact_str, RecoverySourceKind::ImageFile) {
            Ok(session) => session,
            Err(err) => {
                let _ = fs::remove_file(&artifact_path);
                return map_winio_error(err);
            }
        };
    let exposed_size = virtual_session.size_bytes().unwrap_or(assembled_size);
    let virtual_session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);

    {
        let Ok(mut map) = read_sessions().lock() else {
            let _ = fs::remove_file(&artifact_path);
            return -200;
        };
        map.insert(virtual_session_id, virtual_session);
    }

    {
        let Ok(mut map) = virtual_raid_sessions().lock() else {
            if let Ok(mut read_map) = read_sessions().lock() {
                read_map.remove(&virtual_session_id);
            }
            let _ = fs::remove_file(&artifact_path);
            return -200;
        };
        map.insert(
            virtual_session_id,
            VirtualRaidSessionMeta {
                layout: layout.clone(),
                artifact_path: artifact_path.clone(),
            },
        );
    }

    unsafe {
        *out_session_id = virtual_session_id;
        *out_layout = encode_raid_layout(&layout);
    }
    if !out_size_bytes.is_null() {
        unsafe {
            *out_size_bytes = exposed_size;
        }
    }

    0
}

#[no_mangle]
pub extern "C" fn fr_probe_virtual_raid_session(
    virtual_session_id: u64,
    out_layout: *mut FrRaidLayout,
) -> i32 {
    if out_layout.is_null() {
        return -1;
    }

    let Ok(map) = virtual_raid_sessions().lock() else {
        return -200;
    };
    let Some(meta) = map.get(&virtual_session_id) else {
        return 20;
    };

    unsafe {
        *out_layout = encode_raid_layout(&meta.layout);
    }
    0
}

#[no_mangle]
pub extern "C" fn fr_close_virtual_raid_session(virtual_session_id: u64) -> i32 {
    close_virtual_raid_session_internal(virtual_session_id)
}

#[no_mangle]
pub extern "C" fn fr_map_raid_logical_offset(
    layout: *const FrRaidLayout,
    logical_offset_bytes: u64,
    out_mapping: *mut FrRaidLogicalMapping,
) -> i32 {
    if layout.is_null() || out_mapping.is_null() {
        return -1;
    }

    let layout = match decode_raid_layout(unsafe { &*layout }) {
        Ok(layout) => layout,
        Err(status) => return status,
    };

    let mapping = match map_raid_logical_offset(&layout, logical_offset_bytes) {
        Ok(mapping) => mapping,
        Err(err) => return map_raid_error_to_status(err, true),
    };

    unsafe {
        *out_mapping = encode_raid_mapping(&mapping);
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
    fr_get_carve_candidates_from_session_window(
        session_id,
        family_flags,
        0,
        max_scan_bytes,
        out_candidates,
        candidate_capacity,
        out_written,
    )
}

#[no_mangle]
pub extern "C" fn fr_get_carve_candidates_from_session_window(
    session_id: u64,
    family_flags: u32,
    window_offset_bytes: u64,
    window_length_bytes: u64,
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

    let bytes = match read_window_for_carving(session, window_offset_bytes, window_length_bytes) {
        Ok(data) => data,
        Err(err) => return map_winio_error(err),
    };

    if bytes.is_empty() {
        return 0;
    }

    let plan = build_carving_plan(family_flags, window_length_bytes);
    let mut candidates = carve_bytes(&plan, &bytes);
    if window_offset_bytes > 0 {
        let Ok(base_offset) = usize::try_from(window_offset_bytes) else {
            return -4;
        };
        for candidate in &mut candidates {
            candidate.offset = candidate.offset.saturating_add(base_offset);
            candidate.id = format!("carve-{:?}-{:x}", candidate.format, candidate.offset);
        }
    }

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
pub extern "C" fn fr_recover_ext_candidate_to_file(
    session_id: u64,
    inode_number: u64,
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

    if inode_number == 0 {
        return 91;
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

    let mut header = [0u8; 4096];
    match read_from_session(session, 0, &mut header) {
        Ok(true) => {}
        Ok(false) => return 31,
        Err(err) => return map_winio_error(err),
    }

    let Ok(superblock) = parse_ext_superblock(&header) else {
        return 90;
    };

    let inode_offset = match locate_ext_inode_offset(session, &superblock, inode_number) {
        Ok(Some(offset)) => offset,
        Ok(None) => return 91,
        Err(status) => return status,
    };

    let inode_size = superblock.inode_size_bytes as usize;
    if inode_size < 128 {
        return 91;
    }

    let mut inode = vec![0u8; inode_size];
    match read_from_session(session, inode_offset, &mut inode) {
        Ok(true) => {}
        Ok(false) => return 91,
        Err(err) => return map_winio_error(err),
    }

    let mode = read_u16_le_at(&inode, 0);
    let inode_type = mode & 0xF000;
    let is_regular_file = inode_type == 0x8000;
    let is_symlink = inode_type == 0xA000;
    let is_directory = inode_type == 0x4000;
    if !is_regular_file && !is_symlink && !is_directory {
        return 91;
    }

    let size_lo = read_u32_le_at(&inode, 4) as u64;
    let size_hi = if inode_size >= EXT_INODE_SIZE_HIGH_OFFSET + 4 {
        read_u32_le_at(&inode, EXT_INODE_SIZE_HIGH_OFFSET) as u64
    } else {
        0
    };
    let file_size = (size_hi << 32) | size_lo;

    let output_path = Path::new(output_path_str);
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() && fs::create_dir_all(parent).is_err() {
            return 44;
        }
    }

    let Ok(mut output_file) = File::create(output_path) else {
        return 44;
    };

    let (written, partial) = if is_symlink && file_size <= (15 * 4) as u64 {
        let written = match recover_ext_inline_symlink_data(&inode, file_size, &mut output_file) {
            Ok(bytes) => bytes,
            Err(status) => return status,
        };
        (written, false)
    } else {
        match recover_ext_candidate_data(session, &superblock, &inode, file_size, &mut output_file)
        {
            Ok(result) => result,
            Err(status) => return status,
        }
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

    if written == 0 && file_size > 0 {
        return 76;
    }

    0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataRecoveryKind {
    Refs,
    Apfs,
    Hfs,
    Xfs,
    Ufs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MetadataPayloadDescriptor {
    offset_bytes: u64,
    length_bytes: u64,
}

#[no_mangle]
pub extern "C" fn fr_recover_refs_candidate_to_file(
    session_id: u64,
    object_id: u64,
    output_path: *const c_char,
    out_bytes_written: *mut u64,
    out_partial: *mut i32,
) -> i32 {
    recover_metadata_payload_candidate_to_file(
        session_id,
        object_id,
        output_path,
        out_bytes_written,
        out_partial,
        MetadataRecoveryKind::Refs,
    )
}

#[no_mangle]
pub extern "C" fn fr_recover_apfs_candidate_to_file(
    session_id: u64,
    cnid: u64,
    output_path: *const c_char,
    out_bytes_written: *mut u64,
    out_partial: *mut i32,
) -> i32 {
    recover_metadata_payload_candidate_to_file(
        session_id,
        cnid,
        output_path,
        out_bytes_written,
        out_partial,
        MetadataRecoveryKind::Apfs,
    )
}

#[no_mangle]
pub extern "C" fn fr_recover_hfs_candidate_to_file(
    session_id: u64,
    cnid: u32,
    output_path: *const c_char,
    out_bytes_written: *mut u64,
    out_partial: *mut i32,
) -> i32 {
    recover_metadata_payload_candidate_to_file(
        session_id,
        cnid as u64,
        output_path,
        out_bytes_written,
        out_partial,
        MetadataRecoveryKind::Hfs,
    )
}

#[no_mangle]
pub extern "C" fn fr_recover_xfs_candidate_to_file(
    session_id: u64,
    inode_number: u64,
    output_path: *const c_char,
    out_bytes_written: *mut u64,
    out_partial: *mut i32,
) -> i32 {
    recover_metadata_payload_candidate_to_file(
        session_id,
        inode_number,
        output_path,
        out_bytes_written,
        out_partial,
        MetadataRecoveryKind::Xfs,
    )
}

#[no_mangle]
pub extern "C" fn fr_recover_ufs_candidate_to_file(
    session_id: u64,
    inode_number: u32,
    output_path: *const c_char,
    out_bytes_written: *mut u64,
    out_partial: *mut i32,
) -> i32 {
    recover_metadata_payload_candidate_to_file(
        session_id,
        inode_number as u64,
        output_path,
        out_bytes_written,
        out_partial,
        MetadataRecoveryKind::Ufs,
    )
}

fn recover_metadata_payload_candidate_to_file(
    session_id: u64,
    candidate_id: u64,
    output_path: *const c_char,
    out_bytes_written: *mut u64,
    out_partial: *mut i32,
    kind: MetadataRecoveryKind,
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

    if candidate_id == 0 {
        return RECOVERY_STATUS_UNSUPPORTED_LAYOUT;
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

    let image = match kind {
        MetadataRecoveryKind::Refs => read_prefix_for_refs_scan(session),
        MetadataRecoveryKind::Apfs => read_prefix_for_apfs_scan(session),
        MetadataRecoveryKind::Hfs => read_prefix_for_hfs_scan(session),
        MetadataRecoveryKind::Xfs => read_prefix_for_xfs_scan(session),
        MetadataRecoveryKind::Ufs => read_prefix_for_ufs_scan(session),
    };
    let image = match image {
        Ok(bytes) => bytes,
        Err(err) => return map_winio_error(err),
    };
    if image.is_empty() {
        return 31;
    }

    let descriptor = match kind {
        MetadataRecoveryKind::Refs => find_refs_payload_descriptor(&image, candidate_id),
        MetadataRecoveryKind::Apfs => find_metadata_tombstone_payload_descriptor_u64(
            &image,
            APFS_TOMBSTONE_MARKER,
            APFS_TOMBSTONE_RECORD_SIZE,
            8,
            16,
            24,
            candidate_id,
        ),
        MetadataRecoveryKind::Hfs => find_metadata_tombstone_payload_descriptor_u32(
            &image,
            HFS_TOMBSTONE_MARKER,
            HFS_TOMBSTONE_RECORD_SIZE,
            8,
            12,
            20,
            candidate_id as u32,
        ),
        MetadataRecoveryKind::Xfs => find_metadata_tombstone_payload_descriptor_u64(
            &image,
            XFS_TOMBSTONE_MARKER,
            XFS_TOMBSTONE_RECORD_SIZE,
            8,
            16,
            24,
            candidate_id,
        ),
        MetadataRecoveryKind::Ufs => find_metadata_tombstone_payload_descriptor_u32(
            &image,
            UFS_TOMBSTONE_MARKER,
            UFS_TOMBSTONE_RECORD_SIZE,
            8,
            12,
            20,
            candidate_id as u32,
        ),
    };
    let descriptor = match descriptor {
        Ok(value) => value,
        Err(status) => return status,
    };

    if descriptor.length_bytes == 0 {
        return RECOVERY_STATUS_UNSUPPORTED_LAYOUT;
    }

    let output_path = Path::new(output_path_str);
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() && fs::create_dir_all(parent).is_err() {
            return 44;
        }
    }

    let Ok(mut output_file) = File::create(output_path) else {
        return 44;
    };

    let (written, partial) = match copy_session_range_to_file(
        session,
        descriptor.offset_bytes,
        descriptor.length_bytes,
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

    0
}

fn find_refs_payload_descriptor(
    image: &[u8],
    object_id: u64,
) -> Result<MetadataPayloadDescriptor, i32> {
    if object_id == 0 || image.len() < REFS_PAYLOAD_DESCRIPTOR_SIZE {
        return Err(RECOVERY_STATUS_UNSUPPORTED_LAYOUT);
    }

    let mut offset = 0usize;
    while offset + REFS_PAYLOAD_DESCRIPTOR_SIZE <= image.len() {
        if image[offset..offset + REFS_PAYLOAD_MARKER.len()] == REFS_PAYLOAD_MARKER[..] {
            let descriptor = &image[offset..offset + REFS_PAYLOAD_DESCRIPTOR_SIZE];
            let descriptor_object_id = read_u64_le_at(descriptor, 8);
            if descriptor_object_id == object_id {
                let flags = descriptor[32];
                if flags & METADATA_ENCRYPTED_FLAG != 0 {
                    return Err(RECOVERY_STATUS_ENCRYPTED_LOCKED);
                }

                let payload_offset = read_u64_le_at(descriptor, 16);
                let payload_length = read_u64_le_at(descriptor, 24);
                if payload_length == 0 || payload_offset.checked_add(payload_length).is_none() {
                    return Err(RECOVERY_STATUS_UNSUPPORTED_LAYOUT);
                }

                return Ok(MetadataPayloadDescriptor {
                    offset_bytes: payload_offset,
                    length_bytes: payload_length,
                });
            }

            offset = offset.saturating_add(REFS_PAYLOAD_DESCRIPTOR_SIZE);
            continue;
        }

        offset = offset.saturating_add(1);
    }

    Err(RECOVERY_STATUS_UNSUPPORTED_LAYOUT)
}

fn find_metadata_tombstone_payload_descriptor_u64(
    image: &[u8],
    marker: &[u8; 8],
    record_size: usize,
    id_offset: usize,
    _size_offset: usize,
    flags_offset: usize,
    candidate_id: u64,
) -> Result<MetadataPayloadDescriptor, i32> {
    if candidate_id == 0 || record_size == 0 || image.len() < record_size {
        return Err(RECOVERY_STATUS_UNSUPPORTED_LAYOUT);
    }

    let mut offset = 0usize;
    while offset + record_size <= image.len() {
        if image[offset..offset + marker.len()] == marker[..] {
            let record = &image[offset..offset + record_size];
            let record_candidate_id = read_u64_le_at(record, id_offset);
            if record_candidate_id == candidate_id {
                if flags_offset >= record.len() {
                    return Err(RECOVERY_STATUS_UNSUPPORTED_LAYOUT);
                }
                let flags = record[flags_offset];
                if flags & METADATA_ENCRYPTED_FLAG != 0 {
                    return Err(RECOVERY_STATUS_ENCRYPTED_LOCKED);
                }
                return parse_payload_descriptor_after_record(image, offset, record_size);
            }

            offset = offset.saturating_add(record_size);
            continue;
        }

        offset = offset.saturating_add(1);
    }

    Err(RECOVERY_STATUS_UNSUPPORTED_LAYOUT)
}

fn find_metadata_tombstone_payload_descriptor_u32(
    image: &[u8],
    marker: &[u8; 8],
    record_size: usize,
    id_offset: usize,
    _size_offset: usize,
    flags_offset: usize,
    candidate_id: u32,
) -> Result<MetadataPayloadDescriptor, i32> {
    if candidate_id == 0 || record_size == 0 || image.len() < record_size {
        return Err(RECOVERY_STATUS_UNSUPPORTED_LAYOUT);
    }

    let mut offset = 0usize;
    while offset + record_size <= image.len() {
        if image[offset..offset + marker.len()] == marker[..] {
            let record = &image[offset..offset + record_size];
            let record_candidate_id = read_u32_le_at(record, id_offset);
            if record_candidate_id == candidate_id {
                if flags_offset >= record.len() {
                    return Err(RECOVERY_STATUS_UNSUPPORTED_LAYOUT);
                }
                let flags = record[flags_offset];
                if flags & METADATA_ENCRYPTED_FLAG != 0 {
                    return Err(RECOVERY_STATUS_ENCRYPTED_LOCKED);
                }
                return parse_payload_descriptor_after_record(image, offset, record_size);
            }

            offset = offset.saturating_add(record_size);
            continue;
        }

        offset = offset.saturating_add(1);
    }

    Err(RECOVERY_STATUS_UNSUPPORTED_LAYOUT)
}

fn parse_payload_descriptor_after_record(
    image: &[u8],
    record_offset: usize,
    record_size: usize,
) -> Result<MetadataPayloadDescriptor, i32> {
    let Some(descriptor_offset) = record_offset.checked_add(record_size) else {
        return Err(RECOVERY_STATUS_UNSUPPORTED_LAYOUT);
    };
    let Some(descriptor_end) = descriptor_offset.checked_add(PAYLOAD_DESCRIPTOR_SIZE) else {
        return Err(RECOVERY_STATUS_UNSUPPORTED_LAYOUT);
    };
    if descriptor_end > image.len() {
        return Err(RECOVERY_STATUS_UNSUPPORTED_LAYOUT);
    }

    let payload_offset = read_u64_le_at(image, descriptor_offset);
    let payload_length = read_u64_le_at(image, descriptor_offset + 8);
    if payload_length == 0 || payload_offset.checked_add(payload_length).is_none() {
        return Err(RECOVERY_STATUS_UNSUPPORTED_LAYOUT);
    }

    Ok(MetadataPayloadDescriptor {
        offset_bytes: payload_offset,
        length_bytes: payload_length,
    })
}

fn copy_session_range_to_file(
    session: &mut fr_winio::ReadSession,
    offset_bytes: u64,
    length_bytes: u64,
    output_file: &mut File,
) -> Result<(u64, bool), i32> {
    if length_bytes == 0 {
        return Err(RECOVERY_STATUS_UNSUPPORTED_LAYOUT);
    }

    let mut scratch = vec![0u8; 1024 * 1024];
    let mut copied = 0u64;
    let mut partial = false;
    while copied < length_bytes {
        let left = length_bytes - copied;
        let chunk_len = left.min(scratch.len() as u64) as usize;
        let current_offset = match offset_bytes.checked_add(copied) {
            Some(value) => value,
            None => return Err(RECOVERY_STATUS_UNSUPPORTED_LAYOUT),
        };

        match read_from_session(session, current_offset, &mut scratch[..chunk_len]) {
            Ok(true) => {}
            Ok(false) => {
                if copied == 0 {
                    return Err(RECOVERY_STATUS_UNREADABLE_RANGE);
                }
                partial = true;
                break;
            }
            Err(_) => {
                if copied == 0 {
                    return Err(RECOVERY_STATUS_UNREADABLE_RANGE);
                }
                partial = true;
                break;
            }
        }

        if output_file.write_all(&scratch[..chunk_len]).is_err() {
            return Err(44);
        }
        copied = copied.saturating_add(chunk_len as u64);
    }

    Ok((copied, partial))
}

fn delete_virtual_raid_artifact(path: &Path) {
    let _ = fs::remove_file(path);
}

fn close_source_session_internal(session_id: u64) -> i32 {
    let removed = {
        let Ok(mut map) = read_sessions().lock() else {
            return -200;
        };
        map.remove(&session_id).is_some()
    };

    if !removed {
        return 20;
    }

    if let Ok(mut map) = virtual_raid_sessions().lock() {
        if let Some(meta) = map.remove(&session_id) {
            delete_virtual_raid_artifact(&meta.artifact_path);
        }
    }

    0
}

fn close_virtual_raid_session_internal(virtual_session_id: u64) -> i32 {
    let meta = {
        let Ok(map) = virtual_raid_sessions().lock() else {
            return -200;
        };
        match map.get(&virtual_session_id) {
            Some(value) => value.clone(),
            None => return 20,
        }
    };

    let close_status = close_source_session_internal(virtual_session_id);
    if close_status != 0 && close_status != 20 {
        return close_status;
    }

    if let Ok(mut map) = virtual_raid_sessions().lock() {
        map.remove(&virtual_session_id);
    }
    delete_virtual_raid_artifact(&meta.artifact_path);

    if close_status == 20 {
        20
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn fr_close_source_session(session_id: u64) -> i32 {
    close_source_session_internal(session_id)
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

fn encode_carve_signature_pack_metadata() -> FrCarveSignaturePackMetadata {
    let mut out = FrCarveSignaturePackMetadata {
        pack_name: [0u8; 64],
        pack_version: [0u8; 32],
        format_count: 0,
        family_flags: 0,
        formats_csv: [0u8; 512],
    };

    write_utf8(SIGNATURE_PACK_NAME, &mut out.pack_name);
    write_utf8(SIGNATURE_PACK_VERSION, &mut out.pack_version);

    let formats = signature_pack_formats();
    out.format_count = usize_to_u32_saturating(formats.len());

    let mut family_flags = 0u32;
    let mut extensions = Vec::with_capacity(formats.len());
    for format in formats {
        let extension = format.default_extension();
        family_flags |= carve_family_flag_for_extension(extension);
        extensions.push(extension);
    }
    out.family_flags = family_flags;

    extensions.sort_unstable();
    extensions.dedup();
    let csv = extensions.join(",");
    write_utf8(&csv, &mut out.formats_csv);

    out
}

fn carve_family_flag_for_extension(extension: &str) -> u32 {
    match extension {
        "jpg" | "png" | "gif" | "bmp" | "tiff" | "webp" => CARVE_FAMILY_IMAGES,
        "pdf" | "txt" | "rtf" => CARVE_FAMILY_DOCUMENTS,
        "zip" | "gz" | "7z" | "rar" => CARVE_FAMILY_ARCHIVES,
        "docx" | "xlsx" | "pptx" => CARVE_FAMILY_OFFICE,
        "mp4" | "avi" | "mid" | "ogg" | "flac" | "mp3" | "wav" => CARVE_FAMILY_MEDIA,
        _ => 0,
    }
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

fn encode_refs_deleted_candidate(
    candidate: &fr_refs::RefsDeletedCandidate,
) -> FrRefsDeletedCandidate {
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

fn encode_ext_deleted_candidate(candidate: &fr_ext::ExtDeletedCandidate) -> FrExtDeletedCandidate {
    let mut flags = EXT_DELETED_CANDIDATE_FLAG_DELETED;
    if candidate.is_directory {
        flags |= EXT_DELETED_CANDIDATE_FLAG_DIRECTORY;
    }

    let mut out = FrExtDeletedCandidate {
        flags,
        inode_number: candidate.inode_number,
        entry_offset_bytes: candidate.entry_offset_bytes,
        size_bytes: candidate.size_bytes,
        name: [0u8; 128],
        reconstructed_path: [0u8; 256],
    };
    write_utf8(&candidate.name, &mut out.name);
    write_utf8(&candidate.path, &mut out.reconstructed_path);
    out
}

fn encode_apfs_deleted_candidate(
    candidate: &fr_apfs::ApfsDeletedCandidate,
) -> FrApfsDeletedCandidate {
    let mut flags = APFS_DELETED_CANDIDATE_FLAG_DELETED;
    if candidate.is_directory {
        flags |= APFS_DELETED_CANDIDATE_FLAG_DIRECTORY;
    }

    let mut out = FrApfsDeletedCandidate {
        flags,
        _reserved0: 0,
        cnid: candidate.cnid,
        size_bytes: candidate.size_bytes,
        name: [0u8; 128],
        reconstructed_path: [0u8; 256],
    };
    write_utf8(&candidate.name, &mut out.name);
    write_utf8(&candidate.path, &mut out.reconstructed_path);
    out
}

fn encode_hfs_deleted_candidate(candidate: &fr_hfs::HfsDeletedCandidate) -> FrHfsDeletedCandidate {
    let mut flags = HFS_DELETED_CANDIDATE_FLAG_DELETED;
    if candidate.is_directory {
        flags |= HFS_DELETED_CANDIDATE_FLAG_DIRECTORY;
    }

    let mut out = FrHfsDeletedCandidate {
        flags,
        cnid: candidate.cnid,
        size_bytes: candidate.size_bytes,
        name: [0u8; 128],
        reconstructed_path: [0u8; 256],
    };
    write_utf8(&candidate.name, &mut out.name);
    write_utf8(&candidate.path, &mut out.reconstructed_path);
    out
}

fn encode_xfs_deleted_candidate(candidate: &fr_xfs::XfsDeletedCandidate) -> FrXfsDeletedCandidate {
    let mut flags = XFS_DELETED_CANDIDATE_FLAG_DELETED;
    if candidate.is_directory {
        flags |= XFS_DELETED_CANDIDATE_FLAG_DIRECTORY;
    }

    let mut out = FrXfsDeletedCandidate {
        flags,
        inode_number: candidate.inode_number,
        size_bytes: candidate.size_bytes,
        name: [0u8; 128],
        reconstructed_path: [0u8; 256],
    };
    write_utf8(&candidate.name, &mut out.name);
    write_utf8(&candidate.path, &mut out.reconstructed_path);
    out
}

fn encode_ufs_deleted_candidate(candidate: &fr_ufs::UfsDeletedCandidate) -> FrUfsDeletedCandidate {
    let mut flags = UFS_DELETED_CANDIDATE_FLAG_DELETED;
    if candidate.is_directory {
        flags |= UFS_DELETED_CANDIDATE_FLAG_DIRECTORY;
    }

    let mut out = FrUfsDeletedCandidate {
        flags,
        inode_number: candidate.inode_number,
        _reserved0: 0,
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

fn encode_raid_layout(layout: &RaidLayout) -> FrRaidLayout {
    let mut out = FrRaidLayout {
        metadata_family: encode_raid_metadata_family(layout.metadata_family),
        level: encode_raid_level(layout.level),
        member_count: layout.member_count,
        stripe_size_bytes: layout.stripe_size_bytes,
        data_offset_bytes: layout.data_offset_bytes,
        parity_rotation: encode_raid_parity_rotation(layout.parity_rotation),
        confidence_score: layout.confidence_score,
        _reserved0: [0u8; 3],
        disk_order_count: layout.disk_order.len().min(RAID_LAYOUT_MAX_MEMBERS) as u32,
        disk_order: [0u32; RAID_LAYOUT_MAX_MEMBERS],
    };

    for (index, value) in layout
        .disk_order
        .iter()
        .take(RAID_LAYOUT_MAX_MEMBERS)
        .enumerate()
    {
        out.disk_order[index] = *value;
    }

    out
}

fn decode_raid_layout(layout: &FrRaidLayout) -> Result<RaidLayout, i32> {
    if layout.member_count < 2 || layout.member_count as usize > RAID_LAYOUT_MAX_MEMBERS {
        return Err(142);
    }

    let metadata_family = match decode_raid_metadata_family(layout.metadata_family) {
        Some(value) => value,
        None => return Err(142),
    };
    let level = match decode_raid_level(layout.level) {
        Some(value) => value,
        None => return Err(142),
    };
    let parity_rotation = match decode_raid_parity_rotation(layout.parity_rotation) {
        Some(value) => value,
        None => return Err(142),
    };

    let disk_order_count = layout
        .disk_order_count
        .min(layout.member_count)
        .min(RAID_LAYOUT_MAX_MEMBERS as u32) as usize;
    let disk_order = if disk_order_count == 0 {
        (0..layout.member_count).collect()
    } else {
        layout.disk_order[..disk_order_count].to_vec()
    };

    Ok(RaidLayout {
        metadata_family,
        level,
        member_count: layout.member_count,
        stripe_size_bytes: layout.stripe_size_bytes,
        data_offset_bytes: layout.data_offset_bytes,
        parity_rotation,
        disk_order,
        confidence_score: layout.confidence_score,
    })
}

fn decode_raid_manual_override(raw: &FrRaidManualOverride) -> Result<RaidManualOverride, i32> {
    let mut out = RaidManualOverride::default();

    if raw.flags & RAID_MANUAL_OVERRIDE_FLAG_LEVEL != 0 {
        out.level = match decode_raid_level(raw.level) {
            Some(value) => Some(value),
            None => return Err(142),
        };
    }
    if raw.flags & RAID_MANUAL_OVERRIDE_FLAG_STRIPE_SIZE != 0 {
        out.stripe_size_bytes = Some(raw.stripe_size_bytes);
    }
    if raw.flags & RAID_MANUAL_OVERRIDE_FLAG_DATA_OFFSET != 0 {
        out.data_offset_bytes = Some(raw.data_offset_bytes);
    }
    if raw.flags & RAID_MANUAL_OVERRIDE_FLAG_PARITY_ROTATION != 0 {
        out.parity_rotation = match decode_raid_parity_rotation(raw.parity_rotation) {
            Some(value) => Some(value),
            None => return Err(142),
        };
    }
    if raw.flags & RAID_MANUAL_OVERRIDE_FLAG_DISK_ORDER != 0 {
        if raw.disk_order_count == 0 || raw.disk_order_count as usize > RAID_LAYOUT_MAX_MEMBERS {
            return Err(142);
        }

        out.disk_order = Some(raw.disk_order[..raw.disk_order_count as usize].to_vec());
    }

    Ok(out)
}

fn encode_raid_mapping(mapping: &RaidLogicalMapping) -> FrRaidLogicalMapping {
    FrRaidLogicalMapping {
        member_index: mapping.member_index,
        member_offset_bytes: mapping.member_offset_bytes,
        has_parity_member: u32::from(mapping.parity_member_index.is_some()),
        parity_member_index: mapping.parity_member_index.unwrap_or(0),
    }
}

fn encode_raid_metadata_family(family: RaidMetadataFamily) -> u32 {
    match family {
        RaidMetadataFamily::LinuxMd => RAID_METADATA_FAMILY_LINUX_MD,
        RaidMetadataFamily::WindowsStorageSpaces => RAID_METADATA_FAMILY_WINDOWS_STORAGE_SPACES,
    }
}

fn decode_raid_metadata_family(value: u32) -> Option<RaidMetadataFamily> {
    match value {
        RAID_METADATA_FAMILY_LINUX_MD => Some(RaidMetadataFamily::LinuxMd),
        RAID_METADATA_FAMILY_WINDOWS_STORAGE_SPACES => {
            Some(RaidMetadataFamily::WindowsStorageSpaces)
        }
        _ => None,
    }
}

fn encode_raid_level(level: RaidLevel) -> u32 {
    match level {
        RaidLevel::Raid0 => RAID_LEVEL_RAID0,
        RaidLevel::Raid1 => RAID_LEVEL_RAID1,
        RaidLevel::Raid4 => RAID_LEVEL_RAID4,
        RaidLevel::Raid5 => RAID_LEVEL_RAID5,
        RaidLevel::Raid6 => RAID_LEVEL_RAID6,
        RaidLevel::Raid10 => RAID_LEVEL_RAID10,
        RaidLevel::Unknown => RAID_LEVEL_UNKNOWN,
    }
}

fn decode_raid_level(value: u32) -> Option<RaidLevel> {
    match value {
        RAID_LEVEL_RAID0 => Some(RaidLevel::Raid0),
        RAID_LEVEL_RAID1 => Some(RaidLevel::Raid1),
        RAID_LEVEL_RAID4 => Some(RaidLevel::Raid4),
        RAID_LEVEL_RAID5 => Some(RaidLevel::Raid5),
        RAID_LEVEL_RAID6 => Some(RaidLevel::Raid6),
        RAID_LEVEL_RAID10 => Some(RaidLevel::Raid10),
        RAID_LEVEL_UNKNOWN => Some(RaidLevel::Unknown),
        _ => None,
    }
}

fn encode_raid_parity_rotation(rotation: ParityRotation) -> u32 {
    match rotation {
        ParityRotation::LeftSymmetric => RAID_PARITY_LEFT_SYMMETRIC,
        ParityRotation::RightSymmetric => RAID_PARITY_RIGHT_SYMMETRIC,
        ParityRotation::Unknown => RAID_PARITY_UNKNOWN,
    }
}

fn decode_raid_parity_rotation(value: u32) -> Option<ParityRotation> {
    match value {
        RAID_PARITY_LEFT_SYMMETRIC => Some(ParityRotation::LeftSymmetric),
        RAID_PARITY_RIGHT_SYMMETRIC => Some(ParityRotation::RightSymmetric),
        RAID_PARITY_UNKNOWN => Some(ParityRotation::Unknown),
        _ => None,
    }
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

#[derive(Debug, Clone, Copy)]
struct ExtentRun {
    logical_block: u64,
    physical_block: u64,
    block_count: u64,
    is_uninitialized: bool,
}

fn recover_ext_inline_symlink_data(
    inode: &[u8],
    file_size: u64,
    output_file: &mut File,
) -> Result<u64, i32> {
    if file_size == 0 {
        return Ok(0);
    }

    let inline_capacity = 15 * 4;
    if inode.len() < EXT_INODE_BLOCK_POINTERS_OFFSET + inline_capacity {
        return Err(91);
    }

    let inline_len = file_size as usize;
    if inline_len > inline_capacity {
        return Err(91);
    }

    let inline_start = EXT_INODE_BLOCK_POINTERS_OFFSET;
    let inline_end = inline_start + inline_len;
    if output_file
        .write_all(&inode[inline_start..inline_end])
        .is_err()
    {
        return Err(44);
    }

    Ok(file_size)
}

fn recover_ext_candidate_data(
    session: &mut fr_winio::ReadSession,
    superblock: &fr_ext::ExtSuperblock,
    inode: &[u8],
    file_size: u64,
    output_file: &mut File,
) -> Result<(u64, bool), i32> {
    if file_size == 0 {
        return Ok((0, false));
    }

    let block_size = superblock.block_size_bytes as usize;
    if block_size < 1024 {
        return Err(91);
    }

    if inode.len() < EXT_INODE_BLOCK_POINTERS_OFFSET + (15 * 4) {
        return Err(91);
    }

    let inode_flags = read_u32_le_at(inode, EXT_INODE_FLAGS_OFFSET);
    if (inode_flags & EXT_INODE_FLAG_EXTENTS) != 0 {
        return recover_ext_extent_tree_data(
            session,
            block_size,
            &inode[EXT_INODE_BLOCK_POINTERS_OFFSET..EXT_INODE_BLOCK_POINTERS_OFFSET + (15 * 4)],
            file_size,
            output_file,
        );
    }

    let mut remaining = file_size;
    let mut written = 0u64;
    let mut partial = false;
    let mut block_buffer = vec![0u8; block_size];

    for pointer_index in 0..EXT_DIRECT_BLOCK_POINTERS {
        if remaining == 0 {
            break;
        }

        let pointer_offset = EXT_INODE_BLOCK_POINTERS_OFFSET + (pointer_index * 4);
        let block_pointer = read_u32_le_at(inode, pointer_offset);
        if block_pointer == 0 {
            partial = true;
            break;
        }

        let Some(block_offset) = (block_pointer as u64).checked_mul(block_size as u64) else {
            partial = true;
            break;
        };

        let to_read = remaining.min(block_size as u64) as usize;
        match read_from_session(session, block_offset, &mut block_buffer[..to_read]) {
            Ok(true) => {}
            Ok(false) => {
                partial = true;
                break;
            }
            Err(err) => return Err(map_winio_error(err)),
        }

        if output_file.write_all(&block_buffer[..to_read]).is_err() {
            return Err(44);
        }

        written = written.saturating_add(to_read as u64);
        remaining = remaining.saturating_sub(to_read as u64);
    }

    if remaining > 0 {
        let single_indirect_pointer = read_u32_le_at(
            inode,
            EXT_INODE_BLOCK_POINTERS_OFFSET + (EXT_SINGLE_INDIRECT_POINTER_INDEX * 4),
        );
        if single_indirect_pointer == 0 {
            partial = true;
        } else {
            let (single_written, single_partial) = recover_ext_single_indirect_data(
                session,
                block_size,
                single_indirect_pointer,
                remaining,
                output_file,
            )?;
            written = written.saturating_add(single_written);
            remaining = remaining.saturating_sub(single_written);
            partial |= single_partial;
        }
    }

    if remaining > 0 {
        let double_indirect_pointer = read_u32_le_at(
            inode,
            EXT_INODE_BLOCK_POINTERS_OFFSET + (EXT_DOUBLE_INDIRECT_POINTER_INDEX * 4),
        );
        if double_indirect_pointer == 0 {
            partial = true;
        } else {
            let (double_written, double_partial) = recover_ext_double_indirect_data(
                session,
                block_size,
                double_indirect_pointer,
                remaining,
                output_file,
            )?;
            written = written.saturating_add(double_written);
            remaining = remaining.saturating_sub(double_written);
            partial |= double_partial;
        }
    }

    if remaining > 0 {
        let triple_indirect_pointer = read_u32_le_at(
            inode,
            EXT_INODE_BLOCK_POINTERS_OFFSET + (EXT_TRIPLE_INDIRECT_POINTER_INDEX * 4),
        );
        if triple_indirect_pointer == 0 {
            partial = true;
        } else {
            let (triple_written, triple_partial) = recover_ext_triple_indirect_data(
                session,
                block_size,
                triple_indirect_pointer,
                remaining,
                output_file,
            )?;
            written = written.saturating_add(triple_written);
            remaining = remaining.saturating_sub(triple_written);
            partial |= triple_partial;
        }
    }

    if remaining > 0 {
        partial = true;
    }

    Ok((written, partial))
}

fn recover_ext_single_indirect_data(
    session: &mut fr_winio::ReadSession,
    block_size: usize,
    pointer_block: u32,
    mut remaining: u64,
    output_file: &mut File,
) -> Result<(u64, bool), i32> {
    if remaining == 0 {
        return Ok((0, false));
    }

    let Some(pointer_block_offset) = (pointer_block as u64).checked_mul(block_size as u64) else {
        return Ok((0, true));
    };

    let mut indirect_table = vec![0u8; block_size];
    match read_from_session(session, pointer_block_offset, &mut indirect_table) {
        Ok(true) => {}
        Ok(false) => return Ok((0, true)),
        Err(err) => return Err(map_winio_error(err)),
    }

    let mut data_block = vec![0u8; block_size];
    let mut written = 0u64;
    let mut partial = false;
    let entry_count = block_size / 4;
    let mut consumed_entries = 0usize;

    for entry_index in 0..entry_count {
        if remaining == 0 {
            break;
        }

        let block_pointer = read_u32_le_at(&indirect_table, entry_index * 4);
        if block_pointer == 0 {
            partial = true;
            break;
        }

        let Some(block_offset) = (block_pointer as u64).checked_mul(block_size as u64) else {
            partial = true;
            break;
        };

        let to_read = remaining.min(block_size as u64) as usize;
        match read_from_session(session, block_offset, &mut data_block[..to_read]) {
            Ok(true) => {}
            Ok(false) => {
                partial = true;
                break;
            }
            Err(err) => return Err(map_winio_error(err)),
        }

        if output_file.write_all(&data_block[..to_read]).is_err() {
            return Err(44);
        }

        consumed_entries = consumed_entries.saturating_add(1);
        written = written.saturating_add(to_read as u64);
        remaining = remaining.saturating_sub(to_read as u64);
    }

    if remaining > 0 {
        // Remaining bytes can still be recoverable via higher-level indirect trees.
        if consumed_entries < entry_count {
            partial = true;
        }
    }

    Ok((written, partial))
}

fn recover_ext_double_indirect_data(
    session: &mut fr_winio::ReadSession,
    block_size: usize,
    pointer_block: u32,
    mut remaining: u64,
    output_file: &mut File,
) -> Result<(u64, bool), i32> {
    if remaining == 0 {
        return Ok((0, false));
    }

    let Some(pointer_block_offset) = (pointer_block as u64).checked_mul(block_size as u64) else {
        return Ok((0, true));
    };

    let mut first_level_table = vec![0u8; block_size];
    match read_from_session(session, pointer_block_offset, &mut first_level_table) {
        Ok(true) => {}
        Ok(false) => return Ok((0, true)),
        Err(err) => return Err(map_winio_error(err)),
    }

    let mut second_level_table = vec![0u8; block_size];
    let mut data_block = vec![0u8; block_size];
    let mut written = 0u64;
    let mut partial = false;
    let entry_count = block_size / 4;

    'first_level: for first_index in 0..entry_count {
        if remaining == 0 {
            break;
        }

        let second_level_pointer = read_u32_le_at(&first_level_table, first_index * 4);
        if second_level_pointer == 0 {
            partial = true;
            break;
        }

        let Some(second_level_offset) =
            (second_level_pointer as u64).checked_mul(block_size as u64)
        else {
            partial = true;
            break;
        };

        match read_from_session(session, second_level_offset, &mut second_level_table) {
            Ok(true) => {}
            Ok(false) => {
                partial = true;
                break;
            }
            Err(err) => return Err(map_winio_error(err)),
        }

        for second_index in 0..entry_count {
            if remaining == 0 {
                break 'first_level;
            }

            let data_pointer = read_u32_le_at(&second_level_table, second_index * 4);
            if data_pointer == 0 {
                partial = true;
                break 'first_level;
            }

            let Some(data_offset) = (data_pointer as u64).checked_mul(block_size as u64) else {
                partial = true;
                break 'first_level;
            };

            let to_read = remaining.min(block_size as u64) as usize;
            match read_from_session(session, data_offset, &mut data_block[..to_read]) {
                Ok(true) => {}
                Ok(false) => {
                    partial = true;
                    break 'first_level;
                }
                Err(err) => return Err(map_winio_error(err)),
            }

            if output_file.write_all(&data_block[..to_read]).is_err() {
                return Err(44);
            }

            written = written.saturating_add(to_read as u64);
            remaining = remaining.saturating_sub(to_read as u64);
        }
    }

    if remaining > 0 {
        partial = true;
    }

    Ok((written, partial))
}

fn recover_ext_triple_indirect_data(
    session: &mut fr_winio::ReadSession,
    block_size: usize,
    pointer_block: u32,
    mut remaining: u64,
    output_file: &mut File,
) -> Result<(u64, bool), i32> {
    if remaining == 0 {
        return Ok((0, false));
    }

    let Some(pointer_block_offset) = (pointer_block as u64).checked_mul(block_size as u64) else {
        return Ok((0, true));
    };

    let mut first_level_table = vec![0u8; block_size];
    match read_from_session(session, pointer_block_offset, &mut first_level_table) {
        Ok(true) => {}
        Ok(false) => return Ok((0, true)),
        Err(err) => return Err(map_winio_error(err)),
    }

    let mut second_level_table = vec![0u8; block_size];
    let mut third_level_table = vec![0u8; block_size];
    let mut data_block = vec![0u8; block_size];
    let mut written = 0u64;
    let mut partial = false;
    let entry_count = block_size / 4;

    'first_level: for first_index in 0..entry_count {
        if remaining == 0 {
            break;
        }

        let second_level_pointer = read_u32_le_at(&first_level_table, first_index * 4);
        if second_level_pointer == 0 {
            partial = true;
            break;
        }

        let Some(second_level_offset) =
            (second_level_pointer as u64).checked_mul(block_size as u64)
        else {
            partial = true;
            break;
        };

        match read_from_session(session, second_level_offset, &mut second_level_table) {
            Ok(true) => {}
            Ok(false) => {
                partial = true;
                break;
            }
            Err(err) => return Err(map_winio_error(err)),
        }

        for second_index in 0..entry_count {
            if remaining == 0 {
                break 'first_level;
            }

            let third_level_pointer = read_u32_le_at(&second_level_table, second_index * 4);
            if third_level_pointer == 0 {
                partial = true;
                break 'first_level;
            }

            let Some(third_level_offset) =
                (third_level_pointer as u64).checked_mul(block_size as u64)
            else {
                partial = true;
                break 'first_level;
            };

            match read_from_session(session, third_level_offset, &mut third_level_table) {
                Ok(true) => {}
                Ok(false) => {
                    partial = true;
                    break 'first_level;
                }
                Err(err) => return Err(map_winio_error(err)),
            }

            for third_index in 0..entry_count {
                if remaining == 0 {
                    break 'first_level;
                }

                let data_pointer = read_u32_le_at(&third_level_table, third_index * 4);
                if data_pointer == 0 {
                    partial = true;
                    break 'first_level;
                }

                let Some(data_offset) = (data_pointer as u64).checked_mul(block_size as u64) else {
                    partial = true;
                    break 'first_level;
                };

                let to_read = remaining.min(block_size as u64) as usize;
                match read_from_session(session, data_offset, &mut data_block[..to_read]) {
                    Ok(true) => {}
                    Ok(false) => {
                        partial = true;
                        break 'first_level;
                    }
                    Err(err) => return Err(map_winio_error(err)),
                }

                if output_file.write_all(&data_block[..to_read]).is_err() {
                    return Err(44);
                }

                written = written.saturating_add(to_read as u64);
                remaining = remaining.saturating_sub(to_read as u64);
            }
        }
    }

    if remaining > 0 {
        partial = true;
    }

    Ok((written, partial))
}

fn recover_ext_extent_tree_data(
    session: &mut fr_winio::ReadSession,
    block_size: usize,
    root_node: &[u8],
    file_size: u64,
    output_file: &mut File,
) -> Result<(u64, bool), i32> {
    if file_size == 0 {
        return Ok((0, false));
    }

    let mut runs = Vec::new();
    let mut partial = false;
    collect_ext_extent_runs(
        session,
        block_size,
        root_node,
        None,
        &mut runs,
        &mut partial,
    )?;

    if runs.is_empty() {
        return Ok((0, true));
    }

    runs.sort_by_key(|run| run.logical_block);

    let mut remaining = file_size;
    let mut written = 0u64;
    let mut expected_logical_block = 0u64;
    let mut data_block = vec![0u8; block_size];
    let zero_block = vec![0u8; block_size];
    let mut stopped_early = false;

    'runs: for run in runs {
        if remaining == 0 {
            break;
        }

        if run.logical_block < expected_logical_block {
            partial = true;
            stopped_early = true;
            break;
        }

        while expected_logical_block < run.logical_block && remaining > 0 {
            let to_write = remaining.min(block_size as u64) as usize;
            if output_file.write_all(&zero_block[..to_write]).is_err() {
                return Err(44);
            }

            written = written.saturating_add(to_write as u64);
            remaining = remaining.saturating_sub(to_write as u64);
            expected_logical_block = expected_logical_block.saturating_add(1);
        }

        if remaining == 0 {
            break;
        }

        for block_index in 0..run.block_count {
            if remaining == 0 {
                break 'runs;
            }

            let to_read = remaining.min(block_size as u64) as usize;
            if run.is_uninitialized {
                if output_file.write_all(&zero_block[..to_read]).is_err() {
                    return Err(44);
                }
            } else {
                let Some(physical_block) = run.physical_block.checked_add(block_index) else {
                    partial = true;
                    stopped_early = true;
                    break 'runs;
                };
                let Some(block_offset) = physical_block.checked_mul(block_size as u64) else {
                    partial = true;
                    stopped_early = true;
                    break 'runs;
                };
                match read_from_session(session, block_offset, &mut data_block[..to_read]) {
                    Ok(true) => {}
                    Ok(false) => {
                        partial = true;
                        stopped_early = true;
                        break 'runs;
                    }
                    Err(err) => return Err(map_winio_error(err)),
                }

                if output_file.write_all(&data_block[..to_read]).is_err() {
                    return Err(44);
                }
            }

            written = written.saturating_add(to_read as u64);
            remaining = remaining.saturating_sub(to_read as u64);
            expected_logical_block = expected_logical_block.saturating_add(1);
        }
    }

    if !stopped_early {
        while remaining > 0 {
            let to_write = remaining.min(block_size as u64) as usize;
            if output_file.write_all(&zero_block[..to_write]).is_err() {
                return Err(44);
            }

            written = written.saturating_add(to_write as u64);
            remaining = remaining.saturating_sub(to_write as u64);
        }
    }

    if remaining > 0 {
        partial = true;
    }

    Ok((written, partial))
}

fn collect_ext_extent_runs(
    session: &mut fr_winio::ReadSession,
    block_size: usize,
    node_bytes: &[u8],
    expected_depth: Option<u16>,
    runs: &mut Vec<ExtentRun>,
    partial: &mut bool,
) -> Result<(), i32> {
    let Some((entry_count, depth)) = parse_ext_extent_header(node_bytes) else {
        return Err(91);
    };

    if let Some(expected_depth) = expected_depth {
        if depth != expected_depth {
            return Err(91);
        }
    }

    for entry_index in 0..entry_count as usize {
        let entry_offset = EXTENT_HEADER_SIZE + (entry_index * EXTENT_RECORD_SIZE);
        if entry_offset + EXTENT_RECORD_SIZE > node_bytes.len() {
            return Err(91);
        }

        if depth == 0 {
            let logical_block = read_u32_le_at(node_bytes, entry_offset) as u64;
            let raw_length = read_u16_le_at(node_bytes, entry_offset + 4);
            let block_count = (raw_length & !EXTENT_UNINITIALIZED_LENGTH_FLAG) as u64;
            if block_count == 0 {
                continue;
            }
            let is_uninitialized = (raw_length & EXTENT_UNINITIALIZED_LENGTH_FLAG) != 0;

            let start_hi = read_u16_le_at(node_bytes, entry_offset + 6) as u64;
            let start_lo = read_u32_le_at(node_bytes, entry_offset + 8) as u64;
            let physical_block = (start_hi << 32) | start_lo;
            if physical_block == 0 && !is_uninitialized {
                *partial = true;
                continue;
            }

            runs.push(ExtentRun {
                logical_block,
                physical_block,
                block_count,
                is_uninitialized,
            });
        } else {
            let leaf_lo = read_u32_le_at(node_bytes, entry_offset + 4) as u64;
            let leaf_hi = read_u16_le_at(node_bytes, entry_offset + 8) as u64;
            let child_block = (leaf_hi << 32) | leaf_lo;
            if child_block == 0 {
                *partial = true;
                continue;
            }

            let Some(child_offset) = child_block.checked_mul(block_size as u64) else {
                *partial = true;
                continue;
            };

            let mut child_node = vec![0u8; block_size];
            match read_from_session(session, child_offset, &mut child_node) {
                Ok(true) => {}
                Ok(false) => {
                    *partial = true;
                    continue;
                }
                Err(err) => return Err(map_winio_error(err)),
            }

            collect_ext_extent_runs(
                session,
                block_size,
                &child_node,
                Some(depth.saturating_sub(1)),
                runs,
                partial,
            )?;
        }
    }

    Ok(())
}

fn parse_ext_extent_header(node_bytes: &[u8]) -> Option<(u16, u16)> {
    if node_bytes.len() < EXTENT_HEADER_SIZE {
        return None;
    }

    if read_u16_le_at(node_bytes, 0) != EXTENT_HEADER_MAGIC {
        return None;
    }

    let entry_count = read_u16_le_at(node_bytes, 2);
    let max_entries = read_u16_le_at(node_bytes, 4);
    if entry_count > max_entries {
        return None;
    }
    let depth = read_u16_le_at(node_bytes, 6);
    if depth > 5 {
        return None;
    }

    Some((entry_count, depth))
}

fn locate_ext_inode_offset(
    session: &mut fr_winio::ReadSession,
    superblock: &fr_ext::ExtSuperblock,
    inode_number: u64,
) -> Result<Option<u64>, i32> {
    if inode_number == 0 {
        return Ok(None);
    }

    let inodes_per_group = superblock.inodes_per_group as u64;
    if inodes_per_group == 0 {
        return Ok(None);
    }

    let group_count = ext_group_count(superblock);
    if group_count == 0 {
        return Ok(None);
    }

    let inode_index = inode_number - 1;
    let group_index = inode_index / inodes_per_group;
    let index_in_group = inode_index % inodes_per_group;
    if group_index >= group_count {
        return Ok(None);
    }

    let Some(descriptor_offset) =
        ext_first_group_descriptor_offset(superblock).checked_add(group_index.saturating_mul(32))
    else {
        return Ok(None);
    };

    let mut descriptor = [0u8; 32];
    match read_from_session(session, descriptor_offset, &mut descriptor) {
        Ok(true) => {}
        Ok(false) => return Ok(None),
        Err(err) => return Err(map_winio_error(err)),
    }

    let inode_table_block = read_u32_le_at(&descriptor, EXT_GROUP_DESCRIPTOR_INODE_TABLE_OFFSET);
    if inode_table_block == 0 {
        return Ok(None);
    }

    let block_size = superblock.block_size_bytes as u64;
    let inode_size = superblock.inode_size_bytes as u64;

    let Some(inode_table_offset) = (inode_table_block as u64).checked_mul(block_size) else {
        return Ok(None);
    };
    let Some(inode_delta) = index_in_group.checked_mul(inode_size) else {
        return Ok(None);
    };
    let Some(inode_offset) = inode_table_offset.checked_add(inode_delta) else {
        return Ok(None);
    };

    Ok(Some(inode_offset))
}

fn ext_first_group_descriptor_offset(superblock: &fr_ext::ExtSuperblock) -> u64 {
    if superblock.block_size_bytes == 1024 {
        2048
    } else {
        superblock.block_size_bytes as u64
    }
}

fn ext_group_count(superblock: &fr_ext::ExtSuperblock) -> u64 {
    let block_groups = if superblock.blocks_per_group == 0 {
        0
    } else {
        superblock
            .blocks_count
            .saturating_add(superblock.blocks_per_group as u64 - 1)
            / superblock.blocks_per_group as u64
    };
    let inode_groups = if superblock.inodes_per_group == 0 {
        0
    } else {
        (superblock.inodes_count as u64).saturating_add(superblock.inodes_per_group as u64 - 1)
            / superblock.inodes_per_group as u64
    };

    block_groups.max(inode_groups)
}

fn read_u16_le_at(bytes: &[u8], offset: usize) -> u16 {
    let mut value = [0u8; 2];
    value.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_le_bytes(value)
}

fn read_u32_le_at(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn read_u64_le_at(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
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

fn read_window_for_carving(
    session: &mut fr_winio::ReadSession,
    window_offset_bytes: u64,
    window_length_bytes: u64,
) -> Result<Vec<u8>, fr_winio::WinIoError> {
    const UNKNOWN_SIZE_FALLBACK_SCAN_BYTES: u64 = 8 * 1024 * 1024;

    let normalized_window = normalize_max_scan_bytes(window_length_bytes);
    let scan_len_u64 = match session.size_bytes() {
        Some(source_len) => {
            if source_len <= window_offset_bytes {
                return Ok(Vec::new());
            }
            let available = source_len - window_offset_bytes;
            available.min(normalized_window)
        }
        None => normalized_window.min(UNKNOWN_SIZE_FALLBACK_SCAN_BYTES),
    };
    let scan_len =
        usize::try_from(scan_len_u64).map_err(|_| fr_winio::WinIoError::InvalidReadOffset)?;
    if scan_len == 0 {
        return Ok(Vec::new());
    }

    let mut bytes = vec![0u8; scan_len];
    if read_from_session(session, window_offset_bytes, &mut bytes)? {
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

fn read_prefix_for_ext_scan(
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

fn read_prefix_for_apfs_scan(
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

fn read_prefix_for_hfs_scan(
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

fn read_prefix_for_xfs_scan(
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

fn read_prefix_for_ufs_scan(
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

fn read_prefix_for_raid_scan(
    session: &mut fr_winio::ReadSession,
) -> Result<Vec<u8>, fr_winio::WinIoError> {
    const DEFAULT_SCAN_BYTES: u64 = 8 * 1024 * 1024;
    const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;

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

fn build_virtual_raid_artifact_path() -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = NEXT_VIRTUAL_RAID_ARTIFACT_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("fr-virtual-raid-{}-{}.img", timestamp, sequence))
}

fn detect_virtual_raid_layout(
    sessions: &mut HashMap<u64, fr_winio::ReadSession>,
    member_session_ids: &[u64],
    override_cfg: Option<&RaidManualOverride>,
) -> Result<RaidLayout, i32> {
    let mut detected = None;
    for session_id in member_session_ids {
        let Some(session) = sessions.get_mut(session_id) else {
            return Err(20);
        };
        let image = read_prefix_for_raid_scan(session).map_err(map_winio_error)?;
        if image.len() < 4096 {
            continue;
        }

        match resolve_layout_with_override(&image, override_cfg) {
            Ok(Some(layout)) => {
                detected = Some(layout);
                break;
            }
            Ok(None) => continue,
            Err(err) => return Err(map_raid_error_to_status(err, override_cfg.is_some())),
        }
    }

    let Some(layout) = detected else {
        return Err(140);
    };
    if layout.member_count as usize != member_session_ids.len() {
        return Err(141);
    }

    Ok(layout)
}

fn compute_virtual_raid_logical_size(
    layout: &RaidLayout,
    member_sizes: &[u64],
) -> Result<u64, fr_raid::RaidError> {
    if member_sizes.len() != layout.member_count as usize {
        return Err(fr_raid::RaidError::InvalidMemberCount(layout.member_count));
    }
    let stripe = layout.stripe_size_bytes as u64;
    if stripe == 0 {
        return Err(fr_raid::RaidError::InvalidStripeSize(
            layout.stripe_size_bytes,
        ));
    }

    let mut min_usable = u64::MAX;
    for member_size in member_sizes {
        if *member_size < layout.data_offset_bytes {
            return Err(fr_raid::RaidError::BufferTooSmall {
                expected: layout.data_offset_bytes as usize,
                actual: *member_size as usize,
            });
        }
        min_usable = min_usable.min(member_size - layout.data_offset_bytes);
    }

    let aligned_member_bytes = min_usable - (min_usable % stripe);
    let total = match layout.level {
        RaidLevel::Raid0 => aligned_member_bytes
            .checked_mul(layout.member_count as u64)
            .ok_or(fr_raid::RaidError::ArithmeticOverflow(
                "virtual raid0 logical size",
            ))?,
        RaidLevel::Raid1 => min_usable,
        RaidLevel::Raid4 | RaidLevel::Raid5 => {
            let data_disks = layout
                .member_count
                .checked_sub(1)
                .ok_or(fr_raid::RaidError::UnsupportedLayout)?;
            if data_disks == 0 {
                return Err(fr_raid::RaidError::UnsupportedLayout);
            }
            aligned_member_bytes.checked_mul(data_disks as u64).ok_or(
                fr_raid::RaidError::ArithmeticOverflow("virtual raid parity logical size"),
            )?
        }
        RaidLevel::Raid10 => {
            if layout.member_count < 4 || layout.member_count % 2 != 0 {
                return Err(fr_raid::RaidError::UnsupportedLayout);
            }
            aligned_member_bytes
                .checked_mul((layout.member_count / 2) as u64)
                .ok_or(fr_raid::RaidError::ArithmeticOverflow(
                    "virtual raid10 logical size",
                ))?
        }
        RaidLevel::Raid6 | RaidLevel::Unknown => return Err(fr_raid::RaidError::UnsupportedLayout),
    };

    Ok(total)
}

fn assemble_virtual_raid_image(
    sessions: &mut HashMap<u64, fr_winio::ReadSession>,
    member_session_ids: &[u64],
    layout: &RaidLayout,
    artifact_path: &Path,
) -> Result<u64, i32> {
    let mut member_sizes = Vec::with_capacity(member_session_ids.len());
    for session_id in member_session_ids {
        let Some(session) = sessions.get_mut(session_id) else {
            return Err(20);
        };
        member_sizes.push(session.size_bytes().unwrap_or(0));
    }

    let logical_size = compute_virtual_raid_logical_size(layout, &member_sizes)
        .map_err(|err| map_raid_error_to_status(err, false))?;
    if logical_size == 0 {
        return Err(141);
    }

    let mut output = File::create(artifact_path).map_err(|_| 44)?;
    let stripe = layout.stripe_size_bytes as u64;
    let chunk_size = stripe.max(4 * 1024).min(1024 * 1024) as usize;
    let mut scratch = vec![0u8; chunk_size];
    let mut logical_offset = 0u64;

    while logical_offset < logical_size {
        let mapping = map_raid_logical_offset(layout, logical_offset)
            .map_err(|err| map_raid_error_to_status(err, false))?;
        let member_position = mapping.member_index as usize;
        if member_position >= member_session_ids.len() {
            return Err(141);
        }

        let member_session_id = member_session_ids[member_position];
        let Some(member_session) = sessions.get_mut(&member_session_id) else {
            return Err(20);
        };

        let remaining = logical_size - logical_offset;
        let read_len = remaining.min(scratch.len() as u64) as usize;
        let read_slice = &mut scratch[..read_len];
        match read_from_session(member_session, mapping.member_offset_bytes, read_slice) {
            Ok(true) => {}
            Ok(false) => return Err(31),
            Err(err) => return Err(map_winio_error(err)),
        }

        output.write_all(read_slice).map_err(|_| 44)?;
        logical_offset = logical_offset.checked_add(read_len as u64).ok_or(141)?;
    }

    output.flush().map_err(|_| 44)?;
    Ok(logical_size)
}

fn normalize_max_scan_bytes(max_scan_bytes: u64) -> u64 {
    const DEFAULT_MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_ALLOWED_SCAN_BYTES: u64 = usize::MAX as u64;

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

fn map_ext_filesystem_kind(kind: fr_ext::ExtFilesystemKind) -> u32 {
    match kind {
        fr_ext::ExtFilesystemKind::Ext2 => EXT_FILESYSTEM_KIND_EXT2,
        fr_ext::ExtFilesystemKind::Ext3 => EXT_FILESYSTEM_KIND_EXT3,
        fr_ext::ExtFilesystemKind::Ext4 => EXT_FILESYSTEM_KIND_EXT4,
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

fn map_raid_error_to_status(err: fr_raid::RaidError, has_manual_override: bool) -> i32 {
    match err {
        fr_raid::RaidError::InvalidDiskOrder | fr_raid::RaidError::InvalidStripeSize(_)
            if has_manual_override =>
        {
            142
        }
        fr_raid::RaidError::UnsupportedLayout => 141,
        fr_raid::RaidError::InvalidDiskOrder
        | fr_raid::RaidError::InvalidMemberCount(_)
        | fr_raid::RaidError::InvalidStripeSize(_)
        | fr_raid::RaidError::ArithmeticOverflow(_)
        | fr_raid::RaidError::BufferTooSmall { .. } => 141,
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
    fn ffi_probe_raid_layout_from_session_detects_linux_mdraid() {
        let image = build_test_mdraid_image();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-raid-layout-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("mdraid.img");
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

        let mut layout = FrRaidLayout::default();
        assert_eq!(
            fr_probe_raid_layout_from_session(session_id, std::ptr::null(), &mut layout),
            0
        );
        assert_eq!(layout.metadata_family, RAID_METADATA_FAMILY_LINUX_MD);
        assert_eq!(layout.level, RAID_LEVEL_RAID5);
        assert_eq!(layout.member_count, 4);
        assert_eq!(layout.stripe_size_bytes, 128 * 1024);
        assert_eq!(layout.data_offset_bytes, 2048 * 512);
        assert_eq!(layout.parity_rotation, RAID_PARITY_LEFT_SYMMETRIC);
        assert_eq!(layout.disk_order_count, 4);
        assert_eq!(&layout.disk_order[..4], &[0, 1, 2, 3]);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_map_raid_logical_offset_reports_member_and_parity() {
        let layout = FrRaidLayout {
            metadata_family: RAID_METADATA_FAMILY_LINUX_MD,
            level: RAID_LEVEL_RAID5,
            member_count: 4,
            stripe_size_bytes: 64 * 1024,
            data_offset_bytes: 2 * 1024 * 1024,
            parity_rotation: RAID_PARITY_LEFT_SYMMETRIC,
            confidence_score: 85,
            _reserved0: [0u8; 3],
            disk_order_count: 4,
            disk_order: [
                0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        };
        let mut mapping = FrRaidLogicalMapping::default();
        assert_eq!(fr_map_raid_logical_offset(&layout, 0, &mut mapping), 0);
        assert_eq!(mapping.member_index, 0);
        assert_eq!(mapping.member_offset_bytes, 2 * 1024 * 1024);
        assert_eq!(mapping.has_parity_member, 1);
        assert_eq!(mapping.parity_member_index, 3);
    }

    #[test]
    fn ffi_open_virtual_raid_session_reads_assembled_raid0_bytes() {
        let stripe_size = 4096u32;
        let data_offset_sectors = 64u64;
        let member_a = build_test_mdraid_member_image(0, 2, stripe_size, data_offset_sectors, b'A');
        let member_b = build_test_mdraid_member_image(0, 2, stripe_size, data_offset_sectors, b'B');

        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-virtual-raid-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let member_a_path = temp_dir.join("member-a.img");
        let member_b_path = temp_dir.join("member-b.img");
        fs::write(&member_a_path, &member_a).unwrap();
        fs::write(&member_b_path, &member_b).unwrap();

        let member_a_cstr = CString::new(member_a_path.to_string_lossy().as_bytes()).unwrap();
        let member_b_cstr = CString::new(member_b_path.to_string_lossy().as_bytes()).unwrap();

        let mut member_a_session = 0u64;
        let mut member_b_session = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                member_a_cstr.as_ptr(),
                2,
                &mut member_a_session,
                &mut size_bytes
            ),
            0
        );
        assert_eq!(
            fr_open_source_session_readonly(
                member_b_cstr.as_ptr(),
                2,
                &mut member_b_session,
                &mut size_bytes
            ),
            0
        );

        let member_sessions = [member_a_session, member_b_session];
        let mut virtual_session_id = 0u64;
        let mut virtual_size_bytes = 0u64;
        let mut virtual_layout = FrRaidLayout::default();
        assert_eq!(
            fr_open_virtual_raid_session(
                member_sessions.as_ptr(),
                member_sessions.len() as u32,
                std::ptr::null(),
                &mut virtual_session_id,
                &mut virtual_size_bytes,
                &mut virtual_layout
            ),
            0
        );
        assert_eq!(virtual_layout.level, RAID_LEVEL_RAID0);
        assert_eq!(virtual_layout.member_count, 2);
        assert_eq!(virtual_layout.stripe_size_bytes, stripe_size);
        assert_eq!(virtual_layout.data_offset_bytes, data_offset_sectors * 512);
        assert_eq!(virtual_size_bytes, (stripe_size as u64) * 4);

        let mut probed_layout = FrRaidLayout::default();
        assert_eq!(
            fr_probe_virtual_raid_session(virtual_session_id, &mut probed_layout),
            0
        );
        assert_eq!(probed_layout.level, RAID_LEVEL_RAID0);
        assert_eq!(probed_layout.member_count, 2);

        let mut assembled = vec![0u8; (stripe_size as usize) * 4];
        let mut bytes_read = 0u32;
        assert_eq!(
            fr_read_source_session(
                virtual_session_id,
                0,
                assembled.as_mut_ptr(),
                assembled.len() as u32,
                &mut bytes_read
            ),
            0
        );
        assert_eq!(bytes_read as usize, assembled.len());
        assert!(assembled[..stripe_size as usize]
            .iter()
            .all(|byte| *byte == b'A'));
        assert!(assembled[stripe_size as usize..(stripe_size as usize) * 2]
            .iter()
            .all(|byte| *byte == b'B'));
        assert!(
            assembled[(stripe_size as usize) * 2..(stripe_size as usize) * 3]
                .iter()
                .all(|byte| *byte == b'A')
        );
        assert!(
            assembled[(stripe_size as usize) * 3..(stripe_size as usize) * 4]
                .iter()
                .all(|byte| *byte == b'B')
        );

        assert_eq!(fr_close_virtual_raid_session(virtual_session_id), 0);
        assert_eq!(
            fr_probe_virtual_raid_session(virtual_session_id, &mut probed_layout),
            20
        );
        assert_eq!(fr_close_source_session(member_a_session), 0);
        assert_eq!(fr_close_source_session(member_b_session), 0);

        fs::remove_file(&member_a_path).unwrap();
        fs::remove_file(&member_b_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_open_virtual_raid_session_reads_assembled_raid10_bytes() {
        let stripe_size = 4096u32;
        let data_offset_sectors = 64u64;
        let members = [
            build_test_mdraid_member_image(10, 4, stripe_size, data_offset_sectors, b'A'),
            build_test_mdraid_member_image(10, 4, stripe_size, data_offset_sectors, b'B'),
            build_test_mdraid_member_image(10, 4, stripe_size, data_offset_sectors, b'C'),
            build_test_mdraid_member_image(10, 4, stripe_size, data_offset_sectors, b'D'),
        ];

        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-virtual-raid10-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();

        let mut member_session_ids = Vec::new();
        let mut member_paths = Vec::new();
        for (index, image) in members.iter().enumerate() {
            let path = temp_dir.join(format!("member-{}.img", index));
            fs::write(&path, image).unwrap();
            member_paths.push(path.clone());

            let path_cstr = CString::new(path.to_string_lossy().as_bytes()).unwrap();
            let mut session_id = 0u64;
            let mut size_bytes = 0u64;
            assert_eq!(
                fr_open_source_session_readonly(
                    path_cstr.as_ptr(),
                    2,
                    &mut session_id,
                    &mut size_bytes
                ),
                0
            );
            member_session_ids.push(session_id);
        }

        let mut virtual_session_id = 0u64;
        let mut virtual_size_bytes = 0u64;
        let mut virtual_layout = FrRaidLayout::default();
        assert_eq!(
            fr_open_virtual_raid_session(
                member_session_ids.as_ptr(),
                member_session_ids.len() as u32,
                std::ptr::null(),
                &mut virtual_session_id,
                &mut virtual_size_bytes,
                &mut virtual_layout
            ),
            0
        );
        assert_eq!(virtual_layout.level, RAID_LEVEL_RAID10);
        assert_eq!(virtual_layout.member_count, 4);
        assert_eq!(virtual_size_bytes, (stripe_size as u64) * 4);

        let mut assembled = vec![0u8; (stripe_size as usize) * 4];
        let mut bytes_read = 0u32;
        assert_eq!(
            fr_read_source_session(
                virtual_session_id,
                0,
                assembled.as_mut_ptr(),
                assembled.len() as u32,
                &mut bytes_read
            ),
            0
        );
        assert_eq!(bytes_read as usize, assembled.len());
        assert!(assembled[..stripe_size as usize]
            .iter()
            .all(|byte| *byte == b'A'));
        assert!(assembled[stripe_size as usize..(stripe_size as usize) * 2]
            .iter()
            .all(|byte| *byte == b'C'));
        assert!(
            assembled[(stripe_size as usize) * 2..(stripe_size as usize) * 3]
                .iter()
                .all(|byte| *byte == b'A')
        );
        assert!(
            assembled[(stripe_size as usize) * 3..(stripe_size as usize) * 4]
                .iter()
                .all(|byte| *byte == b'C')
        );

        assert_eq!(fr_close_virtual_raid_session(virtual_session_id), 0);
        for session_id in member_session_ids {
            assert_eq!(fr_close_source_session(session_id), 0);
        }
        for path in member_paths {
            fs::remove_file(path).unwrap();
        }
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_open_virtual_raid_session_rejects_duplicate_member_sessions() {
        let member = build_test_mdraid_member_image(0, 2, 4096, 64, b'X');
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-virtual-raid-dupe-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let member_path = temp_dir.join("member.img");
        fs::write(&member_path, &member).unwrap();

        let member_cstr = CString::new(member_path.to_string_lossy().as_bytes()).unwrap();
        let mut member_session_id = 0u64;
        let mut size_bytes = 0u64;
        assert_eq!(
            fr_open_source_session_readonly(
                member_cstr.as_ptr(),
                2,
                &mut member_session_id,
                &mut size_bytes
            ),
            0
        );

        let duplicate_members = [member_session_id, member_session_id];
        let mut virtual_session_id = 0u64;
        let mut virtual_size_bytes = 0u64;
        let mut virtual_layout = FrRaidLayout::default();
        assert_eq!(
            fr_open_virtual_raid_session(
                duplicate_members.as_ptr(),
                duplicate_members.len() as u32,
                std::ptr::null(),
                &mut virtual_session_id,
                &mut virtual_size_bytes,
                &mut virtual_layout
            ),
            142
        );

        assert_eq!(fr_close_source_session(member_session_id), 0);
        fs::remove_file(&member_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
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
    fn ffi_probe_ext_superblock_from_session_parses_ext_image() {
        let image = build_test_ext4_image();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-ext-superblock-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("ext4.img");
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

        let mut superblock = FrExtSuperblockMetadata::default();
        assert_eq!(
            fr_probe_ext_superblock_from_session(session_id, &mut superblock),
            0
        );
        assert_eq!(superblock.filesystem_kind, EXT_FILESYSTEM_KIND_EXT4);
        assert_eq!(superblock.block_size_bytes, 4096);
        assert_eq!(superblock.inode_size_bytes, 256);
        assert_eq!(superblock.total_inodes, 1024);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_get_ext_deleted_candidates_extracts_deleted_entry() {
        let image = build_test_ext4_image_with_deleted_entry();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-ext-candidates-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("ext4-deleted.img");
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

        let mut candidates = vec![empty_ext_deleted_candidate(); 8];
        let mut written = 0u32;
        let status = fr_get_ext_deleted_candidates_from_session(
            session_id,
            128,
            candidates.as_mut_ptr(),
            candidates.len() as u32,
            &mut written,
        );
        assert_eq!(status, 0);
        assert!(written >= 1);
        let first = candidates[0];
        assert_eq!(
            first.flags & EXT_DELETED_CANDIDATE_FLAG_DELETED,
            EXT_DELETED_CANDIDATE_FLAG_DELETED
        );
        assert_eq!(c_string_bytes_to_string(&first.name), "deleted-ext.txt");

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_probe_apfs_container_from_session_parses_container() {
        let image = build_test_apfs_image();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-apfs-probe-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("apfs.img");
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

        let mut container = FrApfsContainerMetadata::default();
        assert_eq!(
            fr_probe_apfs_container_from_session(session_id, &mut container),
            0
        );
        assert_eq!(container.block_size_bytes, 4096);
        assert_eq!(container.block_count, 32_768);
        assert_eq!(container.container_object_id, 99);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_get_apfs_deleted_candidates_extracts_deleted_entry() {
        let image = build_test_apfs_image_with_deleted_tombstone();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-apfs-candidates-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("apfs-deleted.img");
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

        let mut candidates = vec![empty_apfs_deleted_candidate(); 8];
        let mut written = 0u32;
        assert_eq!(
            fr_get_apfs_deleted_candidates_from_session(
                session_id,
                64,
                candidates.as_mut_ptr(),
                candidates.len() as u32,
                &mut written
            ),
            0
        );
        assert!(written >= 1);
        let first = candidates[0];
        assert_eq!(
            first.flags & APFS_DELETED_CANDIDATE_FLAG_DELETED,
            APFS_DELETED_CANDIDATE_FLAG_DELETED
        );
        assert_eq!(first.cnid, 2048);
        assert_eq!(c_string_bytes_to_string(&first.name), "presentation.key");

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_probe_hfs_volume_header_from_session_parses_volume_header() {
        let image = build_test_hfs_image();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-hfs-probe-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("hfs.img");
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

        let mut volume = FrHfsVolumeMetadata::default();
        assert_eq!(
            fr_probe_hfs_volume_header_from_session(session_id, &mut volume),
            0
        );
        assert_eq!(volume.signature, 0x482B);
        assert_eq!(volume.version, 4);
        assert_eq!(volume.block_size_bytes, 4096);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_get_hfs_deleted_candidates_extracts_deleted_entry() {
        let image = build_test_hfs_image_with_deleted_tombstone();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-hfs-candidates-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("hfs-deleted.img");
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

        let mut candidates = vec![empty_hfs_deleted_candidate(); 8];
        let mut written = 0u32;
        assert_eq!(
            fr_get_hfs_deleted_candidates_from_session(
                session_id,
                64,
                candidates.as_mut_ptr(),
                candidates.len() as u32,
                &mut written
            ),
            0
        );
        assert!(written >= 1);
        let first = candidates[0];
        assert_eq!(
            first.flags & HFS_DELETED_CANDIDATE_FLAG_DELETED,
            HFS_DELETED_CANDIDATE_FLAG_DELETED
        );
        assert_eq!(first.cnid, 77);
        assert_eq!(c_string_bytes_to_string(&first.name), "invoice.pages");

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_probe_xfs_superblock_from_session_parses_superblock() {
        let image = build_test_xfs_image();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-xfs-probe-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("xfs.img");
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

        let mut superblock = FrXfsSuperblockMetadata::default();
        assert_eq!(
            fr_probe_xfs_superblock_from_session(session_id, &mut superblock),
            0
        );
        assert_eq!(superblock.block_size_bytes, 4096);
        assert_eq!(superblock.inode_size_bytes, 512);
        assert_eq!(superblock.ag_count, 4);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_get_xfs_deleted_candidates_extracts_deleted_entry() {
        let image = build_test_xfs_image_with_deleted_tombstone();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-xfs-candidates-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("xfs-deleted.img");
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

        let mut candidates = vec![empty_xfs_deleted_candidate(); 8];
        let mut written = 0u32;
        assert_eq!(
            fr_get_xfs_deleted_candidates_from_session(
                session_id,
                64,
                candidates.as_mut_ptr(),
                candidates.len() as u32,
                &mut written
            ),
            0
        );
        assert!(written >= 1);
        let first = candidates[0];
        assert_eq!(
            first.flags & XFS_DELETED_CANDIDATE_FLAG_DELETED,
            XFS_DELETED_CANDIDATE_FLAG_DELETED
        );
        assert_eq!(first.inode_number, 88);
        assert_eq!(c_string_bytes_to_string(&first.name), "audit.log");

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_probe_ufs_superblock_from_session_parses_superblock() {
        let image = build_test_ufs_image();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-ufs-probe-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("ufs.img");
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

        let mut superblock = FrUfsSuperblockMetadata::default();
        assert_eq!(
            fr_probe_ufs_superblock_from_session(session_id, &mut superblock),
            0
        );
        assert_eq!(superblock.magic, 0x1954_0119);
        assert_eq!(superblock.block_size_bytes, 4096);
        assert_eq!(superblock.fragment_size_bytes, 1024);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_get_ufs_deleted_candidates_extracts_deleted_entry() {
        let image = build_test_ufs_image_with_deleted_tombstone();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-ufs-candidates-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("ufs-deleted.img");
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

        let mut candidates = vec![empty_ufs_deleted_candidate(); 8];
        let mut written = 0u32;
        assert_eq!(
            fr_get_ufs_deleted_candidates_from_session(
                session_id,
                64,
                candidates.as_mut_ptr(),
                candidates.len() as u32,
                &mut written
            ),
            0
        );
        assert!(written >= 1);
        let first = candidates[0];
        assert_eq!(
            first.flags & UFS_DELETED_CANDIDATE_FLAG_DELETED,
            UFS_DELETED_CANDIDATE_FLAG_DELETED
        );
        assert_eq!(first.inode_number, 120);
        assert_eq!(c_string_bytes_to_string(&first.name), "passwd.old");

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_refs_candidate_to_file_recovers_payload_from_descriptor() {
        let payload = b"REFS-RECOVERED-PAYLOAD";
        let image = build_test_refs_image_with_deleted_usn_record_and_payload(42, payload, false);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-refs-recover-ok-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("refs-recover.img");
        let output_path = temp_dir.join("refs-recovered.bin");
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
        let status = fr_recover_refs_candidate_to_file(
            session_id,
            42,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(bytes_written, payload.len() as u64);
        assert_eq!(fs::read(&output_path).unwrap(), payload);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_refs_candidate_to_file_returns_unreadable_range_for_out_of_bounds_payload() {
        let payload = b"REFS-OUT-OF-BOUNDS";
        let image = build_test_refs_image_with_deleted_usn_record_and_payload(42, payload, false);
        let mut image = image;
        write_refs_payload_descriptor(
            &mut image,
            16 * 1024,
            42,
            512 * 1024,
            payload.len() as u64,
            false,
        );
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-refs-recover-oob-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("refs-recover-oob.img");
        let output_path = temp_dir.join("refs-recovered-oob.bin");
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

        let mut bytes_written = 99u64;
        let mut partial = -1i32;
        let status = fr_recover_refs_candidate_to_file(
            session_id,
            42,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, RECOVERY_STATUS_UNREADABLE_RANGE);
        assert_eq!(bytes_written, 0);
        assert_eq!(partial, 0);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_apfs_candidate_to_file_recovers_payload_from_descriptor() {
        let payload = b"APFS-CONTENT-PAYLOAD";
        let image = build_test_apfs_image_with_deleted_tombstone_and_payload(2048, payload, false);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-apfs-recover-ok-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("apfs-recover.img");
        let output_path = temp_dir.join("apfs-recovered.bin");
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
        let status = fr_recover_apfs_candidate_to_file(
            session_id,
            2048,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(bytes_written, payload.len() as u64);
        assert_eq!(fs::read(&output_path).unwrap(), payload);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_apfs_candidate_to_file_returns_encrypted_locked_when_candidate_is_locked() {
        let payload = b"APFS-LOCKED-PAYLOAD";
        let image = build_test_apfs_image_with_deleted_tombstone_and_payload(2048, payload, true);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-apfs-recover-locked-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("apfs-recover-locked.img");
        let output_path = temp_dir.join("apfs-recovered-locked.bin");
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

        let mut bytes_written = 7u64;
        let mut partial = -1i32;
        let status = fr_recover_apfs_candidate_to_file(
            session_id,
            2048,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, RECOVERY_STATUS_ENCRYPTED_LOCKED);
        assert_eq!(bytes_written, 0);
        assert_eq!(partial, 0);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_hfs_candidate_to_file_recovers_payload_from_descriptor() {
        let payload = b"HFS-CONTENT-PAYLOAD";
        let image = build_test_hfs_image_with_deleted_tombstone_and_payload(77, payload, false);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-hfs-recover-ok-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("hfs-recover.img");
        let output_path = temp_dir.join("hfs-recovered.bin");
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
        let status = fr_recover_hfs_candidate_to_file(
            session_id,
            77,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(bytes_written, payload.len() as u64);
        assert_eq!(fs::read(&output_path).unwrap(), payload);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_xfs_candidate_to_file_recovers_payload_from_descriptor() {
        let payload = b"XFS-CONTENT-PAYLOAD";
        let image = build_test_xfs_image_with_deleted_tombstone_and_payload(88, payload, false);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-xfs-recover-ok-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("xfs-recover.img");
        let output_path = temp_dir.join("xfs-recovered.bin");
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
        let status = fr_recover_xfs_candidate_to_file(
            session_id,
            88,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(bytes_written, payload.len() as u64);
        assert_eq!(fs::read(&output_path).unwrap(), payload);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_xfs_candidate_to_file_returns_unsupported_layout_without_payload_descriptor() {
        let image = build_test_xfs_image_with_deleted_tombstone();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-xfs-recover-metadata-only-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("xfs-metadata-only.img");
        let output_path = temp_dir.join("xfs-metadata-only.bin");
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
        let status = fr_recover_xfs_candidate_to_file(
            session_id,
            88,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, RECOVERY_STATUS_UNSUPPORTED_LAYOUT);
        assert_eq!(bytes_written, 0);
        assert_eq!(partial, 0);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_ufs_candidate_to_file_recovers_payload_from_descriptor() {
        let payload = b"UFS-CONTENT-PAYLOAD";
        let image = build_test_ufs_image_with_deleted_tombstone_and_payload(120, payload, false);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-ufs-recover-ok-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("ufs-recover.img");
        let output_path = temp_dir.join("ufs-recovered.bin");
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
        let status = fr_recover_ufs_candidate_to_file(
            session_id,
            120,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(bytes_written, payload.len() as u64);
        assert_eq!(fs::read(&output_path).unwrap(), payload);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_ext_candidate_to_file_returns_unsupported_for_missing_inode() {
        let image = build_test_ext4_image();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-ext-recover-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("ext4.img");
        let output_path = temp_dir.join("ext-recovered.bin");
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

        let mut bytes_written = 123u64;
        let mut partial = -1i32;
        let status = fr_recover_ext_candidate_to_file(
            session_id,
            42,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, 91);
        assert_eq!(bytes_written, 0);
        assert_eq!(partial, 0);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_ext_candidate_to_file_recovers_direct_blocks() {
        let payload = b"EXT-RECOVERY-DIRECT-BLOCK";
        let image = build_test_ext4_image_with_recoverable_inode(payload);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-ext-recover-ok-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("ext4-recoverable.img");
        let output_path = temp_dir.join("ext-recovered.bin");
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
        let status = fr_recover_ext_candidate_to_file(
            session_id,
            16,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(bytes_written, payload.len() as u64);
        assert_eq!(fs::read(&output_path).unwrap(), payload);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_ext_candidate_to_file_recovers_single_indirect_blocks() {
        let payload = build_ext_single_indirect_payload();
        let image = build_test_ext4_image_with_single_indirect_recoverable_inode(&payload);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-ext-recover-single-indirect-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("ext4-single-indirect.img");
        let output_path = temp_dir.join("ext-single-indirect-recovered.bin");
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
        let status = fr_recover_ext_candidate_to_file(
            session_id,
            16,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(bytes_written, payload.len() as u64);
        assert_eq!(fs::read(&output_path).unwrap(), payload);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_ext_candidate_to_file_marks_partial_when_single_indirect_pointer_missing() {
        let payload = build_ext_single_indirect_payload();
        let image =
            build_test_ext4_image_with_single_indirect_recoverable_inode_missing_pointer(&payload);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-ext-recover-single-indirect-partial-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("ext4-single-indirect-missing.img");
        let output_path = temp_dir.join("ext-single-indirect-partial.bin");
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
        let status = fr_recover_ext_candidate_to_file(
            session_id,
            16,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, 0);
        assert_eq!(partial, 1);
        assert_eq!(bytes_written, (12 * 4096) as u64);
        assert_eq!(fs::read(&output_path).unwrap(), payload[..12 * 4096]);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_ext_candidate_to_file_recovers_double_indirect_blocks() {
        let payload = build_ext_double_indirect_payload();
        let image = build_test_ext4_image_with_double_indirect_recoverable_inode(&payload);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-ext-recover-double-indirect-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("ext4-double-indirect.img");
        let output_path = temp_dir.join("ext-double-indirect-recovered.bin");
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
        let status = fr_recover_ext_candidate_to_file(
            session_id,
            16,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(bytes_written, payload.len() as u64);
        assert_eq!(fs::read(&output_path).unwrap(), payload);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_ext_candidate_to_file_recovers_triple_indirect_blocks() {
        let payload = build_ext_triple_indirect_payload();
        let image = build_test_ext4_image_with_triple_indirect_recoverable_inode(&payload);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-ext-recover-triple-indirect-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("ext4-triple-indirect.img");
        let output_path = temp_dir.join("ext-triple-indirect-recovered.bin");
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
        let status = fr_recover_ext_candidate_to_file(
            session_id,
            16,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, 0);
        assert_eq!(partial, 1);
        assert_eq!(bytes_written, payload.len() as u64);
        assert_eq!(fs::read(&output_path).unwrap(), payload);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_ext_candidate_to_file_recovers_extent_leaf_inode() {
        let payload = build_ext_extent_leaf_payload();
        let image = build_test_ext4_image_with_extent_leaf_recoverable_inode(&payload);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-ext-recover-extent-leaf-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("ext4-extent-leaf.img");
        let output_path = temp_dir.join("ext-extent-leaf-recovered.bin");
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
        let status = fr_recover_ext_candidate_to_file(
            session_id,
            16,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(bytes_written, payload.len() as u64);
        assert_eq!(fs::read(&output_path).unwrap(), payload);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_ext_candidate_to_file_zero_fills_uninitialized_extent_blocks() {
        let payload = build_ext_extent_uninitialized_payload();
        let image =
            build_test_ext4_image_with_uninitialized_extent_leaf_recoverable_inode(&payload);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-ext-recover-extent-uninitialized-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("ext4-extent-uninitialized.img");
        let output_path = temp_dir.join("ext-extent-uninitialized-recovered.bin");
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
        let status = fr_recover_ext_candidate_to_file(
            session_id,
            16,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(bytes_written, (2 * 4096) as u64);

        let recovered = fs::read(&output_path).unwrap();
        assert_eq!(recovered.len(), 2 * 4096);
        assert_eq!(&recovered[..4096], payload.as_slice());
        assert!(recovered[4096..].iter().all(|byte| *byte == 0));

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_ext_candidate_to_file_recovers_inline_symlink_target() {
        let symlink_target = "logs/2026/latest-report.txt";
        let image = build_test_ext4_image_with_inline_symlink_inode(symlink_target);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-ext-recover-inline-symlink-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("ext4-inline-symlink.img");
        let output_path = temp_dir.join("ext-inline-symlink-recovered.bin");
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
        let status = fr_recover_ext_candidate_to_file(
            session_id,
            16,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(bytes_written, symlink_target.len() as u64);
        assert_eq!(fs::read(&output_path).unwrap(), symlink_target.as_bytes());

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_ext_candidate_to_file_recovers_non_inline_symlink_target() {
        let symlink_target =
            "this/is/a/very/long/symlink/target/path/that/exceeds/the/inline/inode/storage/window";
        let image = build_test_ext4_image_with_non_inline_symlink_inode(symlink_target);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-ext-recover-non-inline-symlink-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("ext4-non-inline-symlink.img");
        let output_path = temp_dir.join("ext-non-inline-symlink-recovered.bin");
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
        let status = fr_recover_ext_candidate_to_file(
            session_id,
            16,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(bytes_written, symlink_target.len() as u64);
        assert_eq!(fs::read(&output_path).unwrap(), symlink_target.as_bytes());

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_recover_ext_candidate_to_file_recovers_directory_inode_bytes() {
        let payload = build_ext_directory_payload();
        let image = build_test_ext4_image_with_directory_inode(&payload);
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-ext-recover-directory-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("ext4-directory.img");
        let output_path = temp_dir.join("ext-directory-recovered.bin");
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
        let status = fr_recover_ext_candidate_to_file(
            session_id,
            16,
            output_path_cstr.as_ptr(),
            &mut bytes_written,
            &mut partial,
        );
        assert_eq!(status, 0);
        assert_eq!(partial, 0);
        assert_eq!(bytes_written, payload.len() as u64);
        assert_eq!(fs::read(&output_path).unwrap(), payload);

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
        assert_eq!(
            first.flags & REFS_DELETED_CANDIDATE_FLAG_DELETED,
            REFS_DELETED_CANDIDATE_FLAG_DELETED
        );
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
    fn ffi_get_fat_deleted_candidates_from_session_returns_nested_deleted_entry() {
        let image = build_test_fat32_image_with_nested_deleted_entry();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-fat-scan-nested-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("fat32-nested.img");
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

        let mut candidates = vec![empty_fat_deleted_candidate(); 32];
        let mut written = 0u32;
        let status = fr_get_fat_deleted_candidates_from_session(
            session_id,
            64,
            candidates.as_mut_ptr(),
            candidates.len() as u32,
            &mut written,
        );
        assert_eq!(status, 0);
        assert!(written >= 2);

        let recovered_paths: Vec<String> = candidates
            .iter()
            .take(written as usize)
            .map(|candidate| c_string_bytes_to_string(&candidate.reconstructed_path))
            .collect();
        assert!(recovered_paths
            .iter()
            .any(|path| path == r".\SUBDIR\_HILD.TXT"));

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_get_fat_deleted_candidates_from_session_recovers_deleted_lfn_name() {
        let image = build_test_fat32_image_with_deleted_lfn_entry();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-fat-scan-lfn-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("fat32-lfn.img");
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
            "QuarterlyReport.txt".to_string()
        );
        assert_eq!(
            c_string_bytes_to_string(&candidates[0].reconstructed_path),
            r".\QuarterlyReport.txt".to_string()
        );

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_get_fat_deleted_candidates_from_session_reports_cluster_loop_status() {
        let image = build_test_fat32_image_with_cluster_loop();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-fat-scan-loop-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("fat32-loop.img");
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
        assert_eq!(status, 73);
        assert_eq!(written, 0);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn ffi_get_fat_deleted_candidates_from_session_reports_invalid_cluster_status() {
        let image = build_test_fat32_image_with_bad_cluster_chain();
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-fat-scan-badcluster-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("fat32-badcluster.img");
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
        assert_eq!(status, 71);
        assert_eq!(written, 0);

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
    fn ffi_carve_candidates_from_session_window_uses_absolute_offsets() {
        let temp_dir = std::env::temp_dir().join(format!(
            "fr-ffi-carve-window-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let image_path = temp_dir.join("carve-window.img");

        let prefix_len = 2 * 1024 * 1024;
        let mut bytes = vec![0x41; prefix_len];
        bytes.extend_from_slice(b"\xFF\xD8\xFF\xE0window-jpeg\xFF\xD9");
        fs::write(&image_path, &bytes).unwrap();

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
        let mut carved = vec![empty_carve_candidate(); 8];
        let status = fr_get_carve_candidates_from_session_window(
            session_id,
            CARVE_FAMILY_IMAGES,
            prefix_len as u64,
            1024 * 1024,
            carved.as_mut_ptr(),
            carved.len() as u32,
            &mut out_written,
        );
        assert_eq!(status, 0);
        assert!(out_written >= 1);

        let first = carved[0];
        assert_eq!(first.offset_bytes, prefix_len as u64);
        assert!(first.length_bytes > 0);

        assert_eq!(fr_close_source_session(session_id), 0);
        fs::remove_file(&image_path).unwrap();
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn normalize_max_scan_bytes_does_not_cap_at_256mib() {
        let requested = 1024_u64 * 1024_u64 * 1024_u64;
        assert_eq!(normalize_max_scan_bytes(requested), requested);
    }

    #[test]
    fn ffi_get_carve_signature_pack_metadata_returns_version_and_formats() {
        let mut metadata = empty_carve_signature_pack_metadata();
        let status = fr_get_carve_signature_pack_metadata(&mut metadata);
        assert_eq!(status, 0);
        assert_eq!(
            c_string_bytes_to_string(&metadata.pack_name),
            SIGNATURE_PACK_NAME
        );
        assert_eq!(
            c_string_bytes_to_string(&metadata.pack_version),
            SIGNATURE_PACK_VERSION
        );
        assert!(metadata.format_count >= 20);
        assert_ne!(metadata.family_flags & CARVE_FAMILY_IMAGES, 0);
        assert_ne!(metadata.family_flags & CARVE_FAMILY_ARCHIVES, 0);
        let formats = c_string_bytes_to_string(&metadata.formats_csv);
        assert!(formats.contains("webp"));
        assert!(formats.contains("7z"));
        assert!(formats.contains("mp4"));
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

    fn empty_carve_signature_pack_metadata() -> FrCarveSignaturePackMetadata {
        FrCarveSignaturePackMetadata {
            pack_name: [0u8; 64],
            pack_version: [0u8; 32],
            format_count: 0,
            family_flags: 0,
            formats_csv: [0u8; 512],
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

    fn empty_ext_deleted_candidate() -> FrExtDeletedCandidate {
        FrExtDeletedCandidate {
            flags: 0,
            inode_number: 0,
            entry_offset_bytes: 0,
            size_bytes: 0,
            name: [0u8; 128],
            reconstructed_path: [0u8; 256],
        }
    }

    fn empty_apfs_deleted_candidate() -> FrApfsDeletedCandidate {
        FrApfsDeletedCandidate {
            flags: 0,
            _reserved0: 0,
            cnid: 0,
            size_bytes: 0,
            name: [0u8; 128],
            reconstructed_path: [0u8; 256],
        }
    }

    fn empty_hfs_deleted_candidate() -> FrHfsDeletedCandidate {
        FrHfsDeletedCandidate {
            flags: 0,
            cnid: 0,
            size_bytes: 0,
            name: [0u8; 128],
            reconstructed_path: [0u8; 256],
        }
    }

    fn empty_xfs_deleted_candidate() -> FrXfsDeletedCandidate {
        FrXfsDeletedCandidate {
            flags: 0,
            inode_number: 0,
            size_bytes: 0,
            name: [0u8; 128],
            reconstructed_path: [0u8; 256],
        }
    }

    fn empty_ufs_deleted_candidate() -> FrUfsDeletedCandidate {
        FrUfsDeletedCandidate {
            flags: 0,
            inode_number: 0,
            _reserved0: 0,
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

    fn build_test_apfs_image() -> Vec<u8> {
        let mut image = vec![0u8; 1024 * 64];
        write_u64(&mut image, 0x08, 99);
        write_u32(&mut image, 0x20, 0x4253_584E);
        write_u32(&mut image, 0x24, 4096);
        write_u64(&mut image, 0x28, 32_768);
        write_u64(&mut image, 0x30, 0x10);
        write_u64(&mut image, 0x40, 0x20);
        image
    }

    fn build_test_apfs_image_with_deleted_tombstone() -> Vec<u8> {
        let mut image = build_test_apfs_image();
        let record = build_apfs_tombstone_record(
            2048,
            16_384,
            true,
            "presentation.key",
            r"projects\presentation.key",
        );
        let offset = 8192usize;
        image[offset..offset + record.len()].copy_from_slice(&record);
        image
    }

    fn build_test_apfs_image_with_deleted_tombstone_and_payload(
        cnid: u64,
        payload: &[u8],
        encrypted: bool,
    ) -> Vec<u8> {
        let mut image = build_test_apfs_image();
        let mut record = build_apfs_tombstone_record(
            cnid,
            payload.len() as u64,
            false,
            "apfs-content.bin",
            r"projects\apfs-content.bin",
        );
        if encrypted {
            record[24] |= METADATA_ENCRYPTED_FLAG;
        }

        let record_offset = 8192usize;
        image[record_offset..record_offset + record.len()].copy_from_slice(&record);
        write_payload_descriptor(
            &mut image,
            record_offset + APFS_TOMBSTONE_RECORD_SIZE,
            24 * 1024,
            payload,
        );
        image
    }

    fn build_apfs_tombstone_record(
        cnid: u64,
        size_bytes: u64,
        is_directory: bool,
        name: &str,
        path: &str,
    ) -> Vec<u8> {
        let mut record = vec![0u8; 316];
        record[..8].copy_from_slice(b"APFSDEL\0");
        write_u64(&mut record, 8, cnid);
        write_u64(&mut record, 16, size_bytes);
        record[24] = if is_directory { 1 } else { 0 };
        record[25] = name.len() as u8;
        record[26] = path.len() as u8;
        record[28..28 + name.len()].copy_from_slice(name.as_bytes());
        record[124..124 + path.len()].copy_from_slice(path.as_bytes());
        record
    }

    fn build_test_hfs_image() -> Vec<u8> {
        let mut image = vec![0u8; 1024 * 64];
        write_u16_be(&mut image, 1024, 0x482B);
        write_u16_be(&mut image, 1026, 4);
        write_u32_be(&mut image, 1056, 200);
        write_u32_be(&mut image, 1060, 80);
        write_u32_be(&mut image, 1064, 4096);
        write_u32_be(&mut image, 1068, 65_536);
        image
    }

    fn build_test_hfs_image_with_deleted_tombstone() -> Vec<u8> {
        let mut image = build_test_hfs_image();
        let record = build_hfs_tombstone_record(
            77,
            12_288,
            false,
            "invoice.pages",
            r"archive\invoice.pages",
        );
        let offset = 4096usize;
        image[offset..offset + record.len()].copy_from_slice(&record);
        image
    }

    fn build_test_hfs_image_with_deleted_tombstone_and_payload(
        cnid: u32,
        payload: &[u8],
        encrypted: bool,
    ) -> Vec<u8> {
        let mut image = build_test_hfs_image();
        let mut record = build_hfs_tombstone_record(
            cnid,
            payload.len() as u64,
            false,
            "hfs-content.bin",
            r"archive\hfs-content.bin",
        );
        if encrypted {
            record[20] |= METADATA_ENCRYPTED_FLAG;
        }

        let record_offset = 4096usize;
        image[record_offset..record_offset + record.len()].copy_from_slice(&record);
        write_payload_descriptor(
            &mut image,
            record_offset + HFS_TOMBSTONE_RECORD_SIZE,
            20 * 1024,
            payload,
        );
        image
    }

    fn build_hfs_tombstone_record(
        cnid: u32,
        size_bytes: u64,
        is_directory: bool,
        name: &str,
        path: &str,
    ) -> Vec<u8> {
        let mut record = vec![0u8; 312];
        record[..8].copy_from_slice(b"HFSDEL\0\0");
        write_u32(&mut record, 8, cnid);
        write_u64(&mut record, 12, size_bytes);
        record[20] = if is_directory { 1 } else { 0 };
        record[21] = name.len() as u8;
        record[22] = path.len() as u8;
        record[24..24 + name.len()].copy_from_slice(name.as_bytes());
        record[120..120 + path.len()].copy_from_slice(path.as_bytes());
        record
    }

    fn build_test_xfs_image() -> Vec<u8> {
        let mut image = vec![0u8; 64 * 1024];
        image[0..4].copy_from_slice(b"XFSB");
        write_u32_be(&mut image, 0x04, 4096);
        write_u64_be(&mut image, 0x08, 1_048_576);
        write_u32_be(&mut image, 0x54, 4);
        write_u16_be(&mut image, 0x68, 512);
        image
    }

    fn build_test_xfs_image_with_deleted_tombstone() -> Vec<u8> {
        let mut image = build_test_xfs_image();
        let record = build_xfs_tombstone_record(88, 10_240, false, "audit.log", r"logs\audit.log");
        let offset = 8192usize;
        image[offset..offset + record.len()].copy_from_slice(&record);
        image
    }

    fn build_test_xfs_image_with_deleted_tombstone_and_payload(
        inode_number: u64,
        payload: &[u8],
        encrypted: bool,
    ) -> Vec<u8> {
        let mut image = build_test_xfs_image();
        let mut record = build_xfs_tombstone_record(
            inode_number,
            payload.len() as u64,
            false,
            "xfs-content.bin",
            r"logs\xfs-content.bin",
        );
        if encrypted {
            record[24] |= METADATA_ENCRYPTED_FLAG;
        }

        let record_offset = 8192usize;
        image[record_offset..record_offset + record.len()].copy_from_slice(&record);
        write_payload_descriptor(
            &mut image,
            record_offset + XFS_TOMBSTONE_RECORD_SIZE,
            28 * 1024,
            payload,
        );
        image
    }

    fn build_xfs_tombstone_record(
        inode_number: u64,
        size_bytes: u64,
        is_directory: bool,
        name: &str,
        path: &str,
    ) -> Vec<u8> {
        let mut record = vec![0u8; 316];
        record[..8].copy_from_slice(b"XFSDEL\0\0");
        write_u64(&mut record, 8, inode_number);
        write_u64(&mut record, 16, size_bytes);
        record[24] = if is_directory { 1 } else { 0 };
        record[25] = name.len() as u8;
        record[26] = path.len() as u8;
        record[28..28 + name.len()].copy_from_slice(name.as_bytes());
        record[124..124 + path.len()].copy_from_slice(path.as_bytes());
        record
    }

    fn build_test_ufs_image() -> Vec<u8> {
        let mut image = vec![0u8; 128 * 1024];
        write_u32(&mut image, 8192 + 0x55C, 0x1954_0119);
        write_u32(&mut image, 8192 + 0x30, 4096);
        write_u32(&mut image, 8192 + 0x34, 1024);
        write_u64(&mut image, 8192 + 0x08, 262_144);
        image
    }

    fn build_test_ufs_image_with_deleted_tombstone() -> Vec<u8> {
        let mut image = build_test_ufs_image();
        let record = build_ufs_tombstone_record(120, 2048, false, "passwd.old", r"etc\passwd.old");
        let offset = 16 * 1024;
        image[offset..offset + record.len()].copy_from_slice(&record);
        image
    }

    fn build_test_ufs_image_with_deleted_tombstone_and_payload(
        inode_number: u32,
        payload: &[u8],
        encrypted: bool,
    ) -> Vec<u8> {
        let mut image = build_test_ufs_image();
        let mut record = build_ufs_tombstone_record(
            inode_number,
            payload.len() as u64,
            false,
            "ufs-content.bin",
            r"etc\ufs-content.bin",
        );
        if encrypted {
            record[20] |= METADATA_ENCRYPTED_FLAG;
        }

        let record_offset = 16 * 1024usize;
        image[record_offset..record_offset + record.len()].copy_from_slice(&record);
        write_payload_descriptor(
            &mut image,
            record_offset + UFS_TOMBSTONE_RECORD_SIZE,
            32 * 1024,
            payload,
        );
        image
    }

    fn build_ufs_tombstone_record(
        inode_number: u32,
        size_bytes: u64,
        is_directory: bool,
        name: &str,
        path: &str,
    ) -> Vec<u8> {
        let mut record = vec![0u8; 312];
        record[..8].copy_from_slice(b"UFSDEL\0\0");
        write_u32(&mut record, 8, inode_number);
        write_u64(&mut record, 12, size_bytes);
        record[20] = if is_directory { 1 } else { 0 };
        record[21] = name.len() as u8;
        record[22] = path.len() as u8;
        record[24..24 + name.len()].copy_from_slice(name.as_bytes());
        record[120..120 + path.len()].copy_from_slice(path.as_bytes());
        record
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

    fn build_test_refs_image_with_deleted_usn_record_and_payload(
        object_id: u64,
        payload: &[u8],
        encrypted: bool,
    ) -> Vec<u8> {
        let mut image = build_test_refs_image_with_deleted_usn_record();
        let payload_offset = 48 * 1024usize;
        image[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);
        write_refs_payload_descriptor(
            &mut image,
            16 * 1024,
            object_id,
            48 * 1024,
            payload.len() as u64,
            encrypted,
        );
        image
    }

    fn write_payload_descriptor(
        image: &mut [u8],
        descriptor_offset: usize,
        payload_offset: usize,
        payload: &[u8],
    ) {
        let payload_end = payload_offset + payload.len();
        image[payload_offset..payload_end].copy_from_slice(payload);
        write_u64(image, descriptor_offset, payload_offset as u64);
        write_u64(image, descriptor_offset + 8, payload.len() as u64);
    }

    fn write_refs_payload_descriptor(
        image: &mut [u8],
        descriptor_offset: usize,
        object_id: u64,
        payload_offset: u64,
        payload_length: u64,
        encrypted: bool,
    ) {
        image[descriptor_offset..descriptor_offset + REFS_PAYLOAD_MARKER.len()]
            .copy_from_slice(REFS_PAYLOAD_MARKER);
        write_u64(image, descriptor_offset + 8, object_id);
        write_u64(image, descriptor_offset + 16, payload_offset);
        write_u64(image, descriptor_offset + 24, payload_length);
        image[descriptor_offset + 32] = if encrypted {
            METADATA_ENCRYPTED_FLAG
        } else {
            0
        };
    }

    fn build_test_ext4_image() -> Vec<u8> {
        let mut image = vec![0u8; 512 * 256];
        write_u32(&mut image, 1024 + 0x00, 1024);
        write_u32(&mut image, 1024 + 0x04, 8192);
        write_u32(&mut image, 1024 + 0x18, 2);
        write_u32(&mut image, 1024 + 0x20, 32768);
        write_u32(&mut image, 1024 + 0x28, 256);
        write_u32(&mut image, 1024 + 0x60, 0x0040);
        write_u16(&mut image, 1024 + 0x38, 0xEF53);
        write_u16(&mut image, 1024 + 0x58, 256);
        image
    }

    fn build_test_ext4_image_with_deleted_entry() -> Vec<u8> {
        let mut image = build_test_ext4_image();
        let entry = build_ext_directory_entry(0, "deleted-ext.txt", 1);
        let offset = 8192usize;
        image[offset..offset + entry.len()].copy_from_slice(&entry);
        image
    }

    fn build_test_ext4_image_with_recoverable_inode(payload: &[u8]) -> Vec<u8> {
        let (mut image, inode_offset) = initialize_ext4_recovery_image(payload.len() as u32);

        let data_block = 30u32;
        write_u32(
            &mut image,
            inode_offset + EXT_INODE_BLOCK_POINTERS_OFFSET,
            data_block,
        );
        let data_offset = data_block as usize * 4096usize;
        image[data_offset..data_offset + payload.len()].copy_from_slice(payload);

        image
    }

    fn build_test_ext4_image_with_single_indirect_recoverable_inode(payload: &[u8]) -> Vec<u8> {
        let (mut image, inode_offset) = initialize_ext4_recovery_image(payload.len() as u32);

        let block_size = 4096usize;
        let direct_block_count = EXT_DIRECT_BLOCK_POINTERS;
        for direct_index in 0..direct_block_count {
            let block = 30u32 + direct_index as u32;
            write_u32(
                &mut image,
                inode_offset + EXT_INODE_BLOCK_POINTERS_OFFSET + (direct_index * 4),
                block,
            );

            let payload_offset = direct_index * block_size;
            let payload_end = payload_offset + block_size;
            let data_offset = block as usize * block_size;
            image[data_offset..data_offset + block_size]
                .copy_from_slice(&payload[payload_offset..payload_end]);
        }

        let pointer_block = 50u32;
        let indirect_data_block = 60u32;
        write_u32(
            &mut image,
            inode_offset
                + EXT_INODE_BLOCK_POINTERS_OFFSET
                + (EXT_SINGLE_INDIRECT_POINTER_INDEX * 4),
            pointer_block,
        );

        let pointer_block_offset = pointer_block as usize * block_size;
        write_u32(&mut image, pointer_block_offset, indirect_data_block);

        let tail_offset = direct_block_count * block_size;
        let tail_end = tail_offset + block_size;
        let indirect_data_offset = indirect_data_block as usize * block_size;
        image[indirect_data_offset..indirect_data_offset + block_size]
            .copy_from_slice(&payload[tail_offset..tail_end]);

        image
    }

    fn build_test_ext4_image_with_single_indirect_recoverable_inode_missing_pointer(
        payload: &[u8],
    ) -> Vec<u8> {
        let (mut image, inode_offset) = initialize_ext4_recovery_image(payload.len() as u32);

        let block_size = 4096usize;
        let direct_block_count = EXT_DIRECT_BLOCK_POINTERS;
        for direct_index in 0..direct_block_count {
            let block = 30u32 + direct_index as u32;
            write_u32(
                &mut image,
                inode_offset + EXT_INODE_BLOCK_POINTERS_OFFSET + (direct_index * 4),
                block,
            );

            let payload_offset = direct_index * block_size;
            let payload_end = payload_offset + block_size;
            let data_offset = block as usize * block_size;
            image[data_offset..data_offset + block_size]
                .copy_from_slice(&payload[payload_offset..payload_end]);
        }

        // Single-indirect pointer intentionally left as zero to trigger partial export.
        image
    }

    fn build_ext_single_indirect_payload() -> Vec<u8> {
        let block_size = 4096usize;
        let block_count = EXT_DIRECT_BLOCK_POINTERS + 1;
        let mut payload = vec![0u8; block_size * block_count];
        for block_index in 0..block_count {
            let fill = (block_index as u8).wrapping_mul(17).wrapping_add(3);
            let start = block_index * block_size;
            let end = start + block_size;
            payload[start..end].fill(fill);
        }
        payload
    }

    fn build_test_ext4_image_with_double_indirect_recoverable_inode(payload: &[u8]) -> Vec<u8> {
        let (mut image, inode_offset) =
            initialize_ext4_recovery_image_with_block_capacity(payload.len() as u32, 2_048);

        let block_size = 4096usize;
        let direct_block_count = EXT_DIRECT_BLOCK_POINTERS;
        let single_block_capacity = block_size / 4;

        for direct_index in 0..direct_block_count {
            let block = 30u32 + direct_index as u32;
            write_u32(
                &mut image,
                inode_offset + EXT_INODE_BLOCK_POINTERS_OFFSET + (direct_index * 4),
                block,
            );

            let payload_offset = direct_index * block_size;
            let payload_end = payload_offset + block_size;
            let data_offset = block as usize * block_size;
            image[data_offset..data_offset + block_size]
                .copy_from_slice(&payload[payload_offset..payload_end]);
        }

        let single_pointer_block = 50u32;
        write_u32(
            &mut image,
            inode_offset
                + EXT_INODE_BLOCK_POINTERS_OFFSET
                + (EXT_SINGLE_INDIRECT_POINTER_INDEX * 4),
            single_pointer_block,
        );

        let single_pointer_block_offset = single_pointer_block as usize * block_size;
        let single_data_start_block = 100u32;
        for single_index in 0..single_block_capacity {
            let data_block = single_data_start_block + single_index as u32;
            write_u32(
                &mut image,
                single_pointer_block_offset + (single_index * 4),
                data_block,
            );

            let payload_offset = (direct_block_count + single_index) * block_size;
            let payload_end = payload_offset + block_size;
            let data_offset = data_block as usize * block_size;
            image[data_offset..data_offset + block_size]
                .copy_from_slice(&payload[payload_offset..payload_end]);
        }

        let double_pointer_block = 60u32;
        let second_level_pointer_block = 61u32;
        let double_data_block = 1_300u32;
        write_u32(
            &mut image,
            inode_offset
                + EXT_INODE_BLOCK_POINTERS_OFFSET
                + (EXT_DOUBLE_INDIRECT_POINTER_INDEX * 4),
            double_pointer_block,
        );

        let double_pointer_block_offset = double_pointer_block as usize * block_size;
        write_u32(
            &mut image,
            double_pointer_block_offset,
            second_level_pointer_block,
        );

        let second_level_pointer_offset = second_level_pointer_block as usize * block_size;
        write_u32(&mut image, second_level_pointer_offset, double_data_block);

        let double_payload_offset = (direct_block_count + single_block_capacity) * block_size;
        let double_payload_end = double_payload_offset + block_size;
        let double_data_offset = double_data_block as usize * block_size;
        image[double_data_offset..double_data_offset + block_size]
            .copy_from_slice(&payload[double_payload_offset..double_payload_end]);

        image
    }

    fn build_ext_double_indirect_payload() -> Vec<u8> {
        let block_size = 4096usize;
        let block_count = EXT_DIRECT_BLOCK_POINTERS + (block_size / 4) + 1;
        let mut payload = vec![0u8; block_size * block_count];
        for block_index in 0..block_count {
            let fill = (block_index as u8).wrapping_mul(13).wrapping_add(7);
            let start = block_index * block_size;
            let end = start + block_size;
            payload[start..end].fill(fill);
        }
        payload
    }

    fn build_test_ext4_image_with_triple_indirect_recoverable_inode(payload: &[u8]) -> Vec<u8> {
        let (mut image, inode_offset) =
            initialize_ext4_recovery_image_with_block_capacity(payload.len() as u32, 512);

        let block_size = 4096usize;
        let direct_block_count = EXT_DIRECT_BLOCK_POINTERS;

        for direct_index in 0..direct_block_count {
            let block = 30u32 + direct_index as u32;
            write_u32(
                &mut image,
                inode_offset + EXT_INODE_BLOCK_POINTERS_OFFSET + (direct_index * 4),
                block,
            );

            let payload_offset = direct_index * block_size;
            let payload_end = payload_offset + block_size;
            let data_offset = block as usize * block_size;
            image[data_offset..data_offset + block_size]
                .copy_from_slice(&payload[payload_offset..payload_end]);
        }

        let single_pointer_block = 50u32;
        let single_data_block = 100u32;
        write_u32(
            &mut image,
            inode_offset
                + EXT_INODE_BLOCK_POINTERS_OFFSET
                + (EXT_SINGLE_INDIRECT_POINTER_INDEX * 4),
            single_pointer_block,
        );
        let single_pointer_block_offset = single_pointer_block as usize * block_size;
        write_u32(&mut image, single_pointer_block_offset, single_data_block);
        let single_payload_offset = direct_block_count * block_size;
        let single_payload_end = single_payload_offset + block_size;
        let single_data_offset = single_data_block as usize * block_size;
        image[single_data_offset..single_data_offset + block_size]
            .copy_from_slice(&payload[single_payload_offset..single_payload_end]);

        let double_pointer_block = 60u32;
        let double_second_level_block = 61u32;
        let double_data_block = 120u32;
        write_u32(
            &mut image,
            inode_offset
                + EXT_INODE_BLOCK_POINTERS_OFFSET
                + (EXT_DOUBLE_INDIRECT_POINTER_INDEX * 4),
            double_pointer_block,
        );
        let double_pointer_block_offset = double_pointer_block as usize * block_size;
        write_u32(
            &mut image,
            double_pointer_block_offset,
            double_second_level_block,
        );
        let double_second_level_offset = double_second_level_block as usize * block_size;
        write_u32(&mut image, double_second_level_offset, double_data_block);
        let double_payload_offset = (direct_block_count + 1) * block_size;
        let double_payload_end = double_payload_offset + block_size;
        let double_data_offset = double_data_block as usize * block_size;
        image[double_data_offset..double_data_offset + block_size]
            .copy_from_slice(&payload[double_payload_offset..double_payload_end]);

        let triple_pointer_block = 70u32;
        let triple_second_level_block = 71u32;
        let triple_third_level_block = 72u32;
        let triple_data_block = 140u32;
        write_u32(
            &mut image,
            inode_offset
                + EXT_INODE_BLOCK_POINTERS_OFFSET
                + (EXT_TRIPLE_INDIRECT_POINTER_INDEX * 4),
            triple_pointer_block,
        );
        let triple_pointer_block_offset = triple_pointer_block as usize * block_size;
        write_u32(
            &mut image,
            triple_pointer_block_offset,
            triple_second_level_block,
        );
        let triple_second_level_offset = triple_second_level_block as usize * block_size;
        write_u32(
            &mut image,
            triple_second_level_offset,
            triple_third_level_block,
        );
        let triple_third_level_offset = triple_third_level_block as usize * block_size;
        write_u32(&mut image, triple_third_level_offset, triple_data_block);
        let triple_payload_offset = (direct_block_count + 2) * block_size;
        let triple_payload_end = triple_payload_offset + block_size;
        let triple_data_offset = triple_data_block as usize * block_size;
        image[triple_data_offset..triple_data_offset + block_size]
            .copy_from_slice(&payload[triple_payload_offset..triple_payload_end]);

        image
    }

    fn build_ext_triple_indirect_payload() -> Vec<u8> {
        let block_size = 4096usize;
        let block_count = EXT_DIRECT_BLOCK_POINTERS + 3;
        let mut payload = vec![0u8; block_size * block_count];
        for block_index in 0..block_count {
            let fill = (block_index as u8).wrapping_mul(19).wrapping_add(11);
            let start = block_index * block_size;
            let end = start + block_size;
            payload[start..end].fill(fill);
        }
        payload
    }

    fn build_test_ext4_image_with_extent_leaf_recoverable_inode(payload: &[u8]) -> Vec<u8> {
        let (mut image, inode_offset) = initialize_ext4_recovery_image(payload.len() as u32);

        write_u32(
            &mut image,
            inode_offset + EXT_INODE_FLAGS_OFFSET,
            EXT_INODE_FLAG_EXTENTS,
        );

        let extent_header_offset = inode_offset + EXT_INODE_BLOCK_POINTERS_OFFSET;
        write_u16(&mut image, extent_header_offset, EXTENT_HEADER_MAGIC);
        write_u16(&mut image, extent_header_offset + 2, 1);
        write_u16(&mut image, extent_header_offset + 4, 4);
        write_u16(&mut image, extent_header_offset + 6, 0);
        write_u32(&mut image, extent_header_offset + 8, 0);

        let data_start_block = 30u32;
        let block_count = payload.len() / 4096;
        let extent_record_offset = extent_header_offset + EXTENT_HEADER_SIZE;
        write_u32(&mut image, extent_record_offset, 0);
        write_u16(&mut image, extent_record_offset + 4, block_count as u16);
        write_u16(&mut image, extent_record_offset + 6, 0);
        write_u32(&mut image, extent_record_offset + 8, data_start_block);

        for block_index in 0..block_count {
            let payload_offset = block_index * 4096;
            let payload_end = payload_offset + 4096;
            let data_offset = (data_start_block as usize + block_index) * 4096usize;
            image[data_offset..data_offset + 4096]
                .copy_from_slice(&payload[payload_offset..payload_end]);
        }

        image
    }

    fn build_ext_extent_leaf_payload() -> Vec<u8> {
        let block_size = 4096usize;
        let block_count = 2usize;
        let mut payload = vec![0u8; block_size * block_count];
        for block_index in 0..block_count {
            let fill = (block_index as u8).wrapping_mul(23).wrapping_add(5);
            let start = block_index * block_size;
            let end = start + block_size;
            payload[start..end].fill(fill);
        }
        payload
    }

    fn build_test_ext4_image_with_uninitialized_extent_leaf_recoverable_inode(
        payload: &[u8],
    ) -> Vec<u8> {
        let (mut image, inode_offset) = initialize_ext4_recovery_image((2 * 4096) as u32);

        write_u32(
            &mut image,
            inode_offset + EXT_INODE_FLAGS_OFFSET,
            EXT_INODE_FLAG_EXTENTS,
        );

        let extent_header_offset = inode_offset + EXT_INODE_BLOCK_POINTERS_OFFSET;
        write_u16(&mut image, extent_header_offset, EXTENT_HEADER_MAGIC);
        write_u16(&mut image, extent_header_offset + 2, 2);
        write_u16(&mut image, extent_header_offset + 4, 4);
        write_u16(&mut image, extent_header_offset + 6, 0);
        write_u32(&mut image, extent_header_offset + 8, 0);

        let first_data_block = 30u32;
        let first_extent_offset = extent_header_offset + EXTENT_HEADER_SIZE;
        write_u32(&mut image, first_extent_offset, 0);
        write_u16(&mut image, first_extent_offset + 4, 1);
        write_u16(&mut image, first_extent_offset + 6, 0);
        write_u32(&mut image, first_extent_offset + 8, first_data_block);

        let second_extent_offset = first_extent_offset + EXTENT_RECORD_SIZE;
        write_u32(&mut image, second_extent_offset, 1);
        write_u16(
            &mut image,
            second_extent_offset + 4,
            EXTENT_UNINITIALIZED_LENGTH_FLAG | 1,
        );
        write_u16(&mut image, second_extent_offset + 6, 0);
        write_u32(&mut image, second_extent_offset + 8, 0);

        let first_data_offset = first_data_block as usize * 4096usize;
        image[first_data_offset..first_data_offset + 4096].copy_from_slice(payload);

        image
    }

    fn build_ext_extent_uninitialized_payload() -> Vec<u8> {
        let mut payload = vec![0u8; 4096];
        payload.fill(0x5A);
        payload
    }

    fn build_test_ext4_image_with_inline_symlink_inode(target: &str) -> Vec<u8> {
        let target_bytes = target.as_bytes();
        let (mut image, inode_offset) = initialize_ext4_recovery_image(target_bytes.len() as u32);

        write_u16(&mut image, inode_offset + 0, 0xA1FF);
        let inline_offset = inode_offset + EXT_INODE_BLOCK_POINTERS_OFFSET;
        image[inline_offset..inline_offset + target_bytes.len()].copy_from_slice(target_bytes);

        image
    }

    fn build_test_ext4_image_with_non_inline_symlink_inode(target: &str) -> Vec<u8> {
        let target_bytes = target.as_bytes();
        let (mut image, inode_offset) = initialize_ext4_recovery_image(target_bytes.len() as u32);

        write_u16(&mut image, inode_offset + 0, 0xA1FF);
        let data_block = 30u32;
        write_u32(
            &mut image,
            inode_offset + EXT_INODE_BLOCK_POINTERS_OFFSET,
            data_block,
        );

        let data_offset = data_block as usize * 4096usize;
        image[data_offset..data_offset + target_bytes.len()].copy_from_slice(target_bytes);

        image
    }

    fn build_test_ext4_image_with_directory_inode(payload: &[u8]) -> Vec<u8> {
        let (mut image, inode_offset) = initialize_ext4_recovery_image(payload.len() as u32);

        write_u16(&mut image, inode_offset + 0, 0x41ED);
        let data_block = 30u32;
        write_u32(
            &mut image,
            inode_offset + EXT_INODE_BLOCK_POINTERS_OFFSET,
            data_block,
        );

        let data_offset = data_block as usize * 4096usize;
        image[data_offset..data_offset + payload.len()].copy_from_slice(payload);

        image
    }

    fn build_ext_directory_payload() -> Vec<u8> {
        let mut payload = vec![0u8; 4096];
        let entry = build_ext_directory_entry(42, "docs", 2);
        payload[..entry.len()].copy_from_slice(&entry);
        payload
    }

    fn initialize_ext4_recovery_image(file_size_bytes: u32) -> (Vec<u8>, usize) {
        initialize_ext4_recovery_image_with_block_capacity(file_size_bytes, 64)
    }

    fn initialize_ext4_recovery_image_with_block_capacity(
        file_size_bytes: u32,
        block_capacity: usize,
    ) -> (Vec<u8>, usize) {
        let mut image = vec![0u8; 4096 * block_capacity];
        write_u32(&mut image, 1024 + 0x00, 1024);
        write_u32(&mut image, 1024 + 0x04, 65_536);
        write_u32(&mut image, 1024 + 0x14, 0);
        write_u32(&mut image, 1024 + 0x18, 2);
        write_u32(&mut image, 1024 + 0x20, 32_768);
        write_u32(&mut image, 1024 + 0x28, 256);
        write_u32(&mut image, 1024 + 0x60, 0x0040);
        write_u16(&mut image, 1024 + 0x38, 0xEF53);
        write_u16(&mut image, 1024 + 0x58, 256);

        // Group descriptor table starts at block 1 for 4 KiB block-size images.
        write_u32(
            &mut image,
            4096 + EXT_GROUP_DESCRIPTOR_INODE_TABLE_OFFSET,
            10,
        );

        let inode_table_offset = 10usize * 4096usize;
        let inode_offset = inode_table_offset + 15usize * 256usize; // inode 16
        write_u16(&mut image, inode_offset + 0, 0x81A4);
        write_u32(&mut image, inode_offset + 4, file_size_bytes);
        write_u32(&mut image, inode_offset + 20, 1_704_067_200);
        write_u16(&mut image, inode_offset + 26, 0);

        (image, inode_offset)
    }

    fn build_ext_directory_entry(inode: u32, name: &str, file_type: u8) -> Vec<u8> {
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

    fn build_test_mdraid_member_image(
        level: i32,
        member_count: u32,
        stripe_size_bytes: u32,
        data_offset_sectors: u64,
        fill_byte: u8,
    ) -> Vec<u8> {
        let data_offset_bytes = data_offset_sectors as usize * 512usize;
        let payload_len = stripe_size_bytes as usize * 2;
        let mut image = vec![0u8; data_offset_bytes + payload_len];
        const MD_BASE: usize = 4096;
        const MD_MAGIC: u32 = 0xA92B4EFC;
        write_u32(&mut image, MD_BASE + 0x00, MD_MAGIC);
        write_u32(&mut image, MD_BASE + 0x04, 1);
        write_u32(&mut image, MD_BASE + 0x48, level as u32);
        write_u32(&mut image, MD_BASE + 0x4C, 0);
        write_u32(&mut image, MD_BASE + 0x50, stripe_size_bytes);
        write_u32(&mut image, MD_BASE + 0x5C, member_count);
        write_u64(&mut image, MD_BASE + 0x80, data_offset_sectors);
        for value in image.iter_mut().skip(data_offset_bytes).take(payload_len) {
            *value = fill_byte;
        }
        image
    }

    fn build_test_mdraid_image() -> Vec<u8> {
        let mut image = vec![0u8; 512 * 256];
        const MD_BASE: usize = 4096;
        const MD_MAGIC: u32 = 0xA92B4EFC;
        write_u32(&mut image, MD_BASE + 0x00, MD_MAGIC);
        write_u32(&mut image, MD_BASE + 0x04, 1);
        write_u32(&mut image, MD_BASE + 0x48, 5);
        write_u32(&mut image, MD_BASE + 0x4C, 0);
        write_u32(&mut image, MD_BASE + 0x50, 128 * 1024);
        write_u32(&mut image, MD_BASE + 0x5C, 4);
        write_u64(&mut image, MD_BASE + 0x80, 2048);
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

    fn build_test_fat32_image_with_nested_deleted_entry() -> Vec<u8> {
        let mut image = build_test_fat32_image_with_deleted_entry();

        let fat_sector_offset = 32 * 512;
        write_u32(&mut image, fat_sector_offset + (6 * 4), 0x0FFF_FFFF);

        let root_sector_offset = 33 * 512;
        image[root_sector_offset + 32] = b'S';
        image[root_sector_offset + 33..root_sector_offset + 40].copy_from_slice(b"UBDIR  ");
        image[root_sector_offset + 32 + 11] = 0x10;
        write_u16(&mut image, root_sector_offset + 32 + 26, 6);
        write_u32(&mut image, root_sector_offset + 32 + 28, 0);
        image[root_sector_offset + 64] = 0x00;

        let nested_directory_sector_offset = 37 * 512;
        image[nested_directory_sector_offset] = 0xE5;
        image[nested_directory_sector_offset + 1..nested_directory_sector_offset + 8]
            .copy_from_slice(b"HILD   ");
        image[nested_directory_sector_offset + 8..nested_directory_sector_offset + 11]
            .copy_from_slice(b"TXT");
        image[nested_directory_sector_offset + 11] = 0x20;
        write_u16(&mut image, nested_directory_sector_offset + 26, 9);
        write_u32(&mut image, nested_directory_sector_offset + 28, 55);
        image[nested_directory_sector_offset + 32] = 0x00;

        image
    }

    fn build_test_fat32_image_with_deleted_lfn_entry() -> Vec<u8> {
        let mut image = build_test_fat32_image_with_deleted_entry();
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

    fn build_test_fat32_image_with_cluster_loop() -> Vec<u8> {
        let mut image = build_test_fat32_image_with_deleted_entry();
        let fat_sector_offset = 32 * 512;
        write_u32(&mut image, fat_sector_offset + (2 * 4), 3);
        write_u32(&mut image, fat_sector_offset + (3 * 4), 2);
        image
    }

    fn build_test_fat32_image_with_bad_cluster_chain() -> Vec<u8> {
        let mut image = build_test_fat32_image_with_deleted_entry();
        let fat_sector_offset = 32 * 512;
        write_u32(&mut image, fat_sector_offset + (2 * 4), 0x0FFF_FFF7);
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

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u16_be(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn write_u32_be(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn write_u64_be(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn align_to_4(value: usize) -> usize {
        (value + 3) & !3
    }

    fn write_i64(bytes: &mut [u8], offset: usize, value: i64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
