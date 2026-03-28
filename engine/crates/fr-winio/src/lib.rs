use fr_types::RecoverySourceKind;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceProbe {
    pub normalized_path: String,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WinIoError {
    #[error("invalid source path")]
    InvalidSourcePath,
    #[error("invalid read offset")]
    InvalidReadOffset,
    #[error("misaligned read: alignment={alignment_bytes} offset={offset} length={length}")]
    MisalignedRead {
        alignment_bytes: u32,
        offset: u64,
        length: usize,
    },
    #[error("unsupported platform")]
    UnsupportedPlatform,
    #[error("access denied ({0})")]
    AccessDenied(u32),
    #[error("source not found ({0})")]
    NotFound(u32),
    #[error("windows api error ({0})")]
    OsError(u32),
}

pub struct ReadSession {
    normalized_path: String,
    size_bytes: Option<u64>,
    alignment_bytes: Option<u32>,
    enforce_alignment: bool,
    inner: platform::PlatformReadSession,
}

impl ReadSession {
    pub fn open(path: &str, kind: RecoverySourceKind) -> Result<Self, WinIoError> {
        platform::open_read_session(path, kind)
    }

    pub fn normalized_path(&self) -> &str {
        &self.normalized_path
    }

    pub fn size_bytes(&self) -> Option<u64> {
        self.size_bytes
    }

    pub fn alignment_bytes(&self) -> Option<u32> {
        self.alignment_bytes
    }

    pub fn alignment_enforced(&self) -> bool {
        self.enforce_alignment
    }

    pub fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize, WinIoError> {
        self.inner.read_at(offset, buffer)
    }
}

pub fn probe_source_read_only(
    path: &str,
    kind: RecoverySourceKind,
) -> Result<SourceProbe, WinIoError> {
    let session = ReadSession::open(path, kind)?;
    Ok(SourceProbe {
        normalized_path: session.normalized_path,
        size_bytes: session.size_bytes,
    })
}

fn normalize_probe_path(path: &str, kind: RecoverySourceKind) -> Result<String, WinIoError> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(WinIoError::InvalidSourcePath);
    }

    match kind {
        RecoverySourceKind::ImageFile => Ok(trimmed.to_string()),
        RecoverySourceKind::Volume => normalize_volume_path(trimmed),
        RecoverySourceKind::PhysicalDisk => normalize_physical_disk_path(trimmed),
    }
}

fn normalize_volume_path(path: &str) -> Result<String, WinIoError> {
    if path.starts_with(r"\\.\") {
        return Ok(path.to_string());
    }

    let cleaned = path.trim_end_matches(['\\', '/']);
    if cleaned.len() == 2 && cleaned.ends_with(':') {
        return Ok(format!(r"\\.\{}", cleaned.to_ascii_uppercase()));
    }

    if cleaned.len() == 1 && cleaned.chars().all(|c| c.is_ascii_alphabetic()) {
        return Ok(format!(r"\\.\{}:", cleaned.to_ascii_uppercase()));
    }

    Err(WinIoError::InvalidSourcePath)
}

fn normalize_physical_disk_path(path: &str) -> Result<String, WinIoError> {
    const PREFIX: &str = r"\\.\PhysicalDrive";

    if path.len() >= PREFIX.len() && path[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        let suffix = &path[PREFIX.len()..];
        let Ok(index) = suffix.parse::<u32>() else {
            return Err(WinIoError::InvalidSourcePath);
        };

        return Ok(format!(r"\\.\PhysicalDrive{}", index));
    }

    let Ok(index) = path.parse::<u32>() else {
        return Err(WinIoError::InvalidSourcePath);
    };

    Ok(format!(r"\\.\PhysicalDrive{}", index))
}

#[cfg(windows)]
mod platform {
    use super::{normalize_probe_path, ReadSession, WinIoError};
    use fr_types::RecoverySourceKind;
    use std::iter;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_HANDLE_EOF,
        ERROR_PATH_NOT_FOUND, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetDiskFreeSpaceW, GetFileSizeEx, ReadFile, SetFilePointerEx,
        FILE_ATTRIBUTE_NORMAL, FILE_BEGIN, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: u32 = 0x0007_00A0;

    pub(super) struct PlatformReadSession {
        handle: HANDLE,
        alignment_bytes: Option<u32>,
        enforce_alignment: bool,
    }

    // Win32 HANDLE values are process-wide kernel object references and can be moved across threads.
    unsafe impl Send for PlatformReadSession {}

    impl PlatformReadSession {
        pub(super) fn read_at(
            &mut self,
            offset: u64,
            buffer: &mut [u8],
        ) -> Result<usize, WinIoError> {
            if buffer.is_empty() {
                return Ok(0);
            }

            if offset > i64::MAX as u64 {
                return Err(WinIoError::InvalidReadOffset);
            }

            if self.enforce_alignment {
                if let Some(alignment) = self.alignment_bytes {
                    if offset % alignment as u64 != 0 || buffer.len() as u64 % alignment as u64 != 0
                    {
                        return Err(WinIoError::MisalignedRead {
                            alignment_bytes: alignment,
                            offset,
                            length: buffer.len(),
                        });
                    }
                }
            }

            let moved = unsafe {
                SetFilePointerEx(self.handle, offset as i64, std::ptr::null_mut(), FILE_BEGIN)
            };
            if moved == 0 {
                return Err(map_last_error());
            }

            let mut bytes_read: u32 = 0;
            let read_result = unsafe {
                ReadFile(
                    self.handle,
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    &mut bytes_read,
                    std::ptr::null_mut(),
                )
            };

            if read_result == 0 {
                let code = unsafe { GetLastError() };
                if code == ERROR_HANDLE_EOF {
                    return Ok(0);
                }
                return Err(map_error_code(code));
            }

            Ok(bytes_read as usize)
        }
    }

    impl Drop for PlatformReadSession {
        fn drop(&mut self) {
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }

    pub(super) fn open_read_session(
        path: &str,
        kind: RecoverySourceKind,
    ) -> Result<ReadSession, WinIoError> {
        let normalized_path = normalize_probe_path(path, kind)?;
        let wide = to_utf16_null(&normalized_path);

        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(map_last_error());
        }

        let mut size: i64 = 0;
        let mut size_bytes = if unsafe { GetFileSizeEx(handle, &mut size) } != 0 && size >= 0 {
            Some(size as u64)
        } else {
            None
        };

        let physical_geometry = if matches!(kind, RecoverySourceKind::PhysicalDisk) {
            query_physical_geometry(handle)
        } else {
            None
        };

        if size_bytes.is_none() {
            size_bytes = physical_geometry.map(|(_, disk_size)| disk_size);
        }

        let (alignment_bytes, enforce_alignment) =
            alignment_strategy(kind, &normalized_path, physical_geometry);

        Ok(ReadSession {
            normalized_path,
            size_bytes,
            alignment_bytes,
            enforce_alignment,
            inner: PlatformReadSession {
                handle,
                alignment_bytes,
                enforce_alignment,
            },
        })
    }

    fn alignment_strategy(
        kind: RecoverySourceKind,
        normalized_path: &str,
        physical_geometry: Option<(u32, u64)>,
    ) -> (Option<u32>, bool) {
        match kind {
            RecoverySourceKind::ImageFile => (None, false),
            RecoverySourceKind::Volume => (
                query_volume_sector_size(normalized_path).or(Some(512)),
                true,
            ),
            RecoverySourceKind::PhysicalDisk => (
                physical_geometry
                    .map(|(sector_size, _)| sector_size)
                    .or(Some(512)),
                true,
            ),
        }
    }

    fn query_physical_geometry(handle: HANDLE) -> Option<(u32, u64)> {
        let mut buffer = [0u8; 128];
        let mut bytes_returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                std::ptr::null(),
                0,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };

        if ok == 0 || bytes_returned < 32 {
            return None;
        }

        let bytes_per_sector = u32::from_le_bytes([buffer[20], buffer[21], buffer[22], buffer[23]]);
        if bytes_per_sector == 0 {
            return None;
        }

        let disk_size = u64::from_le_bytes([
            buffer[24], buffer[25], buffer[26], buffer[27], buffer[28], buffer[29], buffer[30],
            buffer[31],
        ]);

        Some((bytes_per_sector, disk_size))
    }

    fn query_volume_sector_size(normalized_path: &str) -> Option<u32> {
        let Some(volume) = normalized_path.strip_prefix(r"\\.\") else {
            return None;
        };

        if volume.len() != 2 || !volume.ends_with(':') {
            return None;
        }

        let root = format!("{}\\", volume);
        let root_wide = to_utf16_null(&root);

        let mut sectors_per_cluster: u32 = 0;
        let mut bytes_per_sector: u32 = 0;
        let mut free_clusters: u32 = 0;
        let mut total_clusters: u32 = 0;

        let ok = unsafe {
            GetDiskFreeSpaceW(
                root_wide.as_ptr(),
                &mut sectors_per_cluster,
                &mut bytes_per_sector,
                &mut free_clusters,
                &mut total_clusters,
            )
        };

        if ok == 0 || bytes_per_sector == 0 {
            return None;
        }

        Some(bytes_per_sector)
    }

    fn map_last_error() -> WinIoError {
        map_error_code(unsafe { GetLastError() })
    }

    fn map_error_code(code: u32) -> WinIoError {
        match code {
            ERROR_ACCESS_DENIED => WinIoError::AccessDenied(code),
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => WinIoError::NotFound(code),
            _ => WinIoError::OsError(code),
        }
    }

    fn to_utf16_null(input: &str) -> Vec<u16> {
        input.encode_utf16().chain(iter::once(0)).collect()
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{normalize_probe_path, ReadSession, WinIoError};
    use fr_types::RecoverySourceKind;

    pub(super) struct PlatformReadSession;

    impl PlatformReadSession {
        pub(super) fn read_at(
            &mut self,
            _offset: u64,
            _buffer: &mut [u8],
        ) -> Result<usize, WinIoError> {
            Err(WinIoError::UnsupportedPlatform)
        }
    }

    pub(super) fn open_read_session(
        path: &str,
        kind: RecoverySourceKind,
    ) -> Result<ReadSession, WinIoError> {
        let _normalized_path = normalize_probe_path(path, kind)?;
        Err(WinIoError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_volume_drive_letter() {
        let path = normalize_probe_path("d:\\", RecoverySourceKind::Volume).unwrap();
        assert_eq!(path, r"\\.\D:");
    }

    #[test]
    fn normalizes_physical_drive_index() {
        let path = normalize_probe_path("2", RecoverySourceKind::PhysicalDisk).unwrap();
        assert_eq!(path, r"\\.\PhysicalDrive2");
    }

    #[test]
    fn normalizes_physical_drive_path_case_insensitively() {
        let path =
            normalize_probe_path(r"\\.\PHYSICALDRIVE12", RecoverySourceKind::PhysicalDisk).unwrap();
        assert_eq!(path, r"\\.\PhysicalDrive12");
    }

    #[test]
    fn rejects_physical_drive_path_with_non_numeric_suffix() {
        let err = normalize_probe_path(r"\\.\PhysicalDriveX", RecoverySourceKind::PhysicalDisk)
            .unwrap_err();
        assert_eq!(err, WinIoError::InvalidSourcePath);
    }

    #[test]
    fn rejects_invalid_volume_path() {
        let err = normalize_probe_path("not-a-volume", RecoverySourceKind::Volume).unwrap_err();
        assert_eq!(err, WinIoError::InvalidSourcePath);
    }
}
