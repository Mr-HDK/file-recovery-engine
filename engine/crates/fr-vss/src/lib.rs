use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Timelike, Utc};
use fr_types::RecoverySourceKind;
use serde::Deserialize;
use serde_json::Value;
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDescriptor {
    pub name: &'static str,
    pub purpose: &'static str,
    pub source_kind: RecoverySourceKind,
}

pub fn descriptor() -> ModuleDescriptor {
    ModuleDescriptor {
        name: "fr-vss",
        purpose: "Windows VSS snapshot enumeration and read-only snapshot path discovery.",
        source_kind: RecoverySourceKind::Volume,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VssSnapshot {
    pub snapshot_id: String,
    pub volume_name: Option<String>,
    pub device_object: String,
    pub install_time_utc: Option<String>,
    pub snapshot_path: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VssError {
    #[error("unsupported platform")]
    UnsupportedPlatform,
    #[error("PowerShell is not available")]
    PowerShellUnavailable,
    #[error("VSS query failed (exit {exit_code}): {stderr}")]
    QueryFailed { exit_code: i32, stderr: String },
    #[error("failed to parse VSS snapshot output: {0}")]
    Parse(String),
}

pub fn list_snapshots() -> Result<Vec<VssSnapshot>, VssError> {
    platform::list_snapshots()
}

#[derive(Debug, Clone, Deserialize)]
struct RawShadowCopy {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "VolumeName")]
    volume_name: Option<String>,
    #[serde(rename = "DeviceObject")]
    device_object: Option<String>,
    #[serde(rename = "InstallDate")]
    install_date: Option<String>,
}

fn parse_snapshots_from_json(raw_json: &str) -> Result<Vec<RawShadowCopy>, VssError> {
    let trimmed = raw_json.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let value: Value =
        serde_json::from_str(trimmed).map_err(|err| VssError::Parse(err.to_string()))?;

    match value {
        Value::Null => Ok(Vec::new()),
        Value::Array(array) => array
            .into_iter()
            .map(|item| serde_json::from_value(item).map_err(|err| VssError::Parse(err.to_string())))
            .collect(),
        Value::Object(_) => serde_json::from_value(value)
            .map(|single| vec![single])
            .map_err(|err| VssError::Parse(err.to_string())),
        _ => Err(VssError::Parse(
            "unexpected JSON payload shape for VSS snapshots".to_string(),
        )),
    }
}

fn normalize_volume_name(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().trim_end_matches('\\').to_string())
        .filter(|v| !v.is_empty())
        .map(|v| format!(r"{}\{}", v, ""))
}

fn normalize_device_object(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches('\\');
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.starts_with(r"\\?\GLOBALROOT\") {
        return Some(trimmed.to_string());
    }

    if let Some(rest) = trimmed.strip_prefix(r"\Device\") {
        return Some(format!(r"\\?\GLOBALROOT\Device\{}", rest));
    }

    if let Some(rest) = trimmed.strip_prefix(r"\\Device\") {
        return Some(format!(r"\\?\GLOBALROOT\Device\{}", rest));
    }

    None
}

fn snapshot_path_from_device_object(device_object: &str) -> String {
    if device_object.ends_with('\\') {
        device_object.to_string()
    } else {
        format!(r"{}\{}", device_object, "")
    }
}

fn normalize_install_time_utc(value: Option<String>) -> Option<String> {
    let raw = value?.trim().to_string();
    if raw.is_empty() {
        return None;
    }

    if let Ok(parsed) = DateTime::parse_from_rfc3339(&raw) {
        return Some(parsed.with_timezone(&Utc).to_rfc3339());
    }

    if let Some(parsed) = parse_powershell_json_date(&raw) {
        return Some(parsed.to_rfc3339());
    }

    if let Some(parsed) = parse_dmtf_datetime_utc(&raw) {
        return Some(parsed.to_rfc3339());
    }

    Some(raw)
}

fn parse_powershell_json_date(value: &str) -> Option<DateTime<Utc>> {
    // Windows PowerShell 5.1 style: /Date(1706659200000)/
    let token = value.strip_prefix("/Date(")?.strip_suffix(")/")?;
    let millis_part = token.split(['+', '-']).next()?.trim();
    let millis = millis_part.parse::<i64>().ok()?;
    DateTime::from_timestamp_millis(millis)
}

fn parse_dmtf_datetime_utc(value: &str) -> Option<DateTime<Utc>> {
    // DMTF: yyyymmddHHMMSS.mmmmmmsUUU where s is +/- and UUU is minutes offset from UTC.
    if value.len() < 25 {
        return None;
    }

    let dt_part = &value[0..14];
    if value.as_bytes().get(14) != Some(&b'.') {
        return None;
    }
    let micros_part = &value[15..21];
    let sign = value.as_bytes().get(21).copied()? as char;
    let offset_part = &value[22..25];

    let naive = NaiveDateTime::parse_from_str(dt_part, "%Y%m%d%H%M%S").ok()?;
    let micros = micros_part.parse::<u32>().ok()?;
    let naive = naive.with_nanosecond(micros.saturating_mul(1_000))?;

    let offset_minutes = offset_part.parse::<i32>().ok()?;
    let signed_minutes = match sign {
        '+' => offset_minutes,
        '-' => -offset_minutes,
        _ => return None,
    };
    let offset_seconds = signed_minutes.saturating_mul(60);
    let offset = FixedOffset::east_opt(offset_seconds)?;
    offset
        .from_local_datetime(&naive)
        .single()
        .map(|dt| dt.with_timezone(&Utc))
}

fn build_snapshots(raw_json: &str) -> Result<Vec<VssSnapshot>, VssError> {
    let parsed = parse_snapshots_from_json(raw_json)?;
    let mut snapshots = Vec::new();

    for entry in parsed {
        let Some(id) = entry
            .id
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
        else {
            continue;
        };

        let Some(device_object) = entry
            .device_object
            .as_deref()
            .and_then(normalize_device_object)
        else {
            continue;
        };

        snapshots.push(VssSnapshot {
            snapshot_id: id,
            volume_name: normalize_volume_name(entry.volume_name),
            install_time_utc: normalize_install_time_utc(entry.install_date),
            snapshot_path: snapshot_path_from_device_object(&device_object),
            device_object,
        });
    }

    snapshots.sort_by(|a, b| {
        b.install_time_utc
            .cmp(&a.install_time_utc)
            .then_with(|| a.snapshot_id.cmp(&b.snapshot_id))
    });
    Ok(snapshots)
}

#[cfg(windows)]
mod platform {
    use super::*;

    pub(super) fn list_snapshots() -> Result<Vec<VssSnapshot>, VssError> {
        let command = find_powershell().ok_or(VssError::PowerShellUnavailable)?;
        let script = "$ErrorActionPreference='Stop'; $items = Get-CimInstance -ClassName Win32_ShadowCopy | Select-Object ID,InstallDate,DeviceObject,VolumeName; $items | ConvertTo-Json -Compress";
        let output = Command::new(command)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ])
            .output()
            .map_err(|_| VssError::PowerShellUnavailable)?;

        if !output.status.success() {
            let code = output.status.code().unwrap_or(-1);
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(VssError::QueryFailed {
                exit_code: code,
                stderr,
            });
        }

        let stdout = String::from_utf8(output.stdout)
            .map_err(|err| VssError::Parse(format!("non-UTF8 PowerShell output: {}", err)))?;
        build_snapshots(&stdout)
    }

    fn find_powershell() -> Option<&'static str> {
        if Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"])
            .output()
            .is_ok()
        {
            return Some("powershell");
        }

        if Command::new("pwsh")
            .args(["-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"])
            .output()
            .is_ok()
        {
            return Some("pwsh");
        }

        None
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;

    pub(super) fn list_snapshots() -> Result<Vec<VssSnapshot>, VssError> {
        Err(VssError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_snapshots_from_array_json() {
        let json = r#"[
          {
            "ID":"{11111111-1111-1111-1111-111111111111}",
            "VolumeName":"\\\\?\\Volume{abc}\\",
            "DeviceObject":"\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy2",
            "InstallDate":"2026-03-28T10:10:10Z"
          }
        ]"#;

        let snapshots = build_snapshots(json).unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            snapshots[0].snapshot_path,
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\"
        );
        assert_eq!(
            snapshots[0].install_time_utc.as_deref(),
            Some("2026-03-28T10:10:10+00:00")
        );
    }

    #[test]
    fn builds_snapshots_from_single_object_json() {
        let json = r#"{
          "ID":"{22222222-2222-2222-2222-222222222222}",
          "VolumeName":"\\\\?\\Volume{def}\\",
          "DeviceObject":"\\Device\\HarddiskVolumeShadowCopy9",
          "InstallDate":"/Date(1711616400000)/"
        }"#;

        let snapshots = build_snapshots(json).unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            snapshots[0].device_object,
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy9"
        );
        assert_eq!(
            snapshots[0].snapshot_path,
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy9\"
        );
        assert!(snapshots[0]
            .install_time_utc
            .as_deref()
            .is_some_and(|value| value.ends_with("+00:00")));
    }

    #[test]
    fn parse_dmtf_datetime_handles_utc_offset() {
        let value = "20260328141213.123456+120";
        let parsed = parse_dmtf_datetime_utc(value).unwrap();
        assert_eq!(parsed.to_rfc3339(), "2026-03-28T12:12:13.123456+00:00");
    }
}
