use fr_types::RecoverySourceKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDescriptor {
    pub name: &'static str,
    pub purpose: &'static str,
    pub source_kind: RecoverySourceKind,
}

pub fn descriptor() -> ModuleDescriptor {
    ModuleDescriptor {
        name: "fr-validator",
        purpose: "Carving validators (magic, container consistency, mismatch, partial status).",
        source_kind: RecoverySourceKind::Volume,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileFormat {
    Jpeg,
    Png,
    Pdf,
    Zip,
    Docx,
    Xlsx,
    Pptx,
    Utf8Text,
    Mp3,
    Wav,
}

impl FileFormat {
    pub fn default_extension(self) -> &'static str {
        match self {
            FileFormat::Jpeg => "jpg",
            FileFormat::Png => "png",
            FileFormat::Pdf => "pdf",
            FileFormat::Zip => "zip",
            FileFormat::Docx => "docx",
            FileFormat::Xlsx => "xlsx",
            FileFormat::Pptx => "pptx",
            FileFormat::Utf8Text => "txt",
            FileFormat::Mp3 => "mp3",
            FileFormat::Wav => "wav",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub format: FileFormat,
    pub is_valid: bool,
    pub partial: bool,
    pub extension_matches: Option<bool>,
    pub reasons: Vec<String>,
}

pub fn validate_carved_bytes(format: FileFormat, bytes: &[u8]) -> ValidationReport {
    validate_carved_bytes_with_extension(format, bytes, None)
}

pub fn validate_carved_bytes_with_extension(
    format: FileFormat,
    bytes: &[u8],
    extension: Option<&str>,
) -> ValidationReport {
    let mut report = match format {
        FileFormat::Jpeg => validate_jpeg(bytes),
        FileFormat::Png => validate_png(bytes),
        FileFormat::Pdf => validate_pdf(bytes),
        FileFormat::Zip => validate_zip(bytes),
        FileFormat::Docx => validate_office_zip(bytes, FileFormat::Docx),
        FileFormat::Xlsx => validate_office_zip(bytes, FileFormat::Xlsx),
        FileFormat::Pptx => validate_office_zip(bytes, FileFormat::Pptx),
        FileFormat::Utf8Text => validate_utf8_text(bytes),
        FileFormat::Mp3 => validate_mp3(bytes),
        FileFormat::Wav => validate_wav(bytes),
    };
    report.format = format;
    apply_extension_check(&mut report, extension);
    report
}

fn apply_extension_check(report: &mut ValidationReport, extension: Option<&str>) {
    let Some(raw_extension) = extension else {
        report.extension_matches = None;
        return;
    };

    let normalized = raw_extension.trim().trim_start_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        report.extension_matches = None;
        return;
    }

    let expected = report.format.default_extension();
    let matches = normalized == expected;
    report.extension_matches = Some(matches);
    if !matches {
        report.reasons.push(format!(
            "Extension/content mismatch: expected .{}, found .{}",
            expected, normalized
        ));
    }
}

fn validate_jpeg(bytes: &[u8]) -> ValidationReport {
    let mut reasons = Vec::new();
    if bytes.len() < 4 {
        reasons.push("JPEG candidate too small".to_string());
        return invalid(FileFormat::Jpeg, reasons);
    }
    if !bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        reasons.push("JPEG SOI marker missing".to_string());
        return invalid(FileFormat::Jpeg, reasons);
    }

    if find_subsequence(bytes, &[0xFF, 0xD9]).is_none() {
        reasons.push("JPEG EOI marker missing (likely truncated)".to_string());
        return partial(FileFormat::Jpeg, reasons);
    }

    valid(FileFormat::Jpeg, reasons)
}

fn validate_png(bytes: &[u8]) -> ValidationReport {
    const PNG_SIG: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    let mut reasons = Vec::new();
    if bytes.len() < PNG_SIG.len() + 12 {
        reasons.push("PNG candidate too small".to_string());
        return invalid(FileFormat::Png, reasons);
    }
    if !bytes.starts_with(PNG_SIG) {
        reasons.push("PNG signature mismatch".to_string());
        return invalid(FileFormat::Png, reasons);
    }

    let mut cursor = PNG_SIG.len();
    let mut saw_iend = false;
    while cursor + 12 <= bytes.len() {
        let chunk_len = u32::from_be_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]) as usize;
        let chunk_type = &bytes[cursor + 4..cursor + 8];
        let Some(next) = cursor
            .checked_add(12)
            .and_then(|v| v.checked_add(chunk_len))
        else {
            reasons.push("PNG chunk size overflow".to_string());
            return invalid(FileFormat::Png, reasons);
        };
        if next > bytes.len() {
            reasons.push("PNG chunk truncated".to_string());
            return partial(FileFormat::Png, reasons);
        }
        if chunk_type == b"IEND" {
            saw_iend = true;
            break;
        }
        cursor = next;
    }

    if !saw_iend {
        reasons.push("PNG IEND chunk missing (likely truncated)".to_string());
        return partial(FileFormat::Png, reasons);
    }

    valid(FileFormat::Png, reasons)
}

fn validate_pdf(bytes: &[u8]) -> ValidationReport {
    let mut reasons = Vec::new();
    if bytes.len() < 8 {
        reasons.push("PDF candidate too small".to_string());
        return invalid(FileFormat::Pdf, reasons);
    }

    if !bytes.starts_with(b"%PDF-") {
        reasons.push("PDF header marker missing".to_string());
        return invalid(FileFormat::Pdf, reasons);
    }

    if !bytes.windows(5).any(|window| window == b"%%EOF") {
        reasons.push("PDF EOF marker missing (likely truncated)".to_string());
        return partial(FileFormat::Pdf, reasons);
    }

    valid(FileFormat::Pdf, reasons)
}

fn validate_zip(bytes: &[u8]) -> ValidationReport {
    let mut reasons = Vec::new();
    if bytes.len() < 30 {
        reasons.push("ZIP candidate too small".to_string());
        return invalid(FileFormat::Zip, reasons);
    }
    if !bytes.starts_with(b"PK\x03\x04") {
        reasons.push("ZIP local header missing".to_string());
        return invalid(FileFormat::Zip, reasons);
    }

    if !has_plausible_zip_local_header(bytes) {
        reasons.push("ZIP local header fields are inconsistent".to_string());
        return invalid(FileFormat::Zip, reasons);
    }

    if find_last_subsequence(bytes, b"PK\x05\x06").is_none() {
        reasons.push("ZIP EOCD marker missing (likely truncated)".to_string());
        return partial(FileFormat::Zip, reasons);
    }

    valid(FileFormat::Zip, reasons)
}

fn validate_office_zip(bytes: &[u8], format: FileFormat) -> ValidationReport {
    let mut zip_report = validate_zip(bytes);
    if !zip_report.is_valid {
        zip_report.format = format;
        return zip_report;
    }

    let required_tokens: &[&[u8]] = match format {
        FileFormat::Docx => &[b"[Content_Types].xml", b"word/"],
        FileFormat::Xlsx => &[b"[Content_Types].xml", b"xl/"],
        FileFormat::Pptx => &[b"[Content_Types].xml", b"ppt/"],
        _ => &[],
    };

    for token in required_tokens {
        if !bytes.windows(token.len()).any(|window| window == *token) {
            zip_report
                .reasons
                .push("Office container token missing".to_string());
            zip_report.is_valid = false;
            zip_report.partial = false;
            zip_report.format = format;
            return zip_report;
        }
    }

    zip_report.format = format;
    zip_report
}

fn validate_utf8_text(bytes: &[u8]) -> ValidationReport {
    let mut reasons = Vec::new();
    if bytes.len() < 4 {
        reasons.push("Text candidate too small".to_string());
        return invalid(FileFormat::Utf8Text, reasons);
    }

    let text = match std::str::from_utf8(bytes) {
        Ok(value) => value,
        Err(_) => {
            reasons.push("UTF-8 decoding failed".to_string());
            return invalid(FileFormat::Utf8Text, reasons);
        }
    };

    let printable = text
        .chars()
        .filter(|ch| ch.is_ascii_graphic() || ch.is_ascii_whitespace())
        .count();
    let ratio = printable as f32 / text.chars().count().max(1) as f32;
    if ratio < 0.85 {
        reasons.push("UTF-8 text contains excessive non-printable characters".to_string());
        return invalid(FileFormat::Utf8Text, reasons);
    }

    valid(FileFormat::Utf8Text, reasons)
}

fn validate_mp3(bytes: &[u8]) -> ValidationReport {
    let mut reasons = Vec::new();
    if bytes.len() < 4 {
        reasons.push("MP3 candidate too small".to_string());
        return invalid(FileFormat::Mp3, reasons);
    }

    let has_id3 = bytes.starts_with(b"ID3");
    let has_frame_sync = bytes[0] == 0xFF && (bytes[1] & 0xE0) == 0xE0;
    if !has_id3 && !has_frame_sync {
        reasons.push("MP3 signature missing".to_string());
        return invalid(FileFormat::Mp3, reasons);
    }

    if bytes.len() < 256 {
        reasons.push("MP3 stream appears truncated".to_string());
        return partial(FileFormat::Mp3, reasons);
    }

    valid(FileFormat::Mp3, reasons)
}

fn validate_wav(bytes: &[u8]) -> ValidationReport {
    let mut reasons = Vec::new();
    if bytes.len() < 12 {
        reasons.push("WAV candidate too small".to_string());
        return invalid(FileFormat::Wav, reasons);
    }
    if &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        reasons.push("WAV RIFF/WAVE markers missing".to_string());
        return invalid(FileFormat::Wav, reasons);
    }

    let declared_size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize + 8;
    if declared_size > bytes.len() {
        reasons.push("WAV RIFF size exceeds captured bytes (likely truncated)".to_string());
        return partial(FileFormat::Wav, reasons);
    }

    valid(FileFormat::Wav, reasons)
}

fn has_plausible_zip_local_header(bytes: &[u8]) -> bool {
    if bytes.len() < 30 {
        return false;
    }
    let name_len = u16::from_le_bytes([bytes[26], bytes[27]]) as usize;
    let extra_len = u16::from_le_bytes([bytes[28], bytes[29]]) as usize;
    let name_start = 30usize;
    let Some(name_end) = name_start.checked_add(name_len) else {
        return false;
    };
    let Some(header_end) = name_end.checked_add(extra_len) else {
        return false;
    };
    if name_len == 0 || header_end > bytes.len() {
        return false;
    }
    true
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn find_last_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

fn valid(format: FileFormat, reasons: Vec<String>) -> ValidationReport {
    ValidationReport {
        format,
        is_valid: true,
        partial: false,
        extension_matches: None,
        reasons,
    }
}

fn partial(format: FileFormat, reasons: Vec<String>) -> ValidationReport {
    ValidationReport {
        format,
        is_valid: true,
        partial: true,
        extension_matches: None,
        reasons,
    }
}

fn invalid(format: FileFormat, reasons: Vec<String>) -> ValidationReport {
    ValidationReport {
        format,
        is_valid: false,
        partial: false,
        extension_matches: None,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_complete_jpeg() {
        let bytes = [0xFF, 0xD8, 0xFF, 0xE0, 0xAA, 0xBB, 0xFF, 0xD9];
        let report = validate_carved_bytes(FileFormat::Jpeg, &bytes);
        assert!(report.is_valid);
        assert!(!report.partial);
    }

    #[test]
    fn marks_truncated_jpeg_as_partial() {
        let bytes = [0xFF, 0xD8, 0xFF, 0xE0, 0xAA, 0xBB];
        let report = validate_carved_bytes(FileFormat::Jpeg, &bytes);
        assert!(report.is_valid);
        assert!(report.partial);
    }

    #[test]
    fn rejects_png_with_invalid_signature() {
        let bytes = b"NOTPNGDATA";
        let report = validate_carved_bytes(FileFormat::Png, bytes);
        assert!(!report.is_valid);
    }

    #[test]
    fn marks_pdf_without_eof_as_partial() {
        let bytes = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n";
        let report = validate_carved_bytes(FileFormat::Pdf, bytes);
        assert!(report.is_valid);
        assert!(report.partial);
    }

    #[test]
    fn validates_docx_like_zip() {
        let bytes = build_test_zip_blob("word/document.xml", b"[Content_Types].xml");
        let report = validate_carved_bytes(FileFormat::Docx, &bytes);
        assert!(report.is_valid);
    }

    #[test]
    fn detects_extension_mismatch() {
        let bytes = [0xFF, 0xD8, 0xFF, 0xE0, 0xAA, 0xBB, 0xFF, 0xD9];
        let report = validate_carved_bytes_with_extension(FileFormat::Jpeg, &bytes, Some("png"));
        assert_eq!(report.extension_matches, Some(false));
        assert!(report
            .reasons
            .iter()
            .any(|reason| reason.contains("Extension/content mismatch")));
    }

    #[test]
    fn rejects_zip_with_broken_local_header() {
        let bytes = b"PK\x03\x04\x00\x00\x00\x00\x00";
        let report = validate_carved_bytes(FileFormat::Zip, bytes);
        assert!(!report.is_valid);
    }

    fn build_test_zip_blob(file_name: &str, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let name_bytes = file_name.as_bytes();
        let payload_len = payload.len() as u32;

        bytes.extend_from_slice(b"PK\x03\x04");
        bytes.extend_from_slice(&20u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&payload_len.to_le_bytes());
        bytes.extend_from_slice(&payload_len.to_le_bytes());
        bytes.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(name_bytes);
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(b"PK\x05\x06");
        bytes
    }
}
