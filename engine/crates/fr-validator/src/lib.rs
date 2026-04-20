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
    Gif,
    Bmp,
    Tiff,
    Webp,
    Pdf,
    Zip,
    Gzip,
    SevenZip,
    Rar,
    Docx,
    Xlsx,
    Pptx,
    Utf8Text,
    Mp4,
    Ogg,
    Flac,
    Mp3,
    Wav,
}

impl FileFormat {
    pub fn default_extension(self) -> &'static str {
        match self {
            FileFormat::Jpeg => "jpg",
            FileFormat::Png => "png",
            FileFormat::Gif => "gif",
            FileFormat::Bmp => "bmp",
            FileFormat::Tiff => "tiff",
            FileFormat::Webp => "webp",
            FileFormat::Pdf => "pdf",
            FileFormat::Zip => "zip",
            FileFormat::Gzip => "gz",
            FileFormat::SevenZip => "7z",
            FileFormat::Rar => "rar",
            FileFormat::Docx => "docx",
            FileFormat::Xlsx => "xlsx",
            FileFormat::Pptx => "pptx",
            FileFormat::Utf8Text => "txt",
            FileFormat::Mp4 => "mp4",
            FileFormat::Ogg => "ogg",
            FileFormat::Flac => "flac",
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
        FileFormat::Gif => validate_gif(bytes),
        FileFormat::Bmp => validate_bmp(bytes),
        FileFormat::Tiff => validate_tiff(bytes),
        FileFormat::Webp => validate_webp(bytes),
        FileFormat::Pdf => validate_pdf(bytes),
        FileFormat::Zip => validate_zip(bytes),
        FileFormat::Gzip => validate_gzip(bytes),
        FileFormat::SevenZip => validate_sevenz(bytes),
        FileFormat::Rar => validate_rar(bytes),
        FileFormat::Docx => validate_office_zip(bytes, FileFormat::Docx),
        FileFormat::Xlsx => validate_office_zip(bytes, FileFormat::Xlsx),
        FileFormat::Pptx => validate_office_zip(bytes, FileFormat::Pptx),
        FileFormat::Utf8Text => validate_utf8_text(bytes),
        FileFormat::Mp4 => validate_mp4(bytes),
        FileFormat::Ogg => validate_ogg(bytes),
        FileFormat::Flac => validate_flac(bytes),
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

    let normalized = raw_extension
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase();
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

fn validate_gif(bytes: &[u8]) -> ValidationReport {
    let mut reasons = Vec::new();
    if bytes.len() < 13 {
        reasons.push("GIF candidate too small".to_string());
        return invalid(FileFormat::Gif, reasons);
    }

    if !bytes.starts_with(b"GIF87a") && !bytes.starts_with(b"GIF89a") {
        reasons.push("GIF signature mismatch".to_string());
        return invalid(FileFormat::Gif, reasons);
    }

    if bytes.last().copied() != Some(0x3B) {
        reasons.push("GIF trailer missing (likely truncated)".to_string());
        return partial(FileFormat::Gif, reasons);
    }

    valid(FileFormat::Gif, reasons)
}

fn validate_bmp(bytes: &[u8]) -> ValidationReport {
    let mut reasons = Vec::new();
    if bytes.len() < 54 {
        reasons.push("BMP candidate too small".to_string());
        return invalid(FileFormat::Bmp, reasons);
    }

    if &bytes[0..2] != b"BM" {
        reasons.push("BMP signature mismatch".to_string());
        return invalid(FileFormat::Bmp, reasons);
    }

    let declared_size = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
    if declared_size < 54 {
        reasons.push("BMP declared size is implausible".to_string());
        return invalid(FileFormat::Bmp, reasons);
    }
    if declared_size > bytes.len() {
        reasons.push("BMP declared size exceeds captured bytes (likely truncated)".to_string());
        return partial(FileFormat::Bmp, reasons);
    }

    valid(FileFormat::Bmp, reasons)
}

fn validate_tiff(bytes: &[u8]) -> ValidationReport {
    let mut reasons = Vec::new();
    if bytes.len() < 8 {
        reasons.push("TIFF candidate too small".to_string());
        return invalid(FileFormat::Tiff, reasons);
    }

    let little_endian = bytes.starts_with(b"II*\0");
    let big_endian = bytes.starts_with(b"MM\0*");
    if !little_endian && !big_endian {
        reasons.push("TIFF signature mismatch".to_string());
        return invalid(FileFormat::Tiff, reasons);
    }

    let ifd_offset = if little_endian {
        u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize
    } else {
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize
    };
    if ifd_offset >= bytes.len() {
        reasons.push("TIFF first IFD offset exceeds captured bytes (likely truncated)".to_string());
        return partial(FileFormat::Tiff, reasons);
    }

    valid(FileFormat::Tiff, reasons)
}

fn validate_webp(bytes: &[u8]) -> ValidationReport {
    let mut reasons = Vec::new();
    if bytes.len() < 16 {
        reasons.push("WEBP candidate too small".to_string());
        return invalid(FileFormat::Webp, reasons);
    }

    if &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WEBP" {
        reasons.push("WEBP RIFF/WEBP markers missing".to_string());
        return invalid(FileFormat::Webp, reasons);
    }

    let declared_size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize + 8;
    if declared_size > bytes.len() {
        reasons.push("WEBP RIFF size exceeds captured bytes (likely truncated)".to_string());
        return partial(FileFormat::Webp, reasons);
    }

    valid(FileFormat::Webp, reasons)
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

fn validate_gzip(bytes: &[u8]) -> ValidationReport {
    let mut reasons = Vec::new();
    if bytes.len() < 10 {
        reasons.push("GZIP candidate too small".to_string());
        return invalid(FileFormat::Gzip, reasons);
    }
    if bytes[0] != 0x1F || bytes[1] != 0x8B || bytes[2] != 0x08 {
        reasons.push("GZIP signature mismatch".to_string());
        return invalid(FileFormat::Gzip, reasons);
    }

    let flags = bytes[3];
    let mut cursor = 10usize;
    if (flags & 0x04) != 0 {
        if cursor + 2 > bytes.len() {
            reasons.push("GZIP FEXTRA header is truncated".to_string());
            return partial(FileFormat::Gzip, reasons);
        }
        let extra_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
        cursor += 2;
        if cursor + extra_len > bytes.len() {
            reasons.push("GZIP FEXTRA payload is truncated".to_string());
            return partial(FileFormat::Gzip, reasons);
        }
        cursor += extra_len;
    }

    for flag in [0x08u8, 0x10u8] {
        if (flags & flag) != 0 {
            let Some(end) = bytes[cursor..].iter().position(|value| *value == 0) else {
                reasons.push("GZIP optional string field is truncated".to_string());
                return partial(FileFormat::Gzip, reasons);
            };
            cursor += end + 1;
            if cursor > bytes.len() {
                reasons.push("GZIP optional string field overran candidate length".to_string());
                return partial(FileFormat::Gzip, reasons);
            }
        }
    }

    if (flags & 0x02) != 0 {
        if cursor + 2 > bytes.len() {
            reasons.push("GZIP header CRC is truncated".to_string());
            return partial(FileFormat::Gzip, reasons);
        }
        cursor += 2;
    }

    if bytes.len() < cursor + 8 {
        reasons.push("GZIP trailer missing (likely truncated)".to_string());
        return partial(FileFormat::Gzip, reasons);
    }

    valid(FileFormat::Gzip, reasons)
}

fn validate_sevenz(bytes: &[u8]) -> ValidationReport {
    let mut reasons = Vec::new();
    const SIGNATURE: &[u8; 6] = b"7z\xBC\xAF\x27\x1C";
    if bytes.len() < 32 {
        reasons.push("7z candidate too small".to_string());
        return invalid(FileFormat::SevenZip, reasons);
    }
    if &bytes[0..6] != SIGNATURE {
        reasons.push("7z signature mismatch".to_string());
        return invalid(FileFormat::SevenZip, reasons);
    }

    valid(FileFormat::SevenZip, reasons)
}

fn validate_rar(bytes: &[u8]) -> ValidationReport {
    let mut reasons = Vec::new();
    const RAR4_SIG: &[u8; 7] = b"Rar!\x1A\x07\x00";
    const RAR5_SIG: &[u8; 8] = b"Rar!\x1A\x07\x01\x00";
    if bytes.len() < 16 {
        reasons.push("RAR candidate too small".to_string());
        return invalid(FileFormat::Rar, reasons);
    }
    if !bytes.starts_with(RAR4_SIG) && !bytes.starts_with(RAR5_SIG) {
        reasons.push("RAR signature mismatch".to_string());
        return invalid(FileFormat::Rar, reasons);
    }

    valid(FileFormat::Rar, reasons)
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

fn validate_mp4(bytes: &[u8]) -> ValidationReport {
    let mut reasons = Vec::new();
    if bytes.len() < 16 {
        reasons.push("MP4 candidate too small".to_string());
        return invalid(FileFormat::Mp4, reasons);
    }

    let box_size = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if &bytes[4..8] != b"ftyp" {
        reasons.push("MP4 ftyp box missing".to_string());
        return invalid(FileFormat::Mp4, reasons);
    }

    if box_size < 16 {
        reasons.push("MP4 ftyp box size is implausible".to_string());
        return invalid(FileFormat::Mp4, reasons);
    }
    if box_size > bytes.len() {
        reasons.push("MP4 ftyp box exceeds captured bytes (likely truncated)".to_string());
        return partial(FileFormat::Mp4, reasons);
    }

    valid(FileFormat::Mp4, reasons)
}

fn validate_ogg(bytes: &[u8]) -> ValidationReport {
    let mut reasons = Vec::new();
    if bytes.len() < 27 {
        reasons.push("OGG candidate too small".to_string());
        return invalid(FileFormat::Ogg, reasons);
    }
    if &bytes[0..4] != b"OggS" {
        reasons.push("OGG capture pattern missing".to_string());
        return invalid(FileFormat::Ogg, reasons);
    }
    if bytes[4] != 0 {
        reasons.push("OGG version is unsupported".to_string());
        return invalid(FileFormat::Ogg, reasons);
    }

    let segment_count = bytes[26] as usize;
    if 27 + segment_count > bytes.len() {
        reasons.push("OGG segment table truncated".to_string());
        return partial(FileFormat::Ogg, reasons);
    }

    let payload_size: usize = bytes[27..27 + segment_count]
        .iter()
        .map(|value| *value as usize)
        .sum();
    if 27 + segment_count + payload_size > bytes.len() {
        reasons.push("OGG page payload truncated".to_string());
        return partial(FileFormat::Ogg, reasons);
    }

    valid(FileFormat::Ogg, reasons)
}

fn validate_flac(bytes: &[u8]) -> ValidationReport {
    let mut reasons = Vec::new();
    if bytes.len() < 8 {
        reasons.push("FLAC candidate too small".to_string());
        return invalid(FileFormat::Flac, reasons);
    }
    if &bytes[0..4] != b"fLaC" {
        reasons.push("FLAC signature mismatch".to_string());
        return invalid(FileFormat::Flac, reasons);
    }

    let mut cursor = 4usize;
    let mut saw_streaminfo = false;
    loop {
        if cursor + 4 > bytes.len() {
            reasons.push("FLAC metadata header truncated".to_string());
            return partial(FileFormat::Flac, reasons);
        }

        let header = bytes[cursor];
        let is_last = (header & 0x80) != 0;
        let block_type = header & 0x7F;
        let block_len = ((bytes[cursor + 1] as usize) << 16)
            | ((bytes[cursor + 2] as usize) << 8)
            | bytes[cursor + 3] as usize;
        cursor += 4;

        if block_type == 0 {
            saw_streaminfo = true;
        }
        if cursor + block_len > bytes.len() {
            reasons.push("FLAC metadata block truncated".to_string());
            return partial(FileFormat::Flac, reasons);
        }
        cursor += block_len;

        if is_last {
            break;
        }
    }

    if !saw_streaminfo {
        reasons.push("FLAC STREAMINFO metadata block missing".to_string());
        return invalid(FileFormat::Flac, reasons);
    }

    valid(FileFormat::Flac, reasons)
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

    #[test]
    fn validates_complete_gif() {
        let bytes = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xFF\xFF\xFF!\xF9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x01L\x00;";
        let report = validate_carved_bytes(FileFormat::Gif, bytes);
        assert!(report.is_valid);
        assert!(!report.partial);
    }

    #[test]
    fn validates_riff_webp() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"RIFF");
        bytes.extend_from_slice(&(16u32).to_le_bytes());
        bytes.extend_from_slice(b"WEBP");
        bytes.extend_from_slice(b"VP8 ");
        bytes.extend_from_slice(&(4u32).to_le_bytes());
        bytes.extend_from_slice(&[0u8; 4]);
        let report = validate_carved_bytes(FileFormat::Webp, &bytes);
        assert!(report.is_valid);
    }

    #[test]
    fn validates_mp4_ftyp_box() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(24u32).to_be_bytes());
        bytes.extend_from_slice(b"ftyp");
        bytes.extend_from_slice(b"isom");
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(b"isom");
        bytes.extend_from_slice(b"mp41");
        let report = validate_carved_bytes(FileFormat::Mp4, &bytes);
        assert!(report.is_valid);
    }

    #[test]
    fn validates_flac_streaminfo_block() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"fLaC");
        bytes.push(0x80); // last metadata block + STREAMINFO type
        bytes.extend_from_slice(&[0x00, 0x00, 0x04]); // length = 4
        bytes.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let report = validate_carved_bytes(FileFormat::Flac, &bytes);
        assert!(report.is_valid);
    }

    #[test]
    fn validates_gzip_minimal_member() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00]); // ID1 ID2 CM FLG
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // MTIME
        bytes.extend_from_slice(&[0x00, 0xFF]); // XFL OS
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC32
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ISIZE
        let report = validate_carved_bytes(FileFormat::Gzip, &bytes);
        assert!(report.is_valid);
    }

    #[test]
    fn signature_regression_matrix_covers_false_positive_and_partial_edges() {
        struct RegressionCase {
            name: &'static str,
            format: FileFormat,
            bytes: Vec<u8>,
            expected_valid: bool,
            expected_partial: bool,
        }

        let mut valid_webp = Vec::new();
        valid_webp.extend_from_slice(b"RIFF");
        valid_webp.extend_from_slice(&(16u32).to_le_bytes());
        valid_webp.extend_from_slice(b"WEBP");
        valid_webp.extend_from_slice(b"VP8 ");
        valid_webp.extend_from_slice(&(4u32).to_le_bytes());
        valid_webp.extend_from_slice(&[0u8; 4]);

        let mut valid_mp4 = Vec::new();
        valid_mp4.extend_from_slice(&(24u32).to_be_bytes());
        valid_mp4.extend_from_slice(b"ftyp");
        valid_mp4.extend_from_slice(b"isom");
        valid_mp4.extend_from_slice(&0u32.to_be_bytes());
        valid_mp4.extend_from_slice(b"isom");
        valid_mp4.extend_from_slice(b"mp41");

        let cases = vec![
            RegressionCase {
                name: "jpeg-too-short",
                format: FileFormat::Jpeg,
                bytes: vec![0xFF, 0xD8, 0x00],
                expected_valid: false,
                expected_partial: false,
            },
            RegressionCase {
                name: "png-bad-signature",
                format: FileFormat::Png,
                bytes: b"not-a-png".to_vec(),
                expected_valid: false,
                expected_partial: false,
            },
            RegressionCase {
                name: "webp-valid-minimal",
                format: FileFormat::Webp,
                bytes: valid_webp,
                expected_valid: true,
                expected_partial: false,
            },
            RegressionCase {
                name: "webp-truncated-riff-size",
                format: FileFormat::Webp,
                bytes: b"RIFF\x20\x00\x00\x00WEBP".to_vec(),
                expected_valid: false,
                expected_partial: false,
            },
            RegressionCase {
                name: "zip-broken-local-header",
                format: FileFormat::Zip,
                bytes: b"PK\x03\x04\x00\x00\x00\x00\x00".to_vec(),
                expected_valid: false,
                expected_partial: false,
            },
            RegressionCase {
                name: "mp4-valid-ftyp",
                format: FileFormat::Mp4,
                bytes: valid_mp4,
                expected_valid: true,
                expected_partial: false,
            },
            RegressionCase {
                name: "mp4-declared-size-too-large",
                format: FileFormat::Mp4,
                bytes: {
                    let mut bytes = Vec::new();
                    bytes.extend_from_slice(&(128u32).to_be_bytes());
                    bytes.extend_from_slice(b"ftyp");
                    bytes.extend_from_slice(b"isom");
                    bytes.extend_from_slice(&0u32.to_be_bytes());
                    bytes.extend_from_slice(b"isom");
                    bytes
                },
                expected_valid: true,
                expected_partial: true,
            },
            RegressionCase {
                name: "rar-signature-mismatch",
                format: FileFormat::Rar,
                bytes: b"Rax!\x1A\x07\x00....".to_vec(),
                expected_valid: false,
                expected_partial: false,
            },
            RegressionCase {
                name: "flac-streaminfo-present",
                format: FileFormat::Flac,
                bytes: {
                    let mut bytes = Vec::new();
                    bytes.extend_from_slice(b"fLaC");
                    bytes.push(0x80);
                    bytes.extend_from_slice(&[0x00, 0x00, 0x04]);
                    bytes.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
                    bytes
                },
                expected_valid: true,
                expected_partial: false,
            },
            RegressionCase {
                name: "gzip-truncated-trailer",
                format: FileFormat::Gzip,
                bytes: vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0, 0],
                expected_valid: true,
                expected_partial: true,
            },
        ];

        for case in cases {
            let report = validate_carved_bytes(case.format, &case.bytes);
            assert_eq!(report.is_valid, case.expected_valid, "{}", case.name);
            assert_eq!(report.partial, case.expected_partial, "{}", case.name);
        }
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
