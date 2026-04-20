use std::collections::{HashSet, VecDeque};

use fr_scoring::score_candidate_with_reasons;
use fr_types::{ConfidenceTier, EvidenceSource, RecoveryCandidate, RecoverySourceKind};
use fr_validator::{validate_carved_bytes_with_extension, FileFormat, ValidationReport};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDescriptor {
    pub name: &'static str,
    pub purpose: &'static str,
    pub source_kind: RecoverySourceKind,
}

pub fn descriptor() -> ModuleDescriptor {
    ModuleDescriptor {
        name: "fr-carving",
        purpose:
            "Selective signature-based carving with validator-driven false-positive reduction.",
        source_kind: RecoverySourceKind::Volume,
    }
}

pub const SIGNATURE_PACK_NAME: &str = "core-signatures";
pub const SIGNATURE_PACK_VERSION: &str = "2026.04-b1";

pub fn signature_pack_formats() -> &'static [FileFormat] {
    &[
        FileFormat::Jpeg,
        FileFormat::Png,
        FileFormat::Gif,
        FileFormat::Bmp,
        FileFormat::Tiff,
        FileFormat::Webp,
        FileFormat::Pdf,
        FileFormat::Utf8Text,
        FileFormat::Zip,
        FileFormat::Gzip,
        FileFormat::SevenZip,
        FileFormat::Rar,
        FileFormat::Docx,
        FileFormat::Xlsx,
        FileFormat::Pptx,
        FileFormat::Mp4,
        FileFormat::Ogg,
        FileFormat::Flac,
        FileFormat::Mp3,
        FileFormat::Wav,
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CarvingFamily {
    Images,
    Documents,
    Archives,
    Office,
    Media,
}

#[derive(Debug, Clone)]
pub struct CarvingPlan {
    enabled_families: HashSet<CarvingFamily>,
    enabled_formats: HashSet<FileFormat>,
    pub max_scan_bytes: usize,
}

impl Default for CarvingPlan {
    fn default() -> Self {
        // Deliberately conservative: do not enable every signature by default.
        let enabled_families = HashSet::from([CarvingFamily::Images, CarvingFamily::Documents]);
        Self {
            enabled_families,
            enabled_formats: HashSet::new(),
            max_scan_bytes: 64 * 1024 * 1024,
        }
    }
}

impl CarvingPlan {
    pub fn with_family(mut self, family: CarvingFamily) -> Self {
        self.enabled_families.insert(family);
        self
    }

    pub fn without_family(mut self, family: CarvingFamily) -> Self {
        self.enabled_families.remove(&family);
        self
    }

    pub fn with_format(mut self, format: FileFormat) -> Self {
        self.enabled_formats.insert(format);
        self
    }

    pub fn with_max_scan_bytes(mut self, max_scan_bytes: usize) -> Self {
        self.max_scan_bytes = max_scan_bytes.max(1);
        self
    }

    fn format_enabled(&self, format: FileFormat) -> bool {
        if !self.enabled_formats.is_empty() {
            return self.enabled_formats.contains(&format);
        }

        self.enabled_families.contains(&family_for_format(format))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarvedCandidate {
    pub id: String,
    pub format: FileFormat,
    pub family: CarvingFamily,
    pub offset: usize,
    pub length: usize,
    pub partial: bool,
    pub confidence: ConfidenceTier,
    pub diagnostics: Vec<String>,
}

pub fn carve_bytes(plan: &CarvingPlan, source_bytes: &[u8]) -> Vec<CarvedCandidate> {
    let scan_len = source_bytes.len().min(plan.max_scan_bytes);
    let bytes = &source_bytes[..scan_len];

    let mut carved = Vec::new();
    let mut seen = HashSet::new();

    if plan.format_enabled(FileFormat::Jpeg) {
        carve_header_footer(
            bytes,
            FileFormat::Jpeg,
            b"\xFF\xD8\xFF",
            Some(b"\xFF\xD9"),
            &mut seen,
            &mut carved,
        );
    }

    if plan.format_enabled(FileFormat::Png) {
        carve_png(bytes, &mut seen, &mut carved);
    }

    if plan.format_enabled(FileFormat::Gif) {
        carve_header_footer(
            bytes,
            FileFormat::Gif,
            b"GIF89a",
            Some(&[0x3B]),
            &mut seen,
            &mut carved,
        );
        carve_header_footer(
            bytes,
            FileFormat::Gif,
            b"GIF87a",
            Some(&[0x3B]),
            &mut seen,
            &mut carved,
        );
    }

    if plan.format_enabled(FileFormat::Bmp) {
        carve_bmp(bytes, &mut seen, &mut carved);
    }

    if plan.format_enabled(FileFormat::Tiff) {
        carve_tiff(bytes, &mut seen, &mut carved);
    }

    if plan.format_enabled(FileFormat::Webp) {
        carve_webp(bytes, &mut seen, &mut carved);
    }

    if plan.format_enabled(FileFormat::Pdf) {
        carve_header_footer(
            bytes,
            FileFormat::Pdf,
            b"%PDF-",
            Some(b"%%EOF"),
            &mut seen,
            &mut carved,
        );
    }

    if plan.format_enabled(FileFormat::Utf8Text) {
        carve_utf8_bom_text(bytes, &mut seen, &mut carved);
    }

    let zip_related_enabled = [
        FileFormat::Zip,
        FileFormat::Gzip,
        FileFormat::SevenZip,
        FileFormat::Rar,
        FileFormat::Docx,
        FileFormat::Xlsx,
        FileFormat::Pptx,
    ]
    .into_iter()
    .any(|format| plan.format_enabled(format));
    if zip_related_enabled {
        carve_zip_and_office(bytes, plan, &mut seen, &mut carved);
    }

    if plan.format_enabled(FileFormat::Gzip) {
        carve_header_footer(
            bytes,
            FileFormat::Gzip,
            &[0x1F, 0x8B, 0x08],
            None,
            &mut seen,
            &mut carved,
        );
    }

    if plan.format_enabled(FileFormat::SevenZip) {
        carve_header_footer(
            bytes,
            FileFormat::SevenZip,
            b"7z\xBC\xAF\x27\x1C",
            None,
            &mut seen,
            &mut carved,
        );
    }

    if plan.format_enabled(FileFormat::Rar) {
        carve_header_footer(
            bytes,
            FileFormat::Rar,
            b"Rar!\x1A\x07\x00",
            None,
            &mut seen,
            &mut carved,
        );
        carve_header_footer(
            bytes,
            FileFormat::Rar,
            b"Rar!\x1A\x07\x01\x00",
            None,
            &mut seen,
            &mut carved,
        );
    }

    if plan.format_enabled(FileFormat::Mp4) {
        carve_mp4(bytes, &mut seen, &mut carved);
    }

    if plan.format_enabled(FileFormat::Ogg) {
        carve_header_footer(
            bytes,
            FileFormat::Ogg,
            b"OggS",
            None,
            &mut seen,
            &mut carved,
        );
    }

    if plan.format_enabled(FileFormat::Flac) {
        carve_header_footer(
            bytes,
            FileFormat::Flac,
            b"fLaC",
            None,
            &mut seen,
            &mut carved,
        );
    }

    if plan.format_enabled(FileFormat::Wav) {
        carve_wav(bytes, &mut seen, &mut carved);
    }

    if plan.format_enabled(FileFormat::Mp3) {
        carve_header_footer(bytes, FileFormat::Mp3, b"ID3", None, &mut seen, &mut carved);
    }

    carved.sort_by_key(|candidate| candidate.offset);
    carved
}

fn carve_header_footer(
    bytes: &[u8],
    format: FileFormat,
    header: &[u8],
    footer: Option<&[u8]>,
    seen: &mut HashSet<(usize, FileFormat)>,
    carved: &mut Vec<CarvedCandidate>,
) {
    for offset in find_all_subsequences(bytes, header) {
        let end = match footer {
            Some(needle) => find_subsequence(&bytes[offset + header.len()..], needle)
                .map(|position| offset + header.len() + position + needle.len())
                .unwrap_or(bytes.len()),
            None => bytes.len().min(offset.saturating_add(1024 * 1024)),
        };
        push_candidate(bytes, format, offset, end, seen, carved);
    }
}

fn carve_png(
    bytes: &[u8],
    seen: &mut HashSet<(usize, FileFormat)>,
    carved: &mut Vec<CarvedCandidate>,
) {
    const PNG_HEADER: &[u8] = b"\x89PNG\r\n\x1a\n";
    for offset in find_all_subsequences(bytes, PNG_HEADER) {
        let mut cursor = offset + PNG_HEADER.len();
        let mut end = bytes.len();
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
                .and_then(|value| value.checked_add(chunk_len))
            else {
                break;
            };
            if next > bytes.len() {
                break;
            }
            if chunk_type == b"IEND" {
                end = next;
                break;
            }
            cursor = next;
        }
        push_candidate(bytes, FileFormat::Png, offset, end, seen, carved);
    }
}

fn carve_bmp(
    bytes: &[u8],
    seen: &mut HashSet<(usize, FileFormat)>,
    carved: &mut Vec<CarvedCandidate>,
) {
    for offset in find_all_subsequences(bytes, b"BM") {
        if offset + 6 > bytes.len() {
            continue;
        }

        let declared_size = u32::from_le_bytes([
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
        ]) as usize;
        if declared_size < 54 {
            continue;
        }

        let end = bytes.len().min(offset.saturating_add(declared_size));
        push_candidate(bytes, FileFormat::Bmp, offset, end, seen, carved);
    }
}

fn carve_tiff(
    bytes: &[u8],
    seen: &mut HashSet<(usize, FileFormat)>,
    carved: &mut Vec<CarvedCandidate>,
) {
    for header in [b"II*\0".as_slice(), b"MM\0*".as_slice()] {
        for offset in find_all_subsequences(bytes, header) {
            let end = bytes.len().min(offset.saturating_add(8 * 1024 * 1024));
            push_candidate(bytes, FileFormat::Tiff, offset, end, seen, carved);
        }
    }
}

fn carve_webp(
    bytes: &[u8],
    seen: &mut HashSet<(usize, FileFormat)>,
    carved: &mut Vec<CarvedCandidate>,
) {
    for offset in find_all_subsequences(bytes, b"RIFF") {
        if offset + 12 > bytes.len() {
            continue;
        }
        if &bytes[offset + 8..offset + 12] != b"WEBP" {
            continue;
        }

        let declared_size = u32::from_le_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]) as usize
            + 8;
        let end = bytes
            .len()
            .min(offset.saturating_add(declared_size.max(16)));
        push_candidate(bytes, FileFormat::Webp, offset, end, seen, carved);
    }
}

fn carve_mp4(
    bytes: &[u8],
    seen: &mut HashSet<(usize, FileFormat)>,
    carved: &mut Vec<CarvedCandidate>,
) {
    for offset in find_all_subsequences(bytes, b"ftyp") {
        if offset < 4 || offset + 8 > bytes.len() {
            continue;
        }

        let start = offset - 4;
        let declared_size = u32::from_be_bytes([
            bytes[start],
            bytes[start + 1],
            bytes[start + 2],
            bytes[start + 3],
        ]) as usize;
        if declared_size < 16 {
            continue;
        }

        let end = bytes.len().min(start.saturating_add(declared_size));
        push_candidate(bytes, FileFormat::Mp4, start, end, seen, carved);
    }
}

fn carve_utf8_bom_text(
    bytes: &[u8],
    seen: &mut HashSet<(usize, FileFormat)>,
    carved: &mut Vec<CarvedCandidate>,
) {
    for offset in find_all_subsequences(bytes, b"\xEF\xBB\xBF") {
        let mut end = offset + 3;
        while end < bytes.len() {
            if bytes[end] == 0 {
                break;
            }
            end += 1;
        }
        push_candidate(bytes, FileFormat::Utf8Text, offset, end, seen, carved);
    }
}

fn carve_zip_and_office(
    bytes: &[u8],
    plan: &CarvingPlan,
    seen: &mut HashSet<(usize, FileFormat)>,
    carved: &mut Vec<CarvedCandidate>,
) {
    let mut pending = VecDeque::from(find_all_subsequences(bytes, b"PK\x03\x04"));
    while let Some(offset) = pending.pop_front() {
        let end = find_last_subsequence(&bytes[offset..], b"PK\x05\x06")
            .map(|position| offset + position + 4)
            .unwrap_or(bytes.len());

        if plan.format_enabled(FileFormat::Zip) {
            push_candidate(bytes, FileFormat::Zip, offset, end, seen, carved);
        }
        if plan.format_enabled(FileFormat::Docx) {
            push_candidate(bytes, FileFormat::Docx, offset, end, seen, carved);
        }
        if plan.format_enabled(FileFormat::Xlsx) {
            push_candidate(bytes, FileFormat::Xlsx, offset, end, seen, carved);
        }
        if plan.format_enabled(FileFormat::Pptx) {
            push_candidate(bytes, FileFormat::Pptx, offset, end, seen, carved);
        }
    }
}

fn carve_wav(
    bytes: &[u8],
    seen: &mut HashSet<(usize, FileFormat)>,
    carved: &mut Vec<CarvedCandidate>,
) {
    for offset in find_all_subsequences(bytes, b"RIFF") {
        if offset + 12 > bytes.len() {
            continue;
        }
        if &bytes[offset + 8..offset + 12] != b"WAVE" {
            continue;
        }
        let declared_size = u32::from_le_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]) as usize
            + 8;
        let end = bytes.len().min(offset.saturating_add(declared_size));
        push_candidate(bytes, FileFormat::Wav, offset, end, seen, carved);
    }
}

fn push_candidate(
    source_bytes: &[u8],
    format: FileFormat,
    offset: usize,
    end: usize,
    seen: &mut HashSet<(usize, FileFormat)>,
    carved: &mut Vec<CarvedCandidate>,
) {
    if end <= offset {
        return;
    }
    if !seen.insert((offset, format)) {
        return;
    }

    let slice = &source_bytes[offset..end.min(source_bytes.len())];
    let validation =
        validate_carved_bytes_with_extension(format, slice, Some(format.default_extension()));
    if !validation.is_valid {
        return;
    }

    let recovery_candidate = RecoveryCandidate {
        id: format!("carve-{format:?}-{offset:x}"),
        original_name: Some(format!("carve_{offset:08X}.{}", format.default_extension())),
        original_path: None,
        recovered_path: None,
        size_bytes: slice.len() as u64,
        evidence: vec![EvidenceSource::Carve],
        confidence: ConfidenceTier::VeryLow,
        partial: validation.partial,
    };
    let scored = score_candidate_with_reasons(&recovery_candidate);
    let diagnostics = collect_diagnostics(&validation, &scored.reasons);

    carved.push(CarvedCandidate {
        id: recovery_candidate.id,
        format,
        family: family_for_format(format),
        offset,
        length: slice.len(),
        partial: validation.partial,
        confidence: scored.tier,
        diagnostics,
    });
}

fn collect_diagnostics(
    validation: &ValidationReport,
    scoring_reasons: &[&'static str],
) -> Vec<String> {
    let mut diagnostics = validation.reasons.clone();
    for reason in scoring_reasons {
        diagnostics.push((*reason).to_string());
    }
    diagnostics
}

fn find_all_subsequences(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }

    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, window)| if window == needle { Some(index) } else { None })
        .collect()
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

fn family_for_format(format: FileFormat) -> CarvingFamily {
    match format {
        FileFormat::Jpeg
        | FileFormat::Png
        | FileFormat::Gif
        | FileFormat::Bmp
        | FileFormat::Tiff
        | FileFormat::Webp => CarvingFamily::Images,
        FileFormat::Pdf | FileFormat::Utf8Text => CarvingFamily::Documents,
        FileFormat::Zip | FileFormat::Gzip | FileFormat::SevenZip | FileFormat::Rar => {
            CarvingFamily::Archives
        }
        FileFormat::Docx | FileFormat::Xlsx | FileFormat::Pptx => CarvingFamily::Office,
        FileFormat::Mp3
        | FileFormat::Wav
        | FileFormat::Mp4
        | FileFormat::Ogg
        | FileFormat::Flac => CarvingFamily::Media,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_plan_is_selective() {
        let plan = CarvingPlan::default();
        assert!(plan.format_enabled(FileFormat::Jpeg));
        assert!(plan.format_enabled(FileFormat::Pdf));
        assert!(!plan.format_enabled(FileFormat::Zip));
        assert!(!plan.format_enabled(FileFormat::Mp3));
    }

    #[test]
    fn signature_pack_declares_expected_batch_metadata() {
        assert_eq!(SIGNATURE_PACK_NAME, "core-signatures");
        assert_eq!(SIGNATURE_PACK_VERSION, "2026.04-b1");
        assert!(signature_pack_formats().contains(&FileFormat::Webp));
        assert!(signature_pack_formats().contains(&FileFormat::SevenZip));
        assert!(signature_pack_formats().contains(&FileFormat::Mp4));
    }

    #[test]
    fn archives_only_plan_finds_zip_but_not_jpeg() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\xFF\xD8\xFF\xE0AAAA\xFF\xD9");
        bytes.extend_from_slice(&build_test_zip_blob(
            "word/document.xml",
            b"[Content_Types].xml",
        ));

        let plan = CarvingPlan::default()
            .without_family(CarvingFamily::Images)
            .without_family(CarvingFamily::Documents)
            .with_family(CarvingFamily::Archives);
        let carved = carve_bytes(&plan, &bytes);

        assert!(carved
            .iter()
            .any(|candidate| candidate.format == FileFormat::Zip));
        assert!(!carved
            .iter()
            .any(|candidate| candidate.format == FileFormat::Jpeg));
    }

    #[test]
    fn office_targeting_returns_docx_from_zip_payload() {
        let bytes = build_test_zip_blob("word/document.xml", b"[Content_Types].xml");
        let plan = CarvingPlan::default().with_format(FileFormat::Docx);
        let carved = carve_bytes(&plan, &bytes);
        assert_eq!(carved.len(), 1);
        assert_eq!(carved[0].format, FileFormat::Docx);
    }

    #[test]
    fn rejects_false_positive_zip_signature() {
        let bytes = b"prefixPK\x03\x04\x00\x00\x00\x00suffix";
        let plan = CarvingPlan::default().with_format(FileFormat::Zip);
        let carved = carve_bytes(&plan, bytes);
        assert!(carved.is_empty());
    }

    #[test]
    fn marks_truncated_pdf_candidate_partial() {
        let bytes = b"abc%PDF-1.7\ntruncated";
        let plan = CarvingPlan::default();
        let carved = carve_bytes(&plan, bytes);
        let pdf = carved
            .iter()
            .find(|candidate| candidate.format == FileFormat::Pdf)
            .expect("pdf candidate");
        assert!(pdf.partial);
        assert!(matches!(
            pdf.confidence,
            ConfidenceTier::Low | ConfidenceTier::VeryLow
        ));
    }

    #[test]
    fn media_family_can_find_mp4_candidate() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(24u32).to_be_bytes());
        bytes.extend_from_slice(b"ftyp");
        bytes.extend_from_slice(b"isom");
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(b"isom");
        bytes.extend_from_slice(b"mp41");

        let plan = CarvingPlan::default()
            .without_family(CarvingFamily::Images)
            .without_family(CarvingFamily::Documents)
            .with_family(CarvingFamily::Media);
        let carved = carve_bytes(&plan, &bytes);
        assert!(carved
            .iter()
            .any(|candidate| candidate.format == FileFormat::Mp4));
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
