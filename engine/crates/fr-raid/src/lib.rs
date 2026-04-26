use thiserror::Error;

const MD_SUPERBLOCK_V1_OFFSET: usize = 4096;
const MD_SUPERBLOCK_V1_SIZE: usize = 4096;
const MD_MAGIC: u32 = 0xA92B4EFC;

const SPACES_HEADER_OFFSET: usize = 0x200;
const SPACES_SIGNATURE: &[u8; 11] = b"SPACES_RAID";
const IMSM_SIGNATURE: &[u8; 23] = b"Intel Raid ISM Cfg Sig.";
const DDF_SIGNATURE: &[u8; 7] = b"DDF_HDR";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaidMetadataFamily {
    LinuxMd,
    WindowsStorageSpaces,
    IntelImsm,
    Ddf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaidLevel {
    Raid0,
    Raid1,
    Raid4,
    Raid5,
    Raid6,
    Raid10,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParityRotation {
    LeftSymmetric,
    RightSymmetric,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaidLayout {
    pub metadata_family: RaidMetadataFamily,
    pub level: RaidLevel,
    pub member_count: u32,
    pub stripe_size_bytes: u32,
    pub data_offset_bytes: u64,
    pub parity_rotation: ParityRotation,
    pub disk_order: Vec<u32>,
    pub confidence_score: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RaidManualOverride {
    pub level: Option<RaidLevel>,
    pub stripe_size_bytes: Option<u32>,
    pub data_offset_bytes: Option<u64>,
    pub parity_rotation: Option<ParityRotation>,
    pub disk_order: Option<Vec<u32>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaidLogicalMapping {
    pub member_index: u32,
    pub member_offset_bytes: u64,
    pub parity_member_index: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaidDegradedAssessment {
    pub missing_member_count: u32,
    pub sample_count: u32,
    pub recoverable_sample_count: u32,
    pub recoverability_percent: u8,
    pub confidence_penalty: u8,
    pub recommendation: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RaidError {
    #[error("buffer too small: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall { expected: usize, actual: usize },
    #[error("invalid member count: {0}")]
    InvalidMemberCount(u32),
    #[error("invalid stripe size bytes: {0}")]
    InvalidStripeSize(u32),
    #[error("invalid disk order override")]
    InvalidDiskOrder,
    #[error("arithmetic overflow while computing {0}")]
    ArithmeticOverflow(&'static str),
    #[error("unsupported RAID layout for virtual assembly")]
    UnsupportedLayout,
}

pub fn detect_layout(image: &[u8]) -> Result<Option<RaidLayout>, RaidError> {
    if let Some(layout) = detect_mdraid_layout(image)? {
        return Ok(Some(layout));
    }

    if let Some(layout) = detect_storage_spaces_layout(image)? {
        return Ok(Some(layout));
    }

    if let Some(layout) = detect_imsm_layout(image)? {
        return Ok(Some(layout));
    }

    if let Some(layout) = detect_ddf_layout(image)? {
        return Ok(Some(layout));
    }

    Ok(None)
}

pub fn apply_manual_override(
    base: &RaidLayout,
    override_cfg: &RaidManualOverride,
) -> Result<RaidLayout, RaidError> {
    let mut layout = base.clone();

    if let Some(level) = override_cfg.level {
        layout.level = level;
        if level == RaidLevel::Unknown && layout.confidence_score > 5 {
            layout.confidence_score -= 5;
        }
    }

    if let Some(stripe_size) = override_cfg.stripe_size_bytes {
        if !is_valid_stripe_size(stripe_size) {
            return Err(RaidError::InvalidStripeSize(stripe_size));
        }
        layout.stripe_size_bytes = stripe_size;
    }

    if let Some(data_offset) = override_cfg.data_offset_bytes {
        layout.data_offset_bytes = data_offset;
    }

    if let Some(parity_rotation) = override_cfg.parity_rotation {
        layout.parity_rotation = parity_rotation;
    }

    if let Some(order) = &override_cfg.disk_order {
        validate_disk_order(order, layout.member_count)?;
        layout.disk_order = order.clone();
    }

    Ok(layout)
}

pub fn resolve_layout_with_override(
    image: &[u8],
    override_cfg: Option<&RaidManualOverride>,
) -> Result<Option<RaidLayout>, RaidError> {
    let Some(base) = detect_layout(image)? else {
        return Ok(None);
    };

    match override_cfg {
        Some(value) => apply_manual_override(&base, value).map(Some),
        None => Ok(Some(base)),
    }
}

pub fn map_logical_offset(
    layout: &RaidLayout,
    logical_offset_bytes: u64,
) -> Result<RaidLogicalMapping, RaidError> {
    if layout.member_count < 2 {
        return Err(RaidError::InvalidMemberCount(layout.member_count));
    }
    if !is_valid_stripe_size(layout.stripe_size_bytes) {
        return Err(RaidError::InvalidStripeSize(layout.stripe_size_bytes));
    }
    validate_disk_order(&layout.disk_order, layout.member_count)?;

    match layout.level {
        RaidLevel::Raid0 => map_raid0(layout, logical_offset_bytes),
        RaidLevel::Raid1 => map_raid1(layout, logical_offset_bytes),
        RaidLevel::Raid4 => map_raid4(layout, logical_offset_bytes),
        RaidLevel::Raid5 => map_raid5(layout, logical_offset_bytes),
        RaidLevel::Raid10 => map_raid10(layout, logical_offset_bytes),
        RaidLevel::Raid6 | RaidLevel::Unknown => Err(RaidError::UnsupportedLayout),
    }
}

pub fn assess_degraded_layout(
    layout: &RaidLayout,
    missing_members: &[u32],
    sample_count: u32,
) -> Result<RaidDegradedAssessment, RaidError> {
    if layout.member_count < 2 {
        return Err(RaidError::InvalidMemberCount(layout.member_count));
    }
    if !is_valid_stripe_size(layout.stripe_size_bytes) {
        return Err(RaidError::InvalidStripeSize(layout.stripe_size_bytes));
    }
    validate_disk_order(&layout.disk_order, layout.member_count)?;

    let normalized_missing = normalize_missing_members(missing_members, layout.member_count);
    let samples = sample_count.max(8).min(1024);
    let step = layout.stripe_size_bytes as u64;
    let mut recoverable = 0u32;
    for index in 0..samples {
        let logical_offset =
            (index as u64)
                .checked_mul(step)
                .ok_or(RaidError::ArithmeticOverflow(
                    "degraded assessment logical offset",
                ))?;
        let mapping = match map_logical_offset(layout, logical_offset) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if is_mapping_recoverable(layout.level, &mapping, &normalized_missing) {
            recoverable += 1;
        }
    }

    let recoverability_percent = ((recoverable as f64 / samples as f64) * 100.0).round() as u8;
    let confidence_penalty = (100u8.saturating_sub(recoverability_percent)).min(60);
    let recommendation = build_degraded_recommendation(
        layout.level,
        normalized_missing.len() as u32,
        recoverability_percent,
    );

    Ok(RaidDegradedAssessment {
        missing_member_count: normalized_missing.len() as u32,
        sample_count: samples,
        recoverable_sample_count: recoverable,
        recoverability_percent,
        confidence_penalty,
        recommendation,
    })
}

fn detect_mdraid_layout(image: &[u8]) -> Result<Option<RaidLayout>, RaidError> {
    if image.len() < MD_SUPERBLOCK_V1_OFFSET + MD_SUPERBLOCK_V1_SIZE {
        return Ok(None);
    }

    let base = MD_SUPERBLOCK_V1_OFFSET;
    let magic = read_u32_le(image, base)?;
    if magic != MD_MAGIC {
        return Ok(None);
    }

    let major_version = read_u32_le(image, base + 4)?;
    if major_version == 0 {
        return Ok(None);
    }

    let raw_level = read_i32_le(image, base + 0x48)?;
    let raw_layout = read_u32_le(image, base + 0x4C)?;
    let raw_chunk_size = read_u32_le(image, base + 0x50)?;
    let raid_disks = read_u32_le(image, base + 0x5C)?;
    if raid_disks < 2 {
        return Err(RaidError::InvalidMemberCount(raid_disks));
    }

    let data_offset_sectors = read_u64_le(image, base + 0x80)?;
    let data_offset_bytes = data_offset_sectors
        .checked_mul(512)
        .ok_or(RaidError::ArithmeticOverflow("md data offset bytes"))?;
    let stripe_size_bytes = normalize_stripe_size(raw_chunk_size);

    let level = map_md_level(raw_level);
    let parity_rotation = map_md_parity_rotation(raw_layout);
    let confidence = score_metadata_confidence(
        raid_disks,
        raw_chunk_size != 0,
        level != RaidLevel::Unknown,
        parity_rotation != ParityRotation::Unknown,
    );

    Ok(Some(RaidLayout {
        metadata_family: RaidMetadataFamily::LinuxMd,
        level,
        member_count: raid_disks,
        stripe_size_bytes,
        data_offset_bytes,
        parity_rotation,
        disk_order: (0..raid_disks).collect(),
        confidence_score: confidence,
    }))
}

fn detect_storage_spaces_layout(image: &[u8]) -> Result<Option<RaidLayout>, RaidError> {
    let min_len = SPACES_HEADER_OFFSET + 0x220;
    if image.len() < min_len {
        return Ok(None);
    }

    let signature = &image[SPACES_HEADER_OFFSET..SPACES_HEADER_OFFSET + SPACES_SIGNATURE.len()];
    if signature != SPACES_SIGNATURE {
        return Ok(None);
    }

    let raw_level = read_u32_le(image, SPACES_HEADER_OFFSET + 0x10)?;
    let raw_stripe_kib = read_u32_le(image, SPACES_HEADER_OFFSET + 0x14)?;
    let member_count = read_u32_le(image, SPACES_HEADER_OFFSET + 0x18)?;
    let raw_offset_kib = read_u32_le(image, SPACES_HEADER_OFFSET + 0x1C)?;
    let raw_parity = read_u32_le(image, SPACES_HEADER_OFFSET + 0x20)?;

    if member_count < 2 {
        return Err(RaidError::InvalidMemberCount(member_count));
    }

    let stripe_size_bytes = normalize_stripe_size(raw_stripe_kib.saturating_mul(1024));
    let data_offset_bytes =
        (raw_offset_kib as u64)
            .checked_mul(1024)
            .ok_or(RaidError::ArithmeticOverflow(
                "storage spaces data offset bytes",
            ))?;
    let level = map_spaces_level(raw_level);
    let parity_rotation = match raw_parity {
        1 => ParityRotation::RightSymmetric,
        2 => ParityRotation::LeftSymmetric,
        _ => ParityRotation::Unknown,
    };
    let confidence = score_metadata_confidence(
        member_count,
        raw_stripe_kib != 0,
        level != RaidLevel::Unknown,
        parity_rotation != ParityRotation::Unknown,
    );

    Ok(Some(RaidLayout {
        metadata_family: RaidMetadataFamily::WindowsStorageSpaces,
        level,
        member_count,
        stripe_size_bytes,
        data_offset_bytes,
        parity_rotation,
        disk_order: (0..member_count).collect(),
        confidence_score: confidence,
    }))
}

fn detect_imsm_layout(image: &[u8]) -> Result<Option<RaidLayout>, RaidError> {
    let Some(base) = find_signature_offset(image, IMSM_SIGNATURE) else {
        return Ok(None);
    };

    let min_len = base + 0x58;
    if image.len() < min_len {
        return Ok(None);
    }

    let raw_level = read_u32_le(image, base + 0x40)?;
    let member_count = read_u32_le(image, base + 0x44)?;
    if member_count < 2 {
        return Err(RaidError::InvalidMemberCount(member_count));
    }

    let raw_stripe_kib = read_u32_le(image, base + 0x48)?;
    let raw_offset_sectors = read_u64_le(image, base + 0x50)?;
    let stripe_size_bytes = normalize_stripe_size(raw_stripe_kib.saturating_mul(1024));
    let data_offset_bytes = raw_offset_sectors
        .checked_mul(512)
        .ok_or(RaidError::ArithmeticOverflow("imsm data offset bytes"))?;
    let level = map_imsm_level(raw_level);

    let confidence = score_metadata_confidence(
        member_count,
        raw_stripe_kib != 0,
        level != RaidLevel::Unknown,
        true,
    );

    Ok(Some(RaidLayout {
        metadata_family: RaidMetadataFamily::IntelImsm,
        level,
        member_count,
        stripe_size_bytes,
        data_offset_bytes,
        parity_rotation: ParityRotation::LeftSymmetric,
        disk_order: (0..member_count).collect(),
        confidence_score: confidence,
    }))
}

fn detect_ddf_layout(image: &[u8]) -> Result<Option<RaidLayout>, RaidError> {
    let Some(base) = find_signature_offset(image, DDF_SIGNATURE) else {
        return Ok(None);
    };

    let min_len = base + 0x60;
    if image.len() < min_len {
        return Ok(None);
    }

    let raw_level = read_u32_le(image, base + 0x24)?;
    let member_count = read_u32_le(image, base + 0x28)?;
    if member_count < 2 {
        return Err(RaidError::InvalidMemberCount(member_count));
    }
    let raw_stripe_kib = read_u32_le(image, base + 0x2C)?;
    let raw_offset_lba = read_u64_le(image, base + 0x30)?;
    let raw_parity = read_u32_le(image, base + 0x38)?;

    let stripe_size_bytes = normalize_stripe_size(raw_stripe_kib.saturating_mul(1024));
    let data_offset_bytes = raw_offset_lba
        .checked_mul(512)
        .ok_or(RaidError::ArithmeticOverflow("ddf data offset bytes"))?;
    let level = map_ddf_level(raw_level);
    let parity_rotation = match raw_parity {
        1 => ParityRotation::LeftSymmetric,
        2 => ParityRotation::RightSymmetric,
        _ => ParityRotation::Unknown,
    };
    let confidence = score_metadata_confidence(
        member_count,
        raw_stripe_kib != 0,
        level != RaidLevel::Unknown,
        parity_rotation != ParityRotation::Unknown,
    );

    Ok(Some(RaidLayout {
        metadata_family: RaidMetadataFamily::Ddf,
        level,
        member_count,
        stripe_size_bytes,
        data_offset_bytes,
        parity_rotation,
        disk_order: (0..member_count).collect(),
        confidence_score: confidence,
    }))
}

fn map_raid0(
    layout: &RaidLayout,
    logical_offset_bytes: u64,
) -> Result<RaidLogicalMapping, RaidError> {
    let stripe = layout.stripe_size_bytes as u64;
    let stripe_number = logical_offset_bytes / stripe;
    let stripe_offset = logical_offset_bytes % stripe;
    let member_position = stripe_number % layout.member_count as u64;
    let member_stripe_index = stripe_number / layout.member_count as u64;
    let member_offset_bytes = layout
        .data_offset_bytes
        .checked_add(
            member_stripe_index
                .checked_mul(stripe)
                .ok_or(RaidError::ArithmeticOverflow("raid0 member stripe delta"))?,
        )
        .and_then(|value| value.checked_add(stripe_offset))
        .ok_or(RaidError::ArithmeticOverflow("raid0 member offset"))?;

    Ok(RaidLogicalMapping {
        member_index: layout.disk_order[member_position as usize],
        member_offset_bytes,
        parity_member_index: None,
    })
}

fn map_raid1(
    layout: &RaidLayout,
    logical_offset_bytes: u64,
) -> Result<RaidLogicalMapping, RaidError> {
    let member_offset_bytes = layout
        .data_offset_bytes
        .checked_add(logical_offset_bytes)
        .ok_or(RaidError::ArithmeticOverflow("raid1 member offset"))?;
    Ok(RaidLogicalMapping {
        member_index: layout.disk_order[0],
        member_offset_bytes,
        parity_member_index: None,
    })
}

fn map_raid4(
    layout: &RaidLayout,
    logical_offset_bytes: u64,
) -> Result<RaidLogicalMapping, RaidError> {
    let stripe = layout.stripe_size_bytes as u64;
    let data_disks = layout.member_count - 1;
    if data_disks < 1 {
        return Err(RaidError::UnsupportedLayout);
    }

    let full_data_stripe = stripe
        .checked_mul(data_disks as u64)
        .ok_or(RaidError::ArithmeticOverflow("raid4 full stripe bytes"))?;
    let stripe_set = logical_offset_bytes / full_data_stripe;
    let in_set = logical_offset_bytes % full_data_stripe;
    let data_position = in_set / stripe;
    let stripe_offset = in_set % stripe;
    let member_offset_bytes = layout
        .data_offset_bytes
        .checked_add(
            stripe_set
                .checked_mul(stripe)
                .ok_or(RaidError::ArithmeticOverflow("raid4 member stripe delta"))?,
        )
        .and_then(|value| value.checked_add(stripe_offset))
        .ok_or(RaidError::ArithmeticOverflow("raid4 member offset"))?;

    let parity_index = layout.disk_order[(layout.member_count - 1) as usize];
    Ok(RaidLogicalMapping {
        member_index: layout.disk_order[data_position as usize],
        member_offset_bytes,
        parity_member_index: Some(parity_index),
    })
}

fn map_raid5(
    layout: &RaidLayout,
    logical_offset_bytes: u64,
) -> Result<RaidLogicalMapping, RaidError> {
    if layout.member_count < 3 {
        return Err(RaidError::UnsupportedLayout);
    }

    let stripe = layout.stripe_size_bytes as u64;
    let data_disks = layout.member_count - 1;
    let full_data_stripe = stripe
        .checked_mul(data_disks as u64)
        .ok_or(RaidError::ArithmeticOverflow("raid5 full stripe bytes"))?;
    let stripe_set = logical_offset_bytes / full_data_stripe;
    let in_set = logical_offset_bytes % full_data_stripe;
    let data_position = in_set / stripe;
    let stripe_offset = in_set % stripe;

    let parity_position = match layout.parity_rotation {
        ParityRotation::RightSymmetric => (stripe_set % layout.member_count as u64) as u32,
        ParityRotation::LeftSymmetric | ParityRotation::Unknown => {
            ((layout.member_count as u64 - 1 - (stripe_set % layout.member_count as u64))
                % layout.member_count as u64) as u32
        }
    };
    let data_member_position =
        ((parity_position as u64 + 1 + data_position) % layout.member_count as u64) as u32;

    let member_offset_bytes = layout
        .data_offset_bytes
        .checked_add(
            stripe_set
                .checked_mul(stripe)
                .ok_or(RaidError::ArithmeticOverflow("raid5 member stripe delta"))?,
        )
        .and_then(|value| value.checked_add(stripe_offset))
        .ok_or(RaidError::ArithmeticOverflow("raid5 member offset"))?;

    Ok(RaidLogicalMapping {
        member_index: layout.disk_order[data_member_position as usize],
        member_offset_bytes,
        parity_member_index: Some(layout.disk_order[parity_position as usize]),
    })
}

fn map_raid10(
    layout: &RaidLayout,
    logical_offset_bytes: u64,
) -> Result<RaidLogicalMapping, RaidError> {
    if layout.member_count < 4 || layout.member_count % 2 != 0 {
        return Err(RaidError::UnsupportedLayout);
    }

    let stripe = layout.stripe_size_bytes as u64;
    let mirror_pair_count = layout.member_count / 2;
    if mirror_pair_count == 0 {
        return Err(RaidError::UnsupportedLayout);
    }

    let stripe_number = logical_offset_bytes / stripe;
    let stripe_offset = logical_offset_bytes % stripe;
    let pair_position = (stripe_number % mirror_pair_count as u64) as u32;
    let pair_stripe_index = stripe_number / mirror_pair_count as u64;

    let primary_position = pair_position
        .checked_mul(2)
        .ok_or(RaidError::ArithmeticOverflow("raid10 primary position"))?;
    let mirror_position = primary_position
        .checked_add(1)
        .ok_or(RaidError::ArithmeticOverflow("raid10 mirror position"))?;

    let member_offset_bytes = layout
        .data_offset_bytes
        .checked_add(
            pair_stripe_index
                .checked_mul(stripe)
                .ok_or(RaidError::ArithmeticOverflow("raid10 member stripe delta"))?,
        )
        .and_then(|value| value.checked_add(stripe_offset))
        .ok_or(RaidError::ArithmeticOverflow("raid10 member offset"))?;

    Ok(RaidLogicalMapping {
        member_index: layout.disk_order[primary_position as usize],
        member_offset_bytes,
        parity_member_index: Some(layout.disk_order[mirror_position as usize]),
    })
}

fn normalize_stripe_size(raw: u32) -> u32 {
    if is_valid_stripe_size(raw) {
        return raw;
    }

    const DEFAULT: u32 = 64 * 1024;
    DEFAULT
}

fn is_valid_stripe_size(value: u32) -> bool {
    value >= 4 * 1024 && value <= 4 * 1024 * 1024 && value.is_power_of_two()
}

fn validate_disk_order(order: &[u32], member_count: u32) -> Result<(), RaidError> {
    if order.len() != member_count as usize {
        return Err(RaidError::InvalidDiskOrder);
    }

    let mut seen = vec![false; member_count as usize];
    for value in order {
        if *value >= member_count {
            return Err(RaidError::InvalidDiskOrder);
        }
        if seen[*value as usize] {
            return Err(RaidError::InvalidDiskOrder);
        }
        seen[*value as usize] = true;
    }

    Ok(())
}

fn map_md_level(value: i32) -> RaidLevel {
    match value {
        0 => RaidLevel::Raid0,
        1 => RaidLevel::Raid1,
        4 => RaidLevel::Raid4,
        5 => RaidLevel::Raid5,
        6 => RaidLevel::Raid6,
        10 => RaidLevel::Raid10,
        _ => RaidLevel::Unknown,
    }
}

fn map_spaces_level(value: u32) -> RaidLevel {
    match value {
        0 => RaidLevel::Raid0,
        1 => RaidLevel::Raid1,
        4 => RaidLevel::Raid4,
        5 => RaidLevel::Raid5,
        6 => RaidLevel::Raid6,
        10 => RaidLevel::Raid10,
        _ => RaidLevel::Unknown,
    }
}

fn map_imsm_level(value: u32) -> RaidLevel {
    match value {
        0 => RaidLevel::Raid0,
        1 => RaidLevel::Raid1,
        2 => RaidLevel::Raid5,
        3 => RaidLevel::Raid10,
        _ => RaidLevel::Unknown,
    }
}

fn map_ddf_level(value: u32) -> RaidLevel {
    match value {
        0 => RaidLevel::Raid0,
        1 => RaidLevel::Raid1,
        4 => RaidLevel::Raid4,
        5 => RaidLevel::Raid5,
        6 => RaidLevel::Raid6,
        10 => RaidLevel::Raid10,
        _ => RaidLevel::Unknown,
    }
}

fn map_md_parity_rotation(layout: u32) -> ParityRotation {
    match layout {
        0 => ParityRotation::LeftSymmetric,
        1 => ParityRotation::RightSymmetric,
        _ => ParityRotation::Unknown,
    }
}

fn score_metadata_confidence(
    member_count: u32,
    has_chunk: bool,
    known_level: bool,
    known_parity: bool,
) -> u8 {
    let mut score = 40u8;
    if member_count >= 2 {
        score = score.saturating_add(20);
    }
    if known_level {
        score = score.saturating_add(15);
    }
    if has_chunk {
        score = score.saturating_add(15);
    }
    if known_parity {
        score = score.saturating_add(10);
    }
    score.min(99)
}

fn normalize_missing_members(missing_members: &[u32], member_count: u32) -> Vec<u32> {
    let mut members = missing_members
        .iter()
        .copied()
        .filter(|value| *value < member_count)
        .collect::<Vec<_>>();
    members.sort_unstable();
    members.dedup();
    members
}

fn is_mapping_recoverable(
    level: RaidLevel,
    mapping: &RaidLogicalMapping,
    missing_members: &[u32],
) -> bool {
    let data_missing = missing_members.contains(&mapping.member_index);
    let parity_missing = mapping
        .parity_member_index
        .is_some_and(|value| missing_members.contains(&value));

    match level {
        RaidLevel::Raid0 => !data_missing,
        RaidLevel::Raid1 => !data_missing || !parity_missing,
        RaidLevel::Raid4 | RaidLevel::Raid5 => {
            if data_missing {
                missing_members.len() <= 1
            } else {
                true
            }
        }
        RaidLevel::Raid6 => missing_members.len() <= 2,
        RaidLevel::Raid10 => !data_missing || !parity_missing,
        RaidLevel::Unknown => false,
    }
}

fn build_degraded_recommendation(
    level: RaidLevel,
    missing_member_count: u32,
    recoverability_percent: u8,
) -> String {
    if missing_member_count == 0 {
        return "No missing members detected; run full recovery path.".to_string();
    }

    if recoverability_percent >= 95 {
        return format!(
            "{level:?} degraded profile appears recoverable; continue with cautious export and parity verification."
        );
    }

    if recoverability_percent >= 60 {
        return format!(
            "{level:?} degraded profile has mixed recoverability; export critical ranges first and validate hashes."
        );
    }

    format!(
        "{level:?} degraded profile has low recoverability; prefer clone-first triage and manual layout overrides."
    )
}

fn find_signature_offset(bytes: &[u8], signature: &[u8]) -> Option<usize> {
    if signature.is_empty() || bytes.len() < signature.len() {
        return None;
    }

    bytes
        .windows(signature.len())
        .position(|window| window == signature)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, RaidError> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or(RaidError::BufferTooSmall {
            expected: offset + 4,
            actual: bytes.len(),
        })?;
    let mut value = [0u8; 4];
    value.copy_from_slice(slice);
    Ok(u32::from_le_bytes(value))
}

fn read_i32_le(bytes: &[u8], offset: usize) -> Result<i32, RaidError> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or(RaidError::BufferTooSmall {
            expected: offset + 4,
            actual: bytes.len(),
        })?;
    let mut value = [0u8; 4];
    value.copy_from_slice(slice);
    Ok(i32::from_le_bytes(value))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64, RaidError> {
    let slice = bytes
        .get(offset..offset + 8)
        .ok_or(RaidError::BufferTooSmall {
            expected: offset + 8,
            actual: bytes.len(),
        })?;
    let mut value = [0u8; 8];
    value.copy_from_slice(slice);
    Ok(u64::from_le_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_mdraid_layout_from_superblock_v1_header() {
        let image = build_mdraid_image(5, 0, 128 * 1024, 4, 2048);
        let layout = detect_layout(&image).expect("detect").expect("md layout");
        assert_eq!(layout.metadata_family, RaidMetadataFamily::LinuxMd);
        assert_eq!(layout.level, RaidLevel::Raid5);
        assert_eq!(layout.member_count, 4);
        assert_eq!(layout.stripe_size_bytes, 128 * 1024);
        assert_eq!(layout.data_offset_bytes, 2048 * 512);
        assert_eq!(layout.parity_rotation, ParityRotation::LeftSymmetric);
        assert_eq!(layout.disk_order, vec![0, 1, 2, 3]);
        assert!(layout.confidence_score >= 80);
    }

    #[test]
    fn detects_storage_spaces_layout_from_signature() {
        let image = build_spaces_image(1, 64, 3, 4096, 1);
        let layout = detect_layout(&image)
            .expect("detect")
            .expect("spaces layout");
        assert_eq!(
            layout.metadata_family,
            RaidMetadataFamily::WindowsStorageSpaces
        );
        assert_eq!(layout.level, RaidLevel::Raid1);
        assert_eq!(layout.member_count, 3);
        assert_eq!(layout.stripe_size_bytes, 64 * 1024);
        assert_eq!(layout.data_offset_bytes, 4096 * 1024);
        assert_eq!(layout.parity_rotation, ParityRotation::RightSymmetric);
    }

    #[test]
    fn returns_none_when_no_supported_metadata_is_present() {
        let image = vec![0u8; 32 * 1024];
        assert!(detect_layout(&image).expect("detect").is_none());
    }

    #[test]
    fn detects_intel_imsm_layout_from_signature() {
        let image = build_imsm_image(2, 128, 4, 4096);
        let layout = detect_layout(&image).expect("detect").expect("imsm layout");
        assert_eq!(layout.metadata_family, RaidMetadataFamily::IntelImsm);
        assert_eq!(layout.level, RaidLevel::Raid5);
        assert_eq!(layout.member_count, 4);
        assert_eq!(layout.stripe_size_bytes, 128 * 1024);
        assert_eq!(layout.data_offset_bytes, 4096 * 512);
    }

    #[test]
    fn detects_ddf_layout_from_signature() {
        let image = build_ddf_image(5, 64, 5, 8192, 2);
        let layout = detect_layout(&image).expect("detect").expect("ddf layout");
        assert_eq!(layout.metadata_family, RaidMetadataFamily::Ddf);
        assert_eq!(layout.level, RaidLevel::Raid5);
        assert_eq!(layout.member_count, 5);
        assert_eq!(layout.stripe_size_bytes, 64 * 1024);
        assert_eq!(layout.data_offset_bytes, 8192 * 512);
        assert_eq!(layout.parity_rotation, ParityRotation::RightSymmetric);
    }

    #[test]
    fn degraded_assessment_reports_full_recoverability_for_raid5_single_missing_parity() {
        let layout = RaidLayout {
            metadata_family: RaidMetadataFamily::LinuxMd,
            level: RaidLevel::Raid5,
            member_count: 4,
            stripe_size_bytes: 64 * 1024,
            data_offset_bytes: 2 * 1024 * 1024,
            parity_rotation: ParityRotation::LeftSymmetric,
            disk_order: vec![0, 1, 2, 3],
            confidence_score: 85,
        };

        let assessment = assess_degraded_layout(&layout, &[3], 64).expect("assessment");
        assert!(assessment.recoverability_percent >= 95);
        assert_eq!(assessment.missing_member_count, 1);
    }

    #[test]
    fn degraded_assessment_reports_low_recoverability_for_raid0_missing_member() {
        let layout = RaidLayout {
            metadata_family: RaidMetadataFamily::LinuxMd,
            level: RaidLevel::Raid0,
            member_count: 3,
            stripe_size_bytes: 64 * 1024,
            data_offset_bytes: 1_048_576,
            parity_rotation: ParityRotation::Unknown,
            disk_order: vec![0, 1, 2],
            confidence_score: 80,
        };

        let assessment = assess_degraded_layout(&layout, &[1], 64).expect("assessment");
        assert!(assessment.recoverability_percent < 95);
        assert!(assessment.confidence_penalty > 0);
    }

    #[test]
    fn applies_manual_override_for_level_stripe_and_order() {
        let image = build_mdraid_image(5, 0, 128 * 1024, 4, 2048);
        let base = detect_layout(&image).expect("detect").expect("layout");
        let override_cfg = RaidManualOverride {
            level: Some(RaidLevel::Raid0),
            stripe_size_bytes: Some(256 * 1024),
            data_offset_bytes: Some(2 * 1024 * 1024),
            parity_rotation: None,
            disk_order: Some(vec![2, 0, 3, 1]),
        };
        let resolved = apply_manual_override(&base, &override_cfg).expect("override");
        assert_eq!(resolved.level, RaidLevel::Raid0);
        assert_eq!(resolved.stripe_size_bytes, 256 * 1024);
        assert_eq!(resolved.data_offset_bytes, 2 * 1024 * 1024);
        assert_eq!(resolved.disk_order, vec![2, 0, 3, 1]);
    }

    #[test]
    fn rejects_manual_override_with_invalid_disk_order() {
        let image = build_mdraid_image(5, 0, 128 * 1024, 4, 2048);
        let base = detect_layout(&image).expect("detect").expect("layout");
        let override_cfg = RaidManualOverride {
            level: None,
            stripe_size_bytes: None,
            data_offset_bytes: None,
            parity_rotation: None,
            disk_order: Some(vec![0, 1, 1, 3]),
        };
        let err = apply_manual_override(&base, &override_cfg).expect_err("invalid order");
        assert_eq!(err, RaidError::InvalidDiskOrder);
    }

    #[test]
    fn maps_logical_offset_for_raid0_layout() {
        let layout = RaidLayout {
            metadata_family: RaidMetadataFamily::LinuxMd,
            level: RaidLevel::Raid0,
            member_count: 3,
            stripe_size_bytes: 64 * 1024,
            data_offset_bytes: 1_048_576,
            parity_rotation: ParityRotation::Unknown,
            disk_order: vec![2, 0, 1],
            confidence_score: 80,
        };
        let mapping = map_logical_offset(&layout, (64 * 1024 * 3 + 123) as u64).expect("map");
        assert_eq!(mapping.member_index, 2);
        assert_eq!(mapping.member_offset_bytes, 1_048_576 + 64 * 1024 + 123);
        assert_eq!(mapping.parity_member_index, None);
    }

    #[test]
    fn maps_logical_offset_for_raid5_layout() {
        let layout = RaidLayout {
            metadata_family: RaidMetadataFamily::LinuxMd,
            level: RaidLevel::Raid5,
            member_count: 4,
            stripe_size_bytes: 64 * 1024,
            data_offset_bytes: 2_097_152,
            parity_rotation: ParityRotation::LeftSymmetric,
            disk_order: vec![0, 1, 2, 3],
            confidence_score: 85,
        };
        let mapping = map_logical_offset(&layout, 0).expect("map");
        assert_eq!(mapping.member_index, 0);
        assert_eq!(mapping.member_offset_bytes, 2_097_152);
        assert_eq!(mapping.parity_member_index, Some(3));
    }

    #[test]
    fn maps_logical_offset_for_raid10_layout() {
        let layout = RaidLayout {
            metadata_family: RaidMetadataFamily::LinuxMd,
            level: RaidLevel::Raid10,
            member_count: 4,
            stripe_size_bytes: 64 * 1024,
            data_offset_bytes: 512 * 1024,
            parity_rotation: ParityRotation::Unknown,
            disk_order: vec![0, 1, 2, 3],
            confidence_score: 82,
        };

        let first = map_logical_offset(&layout, 0).expect("map first stripe");
        assert_eq!(first.member_index, 0);
        assert_eq!(first.parity_member_index, Some(1));
        assert_eq!(first.member_offset_bytes, 512 * 1024);

        let second = map_logical_offset(&layout, 64 * 1024).expect("map second stripe");
        assert_eq!(second.member_index, 2);
        assert_eq!(second.parity_member_index, Some(3));
        assert_eq!(second.member_offset_bytes, 512 * 1024);
    }

    #[test]
    fn reports_invalid_member_count_during_detection() {
        let image = build_mdraid_image(5, 0, 64 * 1024, 1, 2048);
        let err = detect_layout(&image).expect_err("invalid member count");
        assert_eq!(err, RaidError::InvalidMemberCount(1));
    }

    fn build_mdraid_image(
        level: i32,
        layout: u32,
        chunk_size_bytes: u32,
        raid_disks: u32,
        data_offset_sectors: u64,
    ) -> Vec<u8> {
        let mut image = vec![0u8; 32 * 1024];
        let base = MD_SUPERBLOCK_V1_OFFSET;
        write_u32(&mut image, base, MD_MAGIC);
        write_u32(&mut image, base + 4, 1);
        write_i32(&mut image, base + 0x48, level);
        write_u32(&mut image, base + 0x4C, layout);
        write_u32(&mut image, base + 0x50, chunk_size_bytes);
        write_u32(&mut image, base + 0x5C, raid_disks);
        write_u64(&mut image, base + 0x80, data_offset_sectors);
        image
    }

    fn build_spaces_image(
        level: u32,
        stripe_kib: u32,
        member_count: u32,
        data_offset_kib: u32,
        parity: u32,
    ) -> Vec<u8> {
        let mut image = vec![0u8; 32 * 1024];
        image[SPACES_HEADER_OFFSET..SPACES_HEADER_OFFSET + SPACES_SIGNATURE.len()]
            .copy_from_slice(SPACES_SIGNATURE);
        write_u32(&mut image, SPACES_HEADER_OFFSET + 0x10, level);
        write_u32(&mut image, SPACES_HEADER_OFFSET + 0x14, stripe_kib);
        write_u32(&mut image, SPACES_HEADER_OFFSET + 0x18, member_count);
        write_u32(&mut image, SPACES_HEADER_OFFSET + 0x1C, data_offset_kib);
        write_u32(&mut image, SPACES_HEADER_OFFSET + 0x20, parity);
        image
    }

    fn build_imsm_image(
        level: u32,
        stripe_kib: u32,
        member_count: u32,
        data_offset_sectors: u64,
    ) -> Vec<u8> {
        let mut image = vec![0u8; 64 * 1024];
        let base = 0x1800;
        image[base..base + IMSM_SIGNATURE.len()].copy_from_slice(IMSM_SIGNATURE);
        write_u32(&mut image, base + 0x40, level);
        write_u32(&mut image, base + 0x44, member_count);
        write_u32(&mut image, base + 0x48, stripe_kib);
        write_u64(&mut image, base + 0x50, data_offset_sectors);
        image
    }

    fn build_ddf_image(
        level: u32,
        stripe_kib: u32,
        member_count: u32,
        data_offset_lba: u64,
        parity_rotation: u32,
    ) -> Vec<u8> {
        let mut image = vec![0u8; 64 * 1024];
        let base = 0x400;
        image[base..base + DDF_SIGNATURE.len()].copy_from_slice(DDF_SIGNATURE);
        write_u32(&mut image, base + 0x24, level);
        write_u32(&mut image, base + 0x28, member_count);
        write_u32(&mut image, base + 0x2C, stripe_kib);
        write_u64(&mut image, base + 0x30, data_offset_lba);
        write_u32(&mut image, base + 0x38, parity_rotation);
        image
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_i32(bytes: &mut [u8], offset: usize, value: i32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
