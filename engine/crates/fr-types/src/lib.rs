use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecoverySourceKind {
    PhysicalDisk,
    Volume,
    ImageFile,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EvidenceSource {
    Mft,
    DirectoryIndex,
    Usn,
    Vss,
    Carve,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfidenceTier {
    VeryHigh,
    High,
    Medium,
    Low,
    VeryLow,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryCandidate {
    pub id: String,
    pub original_name: Option<String>,
    pub original_path: Option<String>,
    pub recovered_path: Option<String>,
    pub size_bytes: u64,
    pub evidence: Vec<EvidenceSource>,
    pub confidence: ConfidenceTier,
    pub partial: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanSessionState {
    pub session_id: String,
    pub checkpoint: String,
    pub canceled: bool,
}

impl ScanSessionState {
    pub fn new(session_id: impl Into<String>, checkpoint: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            checkpoint: checkpoint.into(),
            canceled: false,
        }
    }
}
