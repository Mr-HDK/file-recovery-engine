use fr_types::RecoverySourceKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDescriptor {
    pub name: &'static str,
    pub purpose: &'static str,
    pub source_kind: RecoverySourceKind,
}

pub fn descriptor() -> ModuleDescriptor {
    ModuleDescriptor {
        name: "fr-logfile",
        purpose: "Extensible integration seam for $LogFile transaction correlation.",
        source_kind: RecoverySourceKind::Volume,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogfileCorrelationInput {
    pub record_number: u32,
    pub parent_record_number: Option<u64>,
    pub name: Option<String>,
    pub reconstructed_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogfileCorrelationHint {
    pub record_number: u32,
    pub inferred_parent_record_number: Option<u64>,
    pub inferred_name: Option<String>,
    pub inferred_reconstructed_path: Option<String>,
    pub explanation: String,
}

pub trait LogfileCorrelator: Send + Sync {
    fn correlate(&self, candidates: &[LogfileCorrelationInput]) -> Vec<LogfileCorrelationHint>;
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NoopLogfileCorrelator;

impl LogfileCorrelator for NoopLogfileCorrelator {
    fn correlate(&self, _candidates: &[LogfileCorrelationInput]) -> Vec<LogfileCorrelationHint> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_correlator_returns_no_hints() {
        let correlator = NoopLogfileCorrelator;
        let input = vec![LogfileCorrelationInput {
            record_number: 42,
            parent_record_number: Some(5),
            name: Some("report.txt".to_string()),
            reconstructed_path: Some(r"Docs\report.txt".to_string()),
        }];

        let hints = correlator.correlate(&input);
        assert!(hints.is_empty());
    }
}
