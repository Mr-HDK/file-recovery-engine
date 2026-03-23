use std::collections::HashSet;

use fr_types::{ConfidenceTier, EvidenceSource, RecoveryCandidate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoredConfidence {
    pub score: u8,
    pub tier: ConfidenceTier,
    pub reasons: Vec<&'static str>,
}

/// Compatibility API for existing call sites that only consume the tier.
pub fn score_candidate(candidate: &RecoveryCandidate) -> ConfidenceTier {
    score_candidate_with_reasons(candidate).tier
}

pub fn score_candidate_with_reasons(candidate: &RecoveryCandidate) -> ScoredConfidence {
    let evidence: HashSet<EvidenceSource> = candidate.evidence.iter().copied().collect();
    let mut score: i32 = 0;
    let mut reasons = Vec::new();

    if evidence.contains(&EvidenceSource::Mft) {
        score += 80;
        reasons.push("MFT metadata present");
    }

    if evidence.contains(&EvidenceSource::DirectoryIndex) {
        score += 10;
        reasons.push("Directory index corroboration");
    }

    if evidence.contains(&EvidenceSource::Usn) {
        score += 12;
        reasons.push("USN journal corroboration");
    }

    if evidence.contains(&EvidenceSource::Vss) {
        score += 15;
        reasons.push("VSS snapshot corroboration");
    }

    if evidence.contains(&EvidenceSource::Carve) {
        score += 8;
        reasons.push("Signature-based carving evidence");
    }

    let has_metadata_path = candidate.original_name.is_some() && candidate.original_path.is_some();
    if has_metadata_path {
        score += 8;
        reasons.push("Original name/path reconstructed");
    } else {
        score -= 15;
        reasons.push("Original name/path incomplete");
    }

    if candidate.partial {
        score -= 30;
        reasons.push("Partial data recovery");
    }

    let metadata_evidence = evidence.contains(&EvidenceSource::Mft)
        || evidence.contains(&EvidenceSource::DirectoryIndex)
        || evidence.contains(&EvidenceSource::Usn)
        || evidence.contains(&EvidenceSource::Vss);
    if !metadata_evidence && evidence.contains(&EvidenceSource::Carve) {
        // Carve-only candidates should stay low-confidence even when the signature looks clean.
        score = score.min(35);
        reasons.push("Carve-only candidate confidence cap");
    }

    let bounded_score = score.clamp(0, 100) as u8;
    let tier = map_score_to_tier(bounded_score);

    ScoredConfidence {
        score: bounded_score,
        tier,
        reasons,
    }
}

fn map_score_to_tier(score: u8) -> ConfidenceTier {
    match score {
        85..=100 => ConfidenceTier::VeryHigh,
        70..=84 => ConfidenceTier::High,
        50..=69 => ConfidenceTier::Medium,
        30..=49 => ConfidenceTier::Low,
        _ => ConfidenceTier::VeryLow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate_with_evidence(evidence: Vec<EvidenceSource>) -> RecoveryCandidate {
        RecoveryCandidate {
            id: "1".into(),
            original_name: Some("doc.txt".into()),
            original_path: Some("/a/doc.txt".into()),
            recovered_path: None,
            size_bytes: 100,
            evidence,
            confidence: ConfidenceTier::Medium,
            partial: false,
        }
    }

    #[test]
    fn mft_backed_candidate_scores_very_high() {
        let candidate = candidate_with_evidence(vec![EvidenceSource::Mft]);
        let scored = score_candidate_with_reasons(&candidate);

        assert_eq!(scored.tier, ConfidenceTier::VeryHigh);
        assert!(scored.score >= 85);
        assert!(scored.reasons.contains(&"MFT metadata present"));
    }

    #[test]
    fn carve_only_candidate_is_low_or_very_low() {
        let candidate = candidate_with_evidence(vec![EvidenceSource::Carve]);
        let scored = score_candidate_with_reasons(&candidate);

        assert!(matches!(
            scored.tier,
            ConfidenceTier::Low | ConfidenceTier::VeryLow
        ));
        assert!(scored
            .reasons
            .contains(&"Carve-only candidate confidence cap"));
    }

    #[test]
    fn partial_penalty_reduces_score() {
        let mut candidate = candidate_with_evidence(vec![EvidenceSource::Mft, EvidenceSource::Usn]);
        let full = score_candidate_with_reasons(&candidate);

        candidate.partial = true;
        let partial = score_candidate_with_reasons(&candidate);

        assert!(partial.score < full.score);
        assert!(partial.reasons.contains(&"Partial data recovery"));
    }

    #[test]
    fn compatibility_api_uses_weighted_tier() {
        let candidate =
            candidate_with_evidence(vec![EvidenceSource::DirectoryIndex, EvidenceSource::Usn]);
        assert_eq!(
            score_candidate(&candidate),
            score_candidate_with_reasons(&candidate).tier
        );
    }
}
