pub mod vulnerability_detector;
pub mod memory_safety_detector;
pub mod concurrency_detector;
pub mod panic_safety_detector;
pub mod pattern_detector;

pub use vulnerability_detector::VulnerabilityDetector;
pub use memory_safety_detector::MemorySafetyDetector;
pub use concurrency_detector::ConcurrencyDetector;
pub use panic_safety_detector::PanicSafetyDetector;
pub use pattern_detector::PatternDetector;

use crate::analyzer::{Vulnerability, VulnerabilitySeverity, DetectionMethod};
use std::collections::HashMap;

/// Helper function to create a vulnerability with default metadata
pub fn create_vulnerability(
    vulnerability_type: String,
    severity: VulnerabilitySeverity,
    confidence: f64,
    file_path: String,
    line_number: usize,
    description: String,
    detailed_explanation: String,
    remediation_suggestion: String,
    code_snippet: String,
    detection_method: DetectionMethod,
) -> Vulnerability {
    Vulnerability {
        id: format!("{}_{}_{}", vulnerability_type, file_path, line_number),
        vulnerability_type,
        severity,
        confidence,
        file_path,
        line_number,
        column_number: None,
        description,
        detailed_explanation,
        remediation_suggestion,
        code_snippet,
        related_code_locations: Vec::new(),
        detection_method,
        metadata: HashMap::new(),
        detected_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    }
}