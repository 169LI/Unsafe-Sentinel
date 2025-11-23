use crate::utils::error::Result;
use std::path::Path;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};

pub mod vulnerability_analyzer;
pub mod analysis_config;
pub mod analysis_results;
pub mod post_processing;

pub use vulnerability_analyzer::VulnerabilityAnalyzer;
pub use analysis_config::{AnalysisConfig, AnalysisPrecision};
pub use analysis_results::{AnalysisResults, Vulnerability, VulnerabilitySeverity, DetectionMethod};
pub use post_processing::PostProcessor;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisContext {
    pub project_path: String,
    pub analysis_start_time: u64,
    pub analysis_end_time: Option<u64>,
    pub files_analyzed: usize,
    pub lines_of_code: usize,
    pub unsafe_blocks_found: usize,
    pub dependencies: Vec<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl AnalysisContext {
    pub fn new(project_path: String) -> Self {
        Self {
            project_path,
            analysis_start_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            analysis_end_time: None,
            files_analyzed: 0,
            lines_of_code: 0,
            unsafe_blocks_found: 0,
            dependencies: Vec::new(),
            metadata: HashMap::new(),
        }
    }
    
    pub fn finish(&mut self) {
        self.analysis_end_time = Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs());
    }
    
    pub fn duration(&self) -> u64 {
        match self.analysis_end_time {
            Some(end) => end.saturating_sub(self.analysis_start_time),
            None => SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().saturating_sub(self.analysis_start_time),
        }
    }
}