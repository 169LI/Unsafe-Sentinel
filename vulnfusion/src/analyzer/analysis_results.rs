use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use crate::analyzer::AnalysisContext;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResults {
    pub context: AnalysisContext,
    pub vulnerabilities: Vec<Vulnerability>,
    pub statistics: AnalysisStatistics,
    pub performance_metrics: PerformanceMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub vulnerability_type: String,
    pub severity: VulnerabilitySeverity,
    pub confidence: f64,
    pub file_path: String,
    pub line_number: usize,
    pub column_number: Option<usize>,
    pub description: String,
    pub detailed_explanation: String,
    pub remediation_suggestion: String,
    pub code_snippet: String,
    pub related_code_locations: Vec<CodeLocation>,
    pub detection_method: DetectionMethod,
    pub metadata: HashMap<String, serde_json::Value>,
    pub detected_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeLocation {
    pub file_path: String,
    pub line_number: usize,
    pub column_number: Option<usize>,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionMethod {
    StaticAnalysis,
    DataFlowAnalysis,
    ControlFlowAnalysis,
    PatternMatching,
    MachineLearning,
    CrossReference,
    Heuristic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStatistics {
    pub total_files_analyzed: usize,
    pub total_lines_of_code: usize,
    pub unsafe_blocks_found: usize,
    pub functions_analyzed: usize,
    pub total_vulnerabilities: usize,
    pub vulnerabilities_by_severity: HashMap<String, usize>,
    pub vulnerabilities_by_type: HashMap<String, usize>,
    pub false_positive_rate: f64,
    pub coverage_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub analysis_duration_ms: u64,
    pub peak_memory_usage_mb: f64,
    pub files_per_second: f64,
    pub lines_per_second: f64,
    pub analysis_depth_reached: usize,
    pub cache_hit_rate: f64,
}

impl AnalysisResults {
    pub fn new(context: AnalysisContext) -> Self {
        Self {
            context,
            vulnerabilities: Vec::new(),
            statistics: AnalysisStatistics {
                total_files_analyzed: 0,
                total_lines_of_code: 0,
                unsafe_blocks_found: 0,
                functions_analyzed: 0,
                total_vulnerabilities: 0,
                vulnerabilities_by_severity: HashMap::new(),
                vulnerabilities_by_type: HashMap::new(),
                false_positive_rate: 0.0,
                coverage_percentage: 0.0,
            },
            performance_metrics: PerformanceMetrics {
                analysis_duration_ms: 0,
                peak_memory_usage_mb: 0.0,
                files_per_second: 0.0,
                lines_per_second: 0.0,
                analysis_depth_reached: 0,
                cache_hit_rate: 0.0,
            },
        }
    }
    
    pub fn add_vulnerability(&mut self, vulnerability: Vulnerability) {
        self.vulnerabilities.push(vulnerability);
        self.update_statistics();
    }
    
    pub fn add_vulnerabilities(&mut self, vulnerabilities: Vec<Vulnerability>) {
        self.vulnerabilities.extend(vulnerabilities);
        self.update_statistics();
    }
    
    fn update_statistics(&mut self) {
        self.statistics.total_vulnerabilities = self.vulnerabilities.len();
        
        // Count by severity
        self.statistics.vulnerabilities_by_severity.clear();
        for vuln in &self.vulnerabilities {
            let severity = format!("{:?}", vuln.severity);
            *self.statistics.vulnerabilities_by_severity.entry(severity).or_insert(0) += 1;
        }
        
        // Count by type
        self.statistics.vulnerabilities_by_type.clear();
        for vuln in &self.vulnerabilities {
            *self.statistics.vulnerabilities_by_type.entry(vuln.vulnerability_type.clone()).or_insert(0) += 1;
        }
    }
    
    pub fn get_critical_vulnerabilities(&self) -> Vec<&Vulnerability> {
        self.vulnerabilities.iter()
            .filter(|v| matches!(v.severity, VulnerabilitySeverity::Critical))
            .collect()
    }
    
    pub fn get_high_severity_vulnerabilities(&self) -> Vec<&Vulnerability> {
        self.vulnerabilities.iter()
            .filter(|v| matches!(v.severity, VulnerabilitySeverity::High))
            .collect()
    }
    
    pub fn get_vulnerabilities_by_type(&self, vuln_type: &str) -> Vec<&Vulnerability> {
        self.vulnerabilities.iter()
            .filter(|v| v.vulnerability_type == vuln_type)
            .collect()
    }
    
    pub fn has_critical_vulnerabilities(&self) -> bool {
        self.vulnerabilities.iter().any(|v| matches!(v.severity, VulnerabilitySeverity::Critical))
    }
    
    pub fn summary(&self) -> String {
        format!(
            "Analysis completed: {} vulnerabilities found in {} files ({} lines of code)",
            self.statistics.total_vulnerabilities,
            self.statistics.total_files_analyzed,
            self.statistics.total_lines_of_code
        )
    }
}