// 中文说明：
// PatternDetector 使用正则与语法片段特征匹配常见风险模式（Send/Sync 变体、
// API 误用、资源泄漏、transmute、不安全初始化/零化等），提供快速初筛能力。
use crate::utils::error::Result;
use tracing::{debug, info};
use quote::ToTokens;
use once_cell::sync::Lazy;
use regex::Regex;

use crate::analyzer::{Vulnerability, VulnerabilitySeverity, DetectionMethod};
use crate::parser::RustAst;
use crate::graph::AnalysisGraph;
use crate::detector::create_vulnerability;

static VULNERABILITY_PATTERNS: Lazy<Vec<VulnerabilityPattern>> = Lazy::new(|| {
    vec![
        // Send/Sync variance violations
        VulnerabilityPattern {
            name: "send-sync-variance".to_string(),
            pattern: Regex::new(r"unsafe impl.*Send.*for.*<.*>").unwrap(),
            severity: VulnerabilitySeverity::High,
            confidence: 0.8,
            description: "Potential Send/Sync variance violation".to_string(),
            explanation: "Generic type implementing Send/Sync without proper bounds".to_string(),
            remediation: "Add proper Send/Sync bounds to generic parameters".to_string(),
        },
        
        // API misuse patterns
        VulnerabilityPattern {
            name: "api-misuse".to_string(),
            pattern: Regex::new(r"Vec::from_raw_parts").unwrap(),
            severity: VulnerabilitySeverity::High,
            confidence: 0.9,
            description: "Potentially unsafe Vec::from_raw_parts usage".to_string(),
            explanation: "Vec::from_raw_parts requires careful handling of memory safety".to_string(),
            remediation: "Ensure proper length, capacity, and pointer validity".to_string(),
        },
        
        // Resource management patterns
        VulnerabilityPattern {
            name: "resource-leak".to_string(),
            pattern: Regex::new(r"mem::forget\s*\(").unwrap(),
            severity: VulnerabilitySeverity::Medium,
            confidence: 0.8,
            description: "Potential resource leak via mem::forget".to_string(),
            explanation: "mem::forget prevents Drop implementation from running".to_string(),
            remediation: "Consider using ManuallyDrop or proper cleanup patterns".to_string(),
        },
        
        // Transmute patterns
        VulnerabilityPattern {
            name: "invalid-transmute".to_string(),
            pattern: Regex::new(r"mem::transmute\s*::<.*>").unwrap(),
            severity: VulnerabilitySeverity::High,
            confidence: 0.7,
            description: "Potentially invalid transmute usage".to_string(),
            explanation: "mem::transmute can cause undefined behavior if used incorrectly".to_string(),
            remediation: "Use safe conversion methods when possible".to_string(),
        },
        
        // Uninitialized memory patterns
        VulnerabilityPattern {
            name: "uninitialized-memory".to_string(),
            pattern: Regex::new(r"mem::uninitialized\s*\(").unwrap(),
            severity: VulnerabilitySeverity::Critical,
            confidence: 0.9,
            description: "Use of deprecated mem::uninitialized".to_string(),
            explanation: "mem::uninitialized is deprecated and can cause undefined behavior".to_string(),
            remediation: "Use MaybeUninit instead".to_string(),
        },
        
        // Zeroed memory patterns
        VulnerabilityPattern {
            name: "zeroed-memory".to_string(),
            pattern: Regex::new(r"mem::zeroed\s*::<.*>").unwrap(),
            severity: VulnerabilitySeverity::High,
            confidence: 0.7,
            description: "Potential invalid use of mem::zeroed".to_string(),
            explanation: "mem::zeroed can cause undefined behavior for non-zero-initializable types".to_string(),
            remediation: "Use proper initialization or MaybeUninit".to_string(),
        },
    ]
});

pub struct PatternDetector {
    patterns: Vec<VulnerabilityPattern>,
}

impl PatternDetector {
    pub fn new(_config: crate::analyzer::AnalysisConfig) -> Self {
        Self {
            patterns: VULNERABILITY_PATTERNS.clone(),
        }
    }
    
    pub fn detect(&self, ast: &RustAst, _graph: &AnalysisGraph) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        info!("Running pattern-based detection on: {}", ast.file_path);
        
        // Check each unsafe block against vulnerability patterns
        for unsafe_block in &ast.unsafe_blocks {
            let content = &unsafe_block.content;
            
            for pattern in &self.patterns {
                if pattern.pattern.is_match(content) {
                    let vulnerability = create_vulnerability(
                        pattern.name.clone(),
                        pattern.severity.clone(),
                        pattern.confidence,
                        ast.file_path.clone(),
                        unsafe_block.line_start,
                        pattern.description.clone(),
                        pattern.explanation.clone(),
                        pattern.remediation.clone(),
                        unsafe_block.content.clone(),
                        DetectionMethod::PatternMatching,
                    );
                    
                    vulnerabilities.push(vulnerability);
                }
            }
        }
        
        // Check function bodies for patterns
        for func in &ast.functions {
            let func_code = func.to_token_stream().to_string();
            
            for pattern in &self.patterns {
                if pattern.pattern.is_match(&func_code) {
                    let vulnerability = create_vulnerability(
                        pattern.name.clone(),
                        pattern.severity.clone(),
                        pattern.confidence * 0.8, // Slightly lower confidence for function-level patterns
                        ast.file_path.clone(),
                        0, // Line number will be estimated from context
                        pattern.description.clone(),
                        pattern.explanation.clone(),
                        pattern.remediation.clone(),
                        func_code.clone(),
                        DetectionMethod::PatternMatching,
                    );
                    
                    vulnerabilities.push(vulnerability);
                }
            }
        }
        
        debug!("Pattern-based detection found {} vulnerabilities", vulnerabilities.len());
        
        Ok(vulnerabilities)
    }
}

#[derive(Debug, Clone)]
struct VulnerabilityPattern {
    name: String,
    pattern: Regex,
    severity: VulnerabilitySeverity,
    confidence: f64,
    description: String,
    explanation: String,
    remediation: String,
}