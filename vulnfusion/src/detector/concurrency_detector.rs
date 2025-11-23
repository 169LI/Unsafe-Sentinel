// 中文说明：
// ConcurrencyDetector 针对数据竞争、死锁、竞态、同步不当与原子性违背等并发问题，
// 通过启发式模式与简单图查询进行初步识别，辅助定位高风险区域。
use crate::utils::error::Result;
use tracing::{debug, info};
use std::collections::HashSet;
use quote::ToTokens;

use crate::analyzer::{Vulnerability, VulnerabilitySeverity, DetectionMethod};
use crate::parser::RustAst;
use crate::graph::AnalysisGraph;
use crate::detector::create_vulnerability;

pub struct ConcurrencyDetector {
    enabled_checks: HashSet<String>,
}

impl ConcurrencyDetector {
    pub fn new(_config: crate::analyzer::AnalysisConfig) -> Self {
        let mut enabled_checks = HashSet::new();
        
        // Enable all concurrency checks by default
        enabled_checks.insert("data-race".to_string());
        enabled_checks.insert("deadlock".to_string());
        enabled_checks.insert("race-condition".to_string());
        enabled_checks.insert("improper-sync".to_string());
        enabled_checks.insert("atomicity-violation".to_string());
        
        Self { enabled_checks }
    }
    
    pub fn detect(&self, ast: &RustAst, _graph: &AnalysisGraph) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        info!("Running concurrency detection on: {}", ast.file_path);
        
        // Check for data race patterns
        if self.enabled_checks.contains("data-race") {
            vulnerabilities.extend(self.detect_data_races(ast)?);
        }
        
        // Check for deadlock patterns
        if self.enabled_checks.contains("deadlock") {
            vulnerabilities.extend(self.detect_deadlocks(ast)?);
        }
        
        // Check for race condition patterns
        if self.enabled_checks.contains("race-condition") {
            vulnerabilities.extend(self.detect_race_conditions(ast)?);
        }
        
        // Check for improper synchronization
        if self.enabled_checks.contains("improper-sync") {
            vulnerabilities.extend(self.detect_improper_sync(ast)?);
        }
        
        // Check for atomicity violations
        if self.enabled_checks.contains("atomicity-violation") {
            vulnerabilities.extend(self.detect_atomicity_violations(ast)?);
        }
        
        debug!("Concurrency detection found {} vulnerabilities", vulnerabilities.len());
        
        Ok(vulnerabilities)
    }
    
    fn detect_data_races(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Look for patterns that might indicate data races
        for func in &ast.functions {
            let func_code = func.to_token_stream().to_string();
            
            // Check for unsafe concurrent access patterns
            if func_code.contains("unsafe") && self.has_concurrent_access_pattern(&func_code) {
                if self.has_shared_mutable_state(&func_code) {
                    vulnerabilities.push(create_vulnerability(
                        "data-race".to_string(),
                        VulnerabilitySeverity::High,
                        0.7,
                        ast.file_path.clone(),
                        0, // Line number will be estimated from context
                        "Potential data race detected".to_string(),
                        "Function contains unsafe concurrent access to shared mutable state".to_string(),
                        "Use proper synchronization primitives like Mutex or RwLock".to_string(),
                        func_code,
                        DetectionMethod::StaticAnalysis,
                    ));
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn detect_deadlocks(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Look for patterns that might indicate deadlocks
        for func in &ast.functions {
            let func_code = func.to_token_stream().to_string();
            
            // Check for nested lock patterns
            if self.has_nested_lock_pattern(&func_code) {
                vulnerabilities.push(create_vulnerability(
                    "deadlock".to_string(),
                    VulnerabilitySeverity::Medium,
                    0.6,
                    ast.file_path.clone(),
                    0, // Line number will be estimated from context
                    "Potential deadlock detected".to_string(),
                    "Function contains nested lock acquisition which may cause deadlock".to_string(),
                    "Use lock ordering or try_lock to avoid deadlocks".to_string(),
                    func_code,
                    DetectionMethod::StaticAnalysis,
                ));
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn detect_race_conditions(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Look for patterns that might indicate race conditions
        for func in &ast.functions {
            let func_code = func.to_token_stream().to_string();
            
            // Check for check-then-act patterns without proper synchronization
            if self.has_check_then_act_pattern(&func_code) && !self.has_proper_sync(&func_code) {
                vulnerabilities.push(create_vulnerability(
                    "race-condition".to_string(),
                    VulnerabilitySeverity::Medium,
                    0.6,
                    ast.file_path.clone(),
                    0, // Line number will be estimated from context
                    "Potential race condition detected".to_string(),
                    "Function contains check-then-act pattern without proper synchronization".to_string(),
                    "Use atomic operations or proper locking mechanisms".to_string(),
                    func_code,
                    DetectionMethod::StaticAnalysis,
                ));
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn detect_improper_sync(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Look for patterns that indicate improper synchronization
        for impl_block in &ast.implementations {
            let impl_code = impl_block.to_token_stream().to_string();
            
            // 检查未满足安全边界的 Send/Sync 实现：
            // 仅作为启发式风险点；在竞赛 verified-only 模式中，只有同时存在原始指针/内部可变性等更强证据时才会保留
            if impl_code.contains("unsafe impl") && 
               (impl_code.contains("Send") || impl_code.contains("Sync")) {
                let has_bounds = self.has_proper_send_sync_bounds(&impl_code);
                let has_safety_doc = Self::file_has_safety_doc(&ast.file_path);
                if !has_bounds {
                    let mut severity = VulnerabilitySeverity::High;
                    let mut confidence = 0.8;
                    if has_safety_doc {
                        severity = VulnerabilitySeverity::Medium;
                        confidence = 0.45;
                    }
                    vulnerabilities.push(create_vulnerability(
                        "improper-sync".to_string(),
                        severity,
                        confidence,
                        ast.file_path.clone(),
                        0,
                        "Potential improper Send/Sync implementation".to_string(),
                        "Unsafe Send/Sync implementation may not have proper bounds".to_string(),
                        "Ensure proper trait bounds for Send/Sync implementations".to_string(),
                        impl_code,
                        DetectionMethod::StaticAnalysis,
                    ));
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn detect_atomicity_violations(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Look for patterns that might indicate atomicity violations
        for func in &ast.functions {
            let func_code = func.to_token_stream().to_string();
            
            // Check for non-atomic compound operations
            if self.has_compound_operation(&func_code) && !self.has_atomic_operation(&func_code) {
                if self.has_concurrent_access_pattern(&func_code) {
                    vulnerabilities.push(create_vulnerability(
                        "atomicity-violation".to_string(),
                        VulnerabilitySeverity::Medium,
                        0.6,
                        ast.file_path.clone(),
                        0, // Line number will be estimated from context
                        "Potential atomicity violation detected".to_string(),
                        "Function contains compound operations that are not atomic".to_string(),
                        "Use atomic operations or proper synchronization".to_string(),
                        func_code,
                        DetectionMethod::StaticAnalysis,
                    ));
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    // Helper methods for pattern detection
    fn has_concurrent_access_pattern(&self, code: &str) -> bool {
        code.contains("thread") || code.contains("spawn") || code.contains("Arc") || 
        code.contains("Mutex") || code.contains("RwLock") || code.contains("Atomic")
    }
    
    fn has_shared_mutable_state(&self, code: &str) -> bool {
        code.contains("static mut") || 
        (code.contains("unsafe") && code.contains("static"))
    }
    
    fn has_nested_lock_pattern(&self, code: &str) -> bool {
        // Simple heuristic: look for nested lock() calls
        let lock_count = code.matches(".lock()").count() + code.matches(".read()").count() + code.matches(".write()").count();
        lock_count > 1 && self.has_nested_structure(code)
    }
    
    fn has_nested_structure(&self, code: &str) -> bool {
        // Check for nested blocks that might contain locks
        let brace_depth = code.chars().fold(0, |acc, c| match c {
            '{' => acc + 1,
            '}' => acc - 1,
            _ => acc,
        });
        brace_depth > 0 || code.matches('{').count() > 1
    }
    
    fn has_check_then_act_pattern(&self, code: &str) -> bool {
        code.contains("if") && (code.contains("=") || code.contains("insert") || code.contains("remove"))
    }
    
    fn has_proper_sync(&self, code: &str) -> bool {
        code.contains("Mutex") || code.contains("RwLock") || code.contains("Atomic") || code.contains("lock")
    }
    
    fn has_proper_send_sync_bounds(&self, code: &str) -> bool {
        let has_where = code.contains("where") && (code.contains("Send") || code.contains("Sync"));
        let has_generic_bounds = code.contains("<") && (code.contains(": Send") || code.contains(": Sync"));
        has_where || has_generic_bounds
    }

    fn file_has_safety_doc(path: &str) -> bool {
        if let Ok(content) = std::fs::read_to_string(path) {
            let s = content.to_lowercase();
            return s.contains("safety:");
        }
        false
    }
    
    fn has_compound_operation(&self, code: &str) -> bool {
        // Look for compound operations like +=, -=, etc.
        code.contains("+=") || code.contains("-=") || code.contains("*=") || 
        code.contains("/=") || code.contains("%=") || code.contains("&=") || 
        code.contains("|=") || code.contains("^=")
    }
    
    fn has_atomic_operation(&self, code: &str) -> bool {
        code.contains("Atomic") || code.contains("fetch_") || code.contains("compare_and_swap")
    }
}