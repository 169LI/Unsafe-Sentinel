// 中文说明：
// PanicSafetyDetector 针对 panic/unwind/drop/double-panic 等问题进行模式检测，
// 结合 unsafe 状态修改与复杂控制流启发式，辅助找出潜在崩溃路径与不安全行为。
use crate::utils::error::Result;
use tracing::{debug, info};
use std::collections::HashSet;
use quote::ToTokens;

use crate::analyzer::{Vulnerability, VulnerabilitySeverity, DetectionMethod};
use crate::parser::RustAst;
use crate::graph::AnalysisGraph;
use crate::detector::create_vulnerability;

pub struct PanicSafetyDetector {
    enabled_checks: Vec<String>,
}

impl PanicSafetyDetector {
    pub fn new(_config: crate::analyzer::AnalysisConfig) -> Self {
        Self {
            enabled_checks: vec![
                "panic-safety".to_string(),
                "unwind-safety".to_string(),
                "drop-panic".to_string(),
                "double-panic".to_string(),
            ]
        }
    }
    
    pub fn detect(&self, ast: &RustAst, _graph: &AnalysisGraph) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        info!("Running panic safety detection on: {}", ast.file_path);
        
        // Check for panic safety violations
        if self.enabled_checks.contains(&"panic-safety".to_string()) {
            vulnerabilities.extend(self.detect_panic_safety_violations(ast)?);
        }
        
        // Check for unwind safety issues
        if self.enabled_checks.contains(&"unwind-safety".to_string()) {
            vulnerabilities.extend(self.detect_unwind_safety_issues(ast)?);
        }
        
        // Check for drop panic issues
        if self.enabled_checks.contains(&"drop-panic".to_string()) {
            vulnerabilities.extend(self.detect_drop_panic_issues(ast)?);
        }
        
        // Check for double panic issues
        if self.enabled_checks.contains(&"double-panic".to_string()) {
            vulnerabilities.extend(self.detect_double_panic_issues(ast)?);
        }
        
        debug!("Panic safety detection found {} vulnerabilities", vulnerabilities.len());
        
        Ok(vulnerabilities)
    }
    
    fn detect_panic_safety_violations(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Look for patterns that might cause panic safety violations
        for unsafe_block in &ast.unsafe_blocks {
            let content = &unsafe_block.content;
            
            // Check for unsafe operations that might panic
            if self.has_panic_prone_operations(content) && self.has_unsafe_state_modification(content) {
                vulnerabilities.push(create_vulnerability(
                    "panic-safety".to_string(),
                    VulnerabilitySeverity::High,
                    0.8,
                    ast.file_path.clone(),
                    unsafe_block.line_start,
                    "Potential panic safety violation detected".to_string(),
                    "Unsafe block modifies state and may panic, leading to inconsistent state".to_string(),
                    "Ensure panic safety by using proper cleanup mechanisms".to_string(),
                    unsafe_block.content.clone(),
                    DetectionMethod::StaticAnalysis,
                ));
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn detect_unwind_safety_issues(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Look for patterns that might not be unwind-safe
        for func in &ast.functions {
            let func_code = func.to_token_stream().to_string();
            
            // Check for functions that might not be unwind-safe
            if func.sig.unsafety.is_some() && self.has_unsafe_state_operations(&func_code) {
                vulnerabilities.push(create_vulnerability(
                    "unwind-safety".to_string(),
                    VulnerabilitySeverity::Medium,
                    0.6,
                    ast.file_path.clone(),
                    0, // Line number will be estimated from context
                    "Potential unwind safety issue detected".to_string(),
                    "Unsafe function may not be unwind-safe".to_string(),
                    "Ensure proper cleanup in case of unwinding".to_string(),
                    func_code,
                    DetectionMethod::StaticAnalysis,
                ));
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn detect_drop_panic_issues(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Look for Drop implementations that might panic
        for impl_block in &ast.implementations {
            let impl_code = impl_block.to_token_stream().to_string();
            
            // Check for Drop implementations
            if impl_code.contains("Drop") && impl_code.contains("drop") {
                if self.has_panic_in_drop(&impl_code) {
                    let has_unsafe = impl_code.contains("unsafe") || self.has_unsafe_state_operations(&impl_code);
                    let severity = if has_unsafe { VulnerabilitySeverity::Critical } else { VulnerabilitySeverity::High };
                    let confidence = if has_unsafe { 0.9 } else { 0.6 };
                    vulnerabilities.push(create_vulnerability(
                        "drop-panic".to_string(),
                        severity,
                        confidence,
                        ast.file_path.clone(),
                        0,
                        "Potential panic in Drop implementation detected".to_string(),
                        "Drop implementation may panic, which can cause undefined behavior".to_string(),
                        "Ensure Drop implementations never panic".to_string(),
                        impl_code,
                        DetectionMethod::StaticAnalysis,
                    ));
                }
            }
        }

        if vulnerabilities.is_empty() {
            if let Ok(content) = std::fs::read_to_string(&ast.file_path) {
                let has_impl_drop = content.contains("impl Drop for") && content.contains("fn drop");
                let has_panic = content.contains("panic!(");
                if has_impl_drop && has_panic {
                    let has_unsafe = content.contains("unsafe");
                    let severity = if has_unsafe { VulnerabilitySeverity::Critical } else { VulnerabilitySeverity::High };
                    let confidence = if has_unsafe { 0.9 } else { 0.6 };
                    vulnerabilities.push(create_vulnerability(
                        "drop-panic".to_string(),
                        severity,
                        confidence,
                        ast.file_path.clone(),
                        0,
                        "Potential panic in Drop implementation detected".to_string(),
                        "Drop implementation may panic, which can cause undefined behavior".to_string(),
                        "Ensure Drop implementations never panic".to_string(),
                        content,
                        DetectionMethod::StaticAnalysis,
                    ));
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn detect_double_panic_issues(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Look for patterns that might cause double panic
        for func in &ast.functions {
            let func_code = func.to_token_stream().to_string();
            
            // Check for explicit panic calls in unsafe contexts
            if func.sig.unsafety.is_some() && self.has_explicit_panic(&func_code) {
                if self.has_complex_control_flow(&func_code) {
                    vulnerabilities.push(create_vulnerability(
                        "double-panic".to_string(),
                        VulnerabilitySeverity::Medium,
                        0.5,
                        ast.file_path.clone(),
                        0, // Line number will be estimated from context
                        "Potential double panic issue detected".to_string(),
                        "Unsafe function with explicit panic may cause double panic in complex control flow".to_string(),
                        "Avoid explicit panics in unsafe code or ensure proper cleanup".to_string(),
                        func_code,
                        DetectionMethod::StaticAnalysis,
                    ));
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    // Helper methods for pattern detection
    fn has_panic_prone_operations(&self, code: &str) -> bool {
        code.contains("panic!") || 
        code.contains("unwrap") || 
        code.contains("expect") ||
        code.contains("unreachable!") ||
        code.contains("todo!")
    }
    
    fn has_unsafe_state_modification(&self, code: &str) -> bool {
        code.contains("*mut") || 
        code.contains("*const") || 
        code.contains("mem::") ||
        code.contains("ptr::") ||
        (code.contains("=") && code.contains("unsafe"))
    }
    
    fn has_unsafe_state_operations(&self, code: &str) -> bool {
        code.contains("*mut") || 
        code.contains("*const") || 
        code.contains("mem::") ||
        code.contains("ptr::") ||
        code.contains("transmute")
    }
    
    fn has_panic_in_drop(&self, code: &str) -> bool {
        code.contains("panic!") || 
        code.contains("unwrap") || 
        code.contains("expect") ||
        code.contains("assert!") ||
        self.has_panic_prone_operations(code)
    }
    
    fn has_explicit_panic(&self, code: &str) -> bool {
        code.contains("panic!") || code.contains("unreachable!") || code.contains("todo!")
    }
    
    fn has_complex_control_flow(&self, code: &str) -> bool {
        // Check for complex control flow patterns
        let complexity_indicators = [
            "if", "else", "match", "for", "while", "loop", 
            "break", "continue", "return", "?"
        ];
        
        complexity_indicators.iter().map(|&indicator| code.matches(indicator).count()).sum::<usize>() > 3
    }
}