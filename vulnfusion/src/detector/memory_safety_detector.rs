// 中文说明：
// MemorySafetyDetector 实现 UAF、双重释放、泄漏、缓冲区越界、空指针解引用、
// move 后使用、非法转换等模式的基础检测，结合 unsafe 块与函数代码进行启发式识别。
use crate::utils::error::Result;
use tracing::{debug, info};
use std::collections::HashSet;
use quote::ToTokens;
use regex::Regex;

use crate::analyzer::{Vulnerability, VulnerabilitySeverity, DetectionMethod};
use crate::parser::RustAst;
use crate::graph::AnalysisGraph;
use crate::detector::create_vulnerability;

pub struct MemorySafetyDetector {
    enabled_checks: HashSet<String>,
}

impl MemorySafetyDetector {
    pub fn new(config: crate::analyzer::AnalysisConfig) -> Self {
        let mut enabled_checks = HashSet::new();
        
        // Enable all memory safety checks by default
        enabled_checks.insert("use-after-free".to_string());
        enabled_checks.insert("double-free".to_string());
        enabled_checks.insert("memory-leak".to_string());
        enabled_checks.insert("buffer-overflow".to_string());
        enabled_checks.insert("null-pointer-deref".to_string());
        enabled_checks.insert("use-after-move".to_string());
        enabled_checks.insert("invalid-cast".to_string());
        
        Self { enabled_checks }
    }
    
    pub fn detect(&self, ast: &RustAst, _graph: &AnalysisGraph) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        info!("Running memory safety detection on: {}", ast.file_path);
        
        // Check for use-after-free patterns
        if self.enabled_checks.contains("use-after-free") {
            vulnerabilities.extend(self.detect_use_after_free(ast)?);
        }
        
        // Check for double-free patterns
        if self.enabled_checks.contains("double-free") {
            vulnerabilities.extend(self.detect_double_free(ast)?);
        }
        
        // Check for memory leak patterns
        if self.enabled_checks.contains("memory-leak") {
            vulnerabilities.extend(self.detect_memory_leaks(ast)?);
        }
        
        // Check for buffer overflow patterns
        if self.enabled_checks.contains("buffer-overflow") {
            vulnerabilities.extend(self.detect_buffer_overflows(ast)?);
        }

        // Uninitialized memory usage
        vulnerabilities.extend(self.detect_uninitialized_memory(ast)?);

        // Integer overflow impacting memory sizing
        vulnerabilities.extend(self.detect_integer_overflow(ast)?);
        
        // Check for null pointer dereference patterns
        if self.enabled_checks.contains("null-pointer-deref") {
            vulnerabilities.extend(self.detect_null_pointer_deref(ast)?);
        }
        
        // Check for use-after-move patterns
        if self.enabled_checks.contains("use-after-move") {
            vulnerabilities.extend(self.detect_use_after_move(ast)?);
        }
        
        // Check for invalid cast patterns
        if self.enabled_checks.contains("invalid-cast") {
            vulnerabilities.extend(self.detect_invalid_casts(ast)?);
        }
        
        debug!("Memory safety detection found {} vulnerabilities", vulnerabilities.len());
        
        Ok(vulnerabilities)
    }
    
    fn detect_use_after_free(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Look for patterns that might indicate use-after-free
        for unsafe_block in &ast.unsafe_blocks {
            let content_raw = &unsafe_block.content;
            let content = Self::strip_line_comments(content_raw);
            
            // Check for raw pointer usage patterns
            if content.contains("*const") || content.contains("*mut") {
                if self.has_potential_uaf_pattern(&content) {
                    vulnerabilities.push(create_vulnerability(
                        "use-after-free".to_string(),
                        VulnerabilitySeverity::High,
                        0.7,
                        ast.file_path.clone(),
                        unsafe_block.line_start,
                        "Potential use-after-free vulnerability detected".to_string(),
                        "Unsafe block contains raw pointer operations that may lead to use-after-free".to_string(),
                        "Ensure proper lifetime management and avoid dangling pointers".to_string(),
                        unsafe_block.content.clone(),
                        DetectionMethod::StaticAnalysis,
                    ));
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn detect_double_free(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Look for patterns that might indicate double-free
        for unsafe_block in &ast.unsafe_blocks {
            let content_raw = &unsafe_block.content;
            let content = Self::strip_line_comments(content_raw);
            
            // Check for manual memory deallocation patterns
            if content.contains("free") || content.contains("dealloc") {
                if self.has_potential_double_free_pattern(content.as_str()) {
                    vulnerabilities.push(create_vulnerability(
                        "double-free".to_string(),
                        VulnerabilitySeverity::Critical,
                        0.8,
                        ast.file_path.clone(),
                        unsafe_block.line_start,
                        "Potential double-free vulnerability detected".to_string(),
                        "Unsafe block contains memory deallocation that may lead to double-free".to_string(),
                        "Use RAII patterns and avoid manual memory management".to_string(),
                        unsafe_block.content.clone(),
                        DetectionMethod::StaticAnalysis,
                    ));
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn detect_memory_leaks(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Look for patterns that might indicate memory leaks
        for func in &ast.functions {
            let func_code = func.to_token_stream().to_string();
            
            // Check for Box::leak or similar patterns
            if func_code.contains("Box::leak") || func_code.contains("mem::forget") {
                vulnerabilities.push(create_vulnerability(
                    "memory-leak".to_string(),
                    VulnerabilitySeverity::Medium,
                    0.9,
                    ast.file_path.clone(),
                    0, // Line number will be estimated from context
                    "Potential memory leak detected".to_string(),
                    "Function uses Box::leak or mem::forget which may cause memory leaks".to_string(),
                    "Consider using proper ownership patterns or weak references".to_string(),
                    func_code,
                    DetectionMethod::PatternMatching,
                ));
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn detect_buffer_overflows(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Look for unsafe array/slice access patterns
        for unsafe_block in &ast.unsafe_blocks {
            let content_raw = &unsafe_block.content;
            let content = Self::strip_line_comments(content_raw);

            if content.contains("get_unchecked") || content.contains("offset") {
                let arr_len_semicolon = Regex::new(r"let\s+\w+\s*=\s*\[[^\]]*;\s*(\d+)\s*\]").ok();
                let arr_literal = Regex::new(r"let\s+\w+\s*=\s*\[([^\]]+)\]\s*;").ok();
                let re_index = Regex::new(r"get_unchecked\s*\(\s*(\d+)\s*\)").ok();
                let mut safe_constant_index = false;
                let mut literal_len = None;
                if let Some(re) = arr_len_semicolon.as_ref() {
                    if let Some(ca) = re.captures(&content) { literal_len = ca.get(1).and_then(|m| m.as_str().parse().ok()); }
                }
                if literal_len.is_none() {
                    if let Some(re) = arr_literal.as_ref() {
                        if let Some(cap) = re.captures(&content) {
                            let items = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                            let cnt = items.split(',').filter(|s| !s.trim().is_empty()).count();
                            if cnt > 0 { literal_len = Some(cnt); }
                        }
                    }
                }
                if let (Some(rei), Some(n)) = (re_index.as_ref(), literal_len) {
                    if let Some(ci) = rei.captures(&content) {
                        let k: usize = ci.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(usize::MAX);
                        if k < n { safe_constant_index = true; }
                    }
                }
                if !safe_constant_index {
                    vulnerabilities.push(create_vulnerability(
                        "buffer-overflow".to_string(),
                        VulnerabilitySeverity::High,
                        0.8,
                        ast.file_path.clone(),
                        unsafe_block.line_start,
                        "Potential buffer overflow detected".to_string(),
                        "Unsafe block contains unchecked array access that may overflow".to_string(),
                        "Use bounds-checked alternatives or ensure proper bounds validation".to_string(),
                        content_raw.clone(),
                        DetectionMethod::StaticAnalysis,
                    ));
                }
            }

            let re_arr = Regex::new(r"\[\s*0u8\s*;\s*(\d+)\s*\]").ok();
            let re_loop = Regex::new(r"for\s+\w+\s+in\s+0\.\.(\d+)").ok();
            let re_addc = Regex::new(r"add\s*\(\s*(\d+)\s*\)").ok();
                if let (Some(re_a), Some(re_l)) = (re_arr.as_ref(), re_loop.as_ref()) {
                if let (Some(ca), Some(cl)) = (re_a.captures(&content), re_l.captures(&content)) {
                    let n: usize = ca.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
                    let m: usize = cl.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
                    if m > n && content.contains("ptr.add") {
                        vulnerabilities.push(create_vulnerability(
                            "buffer-overflow".to_string(),
                            VulnerabilitySeverity::High,
                            0.9,
                            ast.file_path.clone(),
                            unsafe_block.line_start,
                            "Loop writes beyond buffer length".to_string(),
                            "Pointer arithmetic in loop exceeds allocated buffer length".to_string(),
                            "Ensure loop upper bound does not exceed buffer length".to_string(),
                            content_raw.clone(),
                            DetectionMethod::StaticAnalysis,
                        ));
                    }
                }
            }
            if let (Some(re_a), Some(re_c)) = (re_arr.as_ref(), re_addc.as_ref()) {
                if let (Some(ca), Some(cc)) = (re_a.captures(&content), re_c.captures(&content)) {
                    let n: usize = ca.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
                    let k: usize = cc.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
                    if k >= n && content.contains("ptr.add") {
                        vulnerabilities.push(create_vulnerability(
                            "buffer-overflow".to_string(),
                            VulnerabilitySeverity::High,
                            0.85,
                            ast.file_path.clone(),
                            unsafe_block.line_start,
                            "Pointer add exceeds buffer length".to_string(),
                            "Constant offset exceeds allocated buffer length".to_string(),
                            "Validate pointer offsets against buffer length".to_string(),
                            content_raw.clone(),
                            DetectionMethod::StaticAnalysis,
                        ));
                    }
                }
            }
        }
        
        Ok(vulnerabilities)
    }

    fn detect_uninitialized_memory(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        for unsafe_block in &ast.unsafe_blocks {
            let content = &unsafe_block.content;
            if content.contains("MaybeUninit::<") && content.contains("assume_init") {
                vulnerabilities.push(create_vulnerability(
                    "uninitialized-read".to_string(),
                    VulnerabilitySeverity::High,
                    0.9,
                    ast.file_path.clone(),
                    unsafe_block.line_start,
                    "Uninitialized memory read detected".to_string(),
                    "assume_init used on uninitialized value within unsafe block".to_string(),
                    "Initialize memory before reading or avoid assume_init on uninit".to_string(),
                    unsafe_block.content.clone(),
                    DetectionMethod::StaticAnalysis,
                ));
            }
        }
        Ok(vulnerabilities)
    }

    fn detect_integer_overflow(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        for unsafe_block in &ast.unsafe_blocks {
            let s = unsafe_block.content.to_lowercase();
            if s.contains("u32::max") && s.contains("*") {
                vulnerabilities.push(create_vulnerability(
                    "integer-overflow".to_string(),
                    VulnerabilitySeverity::Medium,
                    0.7,
                    ast.file_path.clone(),
                    unsafe_block.line_start,
                    "Potential integer overflow impacting sizing".to_string(),
                    "Multiplication with u32::MAX may overflow and affect buffer sizing".to_string(),
                    "Use checked arithmetic or constrain values before multiplication".to_string(),
                    unsafe_block.content.clone(),
                    DetectionMethod::StaticAnalysis,
                ));
            }
        }
        Ok(vulnerabilities)
    }
    
    fn detect_null_pointer_deref(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Look for null pointer patterns
        for unsafe_block in &ast.unsafe_blocks {
            let content = &unsafe_block.content;
            
            // Check for null pointer dereference patterns
            if content.contains("ptr::null") || content.contains("ptr::null_mut") {
                if self.has_potential_null_deref_pattern(content) {
                    vulnerabilities.push(create_vulnerability(
                        "null-pointer-deref".to_string(),
                        VulnerabilitySeverity::High,
                        0.8,
                        ast.file_path.clone(),
                        unsafe_block.line_start,
                        "Potential null pointer dereference detected".to_string(),
                        "Unsafe block may dereference null pointer".to_string(),
                        "Add null checks before dereferencing pointers".to_string(),
                        unsafe_block.content.clone(),
                        DetectionMethod::StaticAnalysis,
                    ));
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn detect_use_after_move(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Look for patterns that might indicate use-after-move
        for func in &ast.functions {
            let func_code = func.to_token_stream().to_string();
            
            // Check for mem::uninitialized or similar patterns
            if func_code.contains("mem::uninitialized") {
                vulnerabilities.push(create_vulnerability(
                    "use-after-move".to_string(),
                    VulnerabilitySeverity::High,
                    0.7,
                    ast.file_path.clone(),
                    0, // Line number will be estimated from context
                    "Potential use-after-move detected".to_string(),
                    "Function uses mem::uninitialized which may cause use-after-move".to_string(),
                    "Use MaybeUninit or proper initialization patterns".to_string(),
                    func_code,
                    DetectionMethod::PatternMatching,
                ));
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn detect_invalid_casts(&self, ast: &RustAst) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Look for invalid cast patterns
        for unsafe_block in &ast.unsafe_blocks {
            let content = &unsafe_block.content;
            
            // Check for transmute usage
            if content.contains("mem::transmute") {
                vulnerabilities.push(create_vulnerability(
                    "invalid-cast".to_string(),
                    VulnerabilitySeverity::Medium,
                    0.6,
                    ast.file_path.clone(),
                    unsafe_block.line_start,
                    "Potential invalid cast detected".to_string(),
                    "Unsafe block uses mem::transmute which may cause invalid casts".to_string(),
                    "Use safe conversion methods when possible".to_string(),
                    unsafe_block.content.clone(),
                    DetectionMethod::StaticAnalysis,
                ));
            }
        }
        
        Ok(vulnerabilities)
    }
    
    // Helper methods for pattern detection
    fn has_potential_uaf_pattern(&self, content: &str) -> bool {
        // Simple heuristic: look for pointer dereference after some operation
        content.contains("*") && (
            content.contains("free") || 
            content.contains("dealloc") || 
            content.contains("drop")
        )
    }
    
    fn has_potential_double_free_pattern(&self, content: &str) -> bool {
        // Look for multiple free/dealloc calls on the same variable
        let free_count = content.matches("free").count() + content.matches("dealloc").count();
        free_count > 1
    }
    
    fn has_potential_null_deref_pattern(&self, content: &str) -> bool {
        let s = Self::strip_line_comments(content).to_lowercase();
        let has_null = s.contains("ptr::null") || s.contains("ptr::null_mut");
        let has_deref = s.contains("*");
        let has_check = s.contains("is_null") || s.contains("if");
        has_null && has_deref && !has_check
    }

    fn strip_line_comments(s: &str) -> String {
        s.lines().filter_map(|l| {
            if let Some(idx) = l.find("//") { Some(&l[..idx]) } else { Some(l) }
        }).collect::<Vec<&str>>().join("\n")
    }
}