// 中文说明：
// 常用工具函数集合：时间/大小格式化、字符串/文件名处理、复杂度度量、unsafe 块定位、
// 并行处理辅助与系统信息采集等，为各模块复用提供基础能力。
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use regex::Regex;
use rayon::prelude::*;

use crate::utils::constants::*;
use crate::utils::error::Result;

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m {}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    }
}

pub fn format_file_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

pub fn sanitize_filename(filename: &str) -> String {
    filename
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => c,
            _ => '_',
        })
        .collect()
}

pub fn truncate_string(s: &str, max_length: usize) -> String {
    if s.len() <= max_length {
        s.to_string()
    } else {
        format!("{}...", &s[..max_length.saturating_sub(3)])
    }
}

pub fn count_leading_spaces(line: &str) -> usize {
    line.chars().take_while(|c| c.is_whitespace()).count()
}

pub fn is_rust_keyword(word: &str) -> bool {
    matches!(
        word,
        "as" | "break" | "const" | "continue" | "crate" | "else" | "enum" | "extern" |
        "false" | "fn" | "for" | "if" | "impl" | "in" | "let" | "loop" | "match" |
        "mod" | "move" | "mut" | "pub" | "ref" | "return" | "self" | "Self" |
        "static" | "struct" | "super" | "trait" | "true" | "type" | "unsafe" |
        "use" | "where" | "while" | "async" | "await" | "dyn" | "abstract" | "become" |
        "box" | "do" | "final" | "macro" | "override" | "priv" | "typeof" | "unsized" |
        "virtual" | "yield" | "try"
    )
}

pub fn extract_function_name(line: &str) -> Option<String> {
    let fn_regex = Regex::new(r"fn\s+([a-zA-Z_][a-zA-Z0-9_]*)").ok()?;
    fn_regex.captures(line)?
        .get(1)
        .map(|m| m.as_str().to_string())
}

pub fn extract_struct_name(line: &str) -> Option<String> {
    let struct_regex = Regex::new(r"struct\s+([a-zA-Z_][a-zA-Z0-9_]*)").ok()?;
    struct_regex.captures(line)?
        .get(1)
        .map(|m| m.as_str().to_string())
}

pub fn extract_trait_name(line: &str) -> Option<String> {
    let trait_regex = Regex::new(r"trait\s+([a-zA-Z_][a-zA-Z0-9_]*)").ok()?;
    trait_regex.captures(line)?
        .get(1)
        .map(|m| m.as_str().to_string())
}

pub fn calculate_cyclomatic_complexity(code: &str) -> usize {
    let complexity_keywords = vec![
        "if", "else if", "match", "while", "for", "loop", "&&", "||", "?"
    ];
    
    let mut complexity = 1; // Base complexity
    
    for keyword in complexity_keywords {
        complexity += code.matches(keyword).count();
    }
    
    complexity
}

pub fn calculate_halstead_metrics(code: &str) -> (usize, usize, usize, f64) {
    let operators = Regex::new(r"[\+\-\*/%=<>!&|^~?:;,.()\[\]{}]+").unwrap();
    let operands = Regex::new(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b").unwrap();
    
    let operator_matches: Vec<_> = operators.find_iter(code).map(|m| m.as_str()).collect();
    let operand_matches: Vec<_> = operands.find_iter(code).map(|m| m.as_str()).collect();
    
    let unique_operators = operator_matches.iter().collect::<std::collections::HashSet<_>>().len();
    let unique_operands = operand_matches.iter().collect::<std::collections::HashSet<_>>().len();
    let total_operators = operator_matches.len();
    let total_operands = operand_matches.len();
    
    let vocabulary = unique_operators + unique_operands;
    let length = total_operators + total_operands;
    
    let volume = if vocabulary > 0 {
        length as f64 * (vocabulary as f64).log2()
    } else {
        0.0
    };
    
    (unique_operators, unique_operands, length, volume)
}

pub fn find_unsafe_blocks(code: &str) -> Vec<(usize, usize)> {
    let mut unsafe_blocks = Vec::new();
    let mut start_pos = 0;
    
    while let Some(pos) = code[start_pos..].find("unsafe") {
        let absolute_pos = start_pos + pos;
        if let Some(block_start) = code[absolute_pos..].find('{') {
            let block_start = absolute_pos + block_start;
            if let Some(block_end) = find_matching_brace(&code[block_start..]) {
                unsafe_blocks.push((block_start, block_start + block_end));
            }
        }
        start_pos = absolute_pos + 6;
    }
    
    unsafe_blocks
}

pub fn find_matching_brace(code: &str) -> Option<usize> {
    let mut brace_count = 0;
    let mut in_string = false;
    let mut in_char = false;
    let mut escaped = false;
    
    for (i, ch) in code.char_indices() {
        match ch {
            '\\' if !escaped => escaped = true,
            '"' if !in_char && !escaped => in_string = !in_string,
            '\'' if !in_string && !escaped => in_char = !in_char,
            '{' if !in_string && !in_char && !escaped => {
                brace_count += 1;
            }
            '}' if !in_string && !in_char && !escaped => {
                brace_count -= 1;
                if brace_count == 0 {
                    return Some(i);
                }
            }
            _ => escaped = false,
        }
    }
    
    None
}

pub fn extract_comments(code: &str) -> Vec<String> {
    let line_comments = Regex::new(r"//[^\n]*").unwrap();
    let block_comments = Regex::new(r"/\*.*?\*/").unwrap();
    
    let mut comments = Vec::new();
    
    for cap in line_comments.find_iter(code) {
        comments.push(cap.as_str().to_string());
    }
    
    for cap in block_comments.find_iter(code) {
        comments.push(cap.as_str().to_string());
    }
    
    comments
}

pub fn normalize_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn calculate_similarity(a: &str, b: &str) -> f64 {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    
    let max_len = a_chars.len().max(b_chars.len());
    if max_len == 0 {
        return 1.0;
    }
    
    let distance = levenshtein_distance(&a_chars, &b_chars);
    1.0 - (distance as f64 / max_len as f64)
}

fn levenshtein_distance(a: &[char], b: &[char]) -> usize {
    let mut matrix = vec![vec![0; b.len() + 1]; a.len() + 1];
    
    for i in 0..=a.len() {
        matrix[i][0] = i;
    }
    
    for j in 0..=b.len() {
        matrix[0][j] = j;
    }
    
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            matrix[i][j] = std::cmp::min(
                std::cmp::min(
                    matrix[i - 1][j] + 1,
                    matrix[i][j - 1] + 1
                ),
                matrix[i - 1][j - 1] + cost
            );
        }
    }
    
    matrix[a.len()][b.len()]
}

pub fn parallel_map<T, U, F>(items: Vec<T>, f: F) -> Vec<U>
where
    T: Send,
    U: Send,
    F: Fn(T) -> U + Send + Sync,
{
    items.into_par_iter().map(f).collect()
}

pub fn parallel_filter<T, F>(items: Vec<T>, f: F) -> Vec<T>
where
    T: Send,
    F: Fn(&T) -> bool + Send + Sync,
{
    items.into_par_iter().filter(f).collect()
}

pub fn batch_process<T, U, F>(items: Vec<T>, batch_size: usize, f: F) -> Vec<U>
where
    T: Send + Clone,
    U: Send,
    F: Fn(Vec<T>) -> Vec<U> + Send + Sync,
{
    let batches: Vec<Vec<T>> = items.chunks(batch_size).map(|chunk| chunk.to_vec()).collect();
    
    batches
        .into_par_iter()
        .flat_map(|batch| f(batch))
        .collect()
}

pub fn get_memory_usage() -> Result<f64> {
    // This is a simplified implementation
    // In a real implementation, you'd use platform-specific APIs
    Ok(0.0) // Placeholder
}

pub fn get_system_info() -> HashMap<String, String> {
    let mut info = HashMap::new();
    
    info.insert("os".to_string(), std::env::consts::OS.to_string());
    info.insert("arch".to_string(), std::env::consts::ARCH.to_string());
    info.insert("family".to_string(), std::env::consts::FAMILY.to_string());
    
    if let Ok(num_cpus) = std::thread::available_parallelism() {
        info.insert("cpu_count".to_string(), num_cpus.get().to_string());
    }
    
    info
}