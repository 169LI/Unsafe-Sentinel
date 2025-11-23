use crate::analyzer::{AnalysisResults, Vulnerability, VulnerabilitySeverity};

/// 后处理器：
/// - 去重与基础抑制（如检测到同步原语/边界检查时抑制）
/// - verified-only 竞赛模式：仅保留具备强证据的“确证型”漏洞，并可按需要截断数量
pub struct PostProcessor {
    verified_only: bool,
    max_verified: Option<usize>,
}

impl PostProcessor {
    /// 默认构造：关闭竞赛模式
    pub fn new() -> Self { Self { verified_only: false, max_verified: None } }

    /// 启用竞赛模式（仅确证漏洞 + 可选数量上限）
    pub fn with_verified(verified_only: bool, max_verified: Option<usize>) -> Self {
        Self { verified_only, max_verified }
    }

    /// 主流程：去重→竞赛模式过滤→统计刷新
    pub fn process(&self, mut results: AnalysisResults) -> AnalysisResults {
        let mut vulns = self.filter_and_dedup(results.vulnerabilities);
        if self.verified_only {
            vulns = self.apply_verified_filter(vulns);
            if let Some(maxn) = self.max_verified {
                if vulns.len() > maxn {
                    vulns.sort_by(|a, b| {
                        let sa = Self::sev_to_int(&a.severity);
                        let sb = Self::sev_to_int(&b.severity);
                        sb.cmp(&sa).then(b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal))
                    });
                    vulns.truncate(maxn);
                }
            }
        }
        results.vulnerabilities = vulns;
        results.statistics.total_vulnerabilities = results.vulnerabilities.len();
        results.statistics.vulnerabilities_by_severity.clear();
        for v in &results.vulnerabilities {
            let sev = format!("{:?}", v.severity);
            *results.statistics.vulnerabilities_by_severity.entry(sev).or_insert(0) += 1;
        }
        results.statistics.vulnerabilities_by_type.clear();
        for v in &results.vulnerabilities {
            *results.statistics.vulnerabilities_by_type.entry(v.vulnerability_type.clone()).or_insert(0) += 1;
        }
        results
    }

    /// 基础去重与抑制：
    /// - 同一类型/同一路径/近似行号只保留一个
    /// - 启发式检测到安全护栏（锁、边界检查）则抑制
    fn filter_and_dedup(&self, vulns: Vec<Vulnerability>) -> Vec<Vulnerability> {
        let mut filtered: Vec<Vulnerability> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for v in vulns.into_iter() {
            if self.is_suppressed(&v) { continue; }

            let key = format!("{}::{}::{}",
                              v.vulnerability_type,
                              v.file_path,
                              Self::line_bucket(v.line_number));
            if seen.insert(key) { filtered.push(v); }
        }

        filtered
    }

    fn line_bucket(line: usize) -> usize { if line == 0 { 0 } else { ((line as isize) - 3).max(0) as usize } }

    /// 抑制规则：出现明显安全护栏时不计入结果
    fn is_suppressed(&self, v: &Vulnerability) -> bool {
        let s = v.code_snippet.to_lowercase();

        match v.vulnerability_type.as_str() {
            "data-race" => {
                s.contains("mutex") || s.contains("rwlock") || s.contains("atomic") || s.contains("std::sync::")
            }
            "panic-safety" => {
                !(s.contains("panic!(") || s.contains("unwrap(") || s.contains("expect("))
            }
            "buffer-overflow" => {
                s.contains(".len()") || s.contains("debug_assert!") || s.contains("assert!(")
            }
            "null-pointer-deref" => {
                !(s.contains("*null") || s.contains("ptr::read") || s.contains("ptr::write"))
            }
            _ => false,
        }
    }
    
    /// 竞赛模式过滤：保留具备强证据的确证型漏洞
    fn apply_verified_filter(&self, vulns: Vec<Vulnerability>) -> Vec<Vulnerability> {
        let mut out = Vec::new();
        for v in vulns.into_iter() {
            if Self::is_verified(&v) { out.push(v); }
        }
        out
    }

    fn sev_to_int(sev: &VulnerabilitySeverity) -> i32 {
        match sev { VulnerabilitySeverity::Critical => 4, VulnerabilitySeverity::High => 3, VulnerabilitySeverity::Medium => 2, VulnerabilitySeverity::Low => 1, VulnerabilitySeverity::Info => 0 }
    }

    /// 强证据判定：不同类型对应明确的可复现/语义强信号
    fn is_verified(v: &Vulnerability) -> bool {
        let s = v.code_snippet.to_lowercase();
        let p = v.file_path.to_lowercase();
        if p.contains("/tests/") || p.contains("\\tests\\") || p.contains("/benches/") || p.contains("\\benches\\") || p.contains("/examples/") || p.contains("\\examples\\") || p.contains("/doc/") || p.contains("\\doc\\")
            || p.ends_with("tests.rs") || p.ends_with("test.rs") || p.ends_with("bench.rs") || p.ends_with("benches.rs") {
            return false;
        }
        match v.vulnerability_type.as_str() {
            "buffer-overflow" => {
                (s.contains("get_unchecked(") && regex::Regex::new(r"get_unchecked\s*\(\s*\d+").ok().map(|re| re.is_match(&s)).unwrap_or(false))
                || (s.contains("ptr.add") || s.contains("offset"))
            }
            "double-free" => {
                let cnt = s.matches("free").count() + s.matches("dealloc").count(); cnt > 1
            }
            "use-after-free" => {
                (s.contains("free") || s.contains("dealloc") || s.contains("drop")) && s.contains("*")
            }
            "uninitialized-read" => {
                s.contains("assume_init") && s.contains("maybeuninit::<")
            }
            "null-pointer-deref" => {
                (s.contains("ptr::null") || s.contains("ptr::null_mut")) && s.contains("*") && !(s.contains("is_null") || s.contains("if"))
            }
            "panic-safety" => {
                s.contains("panic!(") || s.contains("unwrap(") || s.contains("expect(")
            }
            "drop-panic" => {
                (s.contains("impl drop") || s.contains("impl Drop"))
                && s.contains("fn drop")
                && (s.contains("panic!(") || s.contains("unwrap(") || s.contains("expect(") || s.contains("assert!("))
            }
            "data-race" => {
                (s.contains("static mut") || s.contains("unsafecell") || s.contains("unsafe_cell") ) && (s.contains("thread") || s.contains("spawn")) && !(s.contains("mutex") || s.contains("rwlock") || s.contains("atomic"))
            }
            "improper-sync" => {
                s.contains("unsafe impl") && (s.contains(" send") || s.contains(" sync")) && (s.contains("*mut") || s.contains("refcell") || s.contains("cell") || s.contains("nonnull"))
            }
            "invalid-transmute" => {
                s.contains("transmute(")
            }
            "memory-leak" => {
                s.contains("box::leak") || s.contains("mem::forget")
            }
            _ => false,
        }
    }
}