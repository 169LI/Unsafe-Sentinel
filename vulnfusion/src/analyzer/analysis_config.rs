// 中文说明：
// AnalysisConfig 保存分析全局配置，如最大递归深度、是否并行、线程数、
// 超时与内存限制、过滤/排除规则以及分析精度等。通过该配置可在竞赛中
// 按需切换“快速/深度/穷尽”模式并控制分析范围。
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    // 最大分析深度（越大越慢，精度更高）
    pub max_depth: usize,
    // 是否启用并行分析（大仓库建议开启）
    pub parallel_analysis: bool,
    // 线程数（0 表示使用可用核心数）
    pub thread_count: usize,
    // 分析超时（秒）
    pub timeout_seconds: u64,
    // 内存限制（MB）
    pub memory_limit_mb: usize,
    // 仅分析指定类型的漏洞（为空表示全部）
    pub vulnerability_filters: HashSet<String>,
    // 排除路径（如 tests/、target/ 等）
    pub excluded_paths: HashSet<String>,
    // 是否分析依赖/测试代码
    pub include_dependencies: bool,
    // 分析精度等级
    pub analysis_precision: AnalysisPrecision,
    // 是否启用机器学习辅助检测
    pub enable_ml_detection: bool,
    // 是否启用跨 crate 分析
    pub enable_cross_crate_analysis: bool,
    // 置信度阈值
    pub min_confidence: f64,
    // 最低严重度级别（0=Info..4=Critical）
    pub min_severity_level: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnalysisPrecision {
    Shallow,
    Normal,
    Deep,
    Exhaustive,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_depth: 10,
            parallel_analysis: true,
            thread_count: 0, // 0 means use all available cores
            timeout_seconds: 300,
            memory_limit_mb: 2048,
            vulnerability_filters: HashSet::new(),
            excluded_paths: {
                let mut s = HashSet::new();
                s.insert("**/target/**".to_string());
                s.insert("**/.git/**".to_string());
                s.insert("**/node_modules/**".to_string());
                s.insert("**/vendor/**".to_string());
                s.insert("**/third_party/**".to_string());
                s.insert("**/build/**".to_string());
                s.insert("**/out/**".to_string());
                s.insert("**/dist/**".to_string());
                s
            },
            include_dependencies: false,
            analysis_precision: AnalysisPrecision::Normal,
            enable_ml_detection: true,
            enable_cross_crate_analysis: false,
            min_confidence: 0.7,
            min_severity_level: 1,
        }
    }
}

impl AnalysisConfig {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn with_precision(precision: AnalysisPrecision) -> Self {
        let mut config = Self::default();
        config.analysis_precision = precision;
        config
    }
    
    pub fn shallow() -> Self {
        Self::with_precision(AnalysisPrecision::Shallow)
    }
    
    pub fn deep() -> Self {
        Self::with_precision(AnalysisPrecision::Deep)
    }
    
    pub fn exhaustive() -> Self {
        Self::with_precision(AnalysisPrecision::Exhaustive)
    }
    
    pub fn add_vulnerability_filter(&mut self, vuln_type: String) {
        self.vulnerability_filters.insert(vuln_type);
    }
    
    pub fn add_excluded_path(&mut self, path: String) {
        self.excluded_paths.insert(path);
    }
    
    pub fn is_path_excluded(&self, path: &str) -> bool {
        self.excluded_paths.iter().any(|pattern| {
            glob::Pattern::new(pattern)
                .ok()
                .map(|p| p.matches(path))
                .unwrap_or_else(|| path.contains(pattern))
        })
    }
    
    pub fn should_analyze_vulnerability(&self, vuln_type: &str) -> bool {
        self.vulnerability_filters.is_empty() || self.vulnerability_filters.contains(vuln_type)
    }

    pub fn set_min_confidence(&mut self, v: f64) { self.min_confidence = v; }
    pub fn set_min_severity_level(&mut self, lvl: i32) { self.min_severity_level = lvl; }
}