// 中文说明：
// 分析配置加载/序列化与命令行覆盖：支持精度、超时、并行、格式与路径过滤等配置，
// 并提供默认值与从文件读取/写入的能力，便于在不同场景快速切换分析策略。
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::utils::error::FileError;
use crate::utils::constants::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub precision: PrecisionLevel,
    pub timeout: Duration,
    pub max_depth: usize,
    pub parallel_files: usize,
    pub memory_limit_mb: usize,
    pub enable_parallel: bool,
    pub enable_cross_crate: bool,
    pub enable_mir_analysis: bool,
    pub enable_dataflow: bool,
    pub enable_control_flow: bool,
    pub enable_call_graph: bool,
    pub output_format: OutputFormat,
    pub output_directory: PathBuf,
    pub include_patterns: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub vulnerability_filters: VulnerabilityFilters,
    pub performance_settings: PerformanceSettings,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PrecisionLevel {
    Shallow,
    Normal,
    Deep,
    Exhaustive,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Html,
    Markdown,
    Text,
    Sarif,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFilters {
    pub min_severity: SeverityLevel,
    pub max_severity: SeverityLevel,
    pub categories: Vec<String>,
    pub exclude_false_positives: bool,
    pub confidence_threshold: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityLevel {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSettings {
    pub enable_caching: bool,
    pub cache_size_mb: usize,
    pub max_threads: usize,
    pub batch_size: usize,
    pub enable_incremental: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            precision: PrecisionLevel::Normal,
            timeout: DEFAULT_TIMEOUT,
            max_depth: DEFAULT_MAX_DEPTH,
            parallel_files: DEFAULT_PARALLEL_FILES,
            memory_limit_mb: DEFAULT_MEMORY_LIMIT_MB,
            enable_parallel: true,
            enable_cross_crate: false,
            enable_mir_analysis: true,
            enable_dataflow: true,
            enable_control_flow: true,
            enable_call_graph: true,
            output_format: OutputFormat::Json,
            output_directory: PathBuf::from("vulnfusion-output"),
            include_patterns: vec!["**/*.rs".to_string()],
            exclude_patterns: vec![
                "**/target/**".to_string(),
                "**/.git/**".to_string(),
                "**/node_modules/**".to_string(),
            ],
            vulnerability_filters: VulnerabilityFilters::default(),
            performance_settings: PerformanceSettings::default(),
        }
    }
}

impl Default for VulnerabilityFilters {
    fn default() -> Self {
        Self {
            min_severity: SeverityLevel::Low,
            max_severity: SeverityLevel::Critical,
            categories: VULNERABILITY_CATEGORIES.iter().map(|s| s.to_string()).collect(),
            exclude_false_positives: true,
            confidence_threshold: 0.5,
        }
    }
}

impl Default for PerformanceSettings {
    fn default() -> Self {
        Self {
            enable_caching: true,
            cache_size_mb: 512,
            max_threads: num_cpus::get(),
            batch_size: 10,
            enable_incremental: false,
        }
    }
}

impl AnalysisConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, FileError> {
        let content = fs::read_to_string(path)?;
        let config: AnalysisConfig = toml::from_str(&content)
            .map_err(|e| FileError::ParseError(format!("Failed to parse config: {}", e)))?;
        Ok(config)
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), FileError> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| FileError::ParseError(format!("Failed to serialize config: {}", e)))?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn from_args(
        precision: Option<String>,
        timeout: Option<u64>,
        max_depth: Option<usize>,
        parallel: Option<bool>,
        output_format: Option<String>,
        output_dir: Option<PathBuf>,
    ) -> Result<Self, String> {
        let mut config = AnalysisConfig::default();

        if let Some(p) = precision {
            config.precision = match p.to_lowercase().as_str() {
                "shallow" => PrecisionLevel::Shallow,
                "normal" => PrecisionLevel::Normal,
                "deep" => PrecisionLevel::Deep,
                "exhaustive" => PrecisionLevel::Exhaustive,
                _ => return Err(format!("Invalid precision level: {}", p)),
            };
        }

        if let Some(t) = timeout {
            config.timeout = Duration::from_secs(t);
        }

        if let Some(d) = max_depth {
            config.max_depth = d;
        }

        if let Some(p) = parallel {
            config.enable_parallel = p;
        }

        if let Some(f) = output_format {
            config.output_format = match f.to_lowercase().as_str() {
                "json" => OutputFormat::Json,
                "html" => OutputFormat::Html,
                "markdown" | "md" => OutputFormat::Markdown,
                "text" | "txt" => OutputFormat::Text,
                "sarif" => OutputFormat::Sarif,
                _ => return Err(format!("Invalid output format: {}", f)),
            };
        }

        if let Some(dir) = output_dir {
            config.output_directory = dir;
        }

        Ok(config)
    }

    pub fn get_timeout_for_precision(&self) -> Duration {
        match self.precision {
            PrecisionLevel::Shallow => Duration::from_secs(60),
            PrecisionLevel::Normal => Duration::from_secs(180),
            PrecisionLevel::Deep => Duration::from_secs(300),
            PrecisionLevel::Exhaustive => Duration::from_secs(600),
        }
    }

    pub fn should_analyze_file(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        // Check exclude patterns first
        for pattern in &self.exclude_patterns {
            if glob::Pattern::new(pattern)
                .ok()
                .map(|p| p.matches(&path_str))
                .unwrap_or(false)
            {
                return false;
            }
        }

        // Check include patterns
        for pattern in &self.include_patterns {
            if glob::Pattern::new(pattern)
                .ok()
                .map(|p| p.matches(&path_str))
                .unwrap_or(false)
            {
                return true;
            }
        }

        false
    }

    pub fn get_analysis_depth(&self) -> usize {
        match self.precision {
            PrecisionLevel::Shallow => 3,
            PrecisionLevel::Normal => 5,
            PrecisionLevel::Deep => 8,
            PrecisionLevel::Exhaustive => 15,
        }
    }

    pub fn get_parallelism_level(&self) -> usize {
        if !self.enable_parallel {
            return 1;
        }

        match self.precision {
            PrecisionLevel::Shallow => self.parallel_files,
            PrecisionLevel::Normal => self.parallel_files / 2,
            PrecisionLevel::Deep => self.parallel_files / 3,
            PrecisionLevel::Exhaustive => 1,
        }
    }
}

impl PrecisionLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            PrecisionLevel::Shallow => "shallow",
            PrecisionLevel::Normal => "normal",
            PrecisionLevel::Deep => "deep",
            PrecisionLevel::Exhaustive => "exhaustive",
        }
    }
}

impl OutputFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            OutputFormat::Json => "json",
            OutputFormat::Html => "html",
            OutputFormat::Markdown => "markdown",
            OutputFormat::Text => "text",
            OutputFormat::Sarif => "sarif",
        }
    }

    pub fn file_extension(&self) -> &'static str {
        match self {
            OutputFormat::Json => ".json",
            OutputFormat::Html => ".html",
            OutputFormat::Markdown => ".md",
            OutputFormat::Text => ".txt",
            OutputFormat::Sarif => ".sarif",
        }
    }
}

impl SeverityLevel {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" => Some(SeverityLevel::Info),
            "low" => Some(SeverityLevel::Low),
            "medium" => Some(SeverityLevel::Medium),
            "high" => Some(SeverityLevel::High),
            "critical" => Some(SeverityLevel::Critical),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SeverityLevel::Info => "info",
            SeverityLevel::Low => "low",
            SeverityLevel::Medium => "medium",
            SeverityLevel::High => "high",
            SeverityLevel::Critical => "critical",
        }
    }

    pub fn numeric_value(&self) -> u8 {
        *self as u8
    }
}

pub fn create_default_config_file<P: AsRef<Path>>(path: P) -> Result<(), FileError> {
    let config = AnalysisConfig::default();
    config.to_file(path)
}

pub fn load_config_with_overrides<P: AsRef<Path>>(
    config_path: Option<P>,
    precision: Option<String>,
    timeout: Option<u64>,
    output_format: Option<String>,
) -> Result<AnalysisConfig, String> {
    let mut config = if let Some(path) = config_path {
        AnalysisConfig::from_file(path)
            .map_err(|e| format!("Failed to load config file: {}", e))?
    } else {
        AnalysisConfig::default()
    };

    // Apply command line overrides
    if let Some(p) = precision {
        config.precision = match p.to_lowercase().as_str() {
            "shallow" => PrecisionLevel::Shallow,
            "normal" => PrecisionLevel::Normal,
            "deep" => PrecisionLevel::Deep,
            "exhaustive" => PrecisionLevel::Exhaustive,
            _ => return Err(format!("Invalid precision level: {}", p)),
        };
    }

    if let Some(t) = timeout {
        config.timeout = Duration::from_secs(t);
    }

    if let Some(f) = output_format {
        config.output_format = match f.to_lowercase().as_str() {
            "json" => OutputFormat::Json,
            "html" => OutputFormat::Html,
            "markdown" | "md" => OutputFormat::Markdown,
            "text" | "txt" => OutputFormat::Text,
            "sarif" => OutputFormat::Sarif,
            _ => return Err(format!("Invalid output format: {}", f)),
        };
    }

    Ok(config)
}