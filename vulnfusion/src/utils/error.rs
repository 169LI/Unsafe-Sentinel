// 中文说明：
// 错误类型与处理工具：统一定义文件/分析/漏洞相关错误枚举，提供友好的显示与
// 恢复性判断、上下文日志输出，以及面向终端/报告的错误文案生成。
use std::fmt;
use std::io;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum FileError {
    IoError(String),
    FileTooLarge(PathBuf),
    PathError(String),
    ParseError(String),
    NotFound(PathBuf),
    PermissionDenied(PathBuf),
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileError::IoError(msg) => write!(f, "IO Error: {}", msg),
            FileError::FileTooLarge(path) => write!(f, "File too large: {}", path.display()),
            FileError::PathError(msg) => write!(f, "Path Error: {}", msg),
            FileError::ParseError(msg) => write!(f, "Parse Error: {}", msg),
            FileError::NotFound(path) => write!(f, "File not found: {}", path.display()),
            FileError::PermissionDenied(path) => write!(f, "Permission denied: {}", path.display()),
        }
    }
}

impl std::error::Error for FileError {}

impl From<io::Error> for FileError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::NotFound => FileError::NotFound(PathBuf::from(error.to_string())),
            io::ErrorKind::PermissionDenied => FileError::PermissionDenied(PathBuf::from(error.to_string())),
            _ => FileError::IoError(error.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum AnalysisError {
    ParseError(String),
    TypeError(String),
    TimeoutError(String),
    MemoryError(String),
    ConfigurationError(String),
    InternalError(String),
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnalysisError::ParseError(msg) => write!(f, "Parse Error: {}", msg),
            AnalysisError::TypeError(msg) => write!(f, "Type Error: {}", msg),
            AnalysisError::TimeoutError(msg) => write!(f, "Timeout Error: {}", msg),
            AnalysisError::MemoryError(msg) => write!(f, "Memory Error: {}", msg),
            AnalysisError::ConfigurationError(msg) => write!(f, "Configuration Error: {}", msg),
            AnalysisError::InternalError(msg) => write!(f, "Internal Error: {}", msg),
        }
    }
}

impl std::error::Error for AnalysisError {}

#[derive(Debug, Clone)]
pub enum VulnerabilityError {
    DetectionError(String),
    ClassificationError(String),
    SeverityError(String),
    ReportError(String),
}

impl fmt::Display for VulnerabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VulnerabilityError::DetectionError(msg) => write!(f, "Detection Error: {}", msg),
            VulnerabilityError::ClassificationError(msg) => write!(f, "Classification Error: {}", msg),
            VulnerabilityError::SeverityError(msg) => write!(f, "Severity Error: {}", msg),
            VulnerabilityError::ReportError(msg) => write!(f, "Report Error: {}", msg),
        }
    }
}

impl std::error::Error for VulnerabilityError {}

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

pub fn handle_file_error(error: FileError) -> String {
    match error {
        FileError::FileTooLarge(path) => {
            format!("File {} is too large to analyze. Maximum size is {} bytes.", 
                   path.display(), crate::utils::constants::MAX_FILE_SIZE)
        }
        FileError::NotFound(path) => {
            format!("File {} not found. Please check the path and try again.", path.display())
        }
        FileError::PermissionDenied(path) => {
            format!("Permission denied for file {}. Please check file permissions.", path.display())
        }
        _ => error.to_string(),
    }
}

pub fn handle_analysis_error(error: AnalysisError) -> String {
    match error {
        AnalysisError::TimeoutError(msg) => {
            format!("Analysis timed out: {}. Consider increasing timeout or reducing analysis scope.", msg)
        }
        AnalysisError::MemoryError(msg) => {
            format!("Memory error during analysis: {}. Consider reducing parallel processing or file size.", msg)
        }
        AnalysisError::ConfigurationError(msg) => {
            format!("Configuration error: {}. Please check your analysis settings.", msg)
        }
        _ => error.to_string(),
    }
}

pub fn format_error_with_context(error: &str, context: &str) -> String {
    format!("Error in {}: {}", context, error)
}

pub fn log_error(error: &dyn std::error::Error, context: &str) {
    eprintln!("[ERROR] {}: {}", context, error);
    if let Some(source) = error.source() {
        eprintln!("[ERROR] Caused by: {}", source);
    }
}

pub fn is_recoverable_error(error: &dyn std::error::Error) -> bool {
    // Determine if an error is recoverable and analysis can continue
    let error_string = error.to_string().to_lowercase();
    
    !error_string.contains("out of memory") &&
    !error_string.contains("stack overflow") &&
    !error_string.contains("segmentation fault") &&
    !error_string.contains("bus error")
}