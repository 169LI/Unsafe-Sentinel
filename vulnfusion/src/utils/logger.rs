// 中文说明：
// 轻量日志系统：支持等级、彩色输出与时间戳，提供分析流程中的关键日志函数与进度上报，
// 便于在终端/报告中观察性能与检测进度。
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::{self, Write};
use lazy_static::lazy_static;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

impl LogLevel {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "trace" => Some(LogLevel::Trace),
            "debug" => Some(LogLevel::Debug),
            "info" => Some(LogLevel::Info),
            "warn" => Some(LogLevel::Warn),
            "error" => Some(LogLevel::Error),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
}

pub struct Logger {
    level: LogLevel,
    enable_colors: bool,
    enable_timestamp: bool,
    output: Mutex<Box<dyn Write + Send>>,
}

lazy_static! {
    static ref GLOBAL_LOGGER: Mutex<Logger> = Mutex::new(Logger::new());
}

impl Logger {
    pub fn new() -> Self {
        Logger {
            level: LogLevel::Info,
            enable_colors: true,
            enable_timestamp: true,
            output: Mutex::new(Box::new(io::stdout())),
        }
    }

    pub fn set_level(&mut self, level: LogLevel) {
        self.level = level;
    }

    pub fn set_colors(&mut self, enable: bool) {
        self.enable_colors = enable;
    }

    pub fn set_timestamp(&mut self, enable: bool) {
        self.enable_timestamp = enable;
    }

    pub fn log(&self, level: LogLevel, message: &str) {
        if level < self.level {
            return;
        }

        let timestamp = if self.enable_timestamp {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            format!("[{}.{:03}]", now.as_secs(), now.subsec_millis())
        } else {
            String::new()
        };

        let level_str = if self.enable_colors {
            self.colorize_level(level)
        } else {
            format!("[{}]", level.as_str())
        };

        let log_message = format!("{} {} {}\n", timestamp, level_str, message);

        if let Ok(mut output) = self.output.lock() {
            let _ = output.write_all(log_message.as_bytes());
            let _ = output.flush();
        }
    }

    fn colorize_level(&self, level: LogLevel) -> String {
        match level {
            LogLevel::Trace => "\x1b[90m[TRACE]\x1b[0m".to_string(),
            LogLevel::Debug => "\x1b[36m[DEBUG]\x1b[0m".to_string(),
            LogLevel::Info => "\x1b[32m[INFO]\x1b[0m".to_string(),
            LogLevel::Warn => "\x1b[33m[WARN]\x1b[0m".to_string(),
            LogLevel::Error => "\x1b[31m[ERROR]\x1b[0m".to_string(),
        }
    }
}

pub fn init_logger(level: LogLevel) {
    if let Ok(mut logger) = GLOBAL_LOGGER.lock() {
        logger.set_level(level);
    }
}

pub fn set_log_level(level: LogLevel) {
    if let Ok(mut logger) = GLOBAL_LOGGER.lock() {
        logger.set_level(level);
    }
}

pub fn enable_colors(enable: bool) {
    if let Ok(mut logger) = GLOBAL_LOGGER.lock() {
        logger.set_colors(enable);
    }
}

pub fn enable_timestamp(enable: bool) {
    if let Ok(mut logger) = GLOBAL_LOGGER.lock() {
        logger.set_timestamp(enable);
    }
}

pub fn trace(message: &str) {
    if let Ok(logger) = GLOBAL_LOGGER.lock() {
        logger.log(LogLevel::Trace, message);
    }
}

pub fn debug(message: &str) {
    if let Ok(logger) = GLOBAL_LOGGER.lock() {
        logger.log(LogLevel::Debug, message);
    }
}

pub fn info(message: &str) {
    if let Ok(logger) = GLOBAL_LOGGER.lock() {
        logger.log(LogLevel::Info, message);
    }
}

pub fn warn(message: &str) {
    if let Ok(logger) = GLOBAL_LOGGER.lock() {
        logger.log(LogLevel::Warn, message);
    }
}

pub fn error(message: &str) {
    if let Ok(logger) = GLOBAL_LOGGER.lock() {
        logger.log(LogLevel::Error, message);
    }
}

pub fn log_analysis_start(project_path: &str, file_count: usize) {
    info(&format!("Starting analysis of project: {} ({} files)", project_path, file_count));
}

pub fn log_analysis_progress(current: usize, total: usize, current_file: &str) {
    let percentage = (current as f64 / total as f64 * 100.0) as u32;
    debug(&format!("Progress: {}/{} ({:.0}%) - Analyzing: {}", current, total, percentage, current_file));
}

pub fn log_vulnerability_found(
    vulnerability_type: &str,
    severity: &str,
    location: &str,
    description: &str,
) {
    warn(&format!(
        "Vulnerability Found - Type: {}, Severity: {}, Location: {}, Description: {}",
        vulnerability_type, severity, location, description
    ));
}

pub fn log_analysis_completed(total_files: usize, vulnerabilities_found: usize, duration: f64) {
    if vulnerabilities_found > 0 {
        info(&format!(
            "Analysis completed - {} files analyzed, {} vulnerabilities found in {:.2}s",
            total_files, vulnerabilities_found, duration
        ));
    } else {
        info(&format!(
            "Analysis completed - {} files analyzed, no vulnerabilities found in {:.2}s",
            total_files, duration
        ));
    }
}

pub fn log_memory_usage(current_mb: f64, peak_mb: f64) {
    debug(&format!("Memory usage - Current: {:.1}MB, Peak: {:.1}MB", current_mb, peak_mb));
}

pub fn log_performance_metric(operation: &str, duration_ms: f64) {
    trace(&format!("Performance - {} took {:.2}ms", operation, duration_ms));
}

pub struct ProgressReporter {
    total: usize,
    current: std::sync::atomic::AtomicUsize,
}

impl ProgressReporter {
    pub fn new(total: usize) -> Self {
        ProgressReporter {
            total,
            current: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn update(&self, current: usize) {
        self.current.store(current, std::sync::atomic::Ordering::Relaxed);
        let percentage = (current as f64 / self.total as f64 * 100.0) as u32;
        if current % 10 == 0 || percentage % 10 == 0 {
            info(&format!("Progress: {}/{} ({:.0}%)", current, self.total, percentage));
        }
    }

    pub fn finish(&self) {
        let current = self.current.load(std::sync::atomic::Ordering::Relaxed);
        info(&format!("Progress: {}/{} (100.0%) - Complete!", current, self.total));
    }
}