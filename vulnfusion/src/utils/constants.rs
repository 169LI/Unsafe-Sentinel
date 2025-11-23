// 中文说明：
// 全局常量与规则集合：默认参数、文件/项目识别、风险模式与函数列表、
// 支持的输出格式与不同精度的超时配置。
use std::time::Duration;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);
pub const DEFAULT_MAX_DEPTH: usize = 10;
pub const DEFAULT_PARALLEL_FILES: usize = 4;
pub const DEFAULT_MEMORY_LIMIT_MB: usize = 2048;

pub const RUST_FILE_EXTENSIONS: &[&str] = &[".rs"];
pub const RUST_PROJECT_FILES: &[&str] = &["Cargo.toml", "Cargo.lock"];

pub const VULNERABILITY_SEVERITY_LEVELS: &[&str] = &["Critical", "High", "Medium", "Low", "Info"];
pub const VULNERABILITY_CATEGORIES: &[&str] = &[
    "Memory Safety",
    "Concurrency",
    "Panic Safety", 
    "Type Safety",
    "Logic Error",
    "Security",
];

pub const MEMORY_SAFETY_PATTERNS: &[&str] = &[
    r"unsafe\s*\{",
    r"std::ptr::",
    r"std::mem::",
    r"std::slice::",
    r"std::alloc::",
    r"std::heap::",
    r"Box::from_raw",
    r"Vec::from_raw_parts",
    r"String::from_raw_parts",
];

pub const CONCURRENCY_PATTERNS: &[&str] = &[
    r"std::thread::",
    r"std::sync::",
    r"std::atomic::",
    r"Arc::",
    r"Mutex::",
    r"RwLock::",
    r"mpsc::",
    r"crossbeam::",
];

pub const PANIC_SAFETY_PATTERNS: &[&str] = &[
    r"panic::",
    r"unwrap\(\)",
    r"expect\(",
    r"assert!",
    r"assert_eq!",
    r"unreachable!",
    r"todo!",
    r"unimplemented!",
];

pub const SUSPICIOUS_FUNCTIONS: &[&str] = &[
    "std::ptr::read",
    "std::ptr::write", 
    "std::ptr::replace",
    "std::ptr::swap",
    "std::mem::transmute",
    "std::mem::forget",
    "std::mem::drop",
    "std::slice::from_raw_parts",
    "std::slice::from_raw_parts_mut",
];

pub const MAX_FILE_SIZE: usize = 10 * 1024 * 1024; // 10MB
pub const MAX_LINE_LENGTH: usize = 1000;
pub const MAX_FUNCTION_COMPLEXITY: usize = 50;

pub const DEFAULT_OUTPUT_FORMAT: &str = "json";
pub const SUPPORTED_OUTPUT_FORMATS: &[&str] = &["json", "html", "markdown", "text", "sarif"];

pub const ANALYSIS_TIMEOUTS: &[(&str, Duration)] = &[
    ("shallow", Duration::from_secs(60)),
    ("normal", Duration::from_secs(180)),
    ("deep", Duration::from_secs(300)),
    ("exhaustive", Duration::from_secs(600)),
];