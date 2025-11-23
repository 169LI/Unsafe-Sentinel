// 中文说明：
// 报告格式化模块集合，统一导出 JSON/HTML/Markdown 三种格式的格式化器，
// 供 ReportGenerator 根据目标格式选择使用。
pub mod json_formatter;
pub mod html_formatter;
pub mod markdown_formatter;

pub use json_formatter::JsonFormatter;
pub use html_formatter::HtmlFormatter;
pub use markdown_formatter::MarkdownFormatter;