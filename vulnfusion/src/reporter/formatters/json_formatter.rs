// 中文说明：
// JsonFormatter 将结果序列化为 JSON；支持是否包含元数据以及是否美化输出，
// 便于脚本处理与平台集成（如 CI 上传、自动统计等）。
use crate::utils::error::Result;
use serde::{Serialize, Deserialize};

use crate::analyzer::AnalysisResults;

pub struct JsonFormatter {
    pretty_print: bool,
    include_metadata: bool,
}

impl JsonFormatter {
    pub fn new() -> Self {
        Self {
            pretty_print: true,
            include_metadata: true,
        }
    }
    
    pub fn with_pretty_print(mut self, pretty: bool) -> Self {
        self.pretty_print = pretty;
        self
    }
    
    pub fn with_metadata(mut self, include: bool) -> Self {
        self.include_metadata = include;
        self
    }
    
    pub fn format(&self, results: &AnalysisResults) -> Result<String> {
        let output = if self.include_metadata {
            serde_json::json!({
                "version": "1.0",
                "tool": {
                    "name": "VulnFusion",
                    "version": "0.1.0",
                },
                "analysis": {
                    "context": results.context,
                    "statistics": results.statistics,
                    "performance": results.performance_metrics,
                },
                "vulnerabilities": results.vulnerabilities,
            })
        } else {
            serde_json::json!({
                "vulnerabilities": results.vulnerabilities,
            })
        };
        
        if self.pretty_print {
            Ok(serde_json::to_string_pretty(&output)?)
        } else {
            Ok(serde_json::to_string(&output)?)
        }
    }
}