// 中文说明：
// ReportGenerator 负责将分析结果格式化为 JSON/HTML/Markdown/TEXT/SARIF 等，
// 支持是否包含代码片段/修复建议，以及按严重程度/类型分组，便于竞赛提交。
use crate::utils::error::Result;
use serde::{Serialize, Deserialize};
use std::path::Path;
use tracing::{info, debug};

use crate::analyzer::{AnalysisResults, VulnerabilitySeverity};
use crate::reporter::formatters::{JsonFormatter, HtmlFormatter, MarkdownFormatter};

pub struct ReportGenerator {
    format: ReportFormat,
    include_code_snippets: bool,
    include_suggestions: bool,
    group_by_severity: bool,
    group_by_type: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportFormat {
    Json,
    Html,
    Markdown,
    Text,
    Sarif,
}

impl ReportGenerator {
    pub fn new() -> Self {
        Self {
            format: ReportFormat::Markdown,
            include_code_snippets: true,
            include_suggestions: true,
            group_by_severity: true,
            group_by_type: false,
        }
    }
    
    pub fn set_format(&mut self, format: &str) {
        self.format = match format.to_lowercase().as_str() {
            "json" => ReportFormat::Json,
            "html" => ReportFormat::Html,
            "markdown" | "md" => ReportFormat::Markdown,
            "text" | "txt" => ReportFormat::Text,
            "sarif" => ReportFormat::Sarif,
            _ => ReportFormat::Markdown,
        };
    }
    
    pub fn generate_report(&self, results: &AnalysisResults) -> Result<String> {
        // 根据目标格式选择对应生成方法
        info!("Generating {} report", format!("{:?}", self.format).to_lowercase());
        
        match self.format {
            ReportFormat::Json => self.generate_json_report(results),
            ReportFormat::Html => self.generate_html_report(results),
            ReportFormat::Markdown => self.generate_markdown_report(results),
            ReportFormat::Text => self.generate_text_report(results),
            ReportFormat::Sarif => self.generate_sarif_report(results),
        }
    }
    
    pub fn save_to_file(&self, results: &AnalysisResults, file_path: &Path) -> Result<()> {
        // 生成并写入报告到文件
        let report_content = self.generate_report(results)?;
        std::fs::write(file_path, report_content)?;
        Ok(())
    }
    
    fn generate_json_report(&self, results: &AnalysisResults) -> Result<String> {
        let formatter = JsonFormatter::new();
        formatter.format(results)
    }
    
    fn generate_html_report(&self, results: &AnalysisResults) -> Result<String> {
        let formatter = HtmlFormatter::new()
            .with_code_snippets(self.include_code_snippets)
            .with_suggestions(self.include_suggestions)
            .group_by_severity(self.group_by_severity)
            .group_by_type(self.group_by_type);
        
        formatter.format(results)
    }
    
    fn generate_markdown_report(&self, results: &AnalysisResults) -> Result<String> {
        let formatter = MarkdownFormatter::new()
            .with_code_snippets(self.include_code_snippets)
            .with_suggestions(self.include_suggestions)
            .group_by_severity(self.group_by_severity)
            .group_by_type(self.group_by_type);
        
        formatter.format(results)
    }
    
    fn generate_text_report(&self, results: &AnalysisResults) -> Result<String> {
        // 纯文本报告，便于终端查看与快速拷贝
        let mut report = String::new();
        
        // Header
        report.push_str(&format!("VulnFusion Analysis Report\n"));
        report.push_str(&format!("============================\n\n"));
        
        // Summary
        report.push_str(&format!("Analysis Summary:\n"));
        report.push_str(&format!("  Total Files Analyzed: {}\n", results.statistics.total_files_analyzed));
        report.push_str(&format!("  Lines of Code: {}\n", results.statistics.total_lines_of_code));
        report.push_str(&format!("  Vulnerabilities Found: {}\n", results.statistics.total_vulnerabilities));
        report.push_str(&format!("  Analysis Duration: {:?}\n\n", results.context.duration()));
        
        // Vulnerabilities by severity
        if !results.statistics.vulnerabilities_by_severity.is_empty() {
            report.push_str("Vulnerabilities by Severity:\n");
            for (severity, count) in &results.statistics.vulnerabilities_by_severity {
                report.push_str(&format!("  {}: {}\n", severity, count));
            }
            report.push_str("\n");
        }
        
        // Vulnerabilities by type
        if !results.statistics.vulnerabilities_by_type.is_empty() {
            report.push_str("Vulnerabilities by Type:\n");
            for (vuln_type, count) in &results.statistics.vulnerabilities_by_type {
                report.push_str(&format!("  {}: {}\n", vuln_type, count));
            }
            report.push_str("\n");
        }
        
        // Detailed vulnerability information
        if !results.vulnerabilities.is_empty() {
            report.push_str("Detailed Vulnerability Information:\n");
            report.push_str("-----------------------------------\n\n");
            
            for (i, vuln) in results.vulnerabilities.iter().enumerate() {
                report.push_str(&format!("Vulnerability #{}\n", i + 1));
                report.push_str(&format!("  Type: {}\n", vuln.vulnerability_type));
                report.push_str(&format!("  Severity: {:?}\n", vuln.severity));
                report.push_str(&format!("  Confidence: {:.1}%\n", vuln.confidence * 100.0));
                report.push_str(&format!("  Location: {}:{}\n", vuln.file_path, vuln.line_number));
                report.push_str(&format!("  Description: {}\n", vuln.description));
                
                if self.include_code_snippets && !vuln.code_snippet.is_empty() {
                    report.push_str(&format!("  Code:\n"));
                    for line in vuln.code_snippet.lines() {
                        report.push_str(&format!("    {}\n", line));
                    }
                }
                
                if self.include_suggestions && !vuln.remediation_suggestion.is_empty() {
                    report.push_str(&format!("  Suggestion: {}\n", vuln.remediation_suggestion));
                }
                
                report.push_str("\n");
            }
        } else {
            report.push_str("No vulnerabilities detected.\n");
        }
        
        Ok(report)
    }
    
    fn generate_sarif_report(&self, results: &AnalysisResults) -> Result<String> {
        // SARIF 是静态分析工具输出的标准交换格式，适合 CI/CD 与平台集成
        
        let sarif_report = serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "VulnFusion",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/vulnfusion/vulnfusion",
                        "rules": self.generate_sarif_rules(results),
                    }
                },
                "results": self.generate_sarif_results(results),
                "invocations": [{
                    "executionSuccessful": true,
                    "endTimeUtc": results.context.analysis_end_time.map(|t| format!("{}", t)),
                }],
                "taxonomies": [{
                    "name": "VulnerabilityTypes",
                    "taxa": self.generate_sarif_taxa(results),
                }],
            }]
        });
        
        Ok(serde_json::to_string_pretty(&sarif_report)?)
    }
    
    fn generate_sarif_rules(&self, results: &AnalysisResults) -> Vec<serde_json::Value> {
        let mut rules = Vec::new();
        let mut seen_types = std::collections::HashSet::new();
        
        for vuln in &results.vulnerabilities {
            if seen_types.insert(vuln.vulnerability_type.clone()) {
                let rule = serde_json::json!({
                    "id": vuln.vulnerability_type.clone(),
                    "name": vuln.vulnerability_type.clone(),
                    "shortDescription": {
                        "text": vuln.description.clone(),
                    },
                    "fullDescription": {
                        "text": vuln.detailed_explanation.clone(),
                    },
                    "help": {
                        "text": vuln.remediation_suggestion.clone(),
                    },
                    "defaultConfiguration": {
                        "level": self.severity_to_sarif_level(&vuln.severity),
                    },
                    "properties": {
                        "confidence": vuln.confidence,
                        "category": "security",
                    },
                });
                
                rules.push(rule);
            }
        }
        
        rules
    }
    
    fn generate_sarif_results(&self, results: &AnalysisResults) -> Vec<serde_json::Value> {
        results.vulnerabilities.iter().map(|vuln| {
            serde_json::json!({
                "ruleId": vuln.vulnerability_type.clone(),
                "level": self.severity_to_sarif_level(&vuln.severity),
                "message": {
                    "text": format!("{}: {}", vuln.description, vuln.detailed_explanation),
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": vuln.file_path.clone(),
                        },
                        "region": {
                            "startLine": vuln.line_number,
                            "startColumn": vuln.column_number.unwrap_or(1),
                        },
                    },
                }],
                "properties": {
                    "confidence": vuln.confidence,
                    "codeSnippet": vuln.code_snippet.clone(),
                    "remediation": vuln.remediation_suggestion.clone(),
                },
            })
        }).collect()
    }
    
    fn generate_sarif_taxa(&self, results: &AnalysisResults) -> Vec<serde_json::Value> {
        let mut taxa = Vec::new();
        let mut seen_types = std::collections::HashSet::new();
        
        for vuln in &results.vulnerabilities {
            if seen_types.insert(vuln.vulnerability_type.clone()) {
                let taxon = serde_json::json!({
                    "id": vuln.vulnerability_type.clone(),
                    "name": vuln.vulnerability_type.clone(),
                    "shortDescription": {
                        "text": vuln.description.clone(),
                    },
                    "defaultConfiguration": {
                        "level": self.severity_to_sarif_level(&vuln.severity),
                    },
                });
                
                taxa.push(taxon);
            }
        }
        
        taxa
    }
    
    fn severity_to_sarif_level(&self, severity: &VulnerabilitySeverity) -> &'static str {
        // 将严重程度转换为 SARIF 等级
        match severity {
            VulnerabilitySeverity::Critical => "error",
            VulnerabilitySeverity::High => "error",
            VulnerabilitySeverity::Medium => "warning",
            VulnerabilitySeverity::Low => "note",
            VulnerabilitySeverity::Info => "none",
        }
    }
}