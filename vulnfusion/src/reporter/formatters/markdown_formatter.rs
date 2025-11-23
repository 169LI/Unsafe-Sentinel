use crate::utils::error::Result;
use crate::analyzer::AnalysisResults;

pub struct MarkdownFormatter {
    include_code_snippets: bool,
    include_suggestions: bool,
    group_by_severity: bool,
    group_by_type: bool,
}

impl MarkdownFormatter {
    pub fn new() -> Self {
        Self {
            include_code_snippets: true,
            include_suggestions: true,
            group_by_severity: true,
            group_by_type: false,
        }
    }
    
    pub fn with_code_snippets(mut self, include: bool) -> Self {
        self.include_code_snippets = include;
        self
    }
    
    pub fn with_suggestions(mut self, include: bool) -> Self {
        self.include_suggestions = include;
        self
    }
    
    pub fn group_by_severity(mut self, group: bool) -> Self {
        self.group_by_severity = group;
        self
    }
    
    pub fn group_by_type(mut self, group: bool) -> Self {
        self.group_by_type = group;
        self
    }
    
    pub fn format(&self, results: &AnalysisResults) -> Result<String> {
        let mut markdown = String::new();
        
        // Header
        markdown.push_str("# VulnFusion 安全分析报告\n\n");
        markdown.push_str("融合 Rudra 与 SafeDrop 的高级漏洞检测\n\n");
        
        // Summary
        markdown.push_str("## 分析摘要\n\n");
        markdown.push_str(&format!("- **分析文件总数：** {}\n", results.statistics.total_files_analyzed));
        markdown.push_str(&format!("- **代码行数：** {}\n", results.statistics.total_lines_of_code));
        markdown.push_str(&format!("- **发现漏洞数：** {}\n", results.statistics.total_vulnerabilities));
        markdown.push_str(&format!("- **分析时长：** {:?}\n", results.context.duration()));
        markdown.push_str(&format!("- **unsafe 块数：** {}\n\n", results.context.unsafe_blocks_found));
        
        // Vulnerabilities by severity
        if !results.statistics.vulnerabilities_by_severity.is_empty() {
            markdown.push_str("### 按严重程度统计\n\n");
            markdown.push_str("| 严重程度 | 数量 |\n");
            markdown.push_str("|----------|-------|\n");
            
            // Sort severities in order: Critical, High, Medium, Low, Info
            let mut severities: Vec<_> = results.statistics.vulnerabilities_by_severity.iter().collect();
            severities.sort_by(|a, b| self.severity_order(a.0).cmp(&self.severity_order(b.0)));
            
            for (severity, count) in severities {
                markdown.push_str(&format!("| {} | {} |\n", severity, count));
            }
            markdown.push_str("\n");
        }
        
        // Vulnerabilities by type
        if !results.statistics.vulnerabilities_by_type.is_empty() {
            markdown.push_str("### 按类型统计\n\n");
            markdown.push_str("| 类型 | 数量 |\n");
            markdown.push_str("|------|-------|\n");
            
            let mut types: Vec<_> = results.statistics.vulnerabilities_by_type.iter().collect();
            types.sort_by(|a, b| b.1.cmp(a.1)); // Sort by count (descending)
            
            for (vuln_type, count) in types {
                markdown.push_str(&format!("| {} | {} |\n", vuln_type, count));
            }
            markdown.push_str("\n");
        }
        
        // Detailed vulnerability information
        if results.vulnerabilities.is_empty() {
            markdown.push_str("## 🎉 未发现漏洞\n\n");
            markdown.push_str("当前代码看起来是安全的，继续保持！\n\n");
        } else {
            markdown.push_str("## 漏洞详情\n\n");
            
            let vulnerabilities = if self.group_by_severity {
                self.group_vulnerabilities_by_severity(&results.vulnerabilities)
            } else if self.group_by_type {
                self.group_vulnerabilities_by_type(&results.vulnerabilities)
            } else {
                vec![("All Vulnerabilities".to_string(), results.vulnerabilities.clone())]
            };
            
            for (group_name, group_vulns) in vulnerabilities {
                if !group_vulns.is_empty() {
                    markdown.push_str(&format!("### {}（共 {} 条）\n\n", group_name, group_vulns.len()));
                    
                    for (i, vuln) in group_vulns.iter().enumerate() {
                        markdown.push_str(&self.format_vulnerability(vuln, i + 1)?);
                    }
                }
            }
        }
        
        // Footer
        markdown.push_str("---\n\n");
        markdown.push_str("*由 VulnFusion 生成 - 高级漏洞检测工具*\n");
        markdown.push_str("*融合 Rudra 与 SafeDrop 技术*\n");
        
        Ok(markdown)
    }
    
    fn format_vulnerability(&self, vuln: &crate::analyzer::Vulnerability, index: usize) -> Result<String> {
        let mut markdown = String::new();
        
        markdown.push_str(&format!("#### 漏洞 #{}：{}\n\n", index, vuln.description));
        
        // Metadata
        markdown.push_str("**详情：**\n");
        markdown.push_str(&format!("- **Type:** `{}`\n", vuln.vulnerability_type));
        markdown.push_str(&format!("- **Severity:** `{}`\n", format!("{:?}", vuln.severity)));
        markdown.push_str(&format!("- **Confidence:** `{:.1}%`\n", vuln.confidence * 100.0));
        markdown.push_str(&format!("- **Location:** `{}:{}`\n", vuln.file_path, vuln.line_number));
        
        if let Some(column) = vuln.column_number {
            markdown.push_str(&format!("- **列号：** `{}`\n", column));
        }
        
        markdown.push_str(&format!("- **检测方法：** `{}`\n", format!("{:?}", vuln.detection_method)));
        markdown.push_str("\n");
        
        // Explanation
        markdown.push_str("**解释：**\n");
        markdown.push_str(&format!("{}\n\n", vuln.detailed_explanation));
        
        // Code snippet
        if self.include_code_snippets && !vuln.code_snippet.is_empty() {
            markdown.push_str("**代码：**\n");
            markdown.push_str("```rust\n");
            markdown.push_str(&vuln.code_snippet);
            markdown.push_str("\n```\n\n");
        }
        
        // Remediation suggestion
        if self.include_suggestions && !vuln.remediation_suggestion.is_empty() {
            markdown.push_str("**💡 建议：**\n");
            markdown.push_str(&format!("{}\n\n", vuln.remediation_suggestion));
        }
        
        // Related locations
        if !vuln.related_code_locations.is_empty() {
            markdown.push_str("**相关位置：**\n");
            for (i, location) in vuln.related_code_locations.iter().enumerate() {
                markdown.push_str(&format!("{}. `{}:{}`\n", i + 1, location.file_path, location.line_number));
                if !location.context.is_empty() {
                    markdown.push_str(&format!("   上下文：{}\n", location.context));
                }
            }
            markdown.push_str("\n");
        }
        
        // Metadata
        if !vuln.metadata.is_empty() {
            markdown.push_str("**附加元数据：**\n");
            for (key, value) in &vuln.metadata {
                markdown.push_str(&format!("- **{}:** {}\n", key, serde_json::to_string(value)?));
            }
            markdown.push_str("\n");
        }
        
        Ok(markdown)
    }
    
    fn group_vulnerabilities_by_severity(&self, vulnerabilities: &[crate::analyzer::Vulnerability]) -> Vec<(String, Vec<crate::analyzer::Vulnerability>)> {
        let mut groups: std::collections::HashMap<String, Vec<crate::analyzer::Vulnerability>> = std::collections::HashMap::new();
        
        for vuln in vulnerabilities {
            let severity = format!("{:?}", vuln.severity);
            groups.entry(severity).or_default().push(vuln.clone());
        }
        
        // Sort by severity (Critical, High, Medium, Low, Info)
        let mut sorted_groups: Vec<(String, Vec<crate::analyzer::Vulnerability>)> = groups.into_iter().collect();
        sorted_groups.sort_by(|a, b| self.severity_order(&a.0).cmp(&self.severity_order(&b.0)));
        
        sorted_groups
    }
    
    fn group_vulnerabilities_by_type(&self, vulnerabilities: &[crate::analyzer::Vulnerability]) -> Vec<(String, Vec<crate::analyzer::Vulnerability>)> {
        let mut groups: std::collections::HashMap<String, Vec<crate::analyzer::Vulnerability>> = std::collections::HashMap::new();
        
        for vuln in vulnerabilities {
            groups.entry(vuln.vulnerability_type.clone()).or_default().push(vuln.clone());
        }
        
        let mut sorted_groups: Vec<(String, Vec<crate::analyzer::Vulnerability>)> = groups.into_iter().collect();
        sorted_groups.sort_by(|a, b| b.1.len().cmp(&a.1.len())); // Sort by count (descending)
        
        sorted_groups
    }
    
    fn severity_order(&self, severity: &str) -> i32 {
        match severity {
            "Critical" => 0,
            "High" => 1,
            "Medium" => 2,
            "Low" => 3,
            "Info" => 4,
            _ => 5,
        }
    }
}