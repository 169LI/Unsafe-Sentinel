// 中文说明：
// HtmlFormatter 以富样式的 HTML 页面展示分析结果，包含摘要卡片、统计图表（Chart.js）、
// 漏洞分组与详细条目，适合竞赛提交与人工审阅。
use crate::utils::error::Result;
use crate::analyzer::AnalysisResults;

pub struct HtmlFormatter {
    include_code_snippets: bool,
    include_suggestions: bool,
    group_by_severity: bool,
    group_by_type: bool,
    include_charts: bool,
}

impl HtmlFormatter {
    pub fn new() -> Self {
        Self {
            include_code_snippets: true,
            include_suggestions: true,
            group_by_severity: true,
            group_by_type: false,
            include_charts: true,
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
    
    pub fn with_charts(mut self, include: bool) -> Self {
        self.include_charts = include;
        self
    }
    
    pub fn format(&self, results: &AnalysisResults) -> Result<String> {
        let mut html = String::new();
        
        // HTML header
        html.push_str(&self.generate_header());
        
        // Summary section
        html.push_str(&self.generate_summary(results)?);
        
        // Statistics section
        if self.include_charts {
            html.push_str(&self.generate_statistics(results)?);
        }
        
        // Vulnerabilities section
        html.push_str(&self.generate_vulnerabilities(results)?);
        
        // Footer
        html.push_str(&self.generate_footer());
        
        Ok(html)
    }
    
    fn generate_header(&self) -> String {
        format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnFusion Analysis Report</title>
    <style>
        {}
    </style>
    {}
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>VulnFusion Security Analysis Report</h1>
            <p class="subtitle">Advanced vulnerability detection combining Rudra and SafeDrop techniques</p>
        </header>
"#, self.generate_css(), if self.include_charts { self.generate_chart_scripts() } else { String::new() })
    }
    
    fn generate_css(&self) -> String {
        r#"
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }
        
        .subtitle {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        .summary {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
        }
        
        .summary h2 {
            color: #2c3e50;
            margin-bottom: 1rem;
            font-size: 1.8rem;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .summary-card {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #3498db;
        }
        
        .summary-card.critical {
            border-left-color: #e74c3c;
        }
        
        .summary-card.high {
            border-left-color: #e67e22;
        }
        
        .summary-card.medium {
            border-left-color: #f39c12;
        }
        
        .summary-card.low {
            border-left-color: #27ae60;
        }
        
        .summary-card h3 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }
        
        .summary-card p {
            color: #7f8c8d;
            font-size: 0.9rem;
        }
        
        .statistics {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
        }
        
        .statistics h2 {
            color: #2c3e50;
            margin-bottom: 1rem;
            font-size: 1.8rem;
        }
        
        .chart-container {
            margin: 1rem 0;
            height: 300px;
        }
        
        .vulnerabilities {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .vulnerabilities h2 {
            color: #2c3e50;
            margin-bottom: 1rem;
            font-size: 1.8rem;
        }
        
        .vulnerability {
            margin-bottom: 2rem;
            padding: 1.5rem;
            border-radius: 8px;
            border-left: 4px solid #3498db;
            background: #f8f9fa;
        }
        
        .vulnerability.critical {
            border-left-color: #e74c3c;
            background: #fdf2f2;
        }
        
        .vulnerability.high {
            border-left-color: #e67e22;
            background: #fef5e7;
        }
        
        .vulnerability.medium {
            border-left-color: #f39c12;
            background: #fffbf0;
        }
        
        .vulnerability.low {
            border-left-color: #27ae60;
            background: #f0fff4;
        }
        
        .vulnerability-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .vulnerability-title {
            font-size: 1.2rem;
            font-weight: 600;
            color: #2c3e50;
        }
        
        .vulnerability-meta {
            display: flex;
            gap: 1rem;
            font-size: 0.9rem;
            color: #7f8c8d;
        }
        
        .severity-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-badge.critical {
            background: #e74c3c;
            color: white;
        }
        
        .severity-badge.high {
            background: #e67e22;
            color: white;
        }
        
        .severity-badge.medium {
            background: #f39c12;
            color: white;
        }
        
        .severity-badge.low {
            background: #27ae60;
            color: white;
        }
        
        .vulnerability-description {
            margin-bottom: 1rem;
            color: #555;
        }
        
        .vulnerability-code {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 1rem;
            border-radius: 6px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            margin: 1rem 0;
        }
        
        .vulnerability-suggestion {
            background: #e8f6f3;
            border: 1px solid #27ae60;
            border-radius: 6px;
            padding: 1rem;
            margin-top: 1rem;
        }
        
        .vulnerability-suggestion h4 {
            color: #27ae60;
            margin-bottom: 0.5rem;
        }
        
        .footer {
            text-align: center;
            padding: 2rem;
            color: #7f8c8d;
            font-size: 0.9rem;
        }
        
        .no-vulnerabilities {
            text-align: center;
            padding: 2rem;
            color: #27ae60;
            font-size: 1.2rem;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }
            
            .vulnerability-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.5rem;
            }
        }
        "#.to_string()
    }
    
    fn generate_chart_scripts(&self) -> String {
        r#"
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script>
            function createSeverityChart(data) {
                const ctx = document.getElementById('severityChart');
                if (!ctx) return;
                
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: Object.keys(data),
                        datasets: [{
                            data: Object.values(data),
                            backgroundColor: [
                                '#e74c3c', // Critical
                                '#e67e22', // High
                                '#f39c12', // Medium
                                '#27ae60', // Low
                            ],
                            borderWidth: 0,
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom',
                            },
                            title: {
                                display: true,
                                text: 'Vulnerabilities by Severity',
                                font: {
                                    size: 16,
                                    weight: 'bold',
                                }
                            }
                        }
                    }
                });
            }
            
            function createTypeChart(data) {
                const ctx = document.getElementById('typeChart');
                if (!ctx) return;
                
                new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: Object.keys(data),
                        datasets: [{
                            label: 'Count',
                            data: Object.values(data),
                            backgroundColor: '#3498db',
                            borderWidth: 0,
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Vulnerabilities by Type',
                                font: {
                                    size: 16,
                                    weight: 'bold',
                                }
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: {
                                    stepSize: 1,
                                }
                            }
                        }
                    }
                });
            }
        </script>
        "#.to_string()
    }
    
    fn generate_summary(&self, results: &AnalysisResults) -> Result<String> {
        let mut summary = String::new();
        
        summary.push_str(r#"<div class="summary">"#);
        summary.push_str(&format!(r#"<h2>Analysis Summary</h2>"#));
        
        // Summary cards
        summary.push_str(r#"<div class="summary-grid">"#);
        
        // Total vulnerabilities card
        let total_class = if results.statistics.total_vulnerabilities == 0 {
            "low"
        } else if results.has_critical_vulnerabilities() {
            "critical"
        } else if !results.get_high_severity_vulnerabilities().is_empty() {
            "high"
        } else {
            "medium"
        };
        
        summary.push_str(&format!(r#"
            <div class="summary-card {}">
                <h3>{}</h3>
                <p>Total Vulnerabilities</p>
            </div>
        "#, total_class, results.statistics.total_vulnerabilities));
        
        // Severity breakdown cards
        for (severity, count) in &results.statistics.vulnerabilities_by_severity {
            let severity_class = severity.to_lowercase();
            summary.push_str(&format!(r#"
                <div class="summary-card {}">
                    <h3>{}</h3>
                    <p>{} Severity</p>
                </div>
            "#, severity_class, count, severity));
        }
        
        // Additional summary cards
        summary.push_str(&format!(r#"
            <div class="summary-card">
                <h3>{}</h3>
                <p>Files Analyzed</p>
            </div>
            <div class="summary-card">
                <h3>{}</h3>
                <p>Lines of Code</p>
            </div>
            <div class="summary-card">
                <h3>{:.1}s</h3>
                <p>Analysis Time</p>
            </div>
        "#, 
            results.statistics.total_files_analyzed,
            results.statistics.total_lines_of_code,
            results.performance_metrics.analysis_duration_ms as f64 / 1000.0
        ));
        
        summary.push_str("</div>"); // Close summary-grid
        summary.push_str("</div>"); // Close summary
        
        Ok(summary)
    }
    
    fn generate_statistics(&self, results: &AnalysisResults) -> Result<String> {
        let mut stats = String::new();
        
        stats.push_str(r#"<div class="statistics">"#);
        stats.push_str(&format!(r#"<h2>Vulnerability Statistics</h2>"#));
        
        // Charts
        stats.push_str(r#"<div class="chart-container">"#);
        stats.push_str(r#"<canvas id="severityChart"></canvas>"#);
        stats.push_str("</div>");
        
        if !results.statistics.vulnerabilities_by_type.is_empty() {
            stats.push_str(r#"<div class="chart-container">"#);
            stats.push_str(r#"<canvas id="typeChart"></canvas>"#);
            stats.push_str("</div>");
        }
        
        stats.push_str("</div>"); // Close statistics
        
        // Add chart data initialization script
        stats.push_str(&format!(r#"
            <script>
                document.addEventListener('DOMContentLoaded', function() {{
                    const severityData = {};
                    createSeverityChart(severityData);
                    
                    const typeData = {};
                    createTypeChart(typeData);
                }});
            </script>
        "#,
            serde_json::to_string(&results.statistics.vulnerabilities_by_severity)?,
            serde_json::to_string(&results.statistics.vulnerabilities_by_type)?
        ));
        
        Ok(stats)
    }
    
    fn generate_vulnerabilities(&self, results: &AnalysisResults) -> Result<String> {
        let mut vulns = String::new();
        
        vulns.push_str(r#"<div class="vulnerabilities">"#);
        vulns.push_str(&format!(r#"<h2>Detected Vulnerabilities</h2>"#));
        
        if results.vulnerabilities.is_empty() {
            vulns.push_str(r#"<div class="no-vulnerabilities">"#);
            vulns.push_str(r#"🎉 No vulnerabilities detected! Your code looks secure."#);
            vulns.push_str("</div>");
        } else {
            let vulnerabilities = if self.group_by_severity {
                self.group_vulnerabilities_by_severity(&results.vulnerabilities)
            } else if self.group_by_type {
                self.group_vulnerabilities_by_type(&results.vulnerabilities)
            } else {
                vec![("All Vulnerabilities".to_string(), results.vulnerabilities.clone())]
            };
            
            for (group_name, group_vulns) in vulnerabilities {
                if !group_vulns.is_empty() {
                    vulns.push_str(&format!(r#"<h3>{} ({} found)</h3>"#, group_name, group_vulns.len()));
                    
                    for vuln in group_vulns {
                        vulns.push_str(&self.format_vulnerability(&vuln)?);
                    }
                }
            }
        }
        
        vulns.push_str("</div>"); // Close vulnerabilities
        
        Ok(vulns)
    }
    
    fn format_vulnerability(&self, vuln: &crate::analyzer::Vulnerability) -> Result<String> {
        let severity_class = format!("{:?}", vuln.severity).to_lowercase();
        let confidence_percent = format!("{:.1}%", vuln.confidence * 100.0);
        
        let mut vuln_html = format!(r#"
            <div class="vulnerability {}">
                <div class="vulnerability-header">
                    <div class="vulnerability-title">{}</div>
                    <div class="vulnerability-meta">
                        <span class="severity-badge {}">{}</span>
                        <span>Confidence: {}</span>
                        <span>{}:{}</span>
                    </div>
                </div>
                <div class="vulnerability-description">
                    <p><strong>Description:</strong> {}</p>
                    <p><strong>Explanation:</strong> {}</p>
                </div>
        "#,
            severity_class,
            vuln.description,
            severity_class,
            format!("{:?}", vuln.severity),
            confidence_percent,
            vuln.file_path,
            vuln.line_number,
            vuln.description,
            vuln.detailed_explanation
        );
        
        if self.include_code_snippets && !vuln.code_snippet.is_empty() {
            vuln_html.push_str(&format!(r#"
                <div class="vulnerability-code">
                    {}
                </div>
            "#, html_escape(&vuln.code_snippet)));
        }
        
        if self.include_suggestions && !vuln.remediation_suggestion.is_empty() {
            vuln_html.push_str(&format!(r#"
                <div class="vulnerability-suggestion">
                    <h4>💡 Suggestion</h4>
                    <p>{}</p>
                </div>
            "#, html_escape(&vuln.remediation_suggestion)));
        }
        
        vuln_html.push_str("</div>");
        
        Ok(vuln_html)
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
    
    fn generate_footer(&self) -> String {
        r#"
    </div>
    <footer class="footer">
        <p>Generated by VulnFusion - Advanced Vulnerability Detection Tool</p>
        <p>Combining Rudra and SafeDrop techniques for superior detection</p>
    </footer>
</body>
</html>
"#.to_string()
    }
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}