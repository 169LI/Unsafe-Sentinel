// HTML report templates
pub const REPORT_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnFusion Security Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f4f4f4; padding: 20px; border-radius: 5px; }
        .vulnerability { margin: 10px 0; padding: 15px; border-left: 4px solid #ff6b6b; background-color: #fff5f5; }
        .critical { border-left-color: #d63031; }
        .high { border-left-color: #e17055; }
        .medium { border-left-color: #fdcb6e; }
        .low { border-left-color: #6c5ce7; }
        .info { border-left-color: #74b9ff; }
        .code-snippet { background-color: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; }
        .statistics { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat-box { text-align: center; padding: 15px; background-color: #e8f4f8; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>VulnFusion Security Analysis Report</h1>
        <p>Generated on: {{ generation_date }}</p>
        <p>Project: {{ project_name }}</p>
        <p>Total Vulnerabilities: {{ total_vulnerabilities }}</p>
    </div>
    
    <div class="statistics">
        <div class="stat-box">
            <h3>{{ critical_count }}</h3>
            <p>Critical</p>
        </div>
        <div class="stat-box">
            <h3>{{ high_count }}</h3>
            <p>High</p>
        </div>
        <div class="stat-box">
            <h3>{{ medium_count }}</h3>
            <p>Medium</p>
        </div>
        <div class="stat-box">
            <h3>{{ low_count }}</h3>
            <p>Low</p>
        </div>
    </div>
    
    <h2>Vulnerabilities Found</h2>
    {% for vuln in vulnerabilities %}
    <div class="vulnerability {{ vuln.severity | lower }}">
        <h3>{{ vuln.vulnerability_type }} - {{ vuln.severity }}</h3>
        <p><strong>File:</strong> {{ vuln.file_path }}:{{ vuln.line_number }}</p>
        <p><strong>Description:</strong> {{ vuln.description }}</p>
        <p><strong>Confidence:</strong> {{ vuln.confidence | round(2) }}</p>
        {% if vuln.code_snippet %}
        <div class="code-snippet">
            <strong>Code:</strong><br>
            <pre>{{ vuln.code_snippet }}</pre>
        </div>
        {% endif %}
        <p><strong>Remediation:</strong> {{ vuln.remediation_suggestion }}</p>
    </div>
    {% endfor %}
</body>
</html>
"#;