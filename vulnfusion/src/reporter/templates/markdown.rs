// Markdown report templates
pub const REPORT_TEMPLATE: &str = r#"# VulnFusion Security Analysis Report

**Generated on:** {{ generation_date }}  
**Project:** {{ project_name }}  
**Total Vulnerabilities:** {{ total_vulnerabilities }}

## Summary Statistics

| Severity | Count |
|----------|-------|
| Critical | {{ critical_count }} |
| High     | {{ high_count }} |
| Medium   | {{ medium_count }} |
| Low      | {{ low_count }} |

## Vulnerabilities Found

{% for vuln in vulnerabilities %}
### {{ vuln.vulnerability_type }} - {{ vuln.severity }}

- **File:** `{{ vuln.file_path }}:{{ vuln.line_number }}`
- **Severity:** {{ vuln.severity }}
- **Confidence:** {{ vuln.confidence | round(2) }}
- **Description:** {{ vuln.description }}

{% if vuln.code_snippet %}
**Code:**
```rust
{{ vuln.code_snippet }}
```
{% endif %}

**Remediation:** {{ vuln.remediation_suggestion }}

---
{% endfor %}
"#;