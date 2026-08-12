"""
SentinelGraph — Report Generator

Generates professional security assessment reports in HTML and JSON.
Uses Jinja2 templates for rich HTML output with severity charts,
finding details, and remediation guidance.
"""

import json
from datetime import datetime
from dataclasses import dataclass, field, asdict
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ReportMetadata:
    """Report metadata."""
    title: str = "Security Assessment Report"
    target: str = ""
    generated_at: str = ""
    scanner_version: str = "SentinelGraph 0.1.0"
    scan_duration: str = ""
    pages_crawled: int = 0
    total_findings: int = 0
    severity_counts: dict = field(default_factory=dict)
    technologies: list = field(default_factory=list)
    headers_grade: str = ""
    ssl_info: dict = field(default_factory=dict)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SentinelGraph — Security Report: {{ meta.target }}</title>
<style>
  :root {
    --bg: #0f1117;
    --surface: #1a1d27;
    --border: #2a2d3a;
    --text: #e2e8f0;
    --text-muted: #94a3b8;
    --accent: #6366f1;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #3b82f6;
    --info: #6b7280;
    --emerald: #10b981;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: 'Inter', 'Segoe UI', sans-serif; line-height: 1.6; }
  .container { max-width: 900px; margin: 0 auto; padding: 40px 24px; }
  .header { text-align: center; margin-bottom: 48px; padding: 40px; background: var(--surface); border-radius: 16px; border: 1px solid var(--border); }
  .header h1 { font-size: 2rem; font-weight: 700; margin-bottom: 8px; color: var(--accent); }
  .header .target { font-family: monospace; font-size: 1.1rem; color: var(--emerald); margin-bottom: 16px; }
  .header .meta { display: flex; justify-content: center; gap: 24px; font-size: 0.8rem; color: var(--text-muted); }
  .metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }
  .metric-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center; }
  .metric-card .value { font-size: 2rem; font-weight: 700; }
  .metric-card .label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; margin-top: 4px; }
  .severity-bar { display: flex; height: 12px; border-radius: 6px; overflow: hidden; gap: 2px; margin: 16px 0; }
  .severity-bar div { transition: width 0.5s ease; }
  .section { background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 24px; margin-bottom: 24px; }
  .section h2 { font-size: 1.2rem; font-weight: 600; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border); }
  .finding { border: 1px solid var(--border); border-radius: 12px; padding: 16px; margin-bottom: 12px; }
  .finding:hover { border-color: var(--accent); }
  .finding-header { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
  .badge { padding: 2px 10px; border-radius: 999px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
  .badge-critical { background: rgba(239,68,68,0.15); color: var(--critical); border: 1px solid rgba(239,68,68,0.3); }
  .badge-high { background: rgba(249,115,22,0.15); color: var(--high); border: 1px solid rgba(249,115,22,0.3); }
  .badge-medium { background: rgba(234,179,8,0.15); color: var(--medium); border: 1px solid rgba(234,179,8,0.3); }
  .badge-low { background: rgba(59,130,246,0.15); color: var(--low); border: 1px solid rgba(59,130,246,0.3); }
  .badge-info { background: rgba(107,114,128,0.15); color: var(--info); border: 1px solid rgba(107,114,128,0.3); }
  .finding-title { font-weight: 600; font-size: 0.95rem; }
  .finding-desc { font-size: 0.8rem; color: var(--text-muted); margin: 8px 0; }
  .finding-url { font-family: monospace; font-size: 0.75rem; color: var(--emerald); word-break: break-all; }
  .remediation { background: rgba(16,185,129,0.05); border: 1px solid rgba(16,185,129,0.15); border-radius: 8px; padding: 12px; margin-top: 12px; }
  .remediation-label { font-size: 0.7rem; font-weight: 600; color: var(--emerald); text-transform: uppercase; margin-bottom: 4px; }
  .remediation-text { font-size: 0.8rem; color: var(--text); }
  .tech-tag { display: inline-block; padding: 4px 12px; background: rgba(99,102,241,0.1); color: var(--accent); border: 1px solid rgba(99,102,241,0.2); border-radius: 6px; font-size: 0.75rem; font-weight: 600; margin: 2px; }
  .ssl-row { display: flex; justify-content: space-between; padding: 8px 12px; background: rgba(255,255,255,0.02); border-radius: 8px; margin-bottom: 4px; }
  .ssl-label { font-size: 0.75rem; color: var(--text-muted); }
  .ssl-value { font-size: 0.8rem; font-weight: 500; }
  .footer { text-align: center; padding: 32px; font-size: 0.75rem; color: var(--text-muted); }
  @media print { body { background: white; color: #1a1a1a; } .container { max-width: 100%; } }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🛡️ SentinelGraph Security Report</h1>
    <div class="target">{{ meta.target }}</div>
    <div class="meta">
      <span>📅 {{ meta.generated_at }}</span>
      <span>⏱ Duration: {{ meta.scan_duration }}</span>
      <span>📄 {{ meta.pages_crawled }} pages probed</span>
    </div>
  </div>

  <div class="metrics">
    <div class="metric-card">
      <div class="value" style="color: var(--accent);">{{ meta.total_findings }}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="metric-card">
      <div class="value" style="color: var(--critical);">{{ meta.severity_counts.get('critical', 0) }}</div>
      <div class="label">Critical</div>
    </div>
    <div class="metric-card">
      <div class="value" style="color: var(--high);">{{ meta.severity_counts.get('high', 0) }}</div>
      <div class="label">High</div>
    </div>
    <div class="metric-card">
      <div class="value" style="color: var(--medium);">{{ meta.severity_counts.get('medium', 0) }}</div>
      <div class="label">Medium</div>
    </div>
  </div>

  <div class="section">
    <h2>Severity Distribution</h2>
    <div class="severity-bar">
      {% for sev, count in meta.severity_counts.items() %}
      <div style="width: {{ (count / meta.total_findings * 100) if meta.total_findings > 0 else 0 }}%; background: var(--{{ sev }});"></div>
      {% endfor %}
    </div>
    {% for sev, count in meta.severity_counts.items() %}
    <span style="font-size: 0.8rem; margin-right: 16px; color: var(--{{ sev }});">● {{ sev|capitalize }}: {{ count }}</span>
    {% endfor %}
  </div>

  {% if meta.technologies %}
  <div class="section">
    <h2>Detected Technologies</h2>
    {% for tech in meta.technologies %}
    <span class="tech-tag">{{ tech }}</span>
    {% endfor %}
  </div>
  {% endif %}

  {% if meta.ssl_info %}
  <div class="section">
    <h2>SSL/TLS Certificate</h2>
    {% for key, value in meta.ssl_info.items() %}
    <div class="ssl-row">
      <span class="ssl-label">{{ key|replace('_', ' ')|title }}</span>
      <span class="ssl-value" style="color: var(--emerald);">{{ value }}</span>
    </div>
    {% endfor %}
  </div>
  {% endif %}

  <div class="section">
    <h2>Security Headers Grade: {{ meta.headers_grade }}</h2>
    <div style="font-size: 3rem; text-align: center; font-weight: 700; color: {% if meta.headers_grade in ['A+', 'A', 'B'] %}var(--emerald){% elif meta.headers_grade == 'C' %}var(--medium){% else %}var(--high){% endif %};">
      {{ meta.headers_grade }}
    </div>
  </div>

  <div class="section">
    <h2>Findings ({{ findings|length }})</h2>
    {% for finding in findings %}
    <div class="finding">
      <div class="finding-header">
        <span class="badge badge-{{ finding.severity }}">{{ finding.severity }}</span>
        <span class="finding-title">{{ finding.title }}</span>
      </div>
      <div class="finding-desc">{{ finding.description }}</div>
      <div class="finding-url">{{ finding.url }}</div>
      {% if finding.remediation %}
      <div class="remediation">
        <div class="remediation-label">Remediation</div>
        <div class="remediation-text">{{ finding.remediation }}</div>
      </div>
      {% endif %}
    </div>
    {% endfor %}
  </div>

  <div class="footer">
    <p>Generated by {{ meta.scanner_version }}</p>
    <p>This report is confidential and intended for authorized personnel only.</p>
  </div>
</div>
</body>
</html>"""


class ReportGenerator:
    """Generates security assessment reports."""

    @staticmethod
    def generate_html(scan_results: dict, output_path: str = "report.html") -> str:
        """Generate HTML report from scan results."""
        from jinja2 import Template

        meta = ReportMetadata(
            target=scan_results.get("target", "Unknown"),
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            scan_duration=f"{scan_results.get('started_at', '')} → {scan_results.get('completed_at', '')}",
            pages_crawled=scan_results.get("pages_crawled", 0),
            total_findings=scan_results.get("total_findings", 0),
            severity_counts=scan_results.get("severity_counts", {}),
            technologies=scan_results.get("technologies", []),
            headers_grade=scan_results.get("headers_grade", ""),
            ssl_info=scan_results.get("ssl_info", {}),
        )

        template = Template(HTML_TEMPLATE)
        html = template.render(
            meta=meta,
            findings=scan_results.get("findings", []),
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info("report.generated", path=output_path, findings=meta.total_findings)
        return output_path

    @staticmethod
    def generate_json(scan_results: dict, output_path: str = "report.json") -> str:
        """Generate JSON report for programmatic consumption."""
        report = {
            "report_version": "1.0",
            "generator": "SentinelGraph 0.1.0",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            **scan_results,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        return output_path

    @staticmethod
    def generate_sarif(scan_results: dict, output_path: str = "report.sarif") -> str:
        """Generate SARIF 2.1.0 report for CI/CD integration."""
        rules = []
        results = []

        for i, finding in enumerate(scan_results.get("findings", [])):
            rule_id = f"SG-{i+1:04d}"
            level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

            rules.append({
                "id": rule_id,
                "shortDescription": {"text": finding.get("title", "")},
                "fullDescription": {"text": finding.get("description", "")},
                "help": {"text": finding.get("remediation", ""), "markdown": finding.get("remediation", "")},
                "defaultConfiguration": {"level": level_map.get(finding.get("severity", "info"), "note")},
            })

            results.append({
                "ruleId": rule_id,
                "message": {"text": finding.get("description", "")},
                "level": level_map.get(finding.get("severity", "info"), "note"),
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.get("url", "")},
                    }
                }],
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SentinelGraph",
                        "version": "0.1.0",
                        "informationUri": "https://sentinelgraph.dev",
                        "rules": rules,
                    }
                },
                "results": results,
            }],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)

        return output_path
