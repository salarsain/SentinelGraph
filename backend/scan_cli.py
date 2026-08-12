#!/usr/bin/env python3
"""
SentinelGraph — CLI Scanner Runner

Standalone script to run a security scan from command line or CI/CD.
No API server needed — runs the scanner directly and outputs results.

Usage:
    python scan_cli.py https://cyberhackathon.pk
    python scan_cli.py https://cyberhackathon.pk --type full --output ./results
"""

import asyncio
import json
import sys
import os
import argparse
from datetime import datetime
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))


async def run_scan(target_url: str, scan_type: str, output_dir: str):
    """Run a security scan and save results."""
    from full_scanner import FullScanner
    from app.engine.report.generator import ReportGenerator

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    results_file = output_path / f"scan_results_{timestamp}.json"
    report_file = output_path / f"scan_report_{timestamp}.html"
    summary_file = output_path / f"scan_summary_{timestamp}.md"

    print(f"═══════════════════════════════════════════════════════")
    print(f"  SentinelGraph Security Scanner v0.1.0")
    print(f"  Target:    {target_url}")
    print(f"  Scan Type: {scan_type}")
    print(f"  Started:   {datetime.utcnow().isoformat()}Z")
    print(f"═══════════════════════════════════════════════════════")

    scanner = FullScanner()

    try:
        if scan_type == "full":
            result = await scanner.scan(target_url)
        else:
            from scanner import run_scan as quick_scan
            result = await quick_scan(target_url)
    except Exception as e:
        print(f"\n❌ Scan failed: {e}")
        # Write error summary
        error_summary = {
            "target": target_url,
            "status": "failed",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        with open(results_file, "w") as f:
            json.dump(error_summary, f, indent=2)
        sys.exit(1)

    # Save JSON results
    with open(results_file, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"\n📄 Results saved: {results_file}")

    # Generate HTML report
    try:
        ReportGenerator.generate_html(result, str(report_file))
        print(f"📊 Report saved: {report_file}")
    except Exception as e:
        print(f"⚠ Report generation failed: {e}")

    # Generate Markdown summary for GitHub Actions
    severity_counts = result.get("severity_counts", {})
    total_findings = result.get("total_findings", 0)
    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    medium = severity_counts.get("medium", 0)
    low = severity_counts.get("low", 0)
    info = severity_counts.get("info", 0)

    md_summary = f"""# 🛡️ SentinelGraph Security Scan Report

**Target:** `{target_url}`
**Date:** {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}
**Status:** {result.get("status", "complete")}
**Headers Grade:** {result.get("headers_grade", "N/A")}

## 📊 Findings Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {critical} |
| 🟠 High | {high} |
| 🟡 Medium | {medium} |
| 🔵 Low | {low} |
| ⚪ Info | {info} |
| **Total** | **{total_findings}** |

## 🔍 Technologies Detected

{chr(10).join(f"- {tech}" for tech in result.get("technologies", []))}

## 🔒 SSL/TLS Info

"""
    ssl_info = result.get("ssl_info", {})
    if ssl_info:
        md_summary += f"""- **Issuer:** {ssl_info.get("issuer", "N/A")}
- **Subject:** {ssl_info.get("subject", "N/A")}
- **Valid From:** {ssl_info.get("valid_from", "N/A")}
- **Valid To:** {ssl_info.get("valid_to", "N/A")}
"""
    else:
        md_summary += "No SSL data available.\n"

    md_summary += f"""
## 📋 Detailed Findings

"""
    for i, finding in enumerate(result.get("findings", []), 1):
        severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(finding.get("severity", "info"), "⚪")
        md_summary += f"""### {i}. {severity_icon} {finding.get("title", "Unknown")}
- **Severity:** {finding.get("severity", "unknown").upper()}
- **URL:** `{finding.get("url", "N/A")}`
- **Category:** {finding.get("category", "N/A")}
- **Confidence:** {finding.get("confidence", 0):.0%}
- **Remediation:** {finding.get("remediation", "N/A")}

"""

    with open(summary_file, "w", encoding="utf-8") as f:
        f.write(md_summary)
    print(f"📝 Summary saved: {summary_file}")

    # Set GitHub Actions outputs if running in CI
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"total_findings={total_findings}\n")
            f.write(f"critical_count={critical}\n")
            f.write(f"high_count={high}\n")
            f.write(f"scan_status={result.get('status', 'complete')}\n")
            f.write(f"results_file={results_file}\n")
            f.write(f"report_file={report_file}\n")
            f.write(f"summary_file={summary_file}\n")

    # Set GitHub Actions step summary
    github_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if github_summary:
        with open(github_summary, "a", encoding="utf-8") as f:
            f.write(md_summary)

    # Print summary
    print(f"\n═══════════════════════════════════════════════════════")
    print(f"  Scan Complete!")
    print(f"  Total Findings: {total_findings}")
    print(f"  Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}")
    print(f"═══════════════════════════════════════════════════════")

    # Exit with error code if critical/high findings found
    if critical > 0 or high > 0:
        print(f"\n⚠ {critical + high} critical/high severity findings detected!")
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="SentinelGraph Security Scanner CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target_url", help="Target URL to scan (e.g., https://cyberhackathon.pk)")
    parser.add_argument("--type", choices=["full", "quick"], default="full", help="Scan type (default: full)")
    parser.add_argument("--output", default="./scan_output", help="Output directory (default: ./scan_output)")
    args = parser.parse_args()

    exit_code = asyncio.run(run_scan(args.target_url, args.type, args.output))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
