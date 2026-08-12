"use client";

import { useState, useEffect } from "react";

interface ScanFinding {
  severity: string;
  title: string;
  description: string;
  url: string;
  category: string;
  remediation: string;
  cvss_score: number | null;
  confidence: number;
}

interface ScanData {
  target: string;
  started_at: string;
  completed_at: string;
  status: string;
  technologies: string[];
  headers_grade: string;
  ssl_info: { issuer: string; subject: string; valid_from: string; valid_to: string };
  pages_crawled: number;
  total_findings: number;
  severity_counts: Record<string, number>;
  findings: ScanFinding[];
}

export default function ReportsView() {
  const [scanData, setScanData] = useState<ScanData | null>(null);
  const [selectedFormat, setSelectedFormat] = useState<"html" | "json" | "sarif">("html");

  useEffect(() => {
    fetch("/scan_results.json")
      .then((res) => res.json())
      .then((data) => setScanData(data))
      .catch(() => {});
  }, []);

  const handleExport = () => {
    if (!scanData) return;

    if (selectedFormat === "json") {
      const blob = new Blob([JSON.stringify(scanData, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sentinelgraph_report_${new Date().toISOString().split("T")[0]}.json`;
      a.click();
    } else if (selectedFormat === "sarif") {
      const sarif = generateSarif(scanData);
      const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sentinelgraph_report.sarif`;
      a.click();
    } else {
      const html = generateHtmlReport(scanData);
      const blob = new Blob([html], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      window.open(url, "_blank");
    }
  };

  const generateSarif = (data: ScanData) => ({
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "SentinelGraph", version: "0.1.0", rules: data.findings.map((f, i) => ({
        id: `SG-${String(i + 1).padStart(4, "0")}`,
        shortDescription: { text: f.title },
        fullDescription: { text: f.description },
        help: { text: f.remediation },
      })) }},
      results: data.findings.map((f, i) => ({
        ruleId: `SG-${String(i + 1).padStart(4, "0")}`,
        message: { text: f.description },
        level: { critical: "error", high: "error", medium: "warning", low: "note", info: "note" }[f.severity] || "note",
        locations: [{ physicalLocation: { artifactLocation: { uri: f.url } } }],
      })),
    }],
  });

  const generateHtmlReport = (data: ScanData) => `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>SentinelGraph Report — ${data.target}</title>
<style>
:root{--bg:#0f1117;--s:#1a1d27;--b:#2a2d3a;--t:#e2e8f0;--m:#94a3b8;--a:#6366f1;--cr:#ef4444;--hi:#f97316;--me:#eab308;--lo:#3b82f6;--in:#6b7280;--em:#10b981}
*{margin:0;padding:0;box-sizing:border-box}body{background:var(--bg);color:var(--t);font-family:'Inter',sans-serif;line-height:1.6}
.c{max-width:900px;margin:0 auto;padding:40px 24px}.h{text-align:center;margin-bottom:48px;padding:40px;background:var(--s);border-radius:16px;border:1px solid var(--b)}
.h h1{font-size:2rem;color:var(--a);margin-bottom:8px}.tgt{font-family:monospace;color:var(--em);font-size:1.1rem;margin-bottom:16px}
.mg{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:32px}.mc{background:var(--s);border:1px solid var(--b);border-radius:12px;padding:20px;text-align:center}
.mc .v{font-size:2rem;font-weight:700}.mc .l{font-size:.75rem;color:var(--m);text-transform:uppercase}
.sc{background:var(--s);border:1px solid var(--b);border-radius:16px;padding:24px;margin-bottom:24px}.sc h2{font-size:1.2rem;font-weight:600;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--b)}
.f{border:1px solid var(--b);border-radius:12px;padding:16px;margin-bottom:12px}.f:hover{border-color:var(--a)}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:.7rem;font-weight:600;text-transform:uppercase}
.badge-critical{background:rgba(239,68,68,.15);color:var(--cr)}.badge-high{background:rgba(249,115,22,.15);color:var(--hi)}
.badge-medium{background:rgba(234,179,8,.15);color:var(--me)}.badge-low{background:rgba(59,130,246,.15);color:var(--lo)}.badge-info{background:rgba(107,114,128,.15);color:var(--in)}
.ft{font-weight:600;font-size:.95rem;margin-left:12px}.fd{font-size:.8rem;color:var(--m);margin:8px 0}.fu{font-family:monospace;font-size:.75rem;color:var(--em)}
.rem{background:rgba(16,185,129,.05);border:1px solid rgba(16,185,129,.15);border-radius:8px;padding:12px;margin-top:12px}
.rem-l{font-size:.7rem;font-weight:600;color:var(--em);text-transform:uppercase;margin-bottom:4px}.rem-t{font-size:.8rem}
.tt{display:inline-block;padding:4px 12px;background:rgba(99,102,241,.1);color:var(--a);border:1px solid rgba(99,102,241,.2);border-radius:6px;font-size:.75rem;font-weight:600;margin:2px}
.ft2{text-align:center;padding:32px;font-size:.75rem;color:var(--m)}
</style></head><body><div class="c">
<div class="h"><h1>🛡️ SentinelGraph Security Report</h1><div class="tgt">${data.target}</div>
<div style="font-size:.8rem;color:var(--m)">Generated: ${new Date().toISOString()} • ${data.pages_crawled} pages probed</div></div>
<div class="mg">
<div class="mc"><div class="v" style="color:var(--a)">${data.total_findings}</div><div class="l">Total Findings</div></div>
<div class="mc"><div class="v" style="color:var(--cr)">${data.severity_counts.critical || 0}</div><div class="l">Critical</div></div>
<div class="mc"><div class="v" style="color:var(--hi)">${data.severity_counts.high || 0}</div><div class="l">High</div></div>
<div class="mc"><div class="v" style="color:var(--me)">${data.severity_counts.medium || 0}</div><div class="l">Medium</div></div>
</div>
${data.technologies.length > 0 ? `<div class="sc"><h2>Technologies</h2>${data.technologies.map(t => `<span class="tt">${t}</span>`).join(" ")}</div>` : ""}
${data.ssl_info ? `<div class="sc"><h2>SSL Certificate</h2><div style="display:grid;gap:8px">${Object.entries(data.ssl_info).map(([k, v]) => `<div style="display:flex;justify-content:space-between;padding:8px 12px;background:rgba(255,255,255,.02);border-radius:8px"><span style="font-size:.75rem;color:var(--m)">${k.replace(/_/g," ")}</span><span style="font-size:.8rem;color:var(--em)">${v}</span></div>`).join("")}</div></div>` : ""}
<div class="sc"><h2>Headers Grade: ${data.headers_grade}</h2><div style="font-size:3rem;text-align:center;font-weight:700;color:${["A+","A","B"].includes(data.headers_grade) ? "var(--em)" : "var(--hi)"}">${data.headers_grade}</div></div>
<div class="sc"><h2>Findings (${data.findings.length})</h2>
${data.findings.map(f => `<div class="f"><div style="display:flex;align-items:center;gap:12px;margin-bottom:8px"><span class="badge badge-${f.severity}">${f.severity}</span><span class="ft">${f.title}</span></div><div class="fd">${f.description}</div><div class="fu">${f.url}</div>${f.remediation ? `<div class="rem"><div class="rem-l">Remediation</div><div class="rem-t">${f.remediation}</div></div>` : ""}</div>`).join("")}
</div><div class="ft2"><p>Generated by SentinelGraph v0.1.0</p><p>This report is confidential.</p></div></div></body></html>`;

  if (!scanData) {
    return (
      <div style={{ maxWidth: 1400 }}>
        <h1 style={{ fontSize: "1.75rem", fontWeight: 700, marginBottom: 8 }}>Reports</h1>
        <div className="glass-card" style={{ padding: 40, textAlign: "center", color: "var(--sg-text-muted)" }}>
          No scan data available. Run a scan first.
        </div>
      </div>
    );
  }

  const formats = [
    { id: "html" as const, label: "HTML Report", icon: "📄", desc: "Rich interactive report — opens in new tab" },
    { id: "json" as const, label: "JSON Export", icon: "📋", desc: "Structured data for programmatic use" },
    { id: "sarif" as const, label: "SARIF 2.1.0", icon: "🔧", desc: "CI/CD integration — GitHub, GitLab, Azure DevOps" },
  ];

  return (
    <div style={{ maxWidth: 1400 }}>
      <div style={{ marginBottom: 32 }}>
        <h1 style={{ fontSize: "1.75rem", fontWeight: 700, marginBottom: 4 }}>Reports</h1>
        <p style={{ color: "var(--sg-text-secondary)", fontSize: "0.875rem" }}>
          Generate and export security assessment reports
        </p>
      </div>

      {/* Report Preview Card */}
      <div className="glass-card animate-fade-in" style={{ padding: 28, marginBottom: 24, opacity: 0 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <div>
            <h2 style={{ fontSize: "1.1rem", fontWeight: 600, marginBottom: 4 }}>Latest Scan Report</h2>
            <p style={{ fontSize: "0.8rem", color: "var(--sg-text-muted)", fontFamily: "monospace" }}>
              {scanData.target}
            </p>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span className="status-dot status-dot-complete" />
            <span style={{ fontSize: "0.8rem", color: "var(--sg-accent-emerald)" }}>Complete</span>
          </div>
        </div>

        {/* Stats Row */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12, marginBottom: 24 }}>
          {[
            { label: "Findings", value: scanData.total_findings, color: "var(--sg-accent-primary)" },
            { label: "Critical", value: scanData.severity_counts.critical || 0, color: "var(--sg-critical)" },
            { label: "High", value: scanData.severity_counts.high || 0, color: "var(--sg-high)" },
            { label: "Medium", value: scanData.severity_counts.medium || 0, color: "var(--sg-medium)" },
            { label: "Low", value: scanData.severity_counts.low || 0, color: "var(--sg-low)" },
          ].map((stat) => (
            <div key={stat.label} style={{ padding: "12px 16px", background: "var(--sg-bg-elevated)", borderRadius: 10, textAlign: "center" }}>
              <div style={{ fontSize: "1.5rem", fontWeight: 700, color: stat.color }}>{stat.value}</div>
              <div style={{ fontSize: "0.7rem", color: "var(--sg-text-muted)", marginTop: 2 }}>{stat.label}</div>
            </div>
          ))}
        </div>

        {/* Info Row */}
        <div style={{ display: "flex", gap: 24, fontSize: "0.8rem", color: "var(--sg-text-secondary)", padding: "12px 16px", background: "var(--sg-bg-elevated)", borderRadius: 10 }}>
          <span>📡 Technologies: <strong style={{ color: "var(--sg-accent-primary)" }}>{scanData.technologies.join(", ")}</strong></span>
          <span>🔒 SSL: <strong style={{ color: "var(--sg-accent-emerald)" }}>{scanData.ssl_info?.issuer}</strong></span>
          <span>📊 Headers: <strong style={{ color: "var(--sg-medium)" }}>{scanData.headers_grade}</strong></span>
          <span>📄 Pages: <strong>{scanData.pages_crawled}</strong></span>
        </div>
      </div>

      {/* Export Format Selection */}
      <div className="glass-card animate-fade-in" style={{ padding: 28, marginBottom: 24, animationDelay: "0.1s", opacity: 0 }}>
        <h2 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: 16 }}>Export Format</h2>
        <div style={{ display: "flex", gap: 12, marginBottom: 24 }}>
          {formats.map((fmt) => {
            const isSelected = selectedFormat === fmt.id;
            return (
              <button
                key={fmt.id}
                onClick={() => setSelectedFormat(fmt.id)}
                style={{
                  flex: 1,
                  padding: "16px 14px",
                  borderRadius: 12,
                  border: `1px solid ${isSelected ? "var(--sg-accent-primary)" : "var(--sg-border)"}`,
                  background: isSelected ? "rgba(99, 102, 241, 0.08)" : "var(--sg-bg-elevated)",
                  cursor: "pointer",
                  textAlign: "center",
                  transition: "all 0.15s ease",
                }}
              >
                <div style={{ fontSize: "1.5rem", marginBottom: 8 }}>{fmt.icon}</div>
                <div style={{ fontSize: "0.85rem", fontWeight: 600, color: isSelected ? "var(--sg-text-primary)" : "var(--sg-text-secondary)", marginBottom: 4 }}>
                  {fmt.label}
                </div>
                <div style={{ fontSize: "0.65rem", color: "var(--sg-text-muted)" }}>{fmt.desc}</div>
              </button>
            );
          })}
        </div>

        <button
          className="btn-primary"
          onClick={handleExport}
          style={{ width: "100%", padding: "14px 0", fontSize: "0.9rem", fontWeight: 600 }}
        >
          🚀 Generate {formats.find(f => f.id === selectedFormat)?.label}
        </button>
      </div>

      {/* Findings Summary Table */}
      <div className="glass-card animate-fade-in" style={{ padding: 28, animationDelay: "0.2s", opacity: 0 }}>
        <h2 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: 16 }}>Findings Summary</h2>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--sg-border)" }}>
                <th style={{ textAlign: "left", padding: "8px 12px", color: "var(--sg-text-muted)", fontSize: "0.7rem", textTransform: "uppercase" }}>Severity</th>
                <th style={{ textAlign: "left", padding: "8px 12px", color: "var(--sg-text-muted)", fontSize: "0.7rem", textTransform: "uppercase" }}>Finding</th>
                <th style={{ textAlign: "left", padding: "8px 12px", color: "var(--sg-text-muted)", fontSize: "0.7rem", textTransform: "uppercase" }}>Category</th>
                <th style={{ textAlign: "left", padding: "8px 12px", color: "var(--sg-text-muted)", fontSize: "0.7rem", textTransform: "uppercase" }}>URL</th>
              </tr>
            </thead>
            <tbody>
              {scanData.findings.map((f, i) => (
                <tr key={i} style={{ borderBottom: "1px solid var(--sg-border)" }}>
                  <td style={{ padding: "10px 12px" }}>
                    <span className={`severity-badge severity-${f.severity}`}>{f.severity}</span>
                  </td>
                  <td style={{ padding: "10px 12px", fontWeight: 500 }}>{f.title}</td>
                  <td style={{ padding: "10px 12px", color: "var(--sg-text-muted)" }}>{f.category}</td>
                  <td style={{ padding: "10px 12px", fontFamily: "monospace", fontSize: "0.7rem", color: "var(--sg-accent-cyan)", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {f.url}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
