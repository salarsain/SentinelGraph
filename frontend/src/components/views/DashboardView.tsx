"use client";

import { useState, useEffect } from "react";
import dynamic from "next/dynamic";

const AttackSurfaceGraph = dynamic(
  () => import("@/components/visualizations/AttackSurfaceGraph"),
  { ssr: false }
);

interface ScanFinding {
  severity: string;
  title: string;
  description: string;
  url: string;
  category: string;
  evidence: Record<string, unknown>;
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
  ssl_info: {
    issuer: string;
    subject: string;
    valid_from: string;
    valid_to: string;
  };
  pages_crawled: number;
  total_findings: number;
  severity_counts: Record<string, number>;
  findings: ScanFinding[];
}

function MetricCard({ label, value, subtext, accent, delay }: {
  label: string; value: string | number; subtext?: string; accent?: string; delay: number;
}) {
  return (
    <div className="glass-card animate-fade-in" style={{ padding: "20px 24px", animationDelay: `${delay * 0.05}s`, opacity: 0 }}>
      <div style={{ fontSize: "0.75rem", color: "var(--sg-text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>{label}</div>
      <div style={{ fontSize: "2rem", fontWeight: 700, color: accent || "var(--sg-text-primary)", lineHeight: 1 }}>{value}</div>
      {subtext && <div style={{ fontSize: "0.75rem", color: "var(--sg-text-secondary)", marginTop: 6 }}>{subtext}</div>}
    </div>
  );
}

function SeverityBar({ counts }: { counts: Record<string, number> }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const segments = [
    { key: "critical", color: "var(--sg-critical)", count: counts.critical || 0 },
    { key: "high", color: "var(--sg-high)", count: counts.high || 0 },
    { key: "medium", color: "var(--sg-medium)", count: counts.medium || 0 },
    { key: "low", color: "var(--sg-low)", count: counts.low || 0 },
    { key: "info", color: "var(--sg-info)", count: counts.info || 0 },
  ];

  return (
    <div>
      <div style={{ display: "flex", height: 12, borderRadius: 6, overflow: "hidden", gap: 2 }}>
        {segments.map((seg) => (
          <div key={seg.key} style={{ width: total > 0 ? `${(seg.count / total) * 100}%` : 0, background: seg.color, transition: "width 0.5s ease", minWidth: seg.count > 0 ? 4 : 0 }} />
        ))}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 12 }}>
        {segments.map((seg) => (
          <div key={seg.key} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: seg.color }} />
            <span style={{ fontSize: "0.7rem", color: "var(--sg-text-secondary)", textTransform: "capitalize" }}>{seg.key} ({seg.count})</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function FindingRow({ finding, index }: { finding: ScanFinding; index: number }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div
      className="animate-fade-in"
      style={{ borderBottom: "1px solid var(--sg-border)", animationDelay: `${index * 0.04}s`, opacity: 0 }}
    >
      <div
        onClick={() => setExpanded(!expanded)}
        style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 0", cursor: "pointer" }}
      >
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
            <span className={`severity-badge severity-${finding.severity}`}>{finding.severity}</span>
            <span style={{ fontSize: "0.875rem", fontWeight: 600 }}>{finding.title}</span>
          </div>
          <div style={{ fontSize: "0.7rem", color: "var(--sg-text-muted)" }}>{finding.category}</div>
        </div>
        <span style={{ color: "var(--sg-text-muted)", fontSize: "0.8rem" }}>{expanded ? "▲" : "▼"}</span>
      </div>
      {expanded && (
        <div style={{ padding: "0 0 16px 0", animation: "fadeInUp 0.2s ease" }}>
          <div style={{ padding: 16, background: "var(--sg-bg-elevated)", borderRadius: 10, fontSize: "0.8rem", lineHeight: 1.7 }}>
            <p style={{ color: "var(--sg-text-secondary)", marginBottom: 12 }}>{finding.description}</p>
            <div style={{ padding: 12, background: "rgba(16, 185, 129, 0.04)", borderRadius: 8, border: "1px solid rgba(16, 185, 129, 0.15)" }}>
              <div style={{ fontSize: "0.7rem", color: "var(--sg-accent-emerald)", fontWeight: 600, marginBottom: 4, textTransform: "uppercase" }}>Remediation</div>
              <div style={{ color: "var(--sg-text-primary)" }}>{finding.remediation}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function DashboardView() {
  const [scanData, setScanData] = useState<ScanData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/scan_results.json")
      .then((res) => res.json())
      .then((data) => { setScanData(data); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div style={{ maxWidth: 1400 }}>
        <div className="skeleton" style={{ height: 40, width: 300, marginBottom: 16 }} />
        <div className="metric-grid" style={{ marginBottom: 32 }}>
          {[1,2,3,4].map(i => <div key={i} className="skeleton" style={{ height: 100 }} />)}
        </div>
      </div>
    );
  }

  if (!scanData) return <div>No scan data available.</div>;

  const { severity_counts: sc } = scanData;

  return (
    <div style={{ maxWidth: 1400 }}>
      {/* Header */}
      <div style={{ marginBottom: 32 }}>
        <h1 style={{ fontSize: "1.75rem", fontWeight: 700, marginBottom: 4 }}>Security Dashboard</h1>
        <p style={{ color: "var(--sg-text-secondary)", fontSize: "0.875rem" }}>
          Live scan results for <span style={{ color: "var(--sg-accent-cyan)", fontFamily: "monospace" }}>{scanData.target}</span>
        </p>
      </div>

      {/* Status Banner */}
      <div className="glass-card glow-accent animate-fade-in" style={{ padding: "16px 24px", marginBottom: 24, display: "flex", alignItems: "center", justifyContent: "space-between", opacity: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span className="status-dot status-dot-complete" />
          <span style={{ fontWeight: 600, fontSize: "0.9rem" }}>Scan Complete</span>
          <span style={{ color: "var(--sg-text-muted)", fontSize: "0.8rem" }}>• {scanData.pages_crawled} pages probed</span>
        </div>
        <div style={{ display: "flex", gap: 16, fontSize: "0.8rem", color: "var(--sg-text-secondary)" }}>
          <span>Technologies: <strong style={{ color: "var(--sg-accent-primary)" }}>{scanData.technologies.join(", ")}</strong></span>
          <span>SSL: <strong style={{ color: "var(--sg-accent-emerald)" }}>{scanData.ssl_info?.issuer || "N/A"}</strong></span>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="metric-grid" style={{ marginBottom: 32 }}>
        <MetricCard label="Total Findings" value={scanData.total_findings} subtext={`${sc.critical + sc.high} require attention`} accent="var(--sg-accent-primary)" delay={1} />
        <MetricCard label="Critical / High" value={`${sc.critical} / ${sc.high}`} subtext={sc.critical > 0 ? "Immediate action required" : "No critical issues"} accent={sc.critical > 0 ? "var(--sg-critical)" : "var(--sg-accent-emerald)"} delay={2} />
        <MetricCard label="Headers Grade" value={scanData.headers_grade} subtext={`${4}/9 security headers present`} accent={scanData.headers_grade >= "C" ? "var(--sg-medium)" : "var(--sg-high)"} delay={3} />
        <MetricCard label="Technologies" value={scanData.technologies.length} subtext={scanData.technologies.join(", ")} accent="var(--sg-accent-cyan)" delay={4} />
      </div>

      {/* Severity Distribution */}
      <div className="glass-card animate-fade-in" style={{ padding: 24, marginBottom: 32, animationDelay: "0.15s", opacity: 0 }}>
        <h2 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: 16 }}>Severity Distribution</h2>
        <SeverityBar counts={sc} />
      </div>

      {/* Two Column: SSL + Technologies */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24, marginBottom: 32 }}>
        <div className="glass-card animate-fade-in" style={{ padding: 24, animationDelay: "0.2s", opacity: 0 }}>
          <h2 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: 16 }}>SSL/TLS Certificate</h2>
          {scanData.ssl_info ? (
            <div style={{ display: "grid", gap: 10 }}>
              {[
                { label: "Issuer", value: scanData.ssl_info.issuer, color: "var(--sg-accent-emerald)" },
                { label: "Subject", value: scanData.ssl_info.subject, color: "var(--sg-accent-cyan)" },
                { label: "Valid From", value: scanData.ssl_info.valid_from, color: "var(--sg-text-secondary)" },
                { label: "Valid To", value: scanData.ssl_info.valid_to, color: "var(--sg-text-secondary)" },
              ].map(item => (
                <div key={item.label} style={{ display: "flex", justifyContent: "space-between", padding: "8px 12px", background: "var(--sg-bg-elevated)", borderRadius: 8 }}>
                  <span style={{ fontSize: "0.75rem", color: "var(--sg-text-muted)" }}>{item.label}</span>
                  <span style={{ fontSize: "0.8rem", fontWeight: 500, color: item.color }}>{item.value}</span>
                </div>
              ))}
            </div>
          ) : <div style={{ color: "var(--sg-text-muted)" }}>No SSL data</div>}
        </div>

        <div className="glass-card animate-fade-in" style={{ padding: 24, animationDelay: "0.25s", opacity: 0 }}>
          <h2 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: 16 }}>Detected Technologies</h2>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {scanData.technologies.map(tech => (
              <span key={tech} style={{
                padding: "6px 14px", borderRadius: 8, fontSize: "0.8rem", fontWeight: 600,
                background: "rgba(99, 102, 241, 0.1)", color: "var(--sg-accent-primary)",
                border: "1px solid rgba(99, 102, 241, 0.2)",
              }}>
                {tech}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Attack Surface Graph */}
      <div className="glass-card animate-fade-in" style={{ padding: 24, marginBottom: 32, animationDelay: "0.28s", opacity: 0 }}>
        <h2 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: 16 }}>Attack Surface Graph</h2>
        <AttackSurfaceGraph />
      </div>

      {/* All Findings */}
      <div className="glass-card animate-fade-in" style={{ padding: 24, animationDelay: "0.3s", opacity: 0 }}>
        <h2 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: 16 }}>
          All Findings ({scanData.total_findings})
          <span style={{ fontSize: "0.75rem", color: "var(--sg-text-muted)", fontWeight: 400, marginLeft: 8 }}>
            Click to expand
          </span>
        </h2>
        {scanData.findings.map((finding, i) => (
          <FindingRow key={i} finding={finding} index={i} />
        ))}
      </div>
    </div>
  );
}
