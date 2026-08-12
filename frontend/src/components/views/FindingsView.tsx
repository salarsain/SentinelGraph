"use client";

import { useState } from "react";

type SeverityFilter = "all" | "critical" | "high" | "medium" | "low" | "info";
type Severity = "critical" | "high" | "medium" | "low" | "info";

interface MockFinding {
  id: string;
  title: string;
  type: string;
  severity: Severity;
  status: string;
  url: string;
  parameter: string | null;
  method: string;
  confidence: number;
  aiConfidence: number | null;
  scanTarget: string;
  cvssScore: number | null;
  cvssVector: string | null;
  detectionRule: string;
  remediation: string;
}

const mockFindings: MockFinding[] = [
  { id: "f-001", title: "SQL Injection in /api/users", type: "sql_injection", severity: "critical" as const, status: "confirmed", url: "api.acmecorp.com/api/users?id=1", parameter: "id", method: "GET", confidence: 0.95, aiConfidence: 0.92, scanTarget: "api.acmecorp.com", cvssScore: 9.8, cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", detectionRule: "SQLI-001", remediation: "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries directly." },
  { id: "f-002", title: "Stored XSS in Comment Field", type: "xss_stored", severity: "critical" as const, status: "new", url: "portal.acmecorp.com/comments", parameter: "body", method: "POST", confidence: 0.88, aiConfidence: 0.85, scanTarget: "portal.acmecorp.com", cvssScore: 8.1, cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N", detectionRule: "XSS-003", remediation: "Sanitize all user input using context-aware output encoding. Implement a strict Content-Security-Policy." },
  { id: "f-003", title: "CORS Wildcard with Credentials", type: "cors_misconfiguration", severity: "high" as const, status: "confirmed", url: "api.acmecorp.com", parameter: null, method: "OPTIONS", confidence: 0.92, aiConfidence: 0.90, scanTarget: "api.acmecorp.com", cvssScore: 7.5, cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", detectionRule: "CORS-001", remediation: "Replace wildcard (*) Access-Control-Allow-Origin with specific trusted origins." },
  { id: "f-004", title: "Open Redirect in /login", type: "open_redirect", severity: "high" as const, status: "new", url: "auth.acmecorp.com/login?redirect=http://evil.com", parameter: "redirect", method: "GET", confidence: 0.78, aiConfidence: 0.71, scanTarget: "auth.acmecorp.com", cvssScore: 6.1, cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", detectionRule: "REDIR-001", remediation: "Validate redirect URLs against a whitelist of allowed domains." },
  { id: "f-005", title: "Missing HSTS Header", type: "missing_security_header", severity: "medium" as const, status: "new", url: "shop.acmecorp.com", parameter: null, method: "GET", confidence: 0.99, aiConfidence: null, scanTarget: "shop.acmecorp.com", cvssScore: 4.3, cvssVector: null, detectionRule: "HDR-001", remediation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" },
  { id: "f-006", title: "Server Version Disclosure (Nginx 1.22.1)", type: "version_disclosure", severity: "low" as const, status: "new", url: "portal.acmecorp.com", parameter: null, method: "GET", confidence: 0.97, aiConfidence: null, scanTarget: "portal.acmecorp.com", cvssScore: 2.6, cvssVector: null, detectionRule: "INFO-003", remediation: "Remove or obfuscate the Server header in Nginx configuration." },
  { id: "f-007", title: "Debug Mode Enabled (Django)", type: "debug_mode_enabled", severity: "high" as const, status: "confirmed", url: "staging.acmecorp.com", parameter: null, method: "GET", confidence: 0.99, aiConfidence: 0.98, scanTarget: "staging.acmecorp.com", cvssScore: 7.5, cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", detectionRule: "DEBUG-001", remediation: "Set DEBUG = False in Django settings for production environments." },
];

function FindingDetail({ finding }: { finding: typeof mockFindings[0] }) {
  return (
    <div className="glass-card" style={{ padding: 28 }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
          <span className={`severity-badge severity-${finding.severity}`}>{finding.severity}</span>
          <span
            style={{
              padding: "3px 10px",
              borderRadius: 6,
              fontSize: "0.7rem",
              fontWeight: 500,
              background: "var(--sg-bg-elevated)",
              color: "var(--sg-text-secondary)",
              border: "1px solid var(--sg-border)",
              textTransform: "capitalize",
            }}
          >
            {finding.status}
          </span>
        </div>
        <h2 style={{ fontSize: "1.25rem", fontWeight: 700, marginBottom: 6 }}>{finding.title}</h2>
        <div style={{ fontSize: "0.8rem", color: "var(--sg-accent-cyan)", fontFamily: "monospace" }}>{finding.url}</div>
      </div>

      {/* Metadata Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 24 }}>
        {[
          { label: "CVSS Score", value: finding.cvssScore?.toString() || "N/A", color: finding.cvssScore && finding.cvssScore >= 9 ? "var(--sg-critical)" : finding.cvssScore && finding.cvssScore >= 7 ? "var(--sg-high)" : "var(--sg-medium)" },
          { label: "Confidence", value: `${Math.round(finding.confidence * 100)}%`, color: "var(--sg-accent-primary)" },
          { label: "AI Confidence", value: finding.aiConfidence ? `${Math.round(finding.aiConfidence * 100)}%` : "—", color: "var(--sg-accent-cyan)" },
          { label: "Detection", value: finding.detectionRule, color: "var(--sg-text-secondary)" },
        ].map((item) => (
          <div key={item.label} style={{ padding: "12px 16px", background: "var(--sg-bg-elevated)", borderRadius: 10 }}>
            <div style={{ fontSize: "0.65rem", color: "var(--sg-text-muted)", textTransform: "uppercase", marginBottom: 4 }}>{item.label}</div>
            <div style={{ fontSize: "1rem", fontWeight: 700, color: item.color }}>{item.value}</div>
          </div>
        ))}
      </div>

      {/* Request Info */}
      <div style={{ marginBottom: 24 }}>
        <h3 style={{ fontSize: "0.85rem", fontWeight: 600, color: "var(--sg-text-secondary)", marginBottom: 12 }}>Request Details</h3>
        <div
          style={{
            padding: 16,
            background: "var(--sg-bg-primary)",
            borderRadius: 10,
            fontFamily: "monospace",
            fontSize: "0.8rem",
            color: "var(--sg-text-secondary)",
            border: "1px solid var(--sg-border)",
            lineHeight: 1.6,
          }}
        >
          <span style={{ color: "var(--sg-accent-emerald)" }}>{finding.method}</span>{" "}
          <span style={{ color: "var(--sg-accent-cyan)" }}>{finding.url}</span>
          {finding.parameter && (
            <>
              <br />
              <span style={{ color: "var(--sg-text-muted)" }}>Parameter:</span>{" "}
              <span style={{ color: "var(--sg-high)" }}>{finding.parameter}</span>
            </>
          )}
          {finding.cvssVector && (
            <>
              <br />
              <span style={{ color: "var(--sg-text-muted)" }}>CVSS:</span>{" "}
              <span style={{ color: "var(--sg-text-secondary)" }}>{finding.cvssVector}</span>
            </>
          )}
        </div>
      </div>

      {/* Remediation */}
      <div>
        <h3 style={{ fontSize: "0.85rem", fontWeight: 600, color: "var(--sg-text-secondary)", marginBottom: 12 }}>Remediation</h3>
        <div
          style={{
            padding: 16,
            background: "rgba(16, 185, 129, 0.04)",
            borderRadius: 10,
            fontSize: "0.85rem",
            color: "var(--sg-text-primary)",
            border: "1px solid rgba(16, 185, 129, 0.15)",
            lineHeight: 1.6,
          }}
        >
          {finding.remediation}
        </div>
      </div>

      {/* Actions */}
      <div style={{ display: "flex", gap: 10, marginTop: 20, justifyContent: "flex-end" }}>
        <button className="btn-ghost" style={{ padding: "8px 16px", fontSize: "0.8rem" }}>Mark False Positive</button>
        <button className="btn-ghost" style={{ padding: "8px 16px", fontSize: "0.8rem" }}>Accepted Risk</button>
        <button className="btn-primary" style={{ padding: "8px 16px", fontSize: "0.8rem" }}>✓ Confirm Finding</button>
      </div>
    </div>
  );
}

export default function FindingsView() {
  const [selectedFinding, setSelectedFinding] = useState<string | null>("f-001");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const selected = mockFindings.find((f) => f.id === selectedFinding);

  const filtered = severityFilter === "all"
    ? mockFindings
    : mockFindings.filter((f) => f.severity === severityFilter);

  const counts = {
    all: mockFindings.length,
    critical: mockFindings.filter((f) => f.severity === "critical").length,
    high: mockFindings.filter((f) => f.severity === "high").length,
    medium: mockFindings.filter((f) => f.severity === "medium").length,
    low: mockFindings.filter((f) => f.severity === "low").length,
    info: mockFindings.filter((f) => f.severity === "info").length,
  };

  return (
    <div style={{ maxWidth: 1400 }}>
      <div style={{ marginBottom: 32 }}>
        <h1 style={{ fontSize: "1.75rem", fontWeight: 700, marginBottom: 4 }}>Findings</h1>
        <p style={{ color: "var(--sg-text-secondary)", fontSize: "0.875rem" }}>
          Security findings across all scans with AI-powered analysis
        </p>
      </div>

      {/* Severity Filter Tabs */}
      <div style={{ display: "flex", gap: 8, marginBottom: 24, flexWrap: "wrap" }}>
        {(["all", "critical", "high", "medium", "low", "info"] as SeverityFilter[]).map((sev) => {
          const isActive = severityFilter === sev;
          const sevColor = sev === "all" ? "var(--sg-accent-primary)" :
            sev === "critical" ? "var(--sg-critical)" :
            sev === "high" ? "var(--sg-high)" :
            sev === "medium" ? "var(--sg-medium)" :
            sev === "low" ? "var(--sg-low)" : "var(--sg-info)";
          return (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              style={{
                padding: "6px 16px",
                borderRadius: 8,
                border: `1px solid ${isActive ? sevColor : "var(--sg-border)"}`,
                background: isActive ? `${sevColor}15` : "transparent",
                color: isActive ? sevColor : "var(--sg-text-secondary)",
                fontSize: "0.8rem",
                fontWeight: isActive ? 600 : 400,
                cursor: "pointer",
                textTransform: "capitalize",
                transition: "all 0.15s ease",
              }}
            >
              {sev} ({counts[sev]})
            </button>
          );
        })}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "380px 1fr", gap: 24 }}>
        {/* Finding List */}
        <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: "calc(100vh - 220px)", overflowY: "auto" }}>
          {filtered.map((finding) => {
            const isSelected = selectedFinding === finding.id;
            return (
              <button
                key={finding.id}
                onClick={() => setSelectedFinding(finding.id)}
                className="glass-card"
                style={{
                  padding: 14,
                  cursor: "pointer",
                  border: `1px solid ${isSelected ? "var(--sg-accent-primary)" : "var(--sg-glass-border)"}`,
                  textAlign: "left",
                  background: isSelected ? "rgba(99, 102, 241, 0.06)" : "var(--sg-glass-bg)",
                  transition: "all 0.15s ease",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                  <span className={`severity-badge severity-${finding.severity}`} style={{ fontSize: "0.65rem", padding: "2px 8px" }}>
                    {finding.severity}
                  </span>
                  <span style={{ fontSize: "0.8rem", fontWeight: 600, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {finding.title}
                  </span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.7rem", color: "var(--sg-text-muted)" }}>
                  <span style={{ fontFamily: "monospace" }}>{finding.scanTarget}</span>
                  <span>{Math.round(finding.confidence * 100)}% conf.</span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Detail Panel */}
        {selected ? (
          <FindingDetail finding={selected} />
        ) : (
          <div className="glass-card" style={{ padding: 40, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--sg-text-muted)" }}>
            Select a finding to view details
          </div>
        )}
      </div>
    </div>
  );
}
