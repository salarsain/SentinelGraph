"use client";

import { useState, useEffect } from "react";
import NewScanModal from "@/components/modals/NewScanModal";

const mockScans = [
  { id: "scan-000", target: "cyberhackathon.pk", scope: "cyberhackathon.pk", status: "complete", progress: 1.0, phase: "Complete", findings: { critical: 0, high: 0, medium: 4, low: 2 }, startedAt: "2026-08-12T15:47:04Z", duration: "8s" },
  { id: "scan-001", target: "api.acmecorp.com", scope: "acmecorp.com", status: "running", progress: 0.67, phase: "Security Testing", findings: { critical: 1, high: 3, medium: 5, low: 2 }, startedAt: "2024-01-15T10:30:00Z", duration: "12m" },
  { id: "scan-002", target: "portal.acmecorp.com", scope: "acmecorp.com", status: "complete", progress: 1.0, phase: "Complete", findings: { critical: 2, high: 7, medium: 9, low: 5 }, startedAt: "2024-01-15T08:00:00Z", duration: "1h 23m" },
  { id: "scan-003", target: "shop.acmecorp.com", scope: "acmecorp.com", status: "running", progress: 0.34, phase: "Crawling", findings: { critical: 0, high: 1, medium: 1, low: 0 }, startedAt: "2024-01-15T10:42:00Z", duration: "5m" },
  { id: "scan-004", target: "auth.acmecorp.com", scope: "acmecorp.com", status: "complete", progress: 1.0, phase: "Complete", findings: { critical: 0, high: 2, medium: 3, low: 2 }, startedAt: "2024-01-14T14:00:00Z", duration: "45m" },
];

const phases = [
  "Scope Validation", "Reconnaissance", "Crawling", "Fingerprinting",
  "API Discovery", "Security Testing", "Verification", "Evidence Collection",
  "Correlation", "AI Analysis", "Risk Scoring", "Report Generation",
];

function ScanDetailPanel({ scan }: { scan: typeof mockScans[0] }) {
  const totalFindings = Object.values(scan.findings).reduce((a, b) => a + b, 0);
  const currentPhaseIdx = phases.indexOf(scan.phase === "Complete" ? phases[phases.length - 1] : scan.phase);

  return (
    <div className="glass-card" style={{ padding: 28 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 24 }}>
        <div>
          <h2 style={{ fontSize: "1.25rem", fontWeight: 700, marginBottom: 4 }}>{scan.target}</h2>
          <div style={{ fontSize: "0.8rem", color: "var(--sg-text-muted)" }}>Scope: {scan.scope} • ID: {scan.id}</div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {scan.status === "running" && (
            <button className="btn-ghost" style={{ padding: "8px 16px", fontSize: "0.8rem", color: "var(--sg-critical)" }}>
              ■ Cancel
            </button>
          )}
          <button className="btn-primary" style={{ padding: "8px 16px", fontSize: "0.8rem" }}>
            {scan.status === "complete" ? "📄 Report" : "↻ Refresh"}
          </button>
        </div>
      </div>

      {/* Progress */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
          <span style={{ fontSize: "0.8rem", color: "var(--sg-text-secondary)" }}>
            {scan.phase}
          </span>
          <span style={{ fontSize: "0.8rem", fontWeight: 600, color: "var(--sg-accent-primary)" }}>
            {Math.round(scan.progress * 100)}%
          </span>
        </div>
        <div className="progress-bar" style={{ height: 8 }}>
          <div className="progress-bar-fill" style={{ width: `${scan.progress * 100}%` }} />
        </div>
      </div>

      {/* Phase Timeline */}
      <div style={{ marginBottom: 28 }}>
        <h3 style={{ fontSize: "0.85rem", fontWeight: 600, marginBottom: 12, color: "var(--sg-text-secondary)" }}>
          Scan Pipeline
        </h3>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8 }}>
          {phases.map((phase, i) => {
            const isComplete = i <= currentPhaseIdx;
            const isCurrent = phase === scan.phase;
            return (
              <div
                key={phase}
                style={{
                  padding: "8px 10px",
                  borderRadius: 8,
                  fontSize: "0.7rem",
                  fontWeight: isCurrent ? 600 : 400,
                  color: isComplete ? "var(--sg-accent-emerald)" : isCurrent ? "var(--sg-accent-primary)" : "var(--sg-text-muted)",
                  background: isCurrent
                    ? "rgba(99, 102, 241, 0.1)"
                    : isComplete
                    ? "rgba(16, 185, 129, 0.06)"
                    : "var(--sg-bg-elevated)",
                  border: `1px solid ${isCurrent ? "rgba(99, 102, 241, 0.3)" : "var(--sg-border)"}`,
                  textAlign: "center",
                }}
              >
                {isComplete && !isCurrent ? "✓ " : isCurrent && scan.status === "running" ? "● " : ""}{phase}
              </div>
            );
          })}
        </div>
      </div>

      {/* Findings Summary */}
      <div>
        <h3 style={{ fontSize: "0.85rem", fontWeight: 600, marginBottom: 12, color: "var(--sg-text-secondary)" }}>
          Findings ({totalFindings})
        </h3>
        <div style={{ display: "flex", gap: 12 }}>
          {[
            { label: "Critical", value: scan.findings.critical, color: "var(--sg-critical)" },
            { label: "High", value: scan.findings.high, color: "var(--sg-high)" },
            { label: "Medium", value: scan.findings.medium, color: "var(--sg-medium)" },
            { label: "Low", value: scan.findings.low, color: "var(--sg-low)" },
          ].map((item) => (
            <div
              key={item.label}
              style={{
                flex: 1,
                padding: "12px 16px",
                borderRadius: 10,
                background: "var(--sg-bg-elevated)",
                textAlign: "center",
              }}
            >
              <div style={{ fontSize: "1.5rem", fontWeight: 700, color: item.color }}>{item.value}</div>
              <div style={{ fontSize: "0.7rem", color: "var(--sg-text-muted)", marginTop: 2 }}>{item.label}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function ScansView() {
  const [scansList, setScansList] = useState(mockScans);
  const [selectedScan, setSelectedScan] = useState<string | null>("scan-000");
  const [showNewScan, setShowNewScan] = useState(false);
  const selected = scansList.find((s) => s.id === selectedScan);

  // Poll scan status from backend
  useEffect(() => {
    const interval = setInterval(() => {
      fetch("http://localhost:8000/api/v1/scan/status")
        .then(r => r.json())
        .then(status => {
          if (status && status.status === "running") {
            setScansList(prev => {
              const targetHost = status.target ? new URL(status.target).hostname : "scan-target";
              const existingIdx = prev.findIndex(s => s.target === targetHost || s.target === status.target);
              if (existingIdx >= 0) {
                const updated = [...prev];
                updated[existingIdx] = {
                  ...updated[existingIdx],
                  status: "running",
                  progress: status.progress / 100,
                  phase: status.current_phase || "Security Testing",
                };
                return updated;
              }
              return prev;
            });
          }
        })
        .catch(() => {});
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ maxWidth: 1400 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 32 }}>
        <div>
          <h1 style={{ fontSize: "1.75rem", fontWeight: 700, marginBottom: 4 }}>Scans</h1>
          <p style={{ color: "var(--sg-text-secondary)", fontSize: "0.875rem" }}>
            Monitor and manage security scans across your targets
          </p>
        </div>
        <button className="btn-primary" onClick={() => setShowNewScan(true)}>+ New Scan</button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "360px 1fr", gap: 24 }}>
        {/* Scan List */}
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {scansList.map((scan) => {
            const isSelected = selectedScan === scan.id;
            const totalFindings = Object.values(scan.findings).reduce((a, b) => a + b, 0);
            return (
              <button
                key={scan.id}
                onClick={() => setSelectedScan(scan.id)}
                className="glass-card"
                style={{
                  padding: 16,
                  cursor: "pointer",
                  border: `1px solid ${isSelected ? "var(--sg-accent-primary)" : "var(--sg-glass-border)"}`,
                  textAlign: "left",
                  transition: "all 0.15s ease",
                  background: isSelected ? "rgba(99, 102, 241, 0.06)" : "var(--sg-glass-bg)",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                  <span style={{ fontWeight: 600, fontSize: "0.875rem" }}>{scan.target}</span>
                  <span className={`status-dot status-dot-${scan.status === "running" ? "running" : scan.status === "complete" ? "complete" : "failed"}`} />
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.75rem", color: "var(--sg-text-muted)" }}>
                  <span>{scan.status === "running" ? scan.phase : scan.status}</span>
                  <span>{totalFindings} findings</span>
                </div>
                {scan.status === "running" && (
                  <div className="progress-bar" style={{ marginTop: 8, height: 4 }}>
                    <div className="progress-bar-fill" style={{ width: `${scan.progress * 100}%` }} />
                  </div>
                )}
              </button>
            );
          })}
        </div>

        {/* Detail Panel */}
        {selected ? (
          <ScanDetailPanel scan={selected} />
        ) : (
          <div className="glass-card" style={{ padding: 40, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--sg-text-muted)" }}>
            Select a scan to view details
          </div>
        )}
      </div>

      <NewScanModal
        isOpen={showNewScan}
        onClose={() => setShowNewScan(false)}
        onSubmit={(config) => {
          try {
            const parsed = new URL(config.targetUrl);
            const host = parsed.hostname;
            const newScanItem = {
              id: `scan-${Date.now()}`,
              target: host,
              scope: host,
              status: "running",
              progress: 0.1,
              phase: "Reconnaissance",
              findings: { critical: 0, high: 0, medium: 0, low: 0 },
              startedAt: new Date().toISOString(),
              duration: "Just started",
            };
            setScansList([newScanItem, ...scansList]);
            setSelectedScan(newScanItem.id);
          } catch { /* ignore */ }
          setShowNewScan(false);
        }}
      />
    </div>
  );
}
