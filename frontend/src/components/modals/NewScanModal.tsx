"use client";

import { useState } from "react";

interface NewScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (config: ScanConfig) => void;
}

interface ScanConfig {
  targetUrl: string;
  scanName: string;
  scanType: "full" | "quick" | "passive";
  maxDepth: number;
  maxRps: number;
  includeSubdomains: boolean;
  enableAI: boolean;
}

export default function NewScanModal({ isOpen, onClose, onSubmit }: NewScanModalProps) {
  const [config, setConfig] = useState<ScanConfig>({
    targetUrl: "",
    scanName: "",
    scanType: "full",
    maxDepth: 5,
    maxRps: 10,
    includeSubdomains: false,
    enableAI: true,
  });
  const [urlError, setUrlError] = useState("");
  const [submitError, setSubmitError] = useState("");
  const [submitSuccess, setSubmitSuccess] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!isOpen) return null;

  const validateUrl = (url: string): boolean => {
    try {
      const parsed = new URL(url);
      if (!["http:", "https:"].includes(parsed.protocol)) {
        setUrlError("URL must start with http:// or https://");
        return false;
      }
      setUrlError("");
      return true;
    } catch {
      setUrlError("Please enter a valid URL (e.g., https://example.com)");
      return false;
    }
  };

  const handleSubmit = async () => {
    if (!validateUrl(config.targetUrl)) return;
    setIsSubmitting(true);
    setSubmitError("");
    setSubmitSuccess("");

    try {
      const res = await fetch("http://localhost:8000/api/v1/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: config.targetUrl,
          scan_type: config.scanType,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || "Failed to start scan");
      }

      setSubmitSuccess(`🚀 Scan started successfully for ${config.targetUrl}!`);
      onSubmit(config);

      setTimeout(() => {
        setIsSubmitting(false);
        onClose();
        setSubmitSuccess("");
      }, 1500);
    } catch (err: unknown) {
      setIsSubmitting(false);
      const message = err instanceof Error ? err.message : "Failed to connect to backend server";
      setSubmitError(message);
    }
  };

  const scanTypes = [
    { id: "full" as const, label: "Full Scan", desc: "Complete security assessment — all 12 phases", icon: "🔍", time: "30-60 min" },
    { id: "quick" as const, label: "Quick Scan", desc: "Header analysis + sensitive paths + cookies", icon: "⚡", time: "5-10 min" },
    { id: "passive" as const, label: "Passive Only", desc: "No active probing — safe for production", icon: "👁️", time: "2-5 min" },
  ];

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 1000,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "rgba(0, 0, 0, 0.6)",
        backdropFilter: "blur(8px)",
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        className="glass-card animate-fade-in"
        style={{
          width: "100%",
          maxWidth: 640,
          padding: 32,
          maxHeight: "90vh",
          overflowY: "auto",
        }}
      >
        {/* Header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 28 }}>
          <div>
            <h2 style={{ fontSize: "1.3rem", fontWeight: 700, marginBottom: 4 }}>New Security Scan</h2>
            <p style={{ fontSize: "0.8rem", color: "var(--sg-text-muted)" }}>
              Enter the website URL you want to test
            </p>
          </div>
          <button
            onClick={onClose}
            style={{
              width: 36, height: 36, borderRadius: 8, border: "1px solid var(--sg-border)",
              background: "transparent", color: "var(--sg-text-secondary)", cursor: "pointer",
              fontSize: "1.1rem", display: "flex", alignItems: "center", justifyContent: "center",
            }}
          >
            ✕
          </button>
        </div>

        {/* Target URL */}
        <div style={{ marginBottom: 24 }}>
          <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, marginBottom: 8, color: "var(--sg-text-secondary)" }}>
            Target URL *
          </label>
          <div style={{ position: "relative" }}>
            <input
              className="input-field"
              type="url"
              placeholder="https://your-website.com"
              value={config.targetUrl}
              onChange={(e) => {
                setConfig({ ...config, targetUrl: e.target.value });
                if (urlError) validateUrl(e.target.value);
              }}
              onBlur={() => config.targetUrl && validateUrl(config.targetUrl)}
              style={{
                fontSize: "1rem",
                padding: "14px 16px",
                borderColor: urlError ? "var(--sg-critical)" : undefined,
              }}
              autoFocus
            />
          </div>
          {urlError && (
            <div style={{ fontSize: "0.75rem", color: "var(--sg-critical)", marginTop: 6 }}>{urlError}</div>
          )}
          <div style={{ fontSize: "0.7rem", color: "var(--sg-text-muted)", marginTop: 6 }}>
            ⚠️ Only scan websites you own or have written authorization to test
          </div>
        </div>

        {/* Scan Name */}
        <div style={{ marginBottom: 24 }}>
          <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, marginBottom: 8, color: "var(--sg-text-secondary)" }}>
            Scan Name
          </label>
          <input
            className="input-field"
            type="text"
            placeholder="e.g., Production API Assessment"
            value={config.scanName}
            onChange={(e) => setConfig({ ...config, scanName: e.target.value })}
          />
        </div>

        {/* Scan Type */}
        <div style={{ marginBottom: 24 }}>
          <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, marginBottom: 8, color: "var(--sg-text-secondary)" }}>
            Scan Type
          </label>
          <div style={{ display: "flex", gap: 10 }}>
            {scanTypes.map((type) => {
              const isSelected = config.scanType === type.id;
              return (
                <button
                  key={type.id}
                  onClick={() => setConfig({ ...config, scanType: type.id })}
                  style={{
                    flex: 1,
                    padding: "14px 12px",
                    borderRadius: 12,
                    border: `1px solid ${isSelected ? "var(--sg-accent-primary)" : "var(--sg-border)"}`,
                    background: isSelected ? "rgba(99, 102, 241, 0.08)" : "var(--sg-bg-elevated)",
                    cursor: "pointer",
                    textAlign: "center",
                    transition: "all 0.15s ease",
                  }}
                >
                  <div style={{ fontSize: "1.3rem", marginBottom: 6 }}>{type.icon}</div>
                  <div style={{ fontSize: "0.8rem", fontWeight: 600, color: isSelected ? "var(--sg-text-primary)" : "var(--sg-text-secondary)" }}>
                    {type.label}
                  </div>
                  <div style={{ fontSize: "0.65rem", color: "var(--sg-text-muted)", marginTop: 4 }}>
                    {type.desc}
                  </div>
                  <div style={{ fontSize: "0.65rem", color: "var(--sg-accent-cyan)", marginTop: 4 }}>
                    ~{type.time}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Advanced Settings */}
        <div style={{ marginBottom: 24 }}>
          <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, marginBottom: 12, color: "var(--sg-text-secondary)" }}>
            Advanced Settings
          </label>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div>
              <label style={{ display: "block", fontSize: "0.7rem", color: "var(--sg-text-muted)", marginBottom: 4 }}>
                Crawl Depth
              </label>
              <input
                className="input-field"
                type="number"
                min={1} max={20}
                value={config.maxDepth}
                onChange={(e) => setConfig({ ...config, maxDepth: parseInt(e.target.value) || 5 })}
              />
            </div>
            <div>
              <label style={{ display: "block", fontSize: "0.7rem", color: "var(--sg-text-muted)", marginBottom: 4 }}>
                Rate Limit (req/sec)
              </label>
              <input
                className="input-field"
                type="number"
                min={1} max={50}
                value={config.maxRps}
                onChange={(e) => setConfig({ ...config, maxRps: parseInt(e.target.value) || 10 })}
              />
            </div>
          </div>
        </div>

        {/* Toggles */}
        <div style={{ display: "flex", gap: 24, marginBottom: 28 }}>
          <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", fontSize: "0.8rem" }}>
            <input
              type="checkbox"
              checked={config.includeSubdomains}
              onChange={(e) => setConfig({ ...config, includeSubdomains: e.target.checked })}
              style={{ accentColor: "var(--sg-accent-primary)" }}
            />
            <span style={{ color: "var(--sg-text-secondary)" }}>Include Subdomains</span>
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", fontSize: "0.8rem" }}>
            <input
              type="checkbox"
              checked={config.enableAI}
              onChange={(e) => setConfig({ ...config, enableAI: e.target.checked })}
              style={{ accentColor: "var(--sg-accent-primary)" }}
            />
            <span style={{ color: "var(--sg-text-secondary)" }}>AI Analysis (Hugging Face)</span>
          </label>
        </div>

        {/* Error/Success Feedback */}
        {submitError && (
          <div style={{
            marginBottom: 20, padding: "10px 14px", borderRadius: 8,
            background: "rgba(239, 68, 68, 0.08)", border: "1px solid rgba(239, 68, 68, 0.2)",
            fontSize: "0.8rem", color: "#ef4444", fontWeight: 500,
          }}>
            ⚠ {submitError}
          </div>
        )}
        {submitSuccess && (
          <div style={{
            marginBottom: 20, padding: "10px 14px", borderRadius: 8,
            background: "rgba(16, 185, 129, 0.08)", border: "1px solid rgba(16, 185, 129, 0.2)",
            fontSize: "0.8rem", color: "var(--sg-accent-emerald)", fontWeight: 500,
          }}>
            {submitSuccess}
          </div>
        )}

        {/* Actions */}
        <div style={{ display: "flex", gap: 12, justifyContent: "flex-end" }}>
          <button className="btn-ghost" onClick={onClose} style={{ padding: "10px 24px" }}>
            Cancel
          </button>
          <button
            className="btn-primary"
            onClick={handleSubmit}
            disabled={!config.targetUrl || isSubmitting}
            style={{
              padding: "10px 32px",
              opacity: (!config.targetUrl || isSubmitting) ? 0.5 : 1,
              cursor: (!config.targetUrl || isSubmitting) ? "not-allowed" : "pointer",
            }}
          >
            {isSubmitting ? "◌ Starting Scan..." : "🚀 Start Scan"}
          </button>
        </div>
      </div>
    </div>
  );
}
