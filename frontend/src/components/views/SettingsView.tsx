"use client";

import { useState, useEffect } from "react";

interface BackendConfig {
  ai_mode: string;
  hf_token_configured: boolean;
  hf_model: string;
}

export default function SettingsView() {
  const [aiMode, setAiMode] = useState("rule_based");
  const [hfToken, setHfToken] = useState("");
  const [hfModel, setHfModel] = useState("mistralai/Mistral-7B-Instruct-v0.3");
  const [maxRps, setMaxRps] = useState(10);
  const [maxDepth, setMaxDepth] = useState(10);
  const [timeout, setTimeout_] = useState(30);
  const [userAgent, setUserAgent] = useState("SentinelGraph/0.1.0 (Security Assessment)");
  const [saved, setSaved] = useState(false);
  const [tokenConfigured, setTokenConfigured] = useState(false);
  const [backendConnected, setBackendConnected] = useState(false);

  useEffect(() => {
    try {
      const stored = localStorage.getItem("sg_settings");
      if (stored) {
        const s = JSON.parse(stored);
        if (s.aiMode) setAiMode(s.aiMode);
        if (s.hfModel) setHfModel(s.hfModel);
        if (s.maxRps) setMaxRps(s.maxRps);
        if (s.maxDepth) setMaxDepth(s.maxDepth);
        if (s.timeout) setTimeout_(s.timeout);
        if (s.userAgent) setUserAgent(s.userAgent);
      }
    } catch { /* ignore */ }

    fetch("http://localhost:8000/api/v1/config")
      .then(r => r.json())
      .then((data: BackendConfig) => {
        setBackendConnected(true);
        if (data.hf_token_configured) setTokenConfigured(true);
        if (data.ai_mode) setAiMode(data.ai_mode);
        if (data.hf_model) setHfModel(data.hf_model);
      })
      .catch(() => setBackendConnected(false));
  }, []);

  const handleSave = () => {
    const settings = { aiMode, hfModel, maxRps, maxDepth, timeout, userAgent };
    localStorage.setItem("sg_settings", JSON.stringify(settings));
    fetch("http://localhost:8000/api/v1/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ai_mode: aiMode, hf_token: hfToken || undefined, hf_model: hfModel, max_rps: maxRps, max_depth: maxDepth, timeout, user_agent: userAgent }),
    }).catch(() => {});
    setSaved(true);
    window.setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div style={{ maxWidth: 900 }}>
      <div style={{ marginBottom: 32 }}>
        <h1 style={{ fontSize: "1.75rem", fontWeight: 700, marginBottom: 4 }}>Settings</h1>
        <p style={{ color: "var(--sg-text-secondary)", fontSize: "0.875rem" }}>Configure scanning parameters and AI analysis</p>
      </div>

      {/* Connection Status */}
      <div className="animate-fade-in" style={{ display: "flex", gap: 12, marginBottom: 20, opacity: 0 }}>
        <div style={{
          padding: "8px 14px", borderRadius: 8, fontSize: "0.75rem", fontWeight: 600,
          background: backendConnected ? "rgba(16, 185, 129, 0.08)" : "rgba(239, 68, 68, 0.08)",
          color: backendConnected ? "var(--sg-accent-emerald)" : "#ef4444",
          border: `1px solid ${backendConnected ? "rgba(16, 185, 129, 0.2)" : "rgba(239, 68, 68, 0.2)"}`,
        }}>
          {backendConnected ? "✓ Backend Connected (localhost:8000)" : "○ Backend Offline"}
        </div>
        {tokenConfigured && (
          <div style={{
            padding: "8px 14px", borderRadius: 8, fontSize: "0.75rem", fontWeight: 600,
            background: "rgba(16, 185, 129, 0.08)", color: "var(--sg-accent-emerald)",
            border: "1px solid rgba(16, 185, 129, 0.2)",
          }}>
            ✓ HuggingFace Token Configured (.env)
          </div>
        )}
      </div>

      {/* AI Configuration */}
      <div className="glass-card animate-fade-in" style={{ padding: 28, marginBottom: 24, opacity: 0 }}>
        <h2 style={{ fontSize: "1.1rem", fontWeight: 600, marginBottom: 20 }}>🤖 AI Analysis Engine</h2>
        <div style={{ marginBottom: 20 }}>
          <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, marginBottom: 8, color: "var(--sg-text-secondary)" }}>Analysis Mode</label>
          <div style={{ display: "flex", gap: 10 }}>
            {[
              { id: "rule_based", label: "Rule-Based", desc: "No API needed — uses vulnerability knowledge base", tag: "Free" },
              { id: "huggingface_api", label: "HuggingFace API", desc: "Uses HF Inference API (free tier available)", tag: "Recommended" },
              { id: "local_transformers", label: "Local Model", desc: "Runs model locally — requires GPU", tag: "Advanced" },
            ].map((mode) => {
              const isSelected = aiMode === mode.id;
              return (
                <button key={mode.id} onClick={() => setAiMode(mode.id)} style={{
                  flex: 1, padding: "14px 12px", borderRadius: 12,
                  border: `1px solid ${isSelected ? "var(--sg-accent-primary)" : "var(--sg-border)"}`,
                  background: isSelected ? "rgba(99, 102, 241, 0.08)" : "var(--sg-bg-elevated)",
                  cursor: "pointer", textAlign: "left", transition: "all 0.15s ease",
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                    <span style={{ fontSize: "0.8rem", fontWeight: 600, color: isSelected ? "var(--sg-text-primary)" : "var(--sg-text-secondary)" }}>{mode.label}</span>
                    <span style={{ fontSize: "0.6rem", padding: "2px 6px", borderRadius: 4, background: "rgba(99,102,241,0.1)", color: "var(--sg-accent-primary)" }}>{mode.tag}</span>
                  </div>
                  <div style={{ fontSize: "0.65rem", color: "var(--sg-text-muted)" }}>{mode.desc}</div>
                </button>
              );
            })}
          </div>
        </div>

        {aiMode !== "rule_based" && (
          <>
            {tokenConfigured ? (
              <div style={{ marginBottom: 16, padding: "12px 16px", borderRadius: 10, background: "rgba(16, 185, 129, 0.06)", border: "1px solid rgba(16, 185, 129, 0.15)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                  <span style={{ fontSize: "0.85rem" }}>✅</span>
                  <span style={{ fontSize: "0.8rem", fontWeight: 600, color: "var(--sg-accent-emerald)" }}>HuggingFace API Token — Configured</span>
                </div>
                <div style={{ fontSize: "0.7rem", color: "var(--sg-text-muted)" }}>
                  Token is loaded from your <code style={{ background: "rgba(99,102,241,0.1)", padding: "1px 5px", borderRadius: 4 }}>.env</code> file (server-side). No action needed.
                </div>
                <div style={{ fontSize: "0.65rem", color: "var(--sg-text-muted)", marginTop: 6 }}>
                  To change it, edit <code style={{ background: "rgba(99,102,241,0.1)", padding: "1px 5px", borderRadius: 4 }}>HF_API_TOKEN</code> in your <code style={{ background: "rgba(99,102,241,0.1)", padding: "1px 5px", borderRadius: 4 }}>.env</code> file and restart the backend.
                </div>
              </div>
            ) : (
              <div style={{ marginBottom: 16 }}>
                <div style={{ marginBottom: 12, padding: "10px 14px", borderRadius: 8, background: "rgba(234, 179, 8, 0.06)", border: "1px solid rgba(234, 179, 8, 0.15)", fontSize: "0.7rem", color: "#eab308" }}>
                  ⚠ Token not detected in .env — enter it below or add <code style={{ background: "rgba(99,102,241,0.1)", padding: "1px 5px", borderRadius: 4 }}>HF_API_TOKEN=hf_xxx</code> to your .env file
                </div>
                <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, marginBottom: 8, color: "var(--sg-text-secondary)" }}>Hugging Face API Token</label>
                <input className="input-field" type="password" placeholder="hf_xxxxxxxxxxxxxxxxxxxx" value={hfToken} onChange={(e) => setHfToken(e.target.value)} />
                <div style={{ fontSize: "0.65rem", color: "var(--sg-text-muted)", marginTop: 4 }}>Get your free token at huggingface.co/settings/tokens</div>
              </div>
            )}
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, marginBottom: 8, color: "var(--sg-text-secondary)" }}>Model</label>
              <input className="input-field" type="text" value={hfModel} onChange={(e) => setHfModel(e.target.value)} />
            </div>
          </>
        )}
      </div>

      {/* Scanning Configuration */}
      <div className="glass-card animate-fade-in" style={{ padding: 28, marginBottom: 24, animationDelay: "0.1s", opacity: 0 }}>
        <h2 style={{ fontSize: "1.1rem", fontWeight: 600, marginBottom: 20 }}>⚙️ Scanning Configuration</h2>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16, marginBottom: 20 }}>
          <div>
            <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, marginBottom: 8, color: "var(--sg-text-secondary)" }}>Rate Limit (req/sec)</label>
            <input className="input-field" type="number" min={1} max={50} value={maxRps} onChange={(e) => setMaxRps(parseInt(e.target.value) || 10)} />
          </div>
          <div>
            <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, marginBottom: 8, color: "var(--sg-text-secondary)" }}>Max Crawl Depth</label>
            <input className="input-field" type="number" min={1} max={20} value={maxDepth} onChange={(e) => setMaxDepth(parseInt(e.target.value) || 10)} />
          </div>
          <div>
            <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, marginBottom: 8, color: "var(--sg-text-secondary)" }}>Request Timeout (sec)</label>
            <input className="input-field" type="number" min={5} max={120} value={timeout} onChange={(e) => setTimeout_(parseInt(e.target.value) || 30)} />
          </div>
        </div>
        <div>
          <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, marginBottom: 8, color: "var(--sg-text-secondary)" }}>User-Agent String</label>
          <input className="input-field" type="text" value={userAgent} onChange={(e) => setUserAgent(e.target.value)} />
        </div>
      </div>

      {/* Save Button */}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 12 }}>
        {saved && (
          <div className="animate-fade-in" style={{ padding: "10px 20px", fontSize: "0.85rem", color: "var(--sg-accent-emerald)", opacity: 0 }}>✓ Settings saved</div>
        )}
        <button className="btn-primary" onClick={handleSave} style={{ padding: "12px 32px" }}>Save Settings</button>
      </div>
    </div>
  );
}
