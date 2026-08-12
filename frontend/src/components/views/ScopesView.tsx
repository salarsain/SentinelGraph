"use client";

const mockScopes = [
  { id: "scope-001", name: "ACME Corp Primary", target: "acmecorp.com", type: "wildcard", status: "active", includeSubdomains: true, maxRps: 10, validatedAt: "2024-01-10", scans: 14, findings: 105 },
  { id: "scope-002", name: "ACME API", target: "api.acmecorp.com", type: "domain", status: "active", includeSubdomains: false, maxRps: 5, validatedAt: "2024-01-12", scans: 3, findings: 23 },
  { id: "scope-003", name: "Dev Environment", target: "dev.acmecorp.com", type: "domain", status: "pending", includeSubdomains: false, maxRps: 2, validatedAt: null, scans: 0, findings: 0 },
];

function ScopeCard({ scope }: { scope: typeof mockScopes[0] }) {
  const statusStyles: Record<string, { color: string; bg: string; border: string }> = {
    active: { color: "var(--sg-accent-emerald)", bg: "rgba(16, 185, 129, 0.08)", border: "rgba(16, 185, 129, 0.25)" },
    pending: { color: "var(--sg-medium)", bg: "rgba(234, 179, 8, 0.08)", border: "rgba(234, 179, 8, 0.25)" },
    suspended: { color: "var(--sg-critical)", bg: "rgba(239, 68, 68, 0.08)", border: "rgba(239, 68, 68, 0.25)" },
  };
  const style = statusStyles[scope.status] || statusStyles.pending;

  return (
    <div className="glass-card" style={{ padding: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
        <div>
          <h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: 4 }}>{scope.name}</h3>
          <div style={{ fontSize: "0.8rem", color: "var(--sg-accent-cyan)", fontFamily: "monospace" }}>
            {scope.includeSubdomains ? "*." : ""}{scope.target}
          </div>
        </div>
        <span
          style={{
            padding: "4px 12px",
            borderRadius: 999,
            fontSize: "0.7rem",
            fontWeight: 600,
            textTransform: "uppercase",
            letterSpacing: "0.05em",
            color: style.color,
            background: style.bg,
            border: `1px solid ${style.border}`,
          }}
        >
          {scope.status}
        </span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 16 }}>
        <div style={{ padding: "10px 12px", background: "var(--sg-bg-elevated)", borderRadius: 8 }}>
          <div style={{ fontSize: "0.65rem", color: "var(--sg-text-muted)", textTransform: "uppercase", marginBottom: 4 }}>Type</div>
          <div style={{ fontSize: "0.85rem", fontWeight: 600 }}>{scope.type}</div>
        </div>
        <div style={{ padding: "10px 12px", background: "var(--sg-bg-elevated)", borderRadius: 8 }}>
          <div style={{ fontSize: "0.65rem", color: "var(--sg-text-muted)", textTransform: "uppercase", marginBottom: 4 }}>Scans</div>
          <div style={{ fontSize: "0.85rem", fontWeight: 600 }}>{scope.scans}</div>
        </div>
        <div style={{ padding: "10px 12px", background: "var(--sg-bg-elevated)", borderRadius: 8 }}>
          <div style={{ fontSize: "0.65rem", color: "var(--sg-text-muted)", textTransform: "uppercase", marginBottom: 4 }}>Rate Limit</div>
          <div style={{ fontSize: "0.85rem", fontWeight: 600 }}>{scope.maxRps} rps</div>
        </div>
      </div>

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ fontSize: "0.75rem", color: "var(--sg-text-muted)" }}>
          {scope.validatedAt ? `Validated ${scope.validatedAt}` : "Awaiting validation"}
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {scope.status === "pending" && (
            <button className="btn-primary" style={{ padding: "6px 14px", fontSize: "0.75rem" }}>
              Validate
            </button>
          )}
          <button className="btn-ghost" style={{ padding: "6px 14px", fontSize: "0.75rem" }}>
            Configure
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ScopesView() {
  return (
    <div style={{ maxWidth: 1400 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 32 }}>
        <div>
          <h1 style={{ fontSize: "1.75rem", fontWeight: 700, marginBottom: 4 }}>Authorized Scopes</h1>
          <p style={{ color: "var(--sg-text-secondary)", fontSize: "0.875rem" }}>
            Manage target scopes and ownership verification
          </p>
        </div>
        <button className="btn-primary">+ New Scope</button>
      </div>

      {/* Scope Gate Warning */}
      <div
        className="glass-card"
        style={{
          padding: "14px 20px",
          marginBottom: 24,
          borderLeft: "3px solid var(--sg-accent-primary)",
          display: "flex",
          alignItems: "center",
          gap: 12,
        }}
      >
        <span style={{ fontSize: "1.1rem" }}>🛡️</span>
        <div style={{ flex: 1 }}>
          <span style={{ fontSize: "0.8rem", fontWeight: 600 }}>Scope Enforcement Gateway Active</span>
          <span style={{ fontSize: "0.75rem", color: "var(--sg-text-muted)", marginLeft: 8 }}>
            All outbound requests are validated against active scopes. SSRF protection and DNS rebinding checks enabled.
          </span>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(400px, 1fr))", gap: 20 }}>
        {mockScopes.map((scope) => (
          <ScopeCard key={scope.id} scope={scope} />
        ))}
      </div>
    </div>
  );
}
