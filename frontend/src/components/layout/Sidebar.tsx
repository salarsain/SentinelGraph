"use client";

import type { ViewType } from "@/app/page";

interface SidebarProps {
  activeView: ViewType;
  onNavigate: (view: ViewType) => void;
}

const navItems: { id: ViewType; label: string; icon: string }[] = [
  { id: "dashboard", label: "Dashboard", icon: "◆" },
  { id: "scans", label: "Scans", icon: "⬡" },
  { id: "scopes", label: "Scopes", icon: "◎" },
  { id: "findings", label: "Findings", icon: "⚠" },
  { id: "reports", label: "Reports", icon: "◧" },
  { id: "settings", label: "Settings", icon: "⚙" },
];

export default function Sidebar({ activeView, onNavigate }: SidebarProps) {
  return (
    <aside
      style={{
        width: 260,
        minWidth: 260,
        display: "flex",
        flexDirection: "column",
        borderRight: "1px solid var(--sg-border)",
        background: "var(--sg-bg-secondary)",
        height: "100vh",
        position: "sticky",
        top: 0,
      }}
    >
      {/* Logo */}
      <div
        style={{
          padding: "24px 20px",
          borderBottom: "1px solid var(--sg-border)",
          display: "flex",
          alignItems: "center",
          gap: 12,
        }}
      >
        <div
          style={{
            width: 36,
            height: 36,
            borderRadius: 10,
            background: "var(--sg-gradient-primary)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 18,
            fontWeight: 700,
            color: "white",
            boxShadow: "0 4px 15px rgba(99, 102, 241, 0.3)",
          }}
        >
          S
        </div>
        <div>
          <h1 style={{ fontSize: "1rem", fontWeight: 700, letterSpacing: "-0.03em" }}>
            SentinelGraph
          </h1>
          <span
            style={{
              fontSize: "0.65rem",
              color: "var(--sg-text-muted)",
              textTransform: "uppercase",
              letterSpacing: "0.1em",
            }}
          >
            Security Platform
          </span>
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, padding: "16px 12px", display: "flex", flexDirection: "column", gap: 4 }}>
        {navItems.map((item) => {
          const isActive = activeView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                padding: "10px 14px",
                borderRadius: 10,
                border: "none",
                cursor: "pointer",
                fontSize: "0.875rem",
                fontWeight: isActive ? 600 : 400,
                color: isActive ? "var(--sg-text-primary)" : "var(--sg-text-secondary)",
                background: isActive
                  ? "rgba(99, 102, 241, 0.12)"
                  : "transparent",
                borderLeft: isActive ? "3px solid var(--sg-accent-primary)" : "3px solid transparent",
                transition: "all 0.15s ease",
                textAlign: "left",
                width: "100%",
              }}
              onMouseEnter={(e) => {
                if (!isActive) {
                  (e.target as HTMLElement).style.background = "var(--sg-bg-hover)";
                  (e.target as HTMLElement).style.color = "var(--sg-text-primary)";
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  (e.target as HTMLElement).style.background = "transparent";
                  (e.target as HTMLElement).style.color = "var(--sg-text-secondary)";
                }
              }}
            >
              <span style={{ fontSize: "1.1rem", width: 24, textAlign: "center" }}>{item.icon}</span>
              {item.label}
            </button>
          );
        })}
      </nav>

      {/* Bottom Section */}
      <div
        style={{
          padding: "16px 20px",
          borderTop: "1px solid var(--sg-border)",
        }}
      >
        <div className="glass-card" style={{ padding: "12px 14px", borderRadius: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div
              style={{
                width: 32,
                height: 32,
                borderRadius: 8,
                background: "var(--sg-bg-elevated)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: "0.8rem",
                fontWeight: 600,
                color: "var(--sg-accent-primary)",
              }}
            >
              KB
            </div>
            <div>
              <div style={{ fontSize: "0.8rem", fontWeight: 600 }}>Analyst</div>
              <div style={{ fontSize: "0.65rem", color: "var(--sg-text-muted)" }}>Security Team</div>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
}
