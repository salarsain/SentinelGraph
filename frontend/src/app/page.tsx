"use client";

import { useState } from "react";
import Sidebar from "@/components/layout/Sidebar";
import DashboardView from "@/components/views/DashboardView";
import ScansView from "@/components/views/ScansView";
import ScopesView from "@/components/views/ScopesView";
import FindingsView from "@/components/views/FindingsView";
import ReportsView from "@/components/views/ReportsView";
import SettingsView from "@/components/views/SettingsView";

export type ViewType = "dashboard" | "scans" | "scopes" | "findings" | "reports" | "settings";

export default function Home() {
  const [activeView, setActiveView] = useState<ViewType>("dashboard");

  const renderView = () => {
    switch (activeView) {
      case "dashboard":
        return <DashboardView />;
      case "scans":
        return <ScansView />;
      case "scopes":
        return <ScopesView />;
      case "findings":
        return <FindingsView />;
      case "reports":
        return <ReportsView />;
      case "settings":
        return <SettingsView />;
      default:
        return <DashboardView />;
    }
  };

  return (
    <div className="flex h-screen overflow-hidden" style={{ position: "relative", zIndex: 1 }}>
      <Sidebar activeView={activeView} onNavigate={setActiveView} />
      <main className="flex-1 overflow-y-auto" style={{ padding: "24px 32px" }}>
        {renderView()}
      </main>
    </div>
  );
}

