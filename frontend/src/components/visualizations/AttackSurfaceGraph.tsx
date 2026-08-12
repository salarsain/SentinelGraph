"use client";

import { useState, useEffect, useRef, useCallback } from "react";

interface GraphNode {
  id: string;
  label: string;
  type: "target" | "endpoint" | "parameter" | "technology" | "finding" | "asset";
  severity?: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  color: string;
}

interface GraphEdge {
  source: string;
  target: string;
  type: string;
}

interface ScanData {
  target: string;
  technologies: string[];
  findings: Array<{
    severity: string;
    title: string;
    url: string;
    category: string;
  }>;
}

const COLORS: Record<string, string> = {
  target: "#6366f1",
  endpoint: "#06b6d4",
  parameter: "#8b5cf6",
  technology: "#10b981",
  finding_critical: "#ef4444",
  finding_high: "#f97316",
  finding_medium: "#eab308",
  finding_low: "#3b82f6",
  finding_info: "#6b7280",
  asset: "#14b8a6",
};

function buildGraph(data: ScanData): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const cx = 400, cy = 300;

  // Central target node
  nodes.push({
    id: "target", label: new URL(data.target).hostname, type: "target",
    x: cx, y: cy, vx: 0, vy: 0, radius: 28, color: COLORS.target,
  });

  // Technology nodes
  data.technologies.forEach((tech, i) => {
    const angle = (i / Math.max(data.technologies.length, 1)) * Math.PI * 2 - Math.PI / 2;
    const dist = 140;
    nodes.push({
      id: `tech-${i}`, label: tech, type: "technology",
      x: cx + Math.cos(angle) * dist, y: cy + Math.sin(angle) * dist,
      vx: 0, vy: 0, radius: 16, color: COLORS.technology,
    });
    edges.push({ source: "target", target: `tech-${i}`, type: "uses" });
  });

  // Finding nodes — group by category
  const categories = [...new Set(data.findings.map(f => f.category))];
  categories.forEach((cat, ci) => {
    const catAngle = (ci / Math.max(categories.length, 1)) * Math.PI * 2;
    const catDist = 250;
    const catX = cx + Math.cos(catAngle) * catDist;
    const catY = cy + Math.sin(catAngle) * catDist;

    const catFindings = data.findings.filter(f => f.category === cat);
    catFindings.forEach((f, fi) => {
      const subAngle = catAngle + ((fi - catFindings.length / 2) * 0.3);
      const subDist = 40 + fi * 15;
      const color = COLORS[`finding_${f.severity}`] || COLORS.finding_info;
      const id = `finding-${ci}-${fi}`;

      nodes.push({
        id, label: f.title.substring(0, 25), type: "finding", severity: f.severity,
        x: catX + Math.cos(subAngle) * subDist, y: catY + Math.sin(subAngle) * subDist,
        vx: 0, vy: 0, radius: 10 + (f.severity === "critical" ? 6 : f.severity === "high" ? 4 : 2),
        color,
      });
      edges.push({ source: "target", target: id, type: "has_finding" });
    });
  });

  return { nodes, edges };
}

export default function AttackSurfaceGraph() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [graphData, setGraphData] = useState<{ nodes: GraphNode[]; edges: GraphEdge[] } | null>(null);
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
  const animFrameRef = useRef<number>(0);

  useEffect(() => {
    fetch("/scan_results.json")
      .then(r => r.json())
      .then(data => {
        const graph = buildGraph(data);
        setGraphData(graph);
      })
      .catch(() => {});
  }, []);

  // Simple force-directed layout
  const simulate = useCallback(() => {
    if (!graphData) return;
    const { nodes, edges } = graphData;

    // Repulsion between all nodes
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[j].x - nodes[i].x;
        const dy = nodes[j].y - nodes[i].y;
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
        const force = 500 / (dist * dist);
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        nodes[i].vx -= fx; nodes[i].vy -= fy;
        nodes[j].vx += fx; nodes[j].vy += fy;
      }
    }

    // Attraction along edges
    for (const edge of edges) {
      const src = nodes.find(n => n.id === edge.source);
      const tgt = nodes.find(n => n.id === edge.target);
      if (!src || !tgt) continue;
      const dx = tgt.x - src.x;
      const dy = tgt.y - src.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const idealDist = src.type === "target" ? 180 : 80;
      const force = (dist - idealDist) * 0.005;
      const fx = (dx / Math.max(dist, 1)) * force;
      const fy = (dy / Math.max(dist, 1)) * force;
      src.vx += fx; src.vy += fy;
      tgt.vx -= fx; tgt.vy -= fy;
    }

    // Center gravity
    const cx = dimensions.width / 2, cy = dimensions.height / 2;
    for (const node of nodes) {
      node.vx += (cx - node.x) * 0.001;
      node.vy += (cy - node.y) * 0.001;
      node.vx *= 0.85; node.vy *= 0.85;
      node.x += node.vx; node.y += node.vy;
      node.x = Math.max(node.radius, Math.min(dimensions.width - node.radius, node.x));
      node.y = Math.max(node.radius, Math.min(dimensions.height - node.radius, node.y));
    }
  }, [graphData, dimensions]);

  // Render loop
  useEffect(() => {
    if (!graphData || !canvasRef.current) return;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const render = () => {
      simulate();
      ctx.clearRect(0, 0, dimensions.width, dimensions.height);

      // Draw edges
      for (const edge of graphData.edges) {
        const src = graphData.nodes.find(n => n.id === edge.source);
        const tgt = graphData.nodes.find(n => n.id === edge.target);
        if (!src || !tgt) continue;

        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);
        ctx.strokeStyle = "rgba(99, 102, 241, 0.15)";
        ctx.lineWidth = 1;
        ctx.stroke();
      }

      // Draw nodes
      for (const node of graphData.nodes) {
        // Glow
        const gradient = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, node.radius * 2);
        gradient.addColorStop(0, node.color + "40");
        gradient.addColorStop(1, "transparent");
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius * 2, 0, Math.PI * 2);
        ctx.fillStyle = gradient;
        ctx.fill();

        // Circle
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fillStyle = node.color + "30";
        ctx.fill();
        ctx.strokeStyle = node.color;
        ctx.lineWidth = hoveredNode?.id === node.id ? 3 : 1.5;
        ctx.stroke();

        // Label
        ctx.font = `${node.type === "target" ? "bold 11px" : "9px"} Inter, sans-serif`;
        ctx.fillStyle = "#e2e8f0";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        if (node.type === "target") {
          ctx.fillText(node.label, node.x, node.y);
        } else {
          ctx.fillText(node.label, node.x, node.y + node.radius + 12);
        }
      }

      animFrameRef.current = requestAnimationFrame(render);
    };

    animFrameRef.current = requestAnimationFrame(render);
    return () => { if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current); };
  }, [graphData, hoveredNode, simulate, dimensions]);

  // Mouse interaction
  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!graphData || !canvasRef.current) return;
    const rect = canvasRef.current.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    let found: GraphNode | null = null;
    for (const node of graphData.nodes) {
      const dx = mx - node.x, dy = my - node.y;
      if (Math.sqrt(dx * dx + dy * dy) < node.radius + 5) {
        found = node;
        break;
      }
    }
    setHoveredNode(found);
  }, [graphData]);

  useEffect(() => {
    const updateSize = () => {
      const container = canvasRef.current?.parentElement;
      if (container) {
        setDimensions({ width: container.clientWidth, height: Math.max(500, container.clientHeight) });
      }
    };
    updateSize();
    window.addEventListener("resize", updateSize);
    return () => window.removeEventListener("resize", updateSize);
  }, []);

  if (!graphData) {
    return (
      <div className="glass-card" style={{ padding: 40, textAlign: "center", color: "var(--sg-text-muted)" }}>
        Loading attack surface graph...
      </div>
    );
  }

  return (
    <div style={{ position: "relative" }}>
      <canvas
        ref={canvasRef}
        width={dimensions.width}
        height={dimensions.height}
        onMouseMove={handleMouseMove}
        style={{ borderRadius: 16, cursor: hoveredNode ? "pointer" : "default" }}
      />

      {/* Legend */}
      <div style={{
        position: "absolute", bottom: 16, left: 16, display: "flex", gap: 16,
        padding: "8px 16px", background: "rgba(15, 17, 23, 0.85)", borderRadius: 10,
        backdropFilter: "blur(10px)", border: "1px solid var(--sg-border)",
      }}>
        {[
          { label: "Target", color: COLORS.target },
          { label: "Technology", color: COLORS.technology },
          { label: "Critical", color: COLORS.finding_critical },
          { label: "High", color: COLORS.finding_high },
          { label: "Medium", color: COLORS.finding_medium },
          { label: "Low/Info", color: COLORS.finding_low },
        ].map(item => (
          <div key={item.label} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: item.color }} />
            <span style={{ fontSize: "0.65rem", color: "var(--sg-text-muted)" }}>{item.label}</span>
          </div>
        ))}
      </div>

      {/* Hover tooltip */}
      {hoveredNode && (
        <div style={{
          position: "absolute", top: 16, right: 16,
          padding: "12px 16px", background: "rgba(15, 17, 23, 0.9)", borderRadius: 10,
          backdropFilter: "blur(10px)", border: "1px solid var(--sg-border)",
          maxWidth: 250,
        }}>
          <div style={{ fontSize: "0.8rem", fontWeight: 600, marginBottom: 4 }}>{hoveredNode.label}</div>
          <div style={{ fontSize: "0.7rem", color: "var(--sg-text-muted)" }}>
            Type: {hoveredNode.type}
            {hoveredNode.severity && <> • Severity: <span style={{ color: COLORS[`finding_${hoveredNode.severity}`] }}>{hoveredNode.severity}</span></>}
          </div>
        </div>
      )}
    </div>
  );
}
