"use client";

import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import {
  RefreshCw,
  Shield,
  AlertTriangle,
  Terminal,
  Key,
  Radar,
  Activity,
  Crosshair,
  Layers,
  Radio,
  CheckCircle2,
  Sparkles,
  Server,
  Zap,
  Play,
  Bell,
} from "lucide-react";

// Core production assets placed at the center of the topology
const CORE_ASSETS = [
  { id: "core-db", label: "PROD-DB-PRIMARY", type: "PostgreSQL Database", relX: 0, relY: -0.12 },
  { id: "core-auth", label: "AUTH-GATEWAY-01", type: "OAuth/JWT Service", relX: -0.15, relY: 0.05 },
  { id: "core-api", label: "API-EDGE-ROUTER", type: "Core Microservice", relX: 0.15, relY: 0.05 },
  { id: "core-vault", label: "KMS-VAULT-CLUSTER", type: "Key Management", relX: -0.08, relY: 0.18 },
  { id: "core-worker", label: "PIPELINE-WORKER", type: "Worker Queue", relX: 0.08, relY: 0.18 },
];

const CATEGORIES = ["secret", "database", "token", "key", "generic"];
const PREFIXES = ["APP", "SVC", "INTERNAL", "STAGING", "BACKUP"];
const SUFFIXES = ["SECRET_KEY", "DB_URI", "API_TOKEN", "ACCESS_KEY", "ADMIN_PASS"];

// Deterministic decoy constellation generator
function generateDecoyConstellation(count = 190) {
  const nodes = [];
  for (let i = 0; i < count; i++) {
    const ring = Math.floor(i / (count / 4));
    const baseRadius = 0.22 + ring * 0.16 + Math.sin(i * 99) * 0.04;
    const angle = i * 2.39996 + Math.cos(i * 13) * 0.2;

    const cat = CATEGORIES[i % CATEGORIES.length];
    const prefix = PREFIXES[i % PREFIXES.length];
    const suffix = SUFFIXES[i % SUFFIXES.length];
    const trapId = `trap_${String((i % 12) + 1).padStart(2, "0")}`;

    nodes.push({
      id: `decoy-${i}`,
      trapId,
      name: `${prefix}_${cat.toUpperCase()}_${suffix}`,
      category: cat,
      relX: Math.cos(angle) * baseRadius,
      relY: Math.sin(angle) * baseRadius * 0.72,
      baseRadius,
      angle,
      speed: Math.sin(i) * 0.0003 + 0.0002,
    });
  }
  return nodes;
}

// Sub-component: Ghost Network Topology View
function GhostTopology({
  alerts,
  staticDecoys,
  triggeredTrapMap,
  totalDecoysCount,
  coreAssetsCount,
  deceptionRatio,
  dwellMultiplier,
  onRefresh,
  isRefreshing,
}) {
  const canvasRef = useRef(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [filterTriggeredOnly, setFilterTriggeredOnly] = useState(false);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    let animationFrameId;
    let width = 0;
    let height = 0;

    const resizeCanvas = () => {
      const rect = canvas.getBoundingClientRect();
      width = rect.width;
      height = rect.height;
      const dpr = window.devicePixelRatio || 1;
      canvas.width = rect.width * dpr;
      canvas.height = rect.height * dpr;
      ctx.scale(dpr, dpr);
    };

    resizeCanvas();
    window.addEventListener("resize", resizeCanvas);

    let tick = 0;

    const render = () => {
      tick += 0.02;
      ctx.clearRect(0, 0, width, height);

      const centerX = width / 2;
      const centerY = height / 2;
      const minDim = Math.min(width, height);

      // Background coordinate grid
      ctx.strokeStyle = "rgba(255, 255, 255, 0.03)";
      ctx.lineWidth = 1;
      const gridSize = 40;
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // Cyan radar sweep rings
      ctx.strokeStyle = "rgba(6, 182, 212, 0.06)";
      ctx.lineWidth = 1;
      [0.2, 0.38, 0.56, 0.74].forEach((ratio) => {
        ctx.beginPath();
        ctx.arc(centerX, centerY, (minDim * ratio) / 2, 0, Math.PI * 2);
        ctx.stroke();
      });

      // Rotating radar beam
      const sweepAngle = tick * 0.35;
      const gradient = ctx.createRadialGradient(centerX, centerY, 10, centerX, centerY, minDim * 0.42);
      gradient.addColorStop(0, "rgba(6, 182, 212, 0.09)");
      gradient.addColorStop(1, "rgba(6, 182, 212, 0)");
      ctx.save();
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.arc(centerX, centerY, minDim * 0.42, sweepAngle, sweepAngle + 0.35);
      ctx.closePath();
      ctx.fillStyle = gradient;
      ctx.fill();
      ctx.restore();

      // Node coordinate calculation
      const corePositions = CORE_ASSETS.map((asset) => ({
        ...asset,
        absX: centerX + asset.relX * minDim,
        absY: centerY + asset.relY * minDim,
      }));

      const decoyPositions = staticDecoys.map((decoy) => {
        const currentAngle = decoy.angle + tick * decoy.speed * 20;
        return {
          ...decoy,
          absX: centerX + Math.cos(currentAngle) * decoy.baseRadius * minDim,
          absY: centerY + Math.sin(currentAngle) * decoy.baseRadius * minDim * 0.72,
          isTriggered: triggeredTrapMap.has(decoy.trapId),
          alertData: triggeredTrapMap.get(decoy.trapId) || null,
        };
      });

      // Decoy interconnection mesh links
      ctx.strokeStyle = "rgba(255, 255, 255, 0.035)";
      ctx.lineWidth = 0.75;
      for (let i = 0; i < decoyPositions.length; i += 2) {
        const nodeA = decoyPositions[i];
        for (let j = i + 1; j < Math.min(i + 6, decoyPositions.length); j++) {
          const nodeB = decoyPositions[j];
          const dist = Math.hypot(nodeA.absX - nodeB.absX, nodeA.absY - nodeB.absY);
          if (dist < minDim * 0.11) {
            ctx.beginPath();
            ctx.moveTo(nodeA.absX, nodeA.absY);
            ctx.lineTo(nodeB.absX, nodeB.absY);
            ctx.stroke();
          }
        }
      }

      // Core-to-decoy connections
      corePositions.forEach((core) => {
        decoyPositions.slice(0, 14).forEach((decoy) => {
          if (Math.hypot(core.absX - decoy.absX, core.absY - decoy.absY) < minDim * 0.16) {
            ctx.strokeStyle = "rgba(6, 182, 212, 0.08)";
            ctx.beginPath();
            ctx.moveTo(core.absX, core.absY);
            ctx.lineTo(decoy.absX, decoy.absY);
            ctx.stroke();
          }
        });
      });

      // Render decoy nodes
      decoyPositions.forEach((node) => {
        if (filterTriggeredOnly && !node.isTriggered) return;

        if (node.isTriggered) {
          const pulseR = 8 + Math.abs(Math.sin(tick * 3)) * 14;
          ctx.beginPath();
          ctx.arc(node.absX, node.absY, pulseR, 0, Math.PI * 2);
          ctx.strokeStyle = "rgba(244, 63, 94, 0.4)";
          ctx.lineWidth = 1.5;
          ctx.stroke();

          ctx.beginPath();
          ctx.arc(node.absX, node.absY, pulseR + 8, 0, Math.PI * 2);
          ctx.strokeStyle = "rgba(244, 63, 94, 0.15)";
          ctx.lineWidth = 1;
          ctx.stroke();

          ctx.beginPath();
          ctx.arc(node.absX, node.absY, 5, 0, Math.PI * 2);
          ctx.fillStyle = "#f43f5e";
          ctx.fill();

          ctx.fillStyle = "#f43f5e";
          ctx.font = "500 10px monospace";
          ctx.fillText(`TRIPPED: ${node.trapId}`, node.absX + 9, node.absY - 6);
        } else {
          ctx.beginPath();
          ctx.arc(node.absX, node.absY, 2.2, 0, Math.PI * 2);
          ctx.fillStyle = "rgba(148, 163, 184, 0.28)";
          ctx.fill();
        }
      });

      // Render attack vectors
      let vectorIndex = 0;
      decoyPositions.forEach((node) => {
        if (!node.isTriggered || !node.alertData) return;

        const attackerAngle = vectorIndex * 1.57 + 0.5;
        const attackerX = centerX + Math.cos(attackerAngle) * (minDim * 0.47);
        const attackerY = centerY + Math.sin(attackerAngle) * (minDim * 0.44);
        vectorIndex++;

        ctx.beginPath();
        ctx.arc(attackerX, attackerY, 6, 0, Math.PI * 2);
        ctx.fillStyle = "#f43f5e";
        ctx.fill();

        ctx.beginPath();
        ctx.arc(attackerX, attackerY, 11, 0, Math.PI * 2);
        ctx.strokeStyle = "rgba(244, 63, 94, 0.4)";
        ctx.lineWidth = 1.5;
        ctx.stroke();

        ctx.fillStyle = "#f43f5e";
        ctx.font = "600 10px sans-serif";
        const attackerIp = node.alertData.source_ip || node.alertData.ip || "Attacker Ingress";
        ctx.fillText(`THREAT INGRESS [${attackerIp}]`, attackerX - 60, attackerY - 14);

        ctx.save();
        ctx.setLineDash([6, 6]);
        ctx.lineDashOffset = -tick * 30;
        ctx.strokeStyle = "rgba(244, 63, 94, 0.75)";
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(attackerX, attackerY);
        ctx.lineTo(node.absX, node.absY);
        ctx.stroke();
        ctx.restore();

        const packetRatio = (tick * 0.65) % 1;
        const packetX = attackerX + (node.absX - attackerX) * packetRatio;
        const packetY = attackerY + (node.absY - attackerY) * packetRatio;

        ctx.beginPath();
        ctx.arc(packetX, packetY, 3.5, 0, Math.PI * 2);
        ctx.fillStyle = "#ffffff";
        ctx.fill();

        const midX = (attackerX + node.absX) / 2;
        const midY = (attackerY + node.absY) / 2;
        ctx.fillStyle = "rgba(15, 23, 42, 0.9)";
        ctx.fillRect(midX - 48, midY - 10, 96, 20);
        ctx.strokeStyle = "rgba(244, 63, 94, 0.3)";
        ctx.strokeRect(midX - 48, midY - 10, 96, 20);
        ctx.fillStyle = "#f43f5e";
        ctx.font = "500 9px monospace";
        ctx.fillText("TARPIT ENGAGED", midX - 38, midY + 3);
      });

      // Render core assets
      corePositions.forEach((core) => {
        const halo = ctx.createRadialGradient(core.absX, core.absY, 4, core.absX, core.absY, 24);
        halo.addColorStop(0, "rgba(6, 182, 212, 0.3)");
        halo.addColorStop(1, "rgba(6, 182, 212, 0)");
        ctx.fillStyle = halo;
        ctx.beginPath();
        ctx.arc(core.absX, core.absY, 24, 0, Math.PI * 2);
        ctx.fill();

        ctx.beginPath();
        ctx.arc(core.absX, core.absY, 12, 0, Math.PI * 2);
        ctx.fillStyle = "#090d16";
        ctx.fill();
        ctx.strokeStyle = "#38bdf8";
        ctx.lineWidth = 2;
        ctx.stroke();

        ctx.beginPath();
        ctx.arc(core.absX, core.absY, 4, 0, Math.PI * 2);
        ctx.fillStyle = "#38bdf8";
        ctx.fill();

        ctx.fillStyle = "#e2e8f0";
        ctx.font = "600 10px sans-serif";
        ctx.textAlign = "center";
        ctx.fillText(core.label, core.absX, core.absY + 22);
        ctx.textAlign = "left";
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    const handleMouseMove = (e) => {
      const rect = canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;
      const minDim = Math.min(rect.width, rect.height);
      const centerX = rect.width / 2;
      const centerY = rect.height / 2;

      for (const core of CORE_ASSETS) {
        if (Math.hypot(mouseX - (centerX + core.relX * minDim), mouseY - (centerY + core.relY * minDim)) < 18) {
          setHoveredNode({
            name: core.label,
            type: "Core Production Asset",
            category: core.type,
            status: "Protected (Zero Exposure)",
            x: mouseX,
            y: mouseY,
          });
          return;
        }
      }

      for (const decoy of staticDecoys) {
        if (Math.hypot(mouseX - (centerX + decoy.relX * minDim), mouseY - (centerY + decoy.relY * minDim)) < 12) {
          const alert = triggeredTrapMap.get(decoy.trapId);
          setHoveredNode({
            name: decoy.name,
            type: "Ghost Decoy Trap",
            category: decoy.category.toUpperCase(),
            status: alert ? `Compromised (${alert.source_ip || "External"})` : "Armed & Silent",
            isTriggered: Boolean(alert),
            tarpit: alert?.status || null,
            x: mouseX,
            y: mouseY,
          });
          return;
        }
      }

      setHoveredNode(null);
    };

    canvas.addEventListener("mousemove", handleMouseMove);

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("resize", resizeCanvas);
      canvas.removeEventListener("mousemove", handleMouseMove);
    };
  }, [staticDecoys, triggeredTrapMap, filterTriggeredOnly]);

  return (
    <div className="space-y-6">
      {/* Live Stats HUD Bar */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="backdrop-blur-xl bg-neutral-900/40 border border-white/8 rounded-2xl p-5 shadow-xl shadow-black/20 hover:border-white/12 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium uppercase tracking-wider text-neutral-400">
              Active Deception Surface
            </span>
            <div className="p-1.5 rounded-lg bg-cyan-500/10 text-cyan-400">
              <Layers className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-semibold tracking-tight text-white">{deceptionRatio}% Density</div>
            <div className="text-xs text-neutral-500 font-mono mt-1">
              {totalDecoysCount} Decoy Entities vs {coreAssetsCount} Core
            </div>
          </div>
        </div>

        <div className="backdrop-blur-xl bg-neutral-900/40 border border-white/8 rounded-2xl p-5 shadow-xl shadow-black/20 hover:border-white/12 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium uppercase tracking-wider text-neutral-400">
              Attacker Dwell Time Multiplier
            </span>
            <div className="p-1.5 rounded-lg bg-amber-500/10 text-amber-400">
              <Crosshair className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-semibold tracking-tight text-amber-300">{dwellMultiplier}</div>
            <div className="text-xs text-neutral-500 font-mono mt-1">Behavioral Tarpit Injected</div>
          </div>
        </div>

        <div className="backdrop-blur-xl bg-neutral-900/40 border border-white/8 rounded-2xl p-5 shadow-xl shadow-black/20 hover:border-white/12 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium uppercase tracking-wider text-neutral-400">
              Neutralized Threats
            </span>
            <div className="p-1.5 rounded-lg bg-rose-500/10 text-rose-400">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-semibold tracking-tight text-rose-400">{alerts.length} Tripped Traps</div>
            <div className="text-xs text-neutral-500 font-mono mt-1">Suspended & Entangled in Mesh</div>
          </div>
        </div>
      </div>

      {/* Interactive Canvas Graph Container */}
      <div className="relative backdrop-blur-xl bg-neutral-900/40 border border-white/8 rounded-2xl overflow-hidden h-155 w-full shadow-2xl shadow-black/40">
        <canvas ref={canvasRef} className="w-full h-full block cursor-crosshair" />

        {/* Top-Left Tactical HUD Overlay */}
        <div className="absolute top-4 left-4 pointer-events-none space-y-2">
          <div className="backdrop-blur-md bg-neutral-950/70 border border-white/8 rounded-xl px-4 py-2.5 shadow-lg">
            <div className="text-xs font-semibold text-white flex items-center gap-2">
              <Radar className="w-3.5 h-3.5 text-cyan-400 animate-spin" />
              DECEPTION TOPOLOGY // REAL-TIME MESH
            </div>
            <div className="text-[10px] text-neutral-400 font-mono mt-0.5">
              SURFACE: {totalDecoysCount} NODES | ORBITAL MESH ACTIVE
            </div>
          </div>

          <div className="backdrop-blur-md bg-neutral-950/70 border border-white/8 rounded-xl p-3 text-[11px] space-y-2 shadow-lg">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 border border-cyan-300" />
              <span className="text-neutral-300">Core Production Asset</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-slate-400/40" />
              <span className="text-neutral-400">Silent Ghost Decoy</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse" />
              <span className="text-rose-400 font-medium">Compromised Canary Trap</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-4 h-0.5 bg-rose-500 border-t border-dashed border-rose-500" />
              <span className="text-rose-400">Active Threat Ingress Vector</span>
            </div>
          </div>
        </div>

        {/* Top-Right Control Buttons */}
        <div className="absolute top-4 right-4 flex gap-2">
          <button
            onClick={() => setFilterTriggeredOnly((prev) => !prev)}
            className={`px-3 py-1.5 text-xs font-medium rounded-xl border transition-all duration-200 cursor-pointer backdrop-blur-md ${
              filterTriggeredOnly
                ? "bg-rose-500/20 text-rose-300 border-rose-500/40 shadow-sm"
                : "bg-neutral-950/70 text-neutral-400 border-white/8 hover:text-white hover:bg-white/4"
            }`}
          >
            {filterTriggeredOnly ? "Showing Triggered Only" : "Show All Nodes"}
          </button>
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className="bg-neutral-950/70 hover:bg-white/4 text-cyan-400 border border-cyan-500/30 px-3.5 py-1.5 rounded-xl text-xs font-medium transition-all duration-200 flex items-center gap-1.5 cursor-pointer backdrop-blur-md shadow-sm"
          >
            <RefreshCw className={`w-3 h-3 ${isRefreshing ? "animate-spin" : ""}`} />
            Sync Topology
          </button>
        </div>

        {/* Node Inspector Tooltip */}
        {hoveredNode && (
          <div
            className="absolute pointer-events-none backdrop-blur-xl bg-neutral-900/90 border border-cyan-500/40 p-3 rounded-xl shadow-2xl text-xs space-y-1 z-20"
            style={{
              left: Math.min(hoveredNode.x + 16, 780),
              top: Math.min(hoveredNode.y + 16, 480),
            }}
          >
            <div className="font-semibold text-white">{hoveredNode.name}</div>
            <div className="text-[11px] text-neutral-400">{hoveredNode.type}</div>
            <div className="text-[11px] text-neutral-300 font-mono">Class: {hoveredNode.category}</div>
            <div className={`text-[11px] font-medium ${hoveredNode.isTriggered ? "text-rose-400" : "text-cyan-400"}`}>
              State: {hoveredNode.status}
            </div>
            {hoveredNode.tarpit && <div className="text-[10px] text-amber-300 font-mono">{hoveredNode.tarpit}</div>}
          </div>
        )}

        {/* Bottom Telemetry Bar */}
        <div className="absolute bottom-3 left-4 right-4 flex items-center justify-between text-[11px] text-neutral-500 pointer-events-none font-mono">
          <span>MESH ENCRYPTION: SHA-256 CANARY TOKENS</span>
          <span className="text-cyan-400">BEHAVIORAL TARPIT RADAR ENGAGED</span>
        </div>
      </div>
    </div>
  );
}

// Main Dashboard Component
export default function SpectreSyncDashboard() {
  const [activeTab, setActiveTab] = useState("deploy");
  const [targetPath, setTargetPath] = useState("");
  const [isDeploying, setIsDeploying] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [logs, setLogs] = useState([]);
  const [decoys, setDecoys] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [testingTrapId, setTestingTrapId] = useState(null);
  const [toastNotification, setToastNotification] = useState(null);
  const redirectTimerRef = useRef(null);

  // Clean up any pending redirect timer on unmount
  useEffect(() => {
    return () => {
      if (redirectTimerRef.current) {
        clearTimeout(redirectTimerRef.current);
      }
    };
  }, []);

  // Telemetry log appender
  const appendLog = useCallback((message, level = "info") => {
    const time = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, { time, message, level }]);
  }, []);

  // Shared alert fetch logic
  const fetchAlerts = useCallback(async () => {
    try {
      const response = await fetch("http://localhost:5000/api/alerts");
      if (!response.ok) throw new Error(`Status ${response.status}`);
      const data = await response.json();
      setAlerts(Array.isArray(data) ? data : data.alerts || []);
    } catch (err) {
      appendLog(`Failed to fetch alerts: ${err.message}`, "error");
    }
  }, [appendLog]);

  // Toolbar manual refresh handler
  const handleManualRefresh = useCallback(async () => {
    setIsRefreshing(true);
    try {
      await fetchAlerts();
    } finally {
      setIsRefreshing(false);
    }
  }, [fetchAlerts]);

  // Trigger or simulate a canary trap activation
  const handleTriggerCanary = async (trapId) => {
    setTestingTrapId(trapId);
    appendLog(`Simulating canary trap hit: ${trapId}...`, "warn");

    try {
      const endpoint = `http://localhost:5000/api/canary?id=${encodeURIComponent(trapId)}`;
      const response = await fetch(endpoint);
      if (!response.ok) throw new Error(`Status ${response.status}`);
      await response.json();

      appendLog(`Canary trap ${trapId} triggered successfully. Tarpit engaged.`, "warn");

      // Show temporary confirmation toast banner
      setToastNotification({
        title: "Canary Trap Activated",
        message: `Trap ${trapId} triggered. Redirecting to SOC Threat Stream...`,
        trapId,
      });

      // Clear any existing redirect timer
      if (redirectTimerRef.current) {
        clearTimeout(redirectTimerRef.current);
      }

      // Automatically switch to the SOC tab after 1.5 seconds and refresh alerts
      redirectTimerRef.current = setTimeout(async () => {
        setActiveTab("soc");
        await fetchAlerts();
        appendLog(`Switched view to SOC Threat Feed. Fresh telemetry synchronized.`, "info");
        // Dismiss toast after redirect
        setTimeout(() => setToastNotification(null), 2500);
      }, 1500);
    } catch (err) {
      appendLog(`Failed to trigger canary ${trapId}: ${err.message}`, "error");
      setToastNotification({
        title: "Simulation Failed",
        message: `Could not trigger canary: ${err.message}`,
        error: true,
      });
      setTimeout(() => setToastNotification(null), 3000);
    } finally {
      setTestingTrapId(null);
    }
  };

  // Periodic and tab-driven alert synchronization
  useEffect(() => {
    if (activeTab !== "soc" && activeTab !== "topology") return;

    let isMounted = true;
    const loadAlerts = async () => {
      try {
        const response = await fetch("http://localhost:5000/api/alerts");
        if (!response.ok) throw new Error(`Status ${response.status}`);
        const data = await response.json();
        if (isMounted) {
          setAlerts(Array.isArray(data) ? data : data.alerts || []);
        }
      } catch (err) {
        if (isMounted) {
          appendLog(`Failed to fetch alerts: ${err.message}`, "error");
        }
      }
    };

    loadAlerts();

    return () => {
      isMounted = false;
    };
  }, [activeTab, appendLog]);

  // Handle Deploy SpectreSync Mesh execution
  const handleDeploy = async () => {
    if (!targetPath.trim()) {
      appendLog("Deployment failed: target repository path is required.", "error");
      return;
    }

    setIsDeploying(true);
    setDecoys([]);
    appendLog(`Initiating deception mesh deployment for: ${targetPath}`, "info");

    try {
      appendLog("Connecting to scanning engine on Express backend...", "info");
      const response = await fetch("http://localhost:5000/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targetPath: targetPath.trim() }),
      });

      if (!response.ok) {
        throw new Error(`Backend error (${response.status}): ${response.statusText}`);
      }

      const result = await response.json();
      appendLog("Repository scan completed successfully.", "success");

      const trapsList = result.traps || result.decoys || [];
      setDecoys(trapsList);

      appendLog(`Synthesized and armed ${trapsList.length} context-aware canary traps.`, "success");
      appendLog("Deception mesh active. Telemetry beacons listening.", "info");
    } catch (err) {
      appendLog(`Deployment error: ${err.message}. Is Express backend running on http://localhost:5000?`, "error");
    } finally {
      setIsDeploying(false);
    }
  };

  const staticDecoys = useMemo(() => generateDecoyConstellation(190), []);

  const triggeredTrapMap = useMemo(() => {
    const map = new Map();
    alerts.forEach((alert) => {
      const tid = alert.trap_id || "trap_01";
      if (!map.has(tid)) {
        map.set(tid, alert);
      }
    });
    return map;
  }, [alerts]);

  const totalDecoysCount = staticDecoys.length;
  const coreAssetsCount = CORE_ASSETS.length;
  const deceptionRatio = useMemo(
    () => ((totalDecoysCount / (totalDecoysCount + coreAssetsCount)) * 100).toFixed(1),
    [totalDecoysCount, coreAssetsCount]
  );

  const dwellMultiplier = useMemo(() => {
    if (alerts.length === 0) return "1.0x (Baseline)";
    const totalTarpitSeconds = alerts.reduce((acc, curr) => acc + (curr.tarpit_duration || 3500) / 1000, 0);
    const avgMult = Math.max(2.4, (totalTarpitSeconds / alerts.length) * 3.8);
    return `${avgMult.toFixed(1)}x Tarpit Retardation`;
  }, [alerts]);

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-200 font-sans selection:bg-cyan-500/20 selection:text-cyan-200 relative overflow-x-hidden pb-20">
      {/* Ambient top gradient glow */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-7xl h-96 bg-[radial-gradient(ellipse_60%_40%_at_50%_0%,rgba(6,182,212,0.1),rgba(255,255,255,0))] pointer-events-none" />

      {/* Floating Top Command Bar */}
      <header className="sticky top-4 z-40 mx-auto max-w-7xl px-4 mb-8">
        <div className="backdrop-blur-xl bg-neutral-900/60 border border-white/8 shadow-2xl shadow-black/40 rounded-2xl px-5 py-3.5 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 shadow-inner">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-sm tracking-tight text-white">SPECTRESYNC</span>
                <span className="text-[10px] uppercase tracking-wider font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded-full">
                  Autonomous Mesh
                </span>
              </div>
              <p className="text-[11px] text-neutral-400 mt-0.5">
                Active Defense · Dynamic Trap Synthesis · Threat Entanglement
              </p>
            </div>
          </div>

          {/* Navigation Segmented Control */}
          <div className="flex items-center gap-1 bg-neutral-950/70 border border-white/6 p-1 rounded-xl">
            <button
              onClick={() => setActiveTab("deploy")}
              className={`px-3.5 py-1.5 text-xs font-medium rounded-lg transition-all duration-200 flex items-center gap-1.5 ${
                activeTab === "deploy"
                  ? "bg-white/8 text-white shadow-sm border border-white/8"
                  : "text-neutral-400 hover:text-neutral-200 hover:bg-white/2"
              }`}
            >
              <Zap className="w-3.5 h-3.5" />
              Mesh Deployment
            </button>
            <button
              onClick={() => setActiveTab("topology")}
              className={`px-3.5 py-1.5 text-xs font-medium rounded-lg transition-all duration-200 flex items-center gap-1.5 ${
                activeTab === "topology"
                  ? "bg-white/8 text-white shadow-sm border border-white/8"
                  : "text-neutral-400 hover:text-neutral-200 hover:bg-white/2"
              }`}
            >
              <Radar className="w-3.5 h-3.5" />
              Ghost Topology
            </button>
            <button
              onClick={() => setActiveTab("soc")}
              className={`px-3.5 py-1.5 text-xs font-medium rounded-lg transition-all duration-200 flex items-center gap-1.5 ${
                activeTab === "soc"
                  ? "bg-white/8 text-white shadow-sm border border-white/8"
                  : "text-neutral-400 hover:text-neutral-200 hover:bg-white/2"
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              Threat Feed
              {alerts.length > 0 && (
                <span className="ml-1 px-1.5 py-0.5 rounded-full text-[10px] bg-rose-500/20 text-rose-400 border border-rose-500/30">
                  {alerts.length}
                </span>
              )}
            </button>
          </div>

          {/* System status pill */}
          <div className="hidden lg:flex items-center gap-2">
            <div className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Mesh Active
            </div>
          </div>
        </div>
      </header>

      {/* Main Workspace Layout */}
      <main className="max-w-7xl mx-auto px-4 space-y-6">
        {/* Canary Activation & Redirection Toast Banner */}
        {toastNotification && (
          <div
            className={`transition-all duration-300 backdrop-blur-xl border rounded-2xl p-4 shadow-2xl flex items-center justify-between gap-4 animate-in fade-in slide-in-from-top-4 ${
              toastNotification.error
                ? "bg-rose-950/60 border-rose-500/30 text-rose-200 shadow-rose-950/40"
                : "bg-cyan-950/60 border-cyan-500/30 text-cyan-200 shadow-cyan-950/40"
            }`}
          >
            <div className="flex items-center gap-3">
              <div
                className={`p-2 rounded-xl border ${
                  toastNotification.error
                    ? "bg-rose-500/10 border-rose-500/30 text-rose-400"
                    : "bg-cyan-500/10 border-cyan-500/30 text-cyan-400"
                }`}
              >
                {toastNotification.error ? (
                  <AlertTriangle className="w-5 h-5" />
                ) : (
                  <Bell className="w-5 h-5 animate-bounce" />
                )}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-xs tracking-wide uppercase text-white">
                    {toastNotification.title}
                  </span>
                  {toastNotification.trapId && (
                    <span className="px-2 py-0.5 rounded-full font-mono text-[10px] bg-cyan-500/20 border border-cyan-500/40 text-cyan-300">
                      {toastNotification.trapId}
                    </span>
                  )}
                </div>
                <p className="text-xs text-neutral-300 mt-0.5">{toastNotification.message}</p>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <div className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-neutral-900/80 border border-white/10 text-[11px] font-mono text-neutral-400">
                <RefreshCw className="w-3 h-3 text-cyan-400 animate-spin" />
                <span>Redirecting...</span>
              </div>
            </div>
          </div>
        )}

        {/* TAB 1: Mesh Deployment */}
        {activeTab === "deploy" && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Target Repository Input Card */}
              <div className="lg:col-span-2 backdrop-blur-xl bg-neutral-900/40 border border-white/8 rounded-2xl p-6 shadow-xl shadow-black/20 hover:border-white/12 transition-all duration-200 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Server className="w-4 h-4 text-cyan-400" />
                    <h2 className="text-xs uppercase tracking-wider font-semibold text-neutral-300">
                      Target Repository Instrumentation
                    </h2>
                  </div>
                  <span className="text-[11px] text-neutral-500 font-mono">v2.4 Deception Engine</span>
                </div>
                <p className="text-xs text-neutral-400 leading-relaxed">
                  Provide the target codebase path to synthesize adaptive honeytokens, database triggers, and canary endpoints.
                </p>

                <div className="flex flex-col sm:flex-row gap-3 pt-2">
                  <input
                    type="text"
                    value={targetPath}
                    onChange={(e) => setTargetPath(e.target.value)}
                    placeholder="/absolute/path/to/target/repository"
                    className="flex-1 bg-neutral-950/80 border border-white/8 focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/30 rounded-xl px-4 py-2.5 text-xs font-mono text-neutral-200 placeholder:text-neutral-600 transition-all outline-none"
                  />
                  <button
                    onClick={handleDeploy}
                    disabled={isDeploying}
                    className="bg-linear-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-neutral-950 font-semibold px-5 py-2.5 rounded-xl text-xs transition-all duration-200 shadow-lg shadow-cyan-500/20 active:scale-[0.98] whitespace-nowrap cursor-pointer flex items-center justify-center gap-2"
                  >
                    {isDeploying ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        Instrumenting...
                      </>
                    ) : (
                      <>
                        <Sparkles className="w-3.5 h-3.5" />
                        Deploy SpectreSync Mesh
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Quick Metrics Bento Card */}
              <div className="backdrop-blur-xl bg-neutral-900/40 border border-white/8 rounded-2xl p-6 shadow-xl shadow-black/20 flex flex-col justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <Radio className="w-4 h-4 text-cyan-400" />
                    <h2 className="text-xs uppercase tracking-wider font-semibold text-neutral-300">
                      Deception Status
                    </h2>
                  </div>
                  <div className="mt-4 space-y-3">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-neutral-400">Armed Traps</span>
                      <span className="font-mono text-white font-medium">{decoys.length}</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-neutral-400">Canary Health</span>
                      <span className="font-mono text-emerald-400 font-medium">100% Operational</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-neutral-400">Tarpit Strategy</span>
                      <span className="font-mono text-cyan-400 font-medium">Adaptive Exponential</span>
                    </div>
                  </div>
                </div>

                <div className="pt-4 border-t border-white/4 flex items-center justify-between text-[11px] text-neutral-500">
                  <span>Engine: SQLite WAL</span>
                  <span className="text-neutral-400">Port 5000</span>
                </div>
              </div>
            </div>

            {/* Agent Execution Telemetry Stream */}
            <div className="backdrop-blur-xl bg-neutral-900/40 border border-white/8 rounded-2xl p-6 shadow-xl shadow-black/20 space-y-4">
              <div className="flex items-center justify-between border-b border-white/6 pb-3">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-xs uppercase tracking-wider font-semibold text-neutral-300">
                    Agent Execution Telemetry
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-neutral-500">{logs.length} events logged</span>
              </div>

              <div className="bg-neutral-950/80 border border-white/6 rounded-xl p-4 h-60 overflow-y-auto space-y-2 font-mono text-xs">
                {logs.length === 0 ? (
                  <div className="text-neutral-600 text-xs italic">
                    Ready for deployment. Enter repository path above to initialize telemetry stream.
                  </div>
                ) : (
                  logs.map((log, index) => (
                    <div key={index} className="flex items-start gap-3">
                      <span className="text-neutral-600 shrink-0 text-[11px]">[{log.time}]</span>
                      <span
                        className={
                          log.level === "error"
                            ? "text-rose-400"
                            : log.level === "success"
                            ? "text-emerald-400"
                            : log.level === "warn"
                            ? "text-amber-300"
                            : "text-cyan-400"
                        }
                      >
                        {log.message}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Synthesized Decoys Bento Card */}
            {decoys.length > 0 && (
              <div className="backdrop-blur-xl bg-neutral-900/40 border border-white/8 rounded-2xl p-6 shadow-xl shadow-black/20 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Key className="w-4 h-4 text-cyan-400" />
                    <h3 className="text-xs uppercase tracking-wider font-semibold text-neutral-300">
                      Synthesized Context-Aware Decoys ({decoys.length})
                    </h3>
                  </div>
                  <span className="text-[11px] text-neutral-500">Live Canary Endpoints</span>
                </div>

                <div className="overflow-x-auto rounded-xl border border-white/6">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="bg-white/2 border-b border-white/6 text-neutral-400 font-medium">
                        <th className="py-3 px-4">Trap ID</th>
                        <th className="py-3 px-4">Variable Name</th>
                        <th className="py-3 px-4">Decoy Value</th>
                        <th className="py-3 px-4">Category</th>
                        <th className="py-3 px-4">Canary Endpoint</th>
                        <th className="py-3 px-4 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/4">
                      {decoys.map((decoy, idx) => {
                        const trapId = decoy.trap_id || decoy.id || `trap_${idx + 1}`;
                        const isTesting = testingTrapId === trapId;

                        return (
                          <tr key={trapId} className="hover:bg-white/2 transition-colors">
                            <td className="py-3 px-4 font-mono font-semibold text-cyan-400">
                              {trapId}
                            </td>
                            <td className="py-3 px-4 font-mono text-white">
                              {decoy.variable_name || decoy.trap_name || decoy.name}
                            </td>
                            <td className="py-3 px-4 font-mono text-neutral-400 truncate max-w-xs">
                              {decoy.decoy_value || decoy.value || "••••••••"}
                            </td>
                            <td className="py-3 px-4">
                              <span className="px-2 py-0.5 rounded-full bg-white/4 border border-white/8 text-neutral-300 text-[10px] font-medium uppercase">
                                {decoy.category || decoy.trap_type || "secret"}
                              </span>
                            </td>
                            <td className="py-3 px-4 font-mono text-neutral-400 hover:text-cyan-300 transition-colors">
                              {decoy.endpoint || decoy.endpoint_url}
                            </td>
                            <td className="py-3 px-4 text-right">
                              <button
                                onClick={() => handleTriggerCanary(trapId)}
                                disabled={isTesting || Boolean(testingTrapId)}
                                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-[11px] font-medium bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 transition-all duration-200 disabled:opacity-40 cursor-pointer shadow-sm active:scale-[0.98]"
                                title="Simulate canary trigger and test tarpit response"
                              >
                                {isTesting ? (
                                  <>
                                    <RefreshCw className="w-3 h-3 animate-spin" />
                                    <span>Tarpitting...</span>
                                  </>
                                ) : (
                                  <>
                                    <Play className="w-3 h-3 text-rose-400" />
                                    <span>Trigger Trap</span>
                                  </>
                                )}
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: Ghost Network Topology */}
        {activeTab === "topology" && (
          <GhostTopology
            alerts={alerts}
            staticDecoys={staticDecoys}
            triggeredTrapMap={triggeredTrapMap}
            totalDecoysCount={totalDecoysCount}
            coreAssetsCount={coreAssetsCount}
            deceptionRatio={deceptionRatio}
            dwellMultiplier={dwellMultiplier}
            onRefresh={handleManualRefresh}
            isRefreshing={isRefreshing}
          />
        )}

        {/* TAB 3: SOC Threat Feed */}
        {activeTab === "soc" && (
          <div className="space-y-6">
            <div className="backdrop-blur-xl bg-neutral-900/40 border border-white/8 rounded-2xl p-5 shadow-xl shadow-black/20 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  <h2 className="text-xs uppercase tracking-wider font-semibold text-neutral-300">
                    Live Security Threat Stream
                  </h2>
                </div>
                <p className="text-xs text-neutral-400 mt-1">
                  Real-time telemetry and attacker entrapment logs from active canary endpoints
                </p>
              </div>
              <button
                onClick={handleManualRefresh}
                disabled={isRefreshing}
                className="bg-neutral-950/80 hover:bg-white/4 text-cyan-400 border border-cyan-500/30 px-4 py-2 rounded-xl text-xs font-medium transition-all duration-200 flex items-center justify-center gap-2 cursor-pointer shadow-sm active:scale-[0.98]"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
                Refresh Feed
              </button>
            </div>

            <div className="backdrop-blur-xl bg-neutral-900/40 border border-white/8 rounded-2xl overflow-hidden shadow-xl shadow-black/20">
              {alerts.length === 0 ? (
                <div className="text-center py-16 text-neutral-500 text-xs">
                  <CheckCircle2 className="w-8 h-8 mx-auto mb-2 text-neutral-600" />
                  No security alerts recorded. All canary traps are silent and armed.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="bg-white/2 border-b border-white/6 text-neutral-400 font-medium">
                        <th className="py-3 px-4">ID</th>
                        <th className="py-3 px-4">Timestamp</th>
                        <th className="py-3 px-4">Source IP</th>
                        <th className="py-3 px-4">Trap Target</th>
                        <th className="py-3 px-4">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/4">
                      {alerts.map((alert, idx) => (
                        <tr key={alert.id || idx} className="hover:bg-white/2 transition-colors">
                          <td className="py-3 px-4 font-mono font-medium text-cyan-400">#{alert.id}</td>
                          <td className="py-3 px-4 font-mono text-neutral-400">{alert.timestamp}</td>
                          <td className="py-3 px-4 font-mono text-white font-medium">
                            {alert.source_ip || alert.ip}
                          </td>
                          <td className="py-3 px-4 font-mono text-neutral-300">
                            {alert.trap_name || alert.type || "Canary Hit"}
                          </td>
                          <td className="py-3 px-4">
                            <span className="px-2.5 py-0.5 rounded-full bg-rose-500/10 border border-rose-500/20 text-rose-400 text-[10px] font-medium">
                              {alert.status || "Triggered"}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      {/* Minimalist Bottom Control Dock */}
      <footer className="fixed bottom-4 left-1/2 -translate-x-1/2 z-40">
        <div className="backdrop-blur-xl bg-neutral-900/80 border border-white/8 shadow-2xl shadow-black/50 rounded-full px-5 py-2 flex items-center gap-6 text-[11px] text-neutral-400">
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
            <span className="text-neutral-300">Mesh Core: Active</span>
          </div>
          <span className="text-white/10">|</span>
          <div className="flex items-center gap-1.5">
            <span className="font-mono text-neutral-300">{alerts.length}</span>
            <span>Entanglements</span>
          </div>
          <span className="text-white/10">|</span>
          <div className="flex items-center gap-1.5">
            <span className="font-mono text-neutral-300">{totalDecoysCount}</span>
            <span>Decoys Armed</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
