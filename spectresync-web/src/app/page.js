"use client";

import { useState, useEffect, useCallback, useRef, useMemo, useSyncExternalStore } from "react";
import SpectreAIAgent from "./SpectreAIAgent";
import Image from "next/image";
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
  Bot,
  Cpu,
  ShieldAlert,
  Sliders,
  ChevronRight,
  Sun,
  Moon,
  Eye,
  Hourglass,
  Check,
  ShieldCheck,
} from "lucide-react";

// Known decoy path and asset mappings for realistic enterprise honeytokens
const KNOWN_TARGETS = {
  trap_01: "/api/v1/auth/keys",
  trap_02: "AWS_SECRET_ACCESS_KEY",
  trap_03: "/admin/config.php",
  trap_04: "PROD_DATABASE_URL",
  trap_05: "/.env.production",
  trap_06: "KMS_MASTER_ENCRYPTION_KEY",
  trap_07: "/api/v2/vault/tokens",
  trap_08: "GITHUB_PERSONAL_ACCESS_TOKEN",
  trap_09: "/internal/metrics/prometheus",
  trap_10: "POSTGRES_REPLICA_CREDENTIALS",
  trap_11: "/api/v1/system/backup.tar.gz",
  trap_12: "STRIPE_RESTRICTED_SECRET_KEY",
};

// Target Canary Asset resolver
function getTrapTargetAsset(alert, decoys = []) {
  if (alert.target_asset) return alert.target_asset;
  if (alert.trap_name) return alert.trap_name;
  if (alert.trap_id && KNOWN_TARGETS[alert.trap_id]) {
    return KNOWN_TARGETS[alert.trap_id];
  }
  const match = decoys.find((d) => (d.trap_id || d.id) === alert.trap_id);
  if (match) {
    return match.endpoint || match.variable_name || match.name || alert.trap_id;
  }
  return alert.trap_id ? `/api/canary?id=${alert.trap_id}` : "/api/v1/auth/tokens";
}

// User-Agent and client environment parser
function formatClientFingerprint(rawUa) {
  if (!rawUa || rawUa === "Unknown" || rawUa === "Canary Hit") {
    return "Python / Scrapy Engine (Bot)";
  }
  const ua = rawUa.toLowerCase();
  if (ua.includes("powershell")) {
    const vMatch = rawUa.match(/powershell\/([\d.]+)/i);
    return vMatch ? `PowerShell v${vMatch[1]}` : "PowerShell v5.1";
  }
  if (ua.includes("curl")) {
    const vMatch = rawUa.match(/curl\/([\d.]+)/i);
    return vMatch ? `cURL Client v${vMatch[1]}` : "cURL CLI Tool";
  }
  if (ua.includes("python") || ua.includes("requests") || ua.includes("urllib")) {
    return "Python-Requests Scanner";
  }
  if (ua.includes("go-http-client")) {
    return "Go HTTP Prober (Automated)";
  }
  if (ua.includes("postman")) {
    return "Postman Runtime Environment";
  }
  if (ua.includes("chrome") && (ua.includes("win") || ua.includes("windows"))) {
    return "Chrome / Win10";
  }
  if (ua.includes("chrome") && ua.includes("mac")) {
    return "Chrome / macOS";
  }
  if (ua.includes("firefox")) {
    return "Firefox / Linux x86_64";
  }
  if (ua.includes("mozilla")) {
    return "Chrome / Win10";
  }
  return rawUa.length > 36 ? `${rawUa.slice(0, 36)}...` : rawUa;
}

// Indian Standard Time (IST, UTC+5:30) Formatter: "DD MMM YYYY, HH:mm:ss IST"
function formatIST(isoDateString) {
  if (!isoDateString) return "N/A";
  try {
    const d = new Date(isoDateString);
    if (isNaN(d.getTime())) return isoDateString;
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone: "Asia/Kolkata",
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).formatToParts(d);

    const map = {};
    for (const p of parts) {
      map[p.type] = p.value;
    }
    return `${map.day} ${map.month} ${map.year}, ${map.hour}:${map.minute}:${map.second} IST`;
  } catch {
    return isoDateString;
  }
}

// Indian Standard Time (IST, UTC+5:30) Formatter: "HH:mm:ss IST"
function formatISTTime(isoDateString) {
  if (!isoDateString) return "N/A";
  try {
    const d = new Date(isoDateString);
    if (isNaN(d.getTime())) return isoDateString;
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone: "Asia/Kolkata",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).formatToParts(d);

    const map = {};
    for (const p of parts) {
      map[p.type] = p.value;
    }
    return `${map.hour}:${map.minute}:${map.second} IST`;
  } catch {
    return isoDateString;
  }
}

// Dynamic defense status resolver: MONITORING | TARPITTED | CANARY_TRIGGERED
function getDefenseStatus(alert) {
  if (alert.defense_status) return alert.defense_status;
  const statusStr = String(alert.status || "").toUpperCase();
  if (statusStr.includes("TARPIT") || statusStr.includes("SUSPENDED")) {
    return "TARPITTED";
  }
  if (statusStr.includes("TRIGGER") || statusStr.includes("TRIPPED") || statusStr.includes("HIT") || statusStr.includes("ARMED")) {
    return "CANARY_TRIGGERED";
  }
  return "MONITORING";
}

// Dynamic threat score calculator (0 - 100%)
function getThreatScore(alert) {
  if (typeof alert.threat_score === "number") return alert.threat_score;
  const status = getDefenseStatus(alert);
  if (status === "TARPITTED") {
    const delay = alert.tarpit_duration || 4500;
    return Math.min(98, Math.max(76, Math.floor(65 + (delay / 10000) * 32)));
  }
  if (status === "CANARY_TRIGGERED") {
    return 89;
  }
  return 34;
}

// Core production assets placed evenly around the center of the topology (well spaced to prevent label collisions)
const CORE_ASSETS = [
  { id: "core-db", label: "PROD-DB-PRIMARY", type: "PostgreSQL Database", relX: 0, relY: -0.19 },
  { id: "core-auth", label: "AUTH-GATEWAY-01", type: "OAuth/JWT Service", relX: -0.22, relY: -0.02 },
  { id: "core-api", label: "API-EDGE-ROUTER", type: "Core Microservice", relX: 0.22, relY: -0.02 },
  { id: "core-vault", label: "KMS-VAULT-CLUSTER", type: "Key Management", relX: -0.12, relY: 0.18 },
  { id: "core-worker", label: "PIPELINE-WORKER", type: "Worker Queue", relX: 0.12, relY: 0.18 },
];

const CATEGORIES = ["secret", "database", "token", "key", "generic"];
const PREFIXES = ["APP", "SVC", "INTERNAL", "STAGING", "BACKUP"];
const SUFFIXES = ["SECRET_KEY", "DB_URI", "API_TOKEN", "ACCESS_KEY", "ADMIN_PASS"];

// Deterministic decoy constellation generator with clear concentric zones
function generateDecoyConstellation(count = 140) {
  const nodes = [];
  const rings = [0.32, 0.42, 0.52];

  for (let i = 0; i < count; i++) {
    const ringIndex = i % rings.length;
    const baseRadius = rings[ringIndex] + ((i * 17) % 7) * 0.008;
    const itemsInRing = Math.floor(count / rings.length);
    const ringPos = Math.floor(i / rings.length);
    const angle = (ringPos / itemsInRing) * Math.PI * 2 + (ringIndex * 0.45);

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
      relY: Math.sin(angle) * baseRadius * 0.76,
      baseRadius,
      angle,
      speed: 0.00015 + ((i % 5) * 0.00005),
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
  theme = "dark",
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
    const isLight = theme === "light";

    const render = () => {
      tick += 0.02;
      ctx.clearRect(0, 0, width, height);

      const centerX = width / 2;
      const centerY = height / 2;
      const minDim = Math.min(width, height);

      // Subtle background grid
      ctx.strokeStyle = isLight ? "rgba(0, 0, 0, 0.04)" : "rgba(255, 255, 255, 0.02)";
      ctx.lineWidth = 1;
      const gridSize = 48;
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

      // Subtle concentric boundary rings
      ctx.strokeStyle = isLight ? "rgba(217, 119, 6, 0.12)" : "rgba(6, 182, 212, 0.08)";
      ctx.lineWidth = 1;
      [0.32, 0.42, 0.52].forEach((radius) => {
        ctx.beginPath();
        ctx.arc(centerX, centerY, minDim * radius, 0, Math.PI * 2);
        ctx.stroke();
      });

      // Node coordinate calculation
      const corePositions = CORE_ASSETS.map((asset) => ({
        ...asset,
        absX: centerX + asset.relX * minDim,
        absY: centerY + asset.relY * minDim,
      }));

      const decoyPositions = staticDecoys.map((decoy) => {
        const currentAngle = decoy.angle + tick * decoy.speed * 12;
        return {
          ...decoy,
          absX: centerX + Math.cos(currentAngle) * decoy.baseRadius * minDim,
          absY: centerY + Math.sin(currentAngle) * decoy.baseRadius * minDim * 0.76,
          isTriggered: triggeredTrapMap.has(decoy.trapId),
          alertData: triggeredTrapMap.get(decoy.trapId) || null,
        };
      });

      // Clean, thin connecting lines between nearby core assets and decoys
      ctx.strokeStyle = isLight ? "rgba(217, 119, 6, 0.16)" : "rgba(6, 182, 212, 0.12)";
      ctx.lineWidth = 0.75;
      corePositions.forEach((core) => {
        decoyPositions.slice(0, 16).forEach((decoy) => {
          if (Math.hypot(core.absX - decoy.absX, core.absY - decoy.absY) < minDim * 0.22) {
            ctx.beginPath();
            ctx.moveTo(core.absX, core.absY);
            ctx.lineTo(decoy.absX, decoy.absY);
            ctx.stroke();
          }
        });
      });

      // Render Active Decoys (Slate/Gray) and Tripped Traps (Red)
      decoyPositions.forEach((node) => {
        if (filterTriggeredOnly && !node.isTriggered) return;

        if (node.isTriggered) {
          // Tripped Traps = Red (Clean pulse ring without visual debris)
          const pulseR = 8 + Math.abs(Math.sin(tick * 2.5)) * 6;
          ctx.beginPath();
          ctx.arc(node.absX, node.absY, pulseR, 0, Math.PI * 2);
          ctx.strokeStyle = "rgba(239, 68, 68, 0.35)";
          ctx.lineWidth = 1.5;
          ctx.stroke();

          ctx.beginPath();
          ctx.arc(node.absX, node.absY, 5, 0, Math.PI * 2);
          ctx.fillStyle = "#ef4444";
          ctx.fill();

          // Clean, high-contrast label with pill background to avoid text clipping
          const labelText = `TRIPPED: ${node.trapId}`;
          ctx.font = "600 10px monospace";
          const textWidth = ctx.measureText(labelText).width;
          const boxX = node.absX + 8;
          const boxY = node.absY - 14;

          ctx.fillStyle = isLight ? "rgba(255, 255, 255, 0.95)" : "rgba(15, 23, 42, 0.85)";
          ctx.fillRect(boxX - 4, boxY - 9, textWidth + 8, 16);
          ctx.strokeStyle = "rgba(239, 68, 68, 0.5)";
          ctx.lineWidth = 1;
          ctx.strokeRect(boxX - 4, boxY - 9, textWidth + 8, 16);

          ctx.fillStyle = isLight ? "#dc2626" : "#fca5a5";
          ctx.fillText(labelText, boxX, boxY + 3);
        } else {
          // Active Decoys = Slate/Gray (Crisp, clean, subtle dots)
          ctx.beginPath();
          ctx.arc(node.absX, node.absY, 2.5, 0, Math.PI * 2);
          ctx.fillStyle = isLight ? "rgba(100, 116, 139, 0.45)" : "rgba(148, 163, 184, 0.35)";
          ctx.fill();
        }
      });

      // Clean attack vector indicators (Thin, restrained dashed red line)
      let vectorIndex = 0;
      decoyPositions.forEach((node) => {
        if (!node.isTriggered || !node.alertData) return;

        const attackerAngle = vectorIndex * 1.57 + 0.5;
        const attackerX = centerX + Math.cos(attackerAngle) * (minDim * 0.49);
        const attackerY = centerY + Math.sin(attackerAngle) * (minDim * 0.45);
        vectorIndex++;

        // Attacker origin point
        ctx.beginPath();
        ctx.arc(attackerX, attackerY, 5, 0, Math.PI * 2);
        ctx.fillStyle = "#ef4444";
        ctx.fill();

        ctx.strokeStyle = "rgba(239, 68, 68, 0.25)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(attackerX, attackerY, 9, 0, Math.PI * 2);
        ctx.stroke();

        // Subtle, thin dashed line from attacker to tripped trap
        ctx.save();
        ctx.setLineDash([4, 4]);
        ctx.lineDashOffset = -tick * 15;
        ctx.strokeStyle = "rgba(239, 68, 68, 0.4)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(attackerX, attackerY);
        ctx.lineTo(node.absX, node.absY);
        ctx.stroke();
        ctx.restore();
      });

      // Render Core Assets = Blue / Accent (Clean AWS/DataDog architecture style)
      corePositions.forEach((core) => {
        // Soft outer glow
        const glow = ctx.createRadialGradient(core.absX, core.absY, 4, core.absX, core.absY, 20);
        glow.addColorStop(0, isLight ? "rgba(217, 119, 6, 0.25)" : "rgba(59, 130, 246, 0.25)");
        glow.addColorStop(1, isLight ? "rgba(217, 119, 6, 0)" : "rgba(59, 130, 246, 0)");
        ctx.fillStyle = glow;
        ctx.beginPath();
        ctx.arc(core.absX, core.absY, 20, 0, Math.PI * 2);
        ctx.fill();

        // Node circle
        ctx.beginPath();
        ctx.arc(core.absX, core.absY, 9, 0, Math.PI * 2);
        ctx.fillStyle = isLight ? "#ffffff" : "#0f172a";
        ctx.fill();
        ctx.strokeStyle = isLight ? "#d97706" : "#3b82f6";
        ctx.lineWidth = 2;
        ctx.stroke();

        // Inner core dot
        ctx.beginPath();
        ctx.arc(core.absX, core.absY, 3.5, 0, Math.PI * 2);
        ctx.fillStyle = isLight ? "#b45309" : "#60a5fa";
        ctx.fill();

        // Floating pill label with clean background to completely avoid overlap
        ctx.font = "600 11px sans-serif";
        const labelWidth = ctx.measureText(core.label).width;
        const pillX = core.absX - labelWidth / 2 - 8;
        const pillY = core.absY + 16;

        ctx.fillStyle = isLight ? "rgba(255, 255, 255, 0.95)" : "rgba(15, 23, 42, 0.9)";
        ctx.fillRect(pillX, pillY, labelWidth + 16, 20);
        ctx.strokeStyle = isLight ? "rgba(217, 119, 6, 0.35)" : "rgba(59, 130, 246, 0.3)";
        ctx.lineWidth = 1;
        ctx.strokeRect(pillX, pillY, labelWidth + 16, 20);

        ctx.fillStyle = isLight ? "#92400e" : "#93c5fd";
        ctx.textAlign = "center";
        ctx.fillText(core.label, core.absX, pillY + 14);
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
  }, [staticDecoys, triggeredTrapMap, filterTriggeredOnly, theme]);

  const isLight = theme === "light";

  return (
    <div className="space-y-6">
      {/* Live Stats HUD Bar */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className={`backdrop-blur-xl border rounded-2xl p-5 shadow-xl transition-all duration-200 ${
          isLight
            ? "bg-white/85 border-slate-200/90 shadow-slate-200/40 text-slate-900"
            : "bg-neutral-900/40 border-white/8 shadow-black/20 text-neutral-200"
        }`}>
          <div className="flex items-center justify-between">
            <span className={`text-[11px] font-medium uppercase tracking-wider ${
              isLight ? "text-slate-500" : "text-neutral-400"
            }`}>
              Active Deception Surface
            </span>
            <div className={`p-1.5 rounded-lg ${
              isLight ? "bg-amber-500/10 text-amber-600" : "bg-cyan-500/10 text-cyan-400"
            }`}>
              <Layers className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className={`text-2xl font-semibold tracking-tight ${
              isLight ? "text-slate-900" : "text-white"
            }`}>
              {deceptionRatio}% Density
            </div>
            <div className={`text-xs font-mono mt-1 ${
              isLight ? "text-slate-500" : "text-neutral-500"
            }`}>
              {totalDecoysCount} Decoy Entities vs {coreAssetsCount} Core
            </div>
          </div>
        </div>

        <div className={`backdrop-blur-xl border rounded-2xl p-5 shadow-xl transition-all duration-200 ${
          isLight
            ? "bg-white/85 border-slate-200/90 shadow-slate-200/40 text-slate-900"
            : "bg-neutral-900/40 border-white/8 shadow-black/20 text-neutral-200"
        }`}>
          <div className="flex items-center justify-between">
            <span className={`text-[11px] font-medium uppercase tracking-wider ${
              isLight ? "text-slate-500" : "text-neutral-400"
            }`}>
              Attacker Dwell Time Multiplier
            </span>
            <div className={`p-1.5 rounded-lg ${
              isLight ? "bg-amber-500/10 text-amber-600" : "bg-amber-500/10 text-amber-400"
            }`}>
              <Crosshair className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className={`text-2xl font-semibold tracking-tight ${
              isLight ? "text-amber-700" : "text-amber-300"
            }`}>
              {dwellMultiplier}
            </div>
            <div className={`text-xs font-mono mt-1 ${
              isLight ? "text-slate-500" : "text-neutral-500"
            }`}>
              Behavioral Tarpit Injected
            </div>
          </div>
        </div>

        <div className={`backdrop-blur-xl border rounded-2xl p-5 shadow-xl transition-all duration-200 ${
          isLight
            ? "bg-white/85 border-slate-200/90 shadow-slate-200/40 text-slate-900"
            : "bg-neutral-900/40 border-white/8 shadow-black/20 text-neutral-200"
        }`}>
          <div className="flex items-center justify-between">
            <span className={`text-[11px] font-medium uppercase tracking-wider ${
              isLight ? "text-slate-500" : "text-neutral-400"
            }`}>
              Neutralized Threats
            </span>
            <div className="p-1.5 rounded-lg bg-rose-500/10 text-rose-500">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-semibold tracking-tight text-rose-500">
              {alerts.length} Tripped Traps
            </div>
            <div className={`text-xs font-mono mt-1 ${
              isLight ? "text-slate-500" : "text-neutral-500"
            }`}>
              Suspended & Entangled in Mesh
            </div>
          </div>
        </div>
      </div>

      {/* Interactive Canvas Graph Container */}
      <div className={`relative backdrop-blur-xl border rounded-2xl overflow-hidden h-155 w-full shadow-2xl transition-all duration-200 ${
        isLight
          ? "bg-white/75 border-slate-200/90 shadow-slate-200/50"
          : "bg-neutral-900/40 border-white/8 shadow-black/40"
      }`}>
        <canvas ref={canvasRef} className="w-full h-full block cursor-crosshair" />

        {/* Top-Left Tactical HUD Overlay & Simplified 3-Status Legend */}
        <div className="absolute top-4 left-4 pointer-events-none space-y-2.5">
          <div className={`backdrop-blur-md border rounded-xl px-4 py-2.5 shadow-lg ${
            isLight
              ? "bg-white/95 border-slate-200 text-slate-900"
              : "bg-neutral-950/80 border-white/8 text-white"
          }`}>
            <div className="text-xs font-semibold flex items-center gap-2">
              <Radar className={`w-3.5 h-3.5 ${isLight ? "text-amber-600" : "text-cyan-400"}`} />
              <span>ACTIVE DECEPTION TOPOLOGY</span>
            </div>
            <div className={`text-[10px] font-mono mt-0.5 ${isLight ? "text-slate-500" : "text-neutral-400"}`}>
              {totalDecoysCount} Decoy Nodes Shielding {coreAssetsCount} Core Assets
            </div>
          </div>

          {/* Clean 3-Status Legend Card */}
          <div className={`backdrop-blur-md border rounded-xl p-3 text-xs space-y-2 shadow-lg ${
            isLight
              ? "bg-white/95 border-slate-200 text-slate-900"
              : "bg-neutral-950/80 border-white/8 text-white"
          }`}>
            <div className={`text-[10px] uppercase font-mono font-semibold tracking-wider mb-1 ${
              isLight ? "text-slate-500" : "text-neutral-400"
            }`}>
              Network Status Key
            </div>
            <div className="flex items-center gap-2.5">
              <span className={`w-3 h-3 rounded-full shrink-0 border ${
                isLight ? "bg-amber-500 border-amber-600" : "bg-blue-500 border-blue-400"
              }`} />
              <div className="leading-tight">
                <span className={`font-medium ${isLight ? "text-slate-900" : "text-white"}`}>
                  {isLight ? "Amber" : "Blue"}
                </span>
                <span className={`text-[11px] block ${isLight ? "text-slate-500" : "text-neutral-400"}`}>
                  Core Assets (Production Servers & DBs)
                </span>
              </div>
            </div>
            <div className="flex items-center gap-2.5">
              <span className="w-2.5 h-2.5 rounded-full bg-slate-400/50 shrink-0" />
              <div className="leading-tight">
                <span className={`font-medium ${isLight ? "text-slate-900" : "text-white"}`}>
                  Slate / Gray
                </span>
                <span className={`text-[11px] block ${isLight ? "text-slate-500" : "text-neutral-400"}`}>
                  Active Decoys (Unarmed & Listening)
                </span>
              </div>
            </div>
            <div className="flex items-center gap-2.5">
              <span className="w-3 h-3 rounded-full bg-rose-500 border border-rose-400 animate-pulse shrink-0" />
              <div className="leading-tight">
                <span className="text-rose-500 font-medium">Red</span>
                <span className={`text-[11px] block ${isLight ? "text-slate-500" : "text-neutral-400"}`}>
                  Tripped Traps (Attacker Entangled in Tarpit)
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Top-Right Control Buttons */}
        <div className="absolute top-4 right-4 flex gap-2">
          <button
            onClick={() => setFilterTriggeredOnly((prev) => !prev)}
            className={`px-3 py-1.5 text-xs font-medium rounded-xl border transition-all duration-200 cursor-pointer backdrop-blur-md ${
              filterTriggeredOnly
                ? "bg-rose-500/20 text-rose-500 border-rose-500/40 shadow-xs"
                : isLight
                ? "bg-white/90 text-slate-700 border-slate-200 hover:bg-slate-100"
                : "bg-neutral-950/70 text-neutral-400 border-white/8 hover:text-white hover:bg-white/4"
            }`}
          >
            {filterTriggeredOnly ? "Showing Tripped Traps Only" : "Show All Nodes"}
          </button>
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className={`px-3.5 py-1.5 rounded-xl text-xs font-medium transition-all duration-200 flex items-center gap-1.5 cursor-pointer backdrop-blur-md shadow-xs ${
              isLight
                ? "bg-white/90 text-amber-700 border border-amber-500/30 hover:bg-amber-50/50"
                : "bg-neutral-950/70 text-cyan-400 border border-cyan-500/30 hover:bg-white/4"
            }`}
          >
            <RefreshCw className={`w-3 h-3 ${isRefreshing ? "animate-spin" : ""}`} />
            Sync Topology
          </button>
        </div>

        {/* Node Inspector Tooltip - Simplified, Clean DataDog/Linear Style */}
        {hoveredNode && (
          <div
            className={`absolute pointer-events-none backdrop-blur-xl border p-3 rounded-xl shadow-2xl text-xs space-y-1 z-20 min-w-48 ${
              isLight
                ? "bg-white/95 border-slate-200 text-slate-800"
                : "bg-neutral-950/95 border-white/10 text-white"
            }`}
            style={{
              left: Math.min(hoveredNode.x + 16, 760),
              top: Math.min(hoveredNode.y + 16, 470),
            }}
          >
            <div className={`font-semibold tracking-tight ${isLight ? "text-slate-900" : "text-white"}`}>
              {hoveredNode.name}
            </div>
            <div className={`text-[11px] ${isLight ? "text-slate-500" : "text-neutral-400"}`}>
              {hoveredNode.type}
            </div>
            <div className={`text-[11px] font-mono ${isLight ? "text-slate-600" : "text-neutral-300"}`}>
              Class: {hoveredNode.category}
            </div>
            <div className={`text-[11px] font-medium ${
              hoveredNode.isTriggered ? "text-rose-500" : isLight ? "text-amber-600" : "text-cyan-400"
            }`}>
              Status: {hoveredNode.status}
            </div>
            {hoveredNode.tarpit && (
              <div className={`text-[10px] font-mono pt-0.5 border-t mt-1 ${
                isLight ? "text-amber-700 border-slate-200" : "text-amber-300 border-white/10"
              }`}>
                Tarpit Delay: {hoveredNode.tarpit}
              </div>
            )}
          </div>
        )}

        {/* Bottom Telemetry Bar */}
        <div className={`absolute bottom-3 left-4 right-4 flex items-center justify-between text-[11px] pointer-events-none font-mono ${
          isLight ? "text-slate-500" : "text-neutral-500"
        }`}>
          <span>MESH ENCRYPTION: SHA-256 CANARY TOKENS</span>
          <span className={isLight ? "text-amber-700 font-semibold" : "text-cyan-400"}>
            BEHAVIORAL TARPIT RADAR ENGAGED
          </span>
        </div>
      </div>
    </div>
  );
}

// Theme store synchronization helpers
function subscribeTheme(callback) {
  window.addEventListener("spectresync-theme-change", callback);
  window.addEventListener("storage", callback);
  return () => {
    window.removeEventListener("spectresync-theme-change", callback);
    window.removeEventListener("storage", callback);
  };
}

function getThemeSnapshot() {
  try {
    const val = localStorage.getItem("spectresync-theme");
    return val === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

function getThemeServerSnapshot() {
  return "dark";
}

// Main Dashboard Component
export default function SpectreSyncDashboard() {
  const theme = useSyncExternalStore(subscribeTheme, getThemeSnapshot, getThemeServerSnapshot);
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
  const [sentinelMode, setSentinelMode] = useState("autonomous"); // "autonomous" | "supervised"
  const [sentinelStatus, setSentinelStatus] = useState("Monitoring Perimeter");
  const [pendingApproval, setPendingApproval] = useState(null);
  const [isSimulating, setIsSimulating] = useState(false);
  const [isAIAgentOpen, setIsAIAgentOpen] = useState(false);
  const [socGreetingText, setSocGreetingText] = useState(
    "SpectreSync SOC initialized. 3 autonomous defense agents actively monitoring telemetry streams. Network posture: OPTIMAL."
  );

  // Keyboard shortcut listener for Ctrl+K or Cmd+K to toggle Spectre AI
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setIsAIAgentOpen((prev) => !prev);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Synchronize root HTML class when theme changes
  useEffect(() => {
    if (theme === "light") {
      document.documentElement.classList.add("light");
      document.documentElement.classList.remove("dark");
    } else {
      document.documentElement.classList.add("dark");
      document.documentElement.classList.remove("light");
    }
  }, [theme]);

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    try {
      localStorage.setItem("spectresync-theme", next);
      window.dispatchEvent(new Event("spectresync-theme-change"));
    } catch {
      // ignore
    }
  };
  const [agentThoughts, setAgentThoughts] = useState([
    {
      time: "20:48:02",
      stage: "PERIMETER_MONITOR",
      thought: "Real-time deception fabric synchronized with SQLite WAL telemetry engine.",
      action: "Standing by on port 5000 /api/canary.",
    },
    {
      time: "20:48:15",
      stage: "SURFACE_RECON",
      thought: "Core production topology evaluated: 4 primary assets shielded across 190 invisible decoys.",
      action: "Orbital decoy constellation locked in active state.",
    },
  ]);

  // Append new AI agent reasoning thought to monologue stream
  const appendAgentThought = useCallback((stage, thought, action) => {
    const time = new Date().toLocaleTimeString();
    setAgentThoughts((prev) => [
      ...prev.slice(-14), // keep last 15 reasoning steps
      { time, stage, thought, action },
    ]);
  }, []);

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
    setSentinelStatus("Analyzing Attack Vector");
    appendLog(`Simulating canary trap hit: ${trapId}...`, "warn");
    appendAgentThought(
      "ANOMALY_DETECTION",
      `Canary token access detected for target [${trapId}]. Querying threat signature against active mesh...`,
      "Engaging behavioral tarpit delay matrix."
    );

    try {
      const endpoint = `http://localhost:5000/api/canary?id=${encodeURIComponent(trapId)}`;
      const response = await fetch(endpoint);
      if (!response.ok) throw new Error(`Status ${response.status}`);
      const data = await response.json();

      const tarpitSeconds = data.tarpit_duration ? (data.tarpit_duration / 1000).toFixed(1) : "3.5";
      setSentinelStatus("Adaptive Tarpitting Active");
      appendLog(`Canary trap ${trapId} triggered successfully. Tarpit engaged (${tarpitSeconds}s).`, "warn");

      appendAgentThought(
        "TARPIT_RETARDATION",
        `Attacker entrapped on [${trapId}]. Exponential delay (${tarpitSeconds}s) injected. Delivering high-value synthetic credentials payload.`,
        "Threat entangled in deception mesh. Logging to SQLite SOC feed."
      );

      // Show temporary confirmation toast banner
      setToastNotification({
        title: "Canary Trap Activated",
        message: `Sentinel entrapped attacker on ${trapId} (${tarpitSeconds}s tarpit). Redirecting to SOC...`,
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
        setSentinelStatus("Perimeter Secured");
        appendLog(`Switched view to SOC Threat Feed. Fresh telemetry synchronized.`, "info");
        setTimeout(() => setToastNotification(null), 2500);
      }, 1500);
    } catch (err) {
      setSentinelStatus("Telemetry Error");
      appendLog(`Failed to trigger canary ${trapId}: ${err.message}`, "error");
      appendAgentThought(
        "ERROR_TELEMETRY",
        `Canary ping failure: ${err.message}. Verifying backend connectivity on port 5000.`,
        "Retry scheduled."
      );
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

  // Real-time threat vector simulation across multi-agent defense pipeline
  const handleSimulateThreatVector = async () => {
    setIsSimulating(true);
    setSentinelStatus("Analyzing Adversarial Vector");

    const attackProfiles = [
      {
        target: "/api/v1/auth/keys",
        ip: "185.220.207.161",
        ua: "CyberSentinel-Agent1 // DDoS Packet Flood (Conf: 99.8%)",
        score: 99,
        status: "TARPITTED",
        delayMs: 8500,
        trapId: "trap_01",
      },
      {
        target: "/admin/config.php",
        ip: "192.0.2.64",
        ua: "CyberSentinel-Agent1 // PortScan Recon (Conf: 100%)",
        score: 93,
        status: "TARPITTED",
        delayMs: 4000,
        trapId: "trap_03",
      },
      {
        target: "AWS_SECRET_ACCESS_KEY",
        ip: "203.0.113.140",
        ua: "CyberSentinel-Agent1 // Brute-Force Patator (Conf: 100%)",
        score: 96,
        status: "CANARY_TRIGGERED",
        delayMs: 6500,
        trapId: "trap_02",
      },
      {
        target: "/api/v1/vault/session",
        ip: "198.51.100.96",
        ua: "CyberSentinel-Agent1 // Slowloris DoS (Conf: 97.4%)",
        score: 95,
        status: "TARPITTED",
        delayMs: 7700,
        trapId: "trap_01",
      },
      {
        target: "/api/v1/vault",
        ip: "198.51.100.44",
        ua: "Go-http-client/2.0 (Automated Harvester)",
        score: 94,
        status: "TARPITTED",
        delayMs: 6400,
        trapId: "trap_01",
      },
      {
        target: "AWS_SECRET_ACCESS_KEY",
        ip: "203.0.113.89",
        ua: "Python-urllib/3.11 (Scrapy Spider)",
        score: 89,
        status: "CANARY_TRIGGERED",
        delayMs: 5100,
        trapId: "trap_02",
      },
      {
        target: "/admin/config.php",
        ip: "192.0.2.14",
        ua: "sqlmap/1.7#dev (Automated SQLi)",
        score: 82,
        status: "TARPITTED",
        delayMs: 4200,
        trapId: "trap_03",
      },
      {
        target: "/.env.production",
        ip: "185.220.101.5",
        ua: "cURL CLI Tool v8.4.0",
        score: 91,
        status: "CANARY_TRIGGERED",
        delayMs: 7800,
        trapId: "trap_05",
      },
      {
        target: "/internal/metrics/prometheus",
        ip: "198.18.0.105",
        ua: "Masscan Prober v1.3",
        score: 68,
        status: "MONITORING",
        delayMs: 1200,
        trapId: "trap_09",
      },
      {
        target: "/api/v2/auth/tokens",
        ip: "194.26.29.112",
        ua: "PostmanRuntime/7.36.0",
        score: 96,
        status: "TARPITTED",
        delayMs: 8900,
        trapId: "trap_07",
      },
    ];

    const pick = attackProfiles[Math.floor(Math.random() * attackProfiles.length)];
    const simId = `sim_${Date.now().toString(36)}`;
    const nowIso = new Date().toISOString();

    const newThreatAlert = {
      id: simId,
      timestamp: nowIso,
      source_ip: pick.ip,
      ip: pick.ip,
      target_asset: pick.target,
      trap_name: pick.target,
      trap_id: pick.trapId,
      user_agent: pick.ua,
      type: pick.ua,
      threat_score: pick.score,
      defense_status: pick.status,
      status: pick.status === "TARPITTED"
        ? `Suspended (${(pick.delayMs / 1000).toFixed(1)}s Tarpit)`
        : pick.status === "CANARY_TRIGGERED"
        ? "Tripped & Armed"
        : "Passive Monitoring",
      tarpit_duration: pick.delayMs,
      supervised_approved: sentinelMode === "autonomous",
    };

    // Prepend directly into alert state for instantaneous UI feedback
    setAlerts((prev) => [newThreatAlert, ...prev]);

    // Multi-agent reasoning stream emissions for the 3 specialized pipeline agents
    appendAgentThought(
      "TRIAGE_AGENT",
      `[Perception] Ingested raw request stream on [${pick.target}] from ${pick.ip} (${pick.ua}). Calculated threat score: ${pick.score}%.`,
      "Forwarded telemetry profile to Deception Agent."
    );

    appendAgentThought(
      "DECEPTION_AGENT",
      `[Generative Synthesis] Synthesizing context-aware honeytoken for [${pick.target}]. Embedded cryptographic canary tracking token.`,
      "Engaging Entanglement Agent for latency injection."
    );

    appendAgentThought(
      "ENTANGLEMENT_AGENT",
      `[Action] Injected ${(pick.delayMs / 1000).toFixed(1)}s exponential tarpit delay with jitter. Attacker socket suspended in deception loop.`,
      sentinelMode === "autonomous"
        ? "Autonomous playbook executed. Attacker neutralized."
        : "Suspended. Awaiting operator confirmation in Supervised Mode."
    );

    appendLog(
      `Threat vector ingested: ${pick.target} from ${pick.ip} (Threat Score: ${pick.score}%, Status: ${pick.status})`,
      pick.score >= 80 ? "error" : "warn"
    );

    // If Express backend is alive, also register canary hit
    try {
      fetch(`http://localhost:5000/api/canary?id=${encodeURIComponent(newThreatAlert.trap_id)}`).catch(() => {});
    } catch {
      // offline fallback is handled gracefully
    }

    setToastNotification({
      title: "Threat Vector Ingested",
      message: `${pick.target} hit from ${pick.ip} (Score: ${pick.score}%)`,
      trapId: pick.target,
    });

    setSocGreetingText(
      `Threat vector detected on [${pick.target}] from IP ${pick.ip}. 3 autonomous defense agents actively containing the vector. Threat score: ${pick.score}%.`
    );

    setSentinelStatus(sentinelMode === "autonomous" ? "Autonomous Containment Active" : "Awaiting Operator Sign-Off");
    setTimeout(() => {
      setIsSimulating(false);
      setTimeout(() => setToastNotification(null), 2500);
    }, 400);
  };

  // One-click operator action handling for Supervised Mode
  const handleOperatorAction = (alertId, actionType) => {
    setAlerts((prev) =>
      prev.map((item) => {
        if ((item.id || item.trap_id) === alertId) {
          if (actionType === "approve_tarpit") {
            return {
              ...item,
              supervised_approved: true,
              defense_status: "TARPITTED",
              status: "Operator Approved (Tarpit Active)",
            };
          }
          if (actionType === "isolate_vector") {
            return {
              ...item,
              supervised_approved: true,
              defense_status: "CANARY_TRIGGERED",
              status: "Vector Isolated (Quarantined)",
            };
          }
          if (actionType === "release_ip") {
            return {
              ...item,
              supervised_approved: true,
              defense_status: "MONITORING",
              status: "Released by Operator",
            };
          }
        }
        return item;
      })
    );

    const alertMatch = alerts.find((a) => (a.id || a.trap_id) === alertId);
    const ip = alertMatch?.source_ip || alertMatch?.ip || "Unknown IP";

    if (actionType === "approve_tarpit") {
      appendAgentThought(
        "OPERATOR_APPROVAL",
        `Operator approved automated tarpit enforcement for IP [${ip}]. Injected exponential delay locked.`,
        "Enforcing delay matrix."
      );
      appendLog(`Operator approved tarpit for ${ip}`, "success");
    } else if (actionType === "isolate_vector") {
      appendAgentThought(
        "OPERATOR_ISOLATE",
        `Operator quarantined attack vector from IP [${ip}]. Decoy routing severed.`,
        "Vector isolated."
      );
      appendLog(`Operator isolated vector for ${ip}`, "warn");
    } else {
      appendAgentThought(
        "OPERATOR_RELEASE",
        `Operator cleared rate penalty and released IP [${ip}].`,
        "Perimeter reset."
      );
      appendLog(`Operator released IP ${ip}`, "info");
    }

    setSocGreetingText(
      `Operator playbook [${actionType.replace("_", " ").toUpperCase()}] applied to IP ${ip}. 3 defense agents maintaining perimeter lockdown.`
    );

    setToastNotification({
      title: "Playbook Executed",
      message: `Action [${actionType.replace("_", " ").toUpperCase()}] applied to ${ip}.`,
    });
    setTimeout(() => setToastNotification(null), 2500);
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

  // Execute actual deployment or stage for supervised approval
  const executeMeshDeployment = async (path) => {
    setIsDeploying(true);
    setSentinelStatus("Synthesizing Deception Fabric");
    setDecoys([]);
    appendLog(`Initiating deception mesh deployment for: ${path}`, "info");

    appendAgentThought(
      "SCAN_INGESTION",
      `Analyzing repository architecture: [${path}]. Extracting environment variables, database keys, and API surface.`,
      "Synthesizing high-probability honeytokens."
    );

    try {
      appendLog("Connecting to scanning engine on Express backend...", "info");
      const response = await fetch("http://localhost:5000/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targetPath: path.trim() }),
      });

      if (!response.ok) {
        throw new Error(`Backend error (${response.status}): ${response.statusText}`);
      }

      const result = await response.json();
      appendLog("Repository scan completed successfully.", "success");

      const trapsList = result.traps || result.decoys || [];
      setDecoys(trapsList);

      appendLog(`Synthesized and armed ${trapsList.length} context-aware canary traps.`, "success");
      appendLog("Mesh Secure: Deception perimeter active. Telemetry beacons listening.", "info");

      setSentinelStatus("Autonomous Defense Active");
      appendAgentThought(
        "AUTONOMOUS_DEPLOY",
        `Synthesized ${trapsList.length} polymorph traps tailored to repo context. Armed canary endpoints across mesh.`,
        "Autonomous perimeter secured. Ready for adversarial probe."
      );

      // Show temporary confirmation toast banner
      setToastNotification({
        title: "Mesh Secure & Traps Bound",
        message: `Autonomous Sentinel armed ${trapsList.length} traps. Redirecting to SOC Threat Feed...`,
      });

      // Clear any existing redirect timer
      if (redirectTimerRef.current) {
        clearTimeout(redirectTimerRef.current);
      }

      // Allow user 2 seconds to read the telemetry statements before redirecting
      redirectTimerRef.current = setTimeout(async () => {
        setActiveTab("soc");
        await fetchAlerts();
        appendLog("Switched view to SOC Threat Feed. Synchronized active threat feed.", "info");
        setTimeout(() => setToastNotification(null), 2500);
      }, 2000);
    } catch (err) {
      setSentinelStatus("Deployment Error");
      appendLog(`Deployment error: ${err.message}. Is Express backend running on http://localhost:5000?`, "error");
      appendAgentThought(
        "SCAN_ABORTED",
        `Failed to reach backend engine: ${err.message}. Ensure Express server is running on port 5000.`,
        "Halting synthesis."
      );
      setToastNotification({
        title: "Deployment Failed",
        message: `Error deploying mesh: ${err.message}`,
        error: true,
      });
      setTimeout(() => setToastNotification(null), 3000);
    } finally {
      setIsDeploying(false);
    }
  };

  // Handle Deploy SpectreSync Mesh execution (respects Autonomous vs Supervised Mode)
  const handleDeploy = async () => {
    if (!targetPath.trim()) {
      appendLog("Deployment failed: target repository path is required.", "error");
      return;
    }

    if (sentinelMode === "supervised") {
      // In Supervised Mode, Sentinel drafts the proposal and awaits operator confirmation
      setSentinelStatus("Awaiting Operator Approval");
      appendAgentThought(
        "SUPERVISED_GATE",
        `Repository scan prepared for [${targetPath}]. Supervised Mode enabled: generating deployment proposal for operator sign-off.`,
        "Action suspended pending manual approval."
      );
      setPendingApproval({
        targetPath: targetPath.trim(),
        recommendedTraps: 5,
        strategy: "Adaptive Contextual Entanglement",
      });
      return;
    }

    // In Autonomous Mode, Sentinel acts immediately
    await executeMeshDeployment(targetPath.trim());
  };

  // Approve action in Supervised Mode
  const handleApproveDeployment = async () => {
    if (!pendingApproval) return;
    const target = pendingApproval.targetPath;
    setPendingApproval(null);
    appendAgentThought(
      "SUPERVISED_APPROVED",
      `Operator confirmed deployment for [${target}]. Sentinel proceeding with autonomous trap binding.`,
      "Deploying mesh."
    );
    await executeMeshDeployment(target);
  };

  // Reject action in Supervised Mode
  const handleRejectDeployment = () => {
    appendAgentThought(
      "SUPERVISED_REJECTED",
      "Operator aborted deployment proposal. Reverting perimeter to passive telemetry state.",
      "Standby."
    );
    setPendingApproval(null);
    setSentinelStatus("Monitoring Perimeter");
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
    return `${avgMult.toFixed(1)}x Tarpit Delay Injection`;
  }, [alerts]);

  const isLight = theme === "light";

  return (
    <div
      className={`min-h-screen font-sans relative overflow-x-hidden pb-28 transition-colors duration-200 ${
        isLight
          ? "bg-[#f8fafc] text-slate-900 selection:bg-amber-500/20 selection:text-amber-900"
          : "bg-[#090d16] text-neutral-200 selection:bg-cyan-500/20 selection:text-cyan-200"
      }`}
    >
      {/* Ambient top gradient glow */}
      <div
        className={`absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-7xl h-96 pointer-events-none ${
          isLight
            ? "bg-[radial-gradient(ellipse_60%_40%_at_50%_0%,rgba(217,119,6,0.08),rgba(255,255,255,0))]"
            : "bg-[radial-gradient(ellipse_60%_40%_at_50%_0%,rgba(16,185,129,0.06),rgba(255,255,255,0))]"
        }`}
      />

      {/* Floating Top Command Bar */}
      <header className="sticky top-4 z-40 mx-auto max-w-7xl px-4 mb-6">
        <div
          className={`backdrop-blur-xl border shadow-2xl rounded-2xl px-5 py-3 flex flex-col md:flex-row md:items-center md:justify-between gap-4 transition-all duration-200 ${
            isLight
              ? "bg-white/85 border-slate-200/90 shadow-slate-200/50"
              : "bg-[#0f172a]/70 border-white/10 shadow-black/50"
          }`}
        >
          {/* Logo & Brand Identity */}
          <a
            href="/"
            className="flex items-center gap-3 group text-left cursor-pointer transition-opacity hover:opacity-95"
            title="SpectreSync - Return to Main View"
          >
            <div className="relative shrink-0 flex items-center justify-center">
              <Image
                src="/assets/spectresync-logo.png"
                alt="SpectreSync Foundation Logo"
                width={36}
                height={36}
                className="h-9 w-9 object-contain drop-shadow-[0_0_8px_rgba(0,255,204,0.4)] hover:rotate-180 transition-transform duration-700 select-none"
                priority
              />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span
                  className={`font-semibold text-sm tracking-tight ${
                    isLight ? "text-slate-900" : "text-white"
                  }`}
                >
                  SPECTRESYNC
                </span>
                <span
                  className={`text-[10px] uppercase tracking-wider font-mono px-2 py-0.5 rounded-full border ${
                    isLight
                      ? "text-amber-700 bg-amber-500/10 border-amber-500/25"
                      : "text-cyan-400 bg-cyan-500/10 border-cyan-500/20"
                  }`}
                >
                  Autonomous Mesh
                </span>
              </div>
              <p
                className={`text-[11px] mt-0.5 ${
                  isLight ? "text-slate-500" : "text-neutral-400"
                }`}
              >
                Active Defense · Dynamic Trap Synthesis · Threat Entanglement
              </p>
            </div>
          </a>

          {/* Right Header Controls: Mode Switcher, Live Sentinel Status, Sync Data, Theme Toggle */}
          <div className="flex items-center flex-wrap gap-2.5">
            {/* Autonomous vs Supervised Defense Mode Switcher */}
            <div
              className={`flex items-center p-0.5 rounded-xl text-xs border ${
                isLight
                  ? "bg-slate-100 border-slate-200"
                  : "bg-neutral-950/70 border-white/8"
              }`}
            >
              <button
                onClick={() => {
                  setSentinelMode("autonomous");
                  appendAgentThought(
                    "MODE_SWITCH",
                    "Switched to Autonomous Defense Sentinel mode. Automatic trap synthesis and tarpitting fully enabled.",
                    "Autonomous guardrails active."
                  );
                }}
                className={`px-3 py-1 rounded-lg font-medium transition-all duration-200 flex items-center gap-1.5 cursor-pointer ${
                  sentinelMode === "autonomous"
                    ? isLight
                      ? "bg-amber-500/20 text-amber-800 border border-amber-500/30 shadow-xs"
                      : "bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm"
                    : isLight
                    ? "text-slate-600 hover:text-slate-900"
                    : "text-neutral-400 hover:text-white"
                }`}
                title="Autonomous Mode: Sentinel detects, synthesizes, and tarpits threats with 0 human intervention"
              >
                <Cpu className={`w-3 h-3 ${isLight ? "text-amber-600" : "text-cyan-400"}`} />
                <span>Autonomous</span>
              </button>
              <button
                onClick={() => {
                  setSentinelMode("supervised");
                  appendAgentThought(
                    "MODE_SWITCH",
                    "Switched to Supervised Mode. Sentinel will draft deception strategies and require operator approval before binding.",
                    "Human-in-the-loop gate armed."
                  );
                }}
                className={`px-3 py-1 rounded-lg font-medium transition-all duration-200 flex items-center gap-1.5 cursor-pointer ${
                  sentinelMode === "supervised"
                    ? isLight
                      ? "bg-amber-500/20 text-amber-800 border border-amber-500/30 shadow-xs"
                      : "bg-amber-500/15 text-amber-300 border border-amber-500/30 shadow-sm"
                    : isLight
                    ? "text-slate-600 hover:text-slate-900"
                    : "text-neutral-400 hover:text-white"
                }`}
                title="Supervised Mode: Sentinel drafts proposals and requires operator approval before deploying"
              >
                <Sliders className={`w-3 h-3 ${isLight ? "text-amber-600" : "text-amber-400"}`} />
                <span>Supervised</span>
              </button>
            </div>

            {/* Live Sentinel status indicator pill */}
            <div
              className={`hidden lg:flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono border ${
                isLight
                  ? "bg-amber-500/10 text-amber-800 border-amber-500/25"
                  : "bg-cyan-500/10 text-cyan-300 border-cyan-500/20"
              }`}
            >
              <span
                className={`w-1.5 h-1.5 rounded-full animate-ping ${
                  isLight ? "bg-amber-600" : "bg-cyan-400"
                }`}
              />
              <span>{sentinelStatus}</span>
            </div>

            {/* Manual Sync Telemetry Button */}
            <button
              onClick={handleManualRefresh}
              disabled={isRefreshing}
              className={`px-3 py-1.5 rounded-xl text-xs font-medium border transition-all flex items-center gap-1.5 cursor-pointer shadow-xs ${
                isLight
                  ? "bg-slate-100 hover:bg-slate-200 border-slate-200 text-slate-700"
                  : "bg-neutral-950/60 hover:bg-white/5 border-white/8 text-neutral-300 hover:text-white"
              }`}
              title="Synchronize fresh telemetry and alert logs"
            >
              <RefreshCw
                className={`w-3 h-3 ${
                  isRefreshing
                    ? `animate-spin ${isLight ? "text-amber-600" : "text-cyan-400"}`
                    : ""
                }`}
              />
              <span className="hidden sm:inline">Sync Data</span>
            </button>

            {/* AI Agent Copilot Trigger Button */}
            <button
              onClick={() => setIsAIAgentOpen((prev) => !prev)}
              className={`px-3 py-1.5 rounded-xl text-xs font-mono font-medium border transition-all flex items-center gap-1.5 cursor-pointer shadow-xs active:scale-95 ${
                isAIAgentOpen
                  ? isLight
                    ? "bg-amber-500/20 text-amber-900 border-amber-500/40"
                    : "bg-cyan-500/25 text-cyan-300 border-cyan-500/50 shadow-cyan-500/20 shadow-sm"
                  : isLight
                  ? "bg-amber-500/10 hover:bg-amber-500/20 text-amber-800 border-amber-500/30"
                  : "bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border-cyan-500/30 hover:border-cyan-500/50"
              }`}
              title="Toggle Spectre AI (Ctrl+K)"
              aria-label="Toggle Spectre AI"
            >
              <Bot className="w-3.5 h-3.5 text-cyan-400" />
              <span>Spectre AI</span>
              <kbd className="hidden md:inline-block px-1.5 py-0.5 text-[9px] font-mono rounded bg-black/30 text-neutral-400 border border-white/10">
                Ctrl+K
              </kbd>
            </button>

            {/* Theme Toggle Button (Sun / Moon) */}
            <button
              onClick={toggleTheme}
              className={`p-1.5 rounded-xl border transition-all duration-200 cursor-pointer shadow-xs flex items-center justify-center ${
                isLight
                  ? "bg-slate-100 hover:bg-slate-200 border-slate-200 text-amber-600"
                  : "bg-neutral-950/70 hover:bg-white/5 border-white/10 text-cyan-400"
              }`}
              title={isLight ? "Switch to Dark Mode" : "Switch to Light Mode"}
              aria-label="Toggle Theme"
            >
              {isLight ? (
                <Moon className="w-4 h-4 text-slate-700" />
              ) : (
                <Sun className="w-4 h-4 text-amber-400" />
              )}
            </button>
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
                ? "bg-rose-950/70 border-rose-500/40 text-rose-200 shadow-rose-950/40"
                : isLight
                ? "bg-white/95 border-amber-500/30 text-slate-800 shadow-amber-900/10"
                : "bg-cyan-950/60 border-cyan-500/30 text-cyan-200 shadow-cyan-950/40"
            }`}
          >
            <div className="flex items-center gap-3">
              <div
                className={`p-2 rounded-xl border ${
                  toastNotification.error
                    ? "bg-rose-500/10 border-rose-500/30 text-rose-400"
                    : isLight
                    ? "bg-amber-500/15 border-amber-500/30 text-amber-700"
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
                  <span
                    className={`font-semibold text-xs tracking-wide uppercase ${
                      isLight ? "text-slate-900" : "text-white"
                    }`}
                  >
                    {toastNotification.title}
                  </span>
                  {toastNotification.trapId && (
                    <span
                      className={`px-2 py-0.5 rounded-full font-mono text-[10px] border ${
                        isLight
                          ? "bg-amber-500/15 border-amber-500/30 text-amber-800"
                          : "bg-cyan-500/20 border-cyan-500/40 text-cyan-300"
                      }`}
                    >
                      {toastNotification.trapId}
                    </span>
                  )}
                </div>
                <p
                  className={`text-xs mt-0.5 ${
                    isLight ? "text-slate-600" : "text-neutral-300"
                  }`}
                >
                  {toastNotification.message}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <div
                className={`flex items-center gap-1.5 px-3 py-1 rounded-lg border text-[11px] font-mono ${
                  isLight
                    ? "bg-slate-100 border-slate-200 text-slate-600"
                    : "bg-neutral-900/80 border-white/10 text-neutral-400"
                }`}
              >
                <RefreshCw
                  className={`w-3 h-3 animate-spin ${
                    isLight ? "text-amber-600" : "text-cyan-400"
                  }`}
                />
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
              <div
                className={`lg:col-span-2 backdrop-blur-xl border rounded-2xl p-6 shadow-xl transition-all duration-200 space-y-4 ${
                  isLight
                    ? "bg-white/85 border-slate-200/90 shadow-slate-200/50"
                    : "bg-neutral-900/40 border-white/8 shadow-black/20"
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Server className={`w-4 h-4 ${isLight ? "text-amber-600" : "text-cyan-400"}`} />
                    <h2
                      className={`text-xs uppercase tracking-wider font-semibold ${
                        isLight ? "text-slate-800" : "text-neutral-300"
                      }`}
                    >
                      Target Repository Instrumentation
                    </h2>
                  </div>
                  <span
                    className={`text-[11px] font-mono ${
                      isLight ? "text-slate-500" : "text-neutral-500"
                    }`}
                  >
                    v2.4 Deception Engine
                  </span>
                </div>
                <p
                  className={`text-xs leading-relaxed ${
                    isLight ? "text-slate-600" : "text-neutral-400"
                  }`}
                >
                  Provide the target codebase path to synthesize adaptive honeytokens, database triggers, and canary endpoints.
                </p>

                <div className="flex flex-col sm:flex-row gap-3 pt-2">
                  <input
                    type="text"
                    value={targetPath}
                    onChange={(e) => setTargetPath(e.target.value)}
                    placeholder="/absolute/path/to/target/repository"
                    className={`flex-1 rounded-xl px-4 py-2.5 text-xs font-mono transition-all outline-none border ${
                      isLight
                        ? "bg-slate-50 border-slate-300 focus:border-amber-500 focus:ring-1 focus:ring-amber-500/30 text-slate-900 placeholder:text-slate-400"
                        : "bg-neutral-950/80 border-white/8 focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/30 text-neutral-200 placeholder:text-neutral-600"
                    }`}
                  />
                  <button
                    onClick={handleDeploy}
                    disabled={isDeploying}
                    className={`font-semibold px-5 py-2.5 rounded-xl text-xs transition-all duration-200 shadow-lg active:scale-[0.98] whitespace-nowrap cursor-pointer flex items-center justify-center gap-2 disabled:opacity-50 ${
                      isLight
                        ? "bg-amber-600 hover:bg-amber-500 text-white shadow-amber-600/25"
                        : "bg-linear-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-neutral-950 shadow-cyan-500/20"
                    }`}
                  >
                    {isDeploying ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        Instrumenting...
                      </>
                    ) : (
                      <>
                        <Sparkles className="w-3.5 h-3.5" />
                        Deploy Mesh & Bind Traps
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Quick Metrics Bento Card */}
              <div
                className={`backdrop-blur-xl border rounded-2xl p-6 shadow-xl flex flex-col justify-between transition-all duration-200 ${
                  isLight
                    ? "bg-white/85 border-slate-200/90 shadow-slate-200/50"
                    : "bg-neutral-900/40 border-white/8 shadow-black/20"
                }`}
              >
                <div>
                  <div className="flex items-center gap-2">
                    <Radio className={`w-4 h-4 ${isLight ? "text-amber-600" : "text-cyan-400"}`} />
                    <h2
                      className={`text-xs uppercase tracking-wider font-semibold ${
                        isLight ? "text-slate-800" : "text-neutral-300"
                      }`}
                    >
                      Deception Status
                    </h2>
                  </div>
                  <div className="mt-4 space-y-3">
                    <div className="flex items-center justify-between text-xs">
                      <span className={isLight ? "text-slate-500" : "text-neutral-400"}>Armed Traps</span>
                      <span className={`font-mono font-medium ${isLight ? "text-slate-900" : "text-white"}`}>
                        {decoys.length}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className={isLight ? "text-slate-500" : "text-neutral-400"}>Canary Health</span>
                      <span className="font-mono text-emerald-600 dark:text-emerald-400 font-medium">100% Operational</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className={isLight ? "text-slate-500" : "text-neutral-400"}>Defense Mode</span>
                      <span
                        className={`font-mono font-medium ${
                          sentinelMode === "autonomous"
                            ? isLight
                              ? "text-amber-700"
                              : "text-cyan-400"
                            : isLight
                            ? "text-amber-800"
                            : "text-amber-300"
                        }`}
                      >
                        {sentinelMode === "autonomous" ? "Autonomous Sentinel" : "Supervised (Human Gate)"}
                      </span>
                    </div>
                  </div>
                </div>

                <div
                  className={`pt-4 border-t flex items-center justify-between text-[11px] ${
                    isLight ? "border-slate-200 text-slate-500" : "border-white/4 text-neutral-500"
                  }`}
                >
                  <span>Engine: SQLite WAL</span>
                  <span className={isLight ? "text-slate-600 font-mono" : "text-neutral-400 font-mono"}>
                    Port 5000
                  </span>
                </div>
              </div>
            </div>

            {/* Supervised Mode Pending Approval Banner */}
            {pendingApproval && (
              <div
                className={`backdrop-blur-xl border rounded-2xl p-5 shadow-2xl space-y-3 animate-in fade-in slide-in-from-top-2 ${
                  isLight
                    ? "bg-amber-50 border-amber-300 shadow-amber-900/10 text-slate-800"
                    : "bg-amber-950/40 border-amber-500/30 shadow-amber-950/20 text-neutral-200"
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <ShieldAlert className="w-5 h-5 text-amber-600 dark:text-amber-400" />
                    <div>
                      <h4
                        className={`text-xs font-semibold uppercase tracking-wider ${
                          isLight ? "text-slate-900" : "text-white"
                        }`}
                      >
                        Supervised Action Required · Sentinel Trap Synthesis Proposal
                      </h4>
                      <p className={`text-xs mt-0.5 ${isLight ? "text-slate-600" : "text-neutral-300"}`}>
                        The AI Sentinel drafted a deception matrix for{" "}
                        <span className="font-mono font-semibold text-amber-700 dark:text-amber-300">
                          {pendingApproval.targetPath}
                        </span>
                        . Confirm deployment to arm the network.
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleRejectDeployment}
                      className={`px-3.5 py-1.5 rounded-xl text-xs font-medium border transition-all cursor-pointer ${
                        isLight
                          ? "bg-white hover:bg-slate-100 text-slate-600 border-slate-300"
                          : "bg-neutral-900/80 hover:bg-neutral-800 text-neutral-400 hover:text-white border-white/10"
                      }`}
                    >
                      Reject
                    </button>
                    <button
                      onClick={handleApproveDeployment}
                      className="px-4 py-1.5 rounded-xl text-xs font-semibold bg-amber-500 hover:bg-amber-400 text-neutral-950 shadow-md shadow-amber-500/20 transition-all cursor-pointer flex items-center gap-1.5"
                    >
                      <span>Approve & Arm Mesh</span>
                      <ChevronRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* AI Security Agent Reasoning Panel ("Autonomous Defense Sentinel") */}
            <div
              className={`backdrop-blur-xl border rounded-2xl p-6 shadow-xl space-y-4 transition-all duration-200 ${
                isLight
                  ? "bg-white/85 border-slate-200/90 shadow-slate-200/50"
                  : "bg-neutral-900/40 border-white/8 shadow-black/20"
              }`}
            >
              <div
                className={`flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b pb-3 ${
                  isLight ? "border-slate-200" : "border-white/6"
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <div
                    className={`p-1.5 rounded-lg border ${
                      isLight
                        ? "bg-amber-500/10 border-amber-500/25 text-amber-700"
                        : "bg-cyan-500/10 border-cyan-500/20 text-cyan-400"
                    }`}
                  >
                    <Bot className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3
                        className={`text-xs uppercase tracking-wider font-semibold ${
                          isLight ? "text-slate-800" : "text-neutral-200"
                        }`}
                      >
                        Autonomous Defense Sentinel · Agent Reasoning Stream
                      </h3>
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-mono border ${
                          isLight
                            ? "bg-amber-500/10 border-amber-500/25 text-amber-800"
                            : "bg-cyan-500/10 border-cyan-500/30 text-cyan-300"
                        }`}
                      >
                        {sentinelStatus}
                      </span>
                    </div>
                    <p
                      className={`text-[11px] mt-0.5 ${
                        isLight ? "text-slate-500" : "text-neutral-400"
                      }`}
                    >
                      Live internal monologue and adaptive decision-making telemetry
                    </p>
                  </div>
                </div>

                <div
                  className={`flex items-center gap-2 text-[11px] font-mono ${
                    isLight ? "text-slate-500" : "text-neutral-400"
                  }`}
                >
                  <span
                    className={`w-2 h-2 rounded-full animate-pulse ${
                      isLight ? "bg-amber-600" : "bg-cyan-400"
                    }`}
                  />
                  <span>Sentinel Core Online</span>
                </div>
              </div>

              {/* Copilot-style Monologue Stream */}
              <div
                className={`border rounded-xl p-4 max-h-72 overflow-y-auto space-y-3 font-mono text-xs ${
                  isLight
                    ? "bg-slate-50 border-slate-200 text-slate-800"
                    : "bg-neutral-950/80 border-white/6 text-neutral-200"
                }`}
              >
                {agentThoughts.map((entry, idx) => (
                  <div
                    key={idx}
                    className={`space-y-1 pb-2 border-b last:border-b-0 last:pb-0 ${
                      isLight ? "border-slate-200" : "border-white/4"
                    }`}
                  >
                    <div className="flex items-center justify-between text-[10px]">
                      <span
                        className={`font-semibold flex items-center gap-1.5 ${
                          isLight ? "text-amber-700" : "text-cyan-400"
                        }`}
                      >
                        <Cpu className={`w-3 h-3 ${isLight ? "text-amber-600" : "text-cyan-400"}`} />
                        [{entry.stage}]
                      </span>
                      <span className={isLight ? "text-slate-400" : "text-neutral-500"}>{entry.time}</span>
                    </div>
                    <div
                      className={`leading-relaxed pl-4 border-l ${
                        isLight
                          ? "text-slate-700 border-amber-500/40"
                          : "text-neutral-200 border-cyan-500/30"
                      }`}
                    >
                      {entry.thought}
                    </div>
                    {entry.action && (
                      <div className="text-[11px] text-emerald-600 dark:text-emerald-400/90 pl-4 font-sans flex items-center gap-1.5">
                        <span className="text-emerald-700 dark:text-emerald-500 font-mono font-bold">Action:</span>
                        <span>{entry.action}</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Agent Execution Telemetry Stream */}
            <div
              className={`backdrop-blur-xl border rounded-2xl p-6 shadow-xl space-y-4 transition-all duration-200 ${
                isLight
                  ? "bg-white/85 border-slate-200/90 shadow-slate-200/50"
                  : "bg-neutral-900/40 border-white/8 shadow-black/20"
              }`}
            >
              <div
                className={`flex items-center justify-between border-b pb-3 ${
                  isLight ? "border-slate-200" : "border-white/6"
                }`}
              >
                <div className="flex items-center gap-2">
                  <Terminal className={`w-4 h-4 ${isLight ? "text-amber-600" : "text-cyan-400"}`} />
                  <h3
                    className={`text-xs uppercase tracking-wider font-semibold ${
                      isLight ? "text-slate-800" : "text-neutral-300"
                    }`}
                  >
                    Agent Execution Telemetry
                  </h3>
                </div>
                <span
                  className={`text-[11px] font-mono ${
                    isLight ? "text-slate-500" : "text-neutral-500"
                  }`}
                >
                  {logs.length} events logged
                </span>
              </div>

              <div
                className={`border rounded-xl p-4 h-60 overflow-y-auto space-y-2 font-mono text-xs ${
                  isLight
                    ? "bg-slate-50 border-slate-200 text-slate-800"
                    : "bg-neutral-950/80 border-white/6 text-neutral-200"
                }`}
              >
                {logs.length === 0 ? (
                  <div className={`text-xs italic ${isLight ? "text-slate-400" : "text-neutral-600"}`}>
                    Ready for deployment. Enter repository path above to initialize telemetry stream.
                  </div>
                ) : (
                  logs.map((log, index) => (
                    <div key={index} className="flex items-start gap-3">
                      <span className={`shrink-0 text-[11px] ${isLight ? "text-slate-400" : "text-neutral-600"}`}>
                        [{log.time}]
                      </span>
                      <span
                        className={
                          log.level === "error"
                            ? "text-rose-500"
                            : log.level === "success"
                            ? isLight
                              ? "text-emerald-700"
                              : "text-emerald-400"
                            : log.level === "warn"
                            ? isLight
                              ? "text-amber-700"
                              : "text-amber-300"
                            : isLight
                            ? "text-amber-800"
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
              <div
                className={`backdrop-blur-xl border rounded-2xl p-6 shadow-xl space-y-4 transition-all duration-200 ${
                  isLight
                    ? "bg-white/85 border-slate-200/90 shadow-slate-200/50"
                    : "bg-neutral-900/40 border-white/8 shadow-black/20"
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Key className={`w-4 h-4 ${isLight ? "text-amber-600" : "text-cyan-400"}`} />
                    <h3
                      className={`text-xs uppercase tracking-wider font-semibold ${
                        isLight ? "text-slate-800" : "text-neutral-300"
                      }`}
                    >
                      Synthesized Context-Aware Decoys ({decoys.length})
                    </h3>
                  </div>
                  <span className={`text-[11px] ${isLight ? "text-slate-500" : "text-neutral-500"}`}>
                    Live Canary Endpoints
                  </span>
                </div>

                <div
                  className={`overflow-x-auto rounded-xl border ${
                    isLight ? "border-slate-200" : "border-white/6"
                  }`}
                >
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr
                        className={`border-b font-medium ${
                          isLight
                            ? "bg-slate-100/70 border-slate-200 text-slate-600"
                            : "bg-white/2 border-white/6 text-neutral-400"
                        }`}
                      >
                        <th className="py-3 px-4">Trap ID</th>
                        <th className="py-3 px-4">Variable Name</th>
                        <th className="py-3 px-4">Decoy Value</th>
                        <th className="py-3 px-4">Category</th>
                        <th className="py-3 px-4">Canary Endpoint</th>
                        <th className="py-3 px-4 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody
                      className={`divide-y ${
                        isLight ? "divide-slate-200" : "divide-white/4"
                      }`}
                    >
                      {decoys.map((decoy, idx) => {
                        const trapId = decoy.trap_id || decoy.id || `trap_${idx + 1}`;
                        const isTesting = testingTrapId === trapId;

                        return (
                          <tr
                            key={trapId}
                            className={`transition-colors ${
                              isLight ? "hover:bg-slate-50" : "hover:bg-white/2"
                            }`}
                          >
                            <td
                              className={`py-3 px-4 font-mono font-semibold ${
                                isLight ? "text-amber-700" : "text-cyan-400"
                              }`}
                            >
                              {trapId}
                            </td>
                            <td
                              className={`py-3 px-4 font-mono ${
                                isLight ? "text-slate-900" : "text-white"
                              }`}
                            >
                              {decoy.variable_name || decoy.trap_name || decoy.name}
                            </td>
                            <td
                              className={`py-3 px-4 font-mono truncate max-w-xs ${
                                isLight ? "text-slate-500" : "text-neutral-400"
                              }`}
                            >
                              {decoy.decoy_value || decoy.value || "••••••••"}
                            </td>
                            <td className="py-3 px-4">
                              <span
                                className={`px-2 py-0.5 rounded-full border text-[10px] font-medium uppercase ${
                                  isLight
                                    ? "bg-slate-100 border-slate-200 text-slate-700"
                                    : "bg-white/4 border-white/8 text-neutral-300"
                                }`}
                              >
                                {decoy.category || decoy.trap_type || "secret"}
                              </span>
                            </td>
                            <td
                              className={`py-3 px-4 font-mono transition-colors ${
                                isLight
                                  ? "text-slate-600 hover:text-amber-700"
                                  : "text-neutral-400 hover:text-cyan-300"
                              }`}
                            >
                              {decoy.endpoint || decoy.endpoint_url}
                            </td>
                            <td className="py-3 px-4 text-right">
                              <button
                                onClick={() => handleTriggerCanary(trapId)}
                                disabled={isTesting || Boolean(testingTrapId)}
                                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-[11px] font-medium bg-rose-500/10 hover:bg-rose-500/20 text-rose-600 dark:text-rose-300 border border-rose-500/30 transition-all duration-200 disabled:opacity-40 cursor-pointer shadow-xs active:scale-[0.98]"
                                title="Simulate canary trigger and test tarpit response"
                              >
                                {isTesting ? (
                                  <>
                                    <RefreshCw className="w-3 h-3 animate-spin" />
                                    <span>Tarpitting...</span>
                                  </>
                                ) : (
                                  <>
                                    <Play className="w-3 h-3 text-rose-500" />
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
            theme={theme}
          />
        )}

        {/* TAB 3: SOC Threat Feed */}
        {activeTab === "soc" && (
          <div className="space-y-6">
            {/* 1. AI SOC Greeter Card & Multi-Agent Defense Controls */}
            <div
              className={`backdrop-blur-xl border rounded-2xl p-5 sm:p-6 shadow-xl transition-all duration-200 ${
                isLight
                  ? "bg-white/85 border-slate-200/90 shadow-slate-200/40 text-slate-900"
                  : "bg-[#090D16]/90 border-slate-800 shadow-black/40 text-neutral-200"
              }`}
            >
              <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-4 border-b border-white/6 dark:border-slate-800/80">
                <div className="flex flex-wrap items-center gap-3">
                  <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                    <ShieldAlert className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h2
                        className={`text-sm tracking-wide font-bold uppercase font-mono ${
                          isLight ? "text-slate-900" : "text-white"
                        }`}
                      >
                        Autonomous SOC Command Loop
                      </h2>
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-medium tracking-wide bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                        ACTIVE DEFENSE LOOP ONLINE
                      </span>
                    </div>
                    <p
                      className={`text-xs mt-0.5 font-mono ${
                        isLight ? "text-slate-500" : "text-neutral-400"
                      }`}
                    >
                      3 specialized AI agents defending network telemetry in real-time
                    </p>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2.5">
                  {/* Mode Selector Toggle */}
                  <div
                    className={`p-1 rounded-xl border flex items-center gap-1 text-xs font-mono ${
                      isLight
                        ? "bg-slate-100 border-slate-300"
                        : "bg-black/60 border-slate-800"
                    }`}
                  >
                    <button
                      onClick={() => setSentinelMode("autonomous")}
                      className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-all duration-200 cursor-pointer ${
                        sentinelMode === "autonomous"
                          ? isLight
                            ? "bg-white text-slate-900 shadow-xs font-semibold"
                            : "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-semibold"
                          : isLight
                          ? "text-slate-600 hover:text-slate-900"
                          : "text-neutral-400 hover:text-neutral-200"
                      }`}
                      title="AI executes defense playbooks automatically"
                    >
                      Autonomous Mode
                    </button>
                    <button
                      onClick={() => setSentinelMode("supervised")}
                      className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-all duration-200 cursor-pointer ${
                        sentinelMode === "supervised"
                          ? isLight
                            ? "bg-white text-slate-900 shadow-xs font-semibold"
                            : "bg-amber-500/20 text-amber-300 border border-amber-500/30 font-semibold"
                          : isLight
                          ? "text-slate-600 hover:text-slate-900"
                          : "text-neutral-400 hover:text-neutral-200"
                      }`}
                      title="Operator approval required for containment playbooks"
                    >
                      Supervised Mode
                    </button>
                  </div>

                  {/* Simulate Threat Vector Button */}
                  <button
                    onClick={handleSimulateThreatVector}
                    disabled={isSimulating}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-mono font-medium bg-linear-to-r from-rose-500/20 to-cyan-500/20 hover:from-rose-500/30 hover:to-cyan-500/30 text-cyan-300 border border-cyan-500/30 shadow-xs active:scale-[0.98] transition-all duration-200 disabled:opacity-50 cursor-pointer"
                    title="Simulate adversarial threat vector and trigger AI multi-agent reasoning pipeline"
                  >
                    {isSimulating ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                        <span>Synthesizing Vector...</span>
                      </>
                    ) : (
                      <>
                        <Zap className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Simulate Threat Vector</span>
                      </>
                    )}
                  </button>

                  {/* Refresh Feed */}
                  <button
                    onClick={handleManualRefresh}
                    disabled={isRefreshing}
                    className={`px-3 py-2 rounded-xl text-xs font-mono font-medium transition-all duration-200 flex items-center justify-center gap-1.5 cursor-pointer shadow-xs active:scale-[0.98] ${
                      isLight
                        ? "bg-slate-100 hover:bg-slate-200 text-slate-800 border border-slate-300"
                        : "bg-slate-900 hover:bg-slate-800 text-neutral-300 border border-slate-700/60"
                    }`}
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
                    <span>Refresh</span>
                  </button>
                </div>
              </div>

              {/* Automated AI Greeter Banner */}
              <div
                className={`mt-4 p-3.5 rounded-xl border flex items-start gap-3 font-mono text-xs transition-colors ${
                  isLight
                    ? "bg-slate-50 border-slate-200 text-slate-700"
                    : "bg-black/50 border-slate-800 text-cyan-300/90"
                }`}
              >
                <Bot className="w-4 h-4 mt-0.5 shrink-0 text-cyan-400" />
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold uppercase tracking-wider text-[11px] text-cyan-400">
                      System Posture Telemetry
                    </span>
                    <span className="text-[10px] text-neutral-500">REAL-TIME INFERENCE</span>
                  </div>
                  <p className="mt-1 leading-relaxed text-xs">
                    {socGreetingText}
                  </p>
                </div>
              </div>
            </div>

            {/* 2. Multi-Agent Defensive Pipeline (Triage, Deception, Entanglement) */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Agent 1: Triage Agent (Perception) */}
              <div
                className={`backdrop-blur-xl border rounded-2xl p-4 shadow-lg transition-all duration-200 ${
                  isLight
                    ? "bg-white/90 border-slate-200 shadow-slate-200/30"
                    : "bg-[#090D16]/90 border-slate-800 shadow-black/20"
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2.5">
                    <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                      <Eye className="w-4 h-4" />
                    </div>
                    <div>
                      <h3
                        className={`text-xs font-bold uppercase font-mono ${
                          isLight ? "text-slate-900" : "text-white"
                        }`}
                      >
                        Triage Agent
                      </h3>
                      <p className="text-[10px] font-mono text-cyan-400">Perception & Ingestion</p>
                    </div>
                  </div>
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/25">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                    LISTENING
                  </span>
                </div>
                <p
                  className={`mt-3 text-xs leading-relaxed ${
                    isLight ? "text-slate-600" : "text-neutral-400"
                  }`}
                >
                  Ingests request headers, User-Agent fingerprints, and traffic velocity to calculate real-time Threat Scores (0–100%).
                </p>
                <div
                  className={`mt-3 pt-3 border-t flex items-center justify-between text-[11px] font-mono ${
                    isLight ? "border-slate-200 text-slate-500" : "border-slate-800 text-neutral-400"
                  }`}
                >
                  <span>Vectors Evaluated</span>
                  <span className="font-bold text-cyan-400">{alerts.length} Ingested</span>
                </div>
              </div>

              {/* Agent 2: Deception Agent (Generative Synthesis) */}
              <div
                className={`backdrop-blur-xl border rounded-2xl p-4 shadow-lg transition-all duration-200 ${
                  isLight
                    ? "bg-white/90 border-slate-200 shadow-slate-200/30"
                    : "bg-[#090D16]/90 border-slate-800 shadow-black/20"
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2.5">
                    <div className="p-2 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400">
                      <Sparkles className="w-4 h-4" />
                    </div>
                    <div>
                      <h3
                        className={`text-xs font-bold uppercase font-mono ${
                          isLight ? "text-slate-900" : "text-white"
                        }`}
                      >
                        Deception Agent
                      </h3>
                      <p className="text-[10px] font-mono text-amber-400">Generative Synthesis</p>
                    </div>
                  </div>
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-amber-500/10 text-amber-400 border border-amber-500/25">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                    FABRIC ARMED
                  </span>
                </div>
                <p
                  className={`mt-3 text-xs leading-relaxed ${
                    isLight ? "text-slate-600" : "text-neutral-400"
                  }`}
                >
                  Dynamically crafts realistic decoy endpoints, mock payload schemas, and embedded canary tracking tokens on demand.
                </p>
                <div
                  className={`mt-3 pt-3 border-t flex items-center justify-between text-[11px] font-mono ${
                    isLight ? "border-slate-200 text-slate-500" : "border-slate-800 text-neutral-400"
                  }`}
                >
                  <span>Canary Constellation</span>
                  <span className="font-bold text-amber-400">
                    {decoys.length > 0 ? decoys.length : 140} Armed Traps
                  </span>
                </div>
              </div>

              {/* Agent 3: Entanglement Agent (Action) */}
              <div
                className={`backdrop-blur-xl border rounded-2xl p-4 shadow-lg transition-all duration-200 ${
                  isLight
                    ? "bg-white/90 border-slate-200 shadow-slate-200/30"
                    : "bg-[#090D16]/90 border-slate-800 shadow-black/20"
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2.5">
                    <div className="p-2 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
                      <Hourglass className="w-4 h-4" />
                    </div>
                    <div>
                      <h3
                        className={`text-xs font-bold uppercase font-mono ${
                          isLight ? "text-slate-900" : "text-white"
                        }`}
                      >
                        Entanglement Agent
                      </h3>
                      <p className="text-[10px] font-mono text-rose-400">Action & Tarpitting</p>
                    </div>
                  </div>
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-rose-500/10 text-rose-400 border border-rose-500/25">
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-pulse" />
                    TARPIT ACTIVE
                  </span>
                </div>
                <p
                  className={`mt-3 text-xs leading-relaxed ${
                    isLight ? "text-slate-600" : "text-neutral-400"
                  }`}
                >
                  Applies network tarpitting by injecting artificial response delays and jitter (500ms to 10,000ms) to lock attacker sockets.
                </p>
                <div
                  className={`mt-3 pt-3 border-t flex items-center justify-between text-[11px] font-mono ${
                    isLight ? "border-slate-200 text-slate-500" : "border-slate-800 text-neutral-400"
                  }`}
                >
                  <span>Dynamic Delay Range</span>
                  <span className="font-bold text-rose-400">500ms - 10,000ms</span>
                </div>
              </div>
            </div>

            {/* 3. Real-Time SOC Threat Feed Table */}
            <div
              className={`backdrop-blur-xl border rounded-2xl overflow-hidden shadow-xl transition-all duration-200 ${
                isLight
                  ? "bg-white/90 border-slate-200/90 shadow-slate-200/40"
                  : "bg-[#090D16]/90 border-slate-800 shadow-black/20"
              }`}
            >
              {alerts.length === 0 ? (
                <div
                  className={`text-center py-16 text-xs ${
                    isLight ? "text-slate-500" : "text-neutral-500"
                  }`}
                >
                  <CheckCircle2
                    className={`w-8 h-8 mx-auto mb-2 ${
                      isLight ? "text-slate-400" : "text-neutral-600"
                    }`}
                  />
                  No security alerts recorded. All canary traps are silent and armed.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse table-fixed">
                    <thead>
                      <tr
                        className={`border-b font-medium font-mono ${
                          isLight
                            ? "bg-slate-100/70 border-slate-200 text-slate-600"
                            : "bg-black/40 border-slate-800 text-neutral-400"
                        }`}
                      >
                        <th className="py-3 px-4 w-36">Timestamp (IST)</th>
                        <th className="py-3 px-4 w-52">Source Client / IP</th>
                        <th className="py-3 px-4">Targeted Canary Asset</th>
                        <th className="py-3 px-4 w-36">Threat Score</th>
                        <th className="py-3 px-4 w-44">Defense Status</th>
                        <th className="py-3 px-4 w-60 text-right">
                          {sentinelMode === "autonomous" ? "Autonomous Playbook" : "Operator Action"}
                        </th>
                      </tr>
                    </thead>
                    <tbody
                      className={`divide-y font-mono ${
                        isLight ? "divide-slate-200/80" : "divide-slate-800/80"
                      }`}
                    >
                      {alerts.map((alert, idx) => {
                        const targetAsset = getTrapTargetAsset(alert, decoys);
                        const fingerprint = formatClientFingerprint(alert.user_agent || alert.type);
                        const istTimestamp = formatISTTime(alert.timestamp);
                        const defenseStatus = getDefenseStatus(alert);
                        const threatScore = getThreatScore(alert);
                        const alertId = alert.id || alert.trap_id || `alert-${idx}`;

                        return (
                          <tr
                            key={alert.id || idx}
                            className={`transition-colors ${
                              isLight ? "hover:bg-slate-50/80" : "hover:bg-white/2"
                            }`}
                          >
                            {/* Timestamp (IST) */}
                            <td
                              className={`py-3.5 px-4 whitespace-nowrap ${
                                isLight ? "text-slate-600" : "text-neutral-400"
                              }`}
                              title={formatIST(alert.timestamp)}
                            >
                              {istTimestamp}
                            </td>

                            {/* Source Client / IP */}
                            <td className="py-3.5 px-4 max-w-50">
                              <div className="flex flex-col gap-0.5 min-w-0">
                                <span
                                  className={`font-bold text-xs truncate ${
                                    isLight ? "text-slate-900" : "text-white"
                                  }`}
                                  title={alert.source_ip || alert.ip || "127.0.0.1"}
                                >
                                  {alert.source_ip || alert.ip || "127.0.0.1"}
                                </span>
                                <span
                                  className={`text-[11px] truncate ${
                                    isLight ? "text-slate-500" : "text-neutral-400"
                                  }`}
                                  title={alert.user_agent || fingerprint}
                                >
                                  {fingerprint}
                                </span>
                              </div>
                            </td>

                            {/* Targeted Canary Asset */}
                            <td className="py-3.5 px-4 max-w-sm">
                              <div className="flex items-center gap-2 min-w-0">
                                <span
                                  className={`font-bold text-xs truncate ${
                                    isLight ? "text-amber-700" : "text-cyan-400"
                                  }`}
                                  title={targetAsset}
                                >
                                  {targetAsset}
                                </span>
                              </div>
                            </td>

                            {/* Threat Score */}
                            <td className="py-3.5 px-4 whitespace-nowrap">
                              <div className="flex items-center gap-2">
                                <span
                                  className={`font-bold text-xs ${
                                    threatScore >= 80
                                      ? "text-rose-400"
                                      : threatScore >= 60
                                      ? "text-amber-400"
                                      : "text-cyan-400"
                                  }`}
                                >
                                  {threatScore}%
                                </span>
                                <div className="w-16 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                                  <div
                                    className={`h-full rounded-full transition-all duration-300 ${
                                      threatScore >= 80
                                        ? "bg-rose-500"
                                        : threatScore >= 60
                                        ? "bg-amber-500"
                                        : "bg-cyan-400"
                                    }`}
                                    style={{ width: `${threatScore}%` }}
                                  />
                                </div>
                              </div>
                            </td>

                            {/* Dynamic Defense Status */}
                            <td className="py-3.5 px-4 whitespace-nowrap">
                              {defenseStatus === "TARPITTED" ? (
                                <span className="inline-flex items-center px-2.5 py-1 rounded-full text-[10px] font-medium bg-amber-500/10 text-amber-400 border border-amber-500/25">
                                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400 mr-1.5 shrink-0 animate-pulse" />
                                  TARPITTED
                                </span>
                              ) : defenseStatus === "CANARY_TRIGGERED" ? (
                                <span className="inline-flex items-center px-2.5 py-1 rounded-full text-[10px] font-medium bg-rose-500/10 text-rose-400 border border-rose-500/25">
                                  <span className="w-1.5 h-1.5 rounded-full bg-rose-500 mr-1.5 shrink-0 animate-pulse" />
                                  CANARY_TRIGGERED
                                </span>
                              ) : (
                                <span className="inline-flex items-center px-2.5 py-1 rounded-full text-[10px] font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/25">
                                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mr-1.5 shrink-0" />
                                  MONITORING
                                </span>
                              )}
                            </td>

                            {/* Playbook / Operator Action */}
                            <td className="py-3.5 px-4 text-right whitespace-nowrap">
                              {sentinelMode === "autonomous" ? (
                                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/25">
                                  <ShieldCheck className="w-3.5 h-3.5" />
                                  <span>Auto-Mitigated</span>
                                </span>
                              ) : alert.supervised_approved ? (
                                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/25">
                                  <Check className="w-3 h-3" />
                                  <span>{alert.status || "Operator Approved"}</span>
                                </span>
                              ) : (
                                <div className="inline-flex items-center gap-1.5 justify-end">
                                  <button
                                    onClick={() => handleOperatorAction(alertId, "approve_tarpit")}
                                    className="px-2 py-1 rounded-lg text-[10px] font-medium bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/30 transition-all cursor-pointer active:scale-95"
                                    title="Approve automated tarpit latency injection"
                                  >
                                    Approve Tarpit
                                  </button>
                                  <button
                                    onClick={() => handleOperatorAction(alertId, "isolate_vector")}
                                    className="px-2 py-1 rounded-lg text-[10px] font-medium bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30 transition-all cursor-pointer active:scale-95"
                                    title="Quarantine and isolate attack vector"
                                  >
                                    Isolate
                                  </button>
                                  <button
                                    onClick={() => handleOperatorAction(alertId, "release_ip")}
                                    className="px-2 py-1 rounded-lg text-[10px] font-medium bg-slate-800 hover:bg-slate-700 text-neutral-400 hover:text-white border border-slate-700 transition-all cursor-pointer active:scale-95"
                                    title="Clear penalty and release IP"
                                  >
                                    Release
                                  </button>
                                </div>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      {/* Dynamic Translucent Bottom Dockbar */}
      <nav
        aria-label="Main Navigation Dock"
        className={`fixed bottom-6 left-1/2 -translate-x-1/2 z-50 backdrop-blur-md rounded-full border shadow-2xl px-4 py-2 flex items-center gap-1.5 sm:gap-2 transition-all duration-300 ${
          isLight
            ? "bg-white/85 border-slate-300/80 shadow-slate-300/60"
            : "bg-slate-900/70 border-slate-700/50 shadow-black/80"
        }`}
      >
        <button
          onClick={() => setActiveTab("deploy")}
          className={`px-3.5 sm:px-4 py-2 text-xs font-medium rounded-full transition-all duration-200 flex items-center gap-2 cursor-pointer ${
            activeTab === "deploy"
              ? isLight
                ? "bg-amber-500/15 text-amber-800 border border-amber-500/35 font-semibold shadow-xs"
                : "bg-slate-800/90 text-white shadow-md border border-white/15"
              : isLight
              ? "text-slate-600 hover:text-slate-900 hover:bg-slate-100/70"
              : "text-neutral-400 hover:text-white hover:bg-white/5"
          }`}
        >
          <Zap className={`w-3.5 h-3.5 ${isLight ? "text-amber-600" : "text-cyan-400"}`} />
          <span>Mesh Deployment</span>
        </button>

        <button
          onClick={() => setActiveTab("topology")}
          className={`px-3.5 sm:px-4 py-2 text-xs font-medium rounded-full transition-all duration-200 flex items-center gap-2 cursor-pointer ${
            activeTab === "topology"
              ? isLight
                ? "bg-amber-500/15 text-amber-800 border border-amber-500/35 font-semibold shadow-xs"
                : "bg-slate-800/90 text-white shadow-md border border-white/15"
              : isLight
              ? "text-slate-600 hover:text-slate-900 hover:bg-slate-100/70"
              : "text-neutral-400 hover:text-white hover:bg-white/5"
          }`}
        >
          <Radar className={`w-3.5 h-3.5 ${isLight ? "text-amber-600" : "text-cyan-400"}`} />
          <span>Ghost Topology</span>
        </button>

        <button
          onClick={() => setActiveTab("soc")}
          className={`px-3.5 sm:px-4 py-2 text-xs font-medium rounded-full transition-all duration-200 flex items-center gap-2 cursor-pointer ${
            activeTab === "soc"
              ? isLight
                ? "bg-amber-500/15 text-amber-800 border border-amber-500/35 font-semibold shadow-xs"
                : "bg-slate-800/90 text-white shadow-md border border-white/15"
              : isLight
              ? "text-slate-600 hover:text-slate-900 hover:bg-slate-100/70"
              : "text-neutral-400 hover:text-white hover:bg-white/5"
          }`}
        >
          <Activity className="w-3.5 h-3.5 text-rose-500" />
          <span>Threat Feed</span>
          {alerts.length > 0 && (
            <span className="ml-0.5 px-1.5 py-0.5 rounded-full text-[10px] font-mono bg-rose-500/20 text-rose-600 dark:text-rose-300 border border-rose-500/30">
              {alerts.length}
            </span>
          )}
        </button>

        <div className={`h-4 w-px mx-0.5 ${isLight ? "bg-slate-300" : "bg-slate-700"}`} />

        <button
          onClick={() => setIsAIAgentOpen((prev) => !prev)}
          className={`px-3.5 sm:px-4 py-2 text-xs font-medium rounded-full transition-all duration-200 flex items-center gap-2 cursor-pointer ${
            isAIAgentOpen
              ? isLight
                ? "bg-amber-500/20 text-amber-800 border border-amber-500/40 font-semibold shadow-xs"
                : "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold shadow-md"
              : isLight
              ? "text-slate-600 hover:text-slate-900 hover:bg-slate-100/70"
              : "text-neutral-400 hover:text-white hover:bg-white/5"
          }`}
          title="Toggle Spectre AI (Ctrl+K)"
        >
          <Bot className={`w-3.5 h-3.5 ${isAIAgentOpen ? "text-cyan-400 animate-pulse" : isLight ? "text-amber-600" : "text-cyan-400"}`} />
          <span>Spectre AI</span>
        </button>
      </nav>

      {/* Sleek Minimalist Bottom-Right Status Floater */}
      <div
        className={`fixed bottom-6 right-6 z-50 flex items-center gap-2 px-3.5 py-2 rounded-full backdrop-blur-md border shadow-2xl transition-all duration-200 text-xs font-mono select-none ${
          isLight
            ? "bg-white/85 border-slate-300/80 text-slate-800 shadow-slate-300/60"
            : "bg-slate-900/80 border-slate-700/60 text-slate-200 shadow-black/70"
        }`}
      >
        <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse shrink-0" />
        <span className="font-semibold tracking-tight font-sans">Mesh Active</span>
      </div>

      {/* Autonomous In-Website Spectre AI Drawer */}
      <SpectreAIAgent
        isOpen={isAIAgentOpen}
        onClose={() => setIsAIAgentOpen(false)}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        sentinelMode={sentinelMode}
        setSentinelMode={setSentinelMode}
        sentinelStatus={sentinelStatus}
        setSentinelStatus={setSentinelStatus}
        alerts={alerts}
        decoys={decoys}
        targetPath={targetPath}
        setTargetPath={setTargetPath}
        executeMeshDeployment={executeMeshDeployment}
        handleSimulateThreatVector={handleSimulateThreatVector}
        handleOperatorAction={handleOperatorAction}
        appendLog={appendLog}
        appendAgentThought={appendAgentThought}
        handleManualRefresh={handleManualRefresh}
        isLight={isLight}
        deceptionRatio={deceptionRatio}
        dwellMultiplier={dwellMultiplier}
      />
    </div>
  );
}
