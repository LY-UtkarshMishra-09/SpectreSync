"use client";

import { useState, useEffect, useCallback } from "react";
import { RefreshCw, Shield, AlertTriangle, Terminal, Key, Database, Globe } from "lucide-react";

export default function SpectreSyncDashboard() {
  const [activeTab, setActiveTab] = useState("deploy");
  const [targetPath, setTargetPath] = useState("");
  const [isDeploying, setIsDeploying] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [logs, setLogs] = useState([]);
  const [decoys, setDecoys] = useState([]);
  const [alerts, setAlerts] = useState([]);

  // Append entry with timestamp to the telemetry log
  const appendLog = useCallback((message, level = "info") => {
    const time = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, { time, message, level }]);
  }, []);

  // Fetch security alerts from Express backend
  const fetchAlerts = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const response = await fetch("http://localhost:5000/api/alerts");
      if (!response.ok) {
        throw new Error(`Server returned status ${response.status}`);
      }
      const data = await response.json();
      setAlerts(Array.isArray(data) ? data : data.alerts || []);
    } catch (err) {
      appendLog(`Failed to fetch alerts: ${err.message}`, "error");
    } finally {
      setIsRefreshing(false);
    }
  }, [appendLog]);

  // Load alerts on mount and when user switches to the SOC tab
  useEffect(() => {
    if (activeTab === "soc") {
      fetchAlerts();
    }
  }, [activeTab, fetchAlerts]);

  // Initial alert query on load
  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

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

      // Extract traps from scan result
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

  return (
    <div className="min-h-screen bg-[#0a0e17] text-[#c9d1d9] font-mono p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        
        {/* Header Bar */}
        <header className="border-b border-[#30363d] pb-4 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-[#00ffae] tracking-wider flex items-center gap-2">
              <Shield className="w-6 h-6 text-[#00ffae]" />
              SPECTRESYNC | AUTONOMOUS DECEPTION MESH
            </h1>
            <p className="text-xs text-[#8b949e] mt-1">
              Active Defense · Dynamic Trap Synthesis · Threat Entanglement
            </p>
          </div>

          {/* Navigation Tabs */}
          <div className="flex gap-2 bg-[#161b22] p-1 rounded border border-[#30363d]">
            <button
              onClick={() => setActiveTab("deploy")}
              className={`px-4 py-2 text-xs font-semibold rounded transition-colors ${
                activeTab === "deploy"
                  ? "bg-[#00ffae] text-[#0a0e17]"
                  : "text-[#8b949e] hover:text-[#c9d1d9]"
              }`}
            >
              Mesh Deployment
            </button>
            <button
              onClick={() => setActiveTab("soc")}
              className={`px-4 py-2 text-xs font-semibold rounded transition-colors ${
                activeTab === "soc"
                  ? "bg-[#00ffae] text-[#0a0e17]"
                  : "text-[#8b949e] hover:text-[#c9d1d9]"
              }`}
            >
              SOC Threat Feed
            </button>
          </div>
        </header>

        {/* TAB 1: Mesh Deployment */}
        {activeTab === "deploy" && (
          <div className="space-y-6">
            
            {/* Target Path Configuration Card */}
            <div className="bg-[#161b22] border border-[#30363d] rounded p-5 space-y-4">
              <h2 className="text-sm font-semibold text-[#00ffae]">TARGET REPOSITORY CONFIGURATION</h2>
              <div className="flex flex-col sm:flex-row gap-3">
                <input
                  type="text"
                  value={targetPath}
                  onChange={(e) => setTargetPath(e.target.value)}
                  placeholder="/absolute/path/to/target/repository"
                  className="flex-1 bg-[#0d1117] border border-[#30363d] rounded px-4 py-2 text-sm text-[#c9d1d9] focus:outline-none focus:border-[#00ffae]"
                />
                <button
                  onClick={handleDeploy}
                  disabled={isDeploying}
                  className="bg-[#00ffae] hover:bg-[#00cc8b] disabled:opacity-50 text-[#0a0e17] font-bold px-6 py-2 rounded text-sm transition-colors whitespace-nowrap cursor-pointer"
                >
                  {isDeploying ? "Deploying Mesh..." : "Deploy SpectreSync Mesh"}
                </button>
              </div>
            </div>

            {/* Agent Execution Telemetry Box */}
            <div className="bg-[#161b22] border border-[#30363d] rounded p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-[#00ffae] flex items-center gap-2">
                  <Terminal className="w-4 h-4" />
                  AGENT EXECUTION TELEMETRY
                </h2>
                <span className="text-xs text-[#8b949e]">{logs.length} events logged</span>
              </div>
              <div className="bg-[#0d1117] border border-[#30363d] rounded p-4 h-56 overflow-y-auto space-y-1 text-xs">
                {logs.length === 0 ? (
                  <div className="text-[#8b949e] italic">Telemetry logs will stream here during deployment...</div>
                ) : (
                  logs.map((log, index) => (
                    <div key={index} className="flex gap-2">
                      <span className="text-[#8b949e]">[{log.time}]</span>
                      <span
                        className={
                          log.level === "error"
                            ? "text-[#ff5555]"
                            : log.level === "success"
                            ? "text-[#00ffae]"
                            : log.level === "warn"
                            ? "text-[#f1fa8c]"
                            : "text-[#58a6ff]"
                        }
                      >
                        {log.message}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Generated Context-Aware Decoys */}
            {decoys.length > 0 && (
              <div className="bg-[#161b22] border border-[#30363d] rounded p-5 space-y-4">
                <h2 className="text-sm font-semibold text-[#00ffae] flex items-center gap-2">
                  <Key className="w-4 h-4" />
                  SYNTHESIZED CONTEXT-AWARE DECOYS ({decoys.length})
                </h2>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-[#30363d] text-[#8b949e]">
                        <th className="py-2 px-3">Trap ID</th>
                        <th className="py-2 px-3">Variable Name</th>
                        <th className="py-2 px-3">Decoy Value</th>
                        <th className="py-2 px-3">Category</th>
                        <th className="py-2 px-3">Canary Endpoint</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#30363d]/50">
                      {decoys.map((decoy, idx) => (
                        <tr key={idx} className="hover:bg-[#0d1117]/50">
                          <td className="py-2 px-3 text-[#00ffae] font-bold">{decoy.trap_id || decoy.id || `trap_${idx + 1}`}</td>
                          <td className="py-2 px-3 font-semibold">{decoy.variable_name || decoy.trap_name || decoy.name}</td>
                          <td className="py-2 px-3 text-[#8b949e] truncate max-w-xs">{decoy.decoy_value || decoy.value || "••••••••"}</td>
                          <td className="py-2 px-3">
                            <span className="px-2 py-0.5 rounded bg-[#30363d] text-[#c9d1d9] text-[10px]">
                              {decoy.category || decoy.trap_type || "secret"}
                            </span>
                          </td>
                          <td className="py-2 px-3 text-[#58a6ff]">{decoy.endpoint || decoy.endpoint_url}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: SOC Threat Feed */}
        {activeTab === "soc" && (
          <div className="space-y-6">
            
            {/* Feed Control Bar */}
            <div className="flex items-center justify-between bg-[#161b22] border border-[#30363d] rounded p-4">
              <div>
                <h2 className="text-sm font-semibold text-[#00ffae] flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-[#00ffae]" />
                  ACTIVE THREAT ALERTS
                </h2>
                <p className="text-xs text-[#8b949e] mt-0.5">Real-time telemetry from canary mesh endpoints</p>
              </div>
              <button
                onClick={fetchAlerts}
                disabled={isRefreshing}
                className="flex items-center gap-2 bg-[#0d1117] hover:bg-[#30363d] text-[#00ffae] border border-[#00ffae] px-4 py-2 rounded text-xs font-semibold transition-colors cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
                Refresh Feed
              </button>
            </div>

            {/* Security Alerts Table */}
            <div className="bg-[#161b22] border border-[#30363d] rounded p-5 overflow-x-auto">
              {alerts.length === 0 ? (
                <div className="text-center py-10 text-[#8b949e] text-xs">
                  No alerts recorded. All canary traps are silent.
                </div>
              ) : (
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-[#30363d] text-[#8b949e]">
                      <th className="py-2 px-3">ID</th>
                      <th className="py-2 px-3">Timestamp</th>
                      <th className="py-2 px-3">Source IP</th>
                      <th className="py-2 px-3">Type</th>
                      <th className="py-2 px-3">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#30363d]/50">
                    {alerts.map((alert, idx) => (
                      <tr key={idx} className="hover:bg-[#0d1117]/50">
                        <td className="py-2 px-3 text-[#00ffae] font-bold">#{alert.id}</td>
                        <td className="py-2 px-3 text-[#8b949e]">{alert.timestamp}</td>
                        <td className="py-2 px-3 font-semibold text-[#c9d1d9]">{alert.source_ip}</td>
                        <td className="py-2 px-3">
                          <span className="px-2 py-0.5 rounded bg-[#30363d] text-[#c9d1d9] text-[10px]">
                            {alert.trap_name || alert.type || "Canary Hit"}
                          </span>
                        </td>
                        <td className="py-2 px-3">
                          <span className="px-2 py-0.5 rounded bg-[#ff5555]/20 text-[#ff5555] font-bold text-[10px] border border-[#ff5555]/30">
                            {alert.status || "Triggered"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}

      </div>
    </div>
  );
}

