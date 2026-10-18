"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import {
  Bot,
  Terminal,
  Cpu,
  CornerDownLeft,
  Trash2,
  Minimize2,
  RefreshCw,
} from "lucide-react";

export default function SpectreAIAgent({
  isOpen,
  onClose,
  activeTab,
  setActiveTab,
  sentinelMode,
  setSentinelMode,
  sentinelStatus,
  setSentinelStatus,
  alerts,
  decoys,
  targetPath,
  setTargetPath,
  executeMeshDeployment,
  handleSimulateThreatVector,
  handleOperatorAction,
  appendLog,
  appendAgentThought,
  handleManualRefresh,
  isLight,
  deceptionRatio,
  dwellMultiplier,
}) {
  const [messages, setMessages] = useState([
    {
      id: "init-1",
      sender: "agent",
      timestamp: new Date().toLocaleTimeString(),
      thought:
        "Autonomous Agent core initialized. Telemetry channels mapped to SQLite WAL engine. Ready to receive operator directives.",
      toolCall: null,
      content:
        "SpectreSync Autonomous Agent online. I can execute mesh deployments, simulate adversarial vectors, adjust tarpit throttling, isolate suspicious IPs, or switch dashboard perspectives. Type a command or ask a question.",
    },
  ]);
  const [inputVal, setInputVal] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const [showThinking, setShowThinking] = useState(true);
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, []);

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
      setTimeout(() => inputRef.current?.focus(), 150);
    }
  }, [isOpen, messages, scrollToBottom]);

  // Execute agentic command workflow
  const processCommand = async (rawInput) => {
    const text = rawInput.trim();
    if (!text || isProcessing) return;

    const userMsgId = `user-${Date.now()}`;
    const userTimestamp = new Date().toLocaleTimeString();

    // Append user input
    setMessages((prev) => [
      ...prev,
      {
        id: userMsgId,
        sender: "user",
        timestamp: userTimestamp,
        content: text,
      },
    ]);
    setInputVal("");
    setIsProcessing(true);

    if (appendLog) {
      appendLog(`AI Copilot command dispatched from [${String(activeTab).toUpperCase()}]: "${text}"`, "info");
    }

    const lower = text.toLowerCase();
    const agentMsgId = `agent-${Date.now()}`;
    const agentTimestamp = new Date().toLocaleTimeString();

    // Simulate agentic reasoning step delay for realistic copilot feel
    await new Promise((r) => setTimeout(r, 450));

    // Decision Logic & Tool Execution Engine
    let thoughtText = "";
    let toolCallData = null;
    let replyText = "";

    // 1. Mesh Deployment Commands
    if (lower.startsWith("/deploy") || lower.includes("deploy mesh") || lower.includes("deploy deception") || lower.includes("scan repo")) {
      const match = text.match(/\/deploy\s+(.+)/i) || text.match(/for\s+([^\s]+)/i);
      const chosenPath = match ? match[1].trim() : (targetPath || "./src");

      thoughtText = `Identified deployment directive. Target repository path: [${chosenPath}]. Initiating multi-layer deception synthesis pipeline.`;
      toolCallData = {
        tool: "execute_mesh_deployment",
        args: { path: chosenPath, mode: sentinelMode },
      };

      appendAgentThought(
        "AGENT_EXECUTE",
        `Autonomous agent dispatched deployment command for [${chosenPath}].`,
        "Executing synthetic trap bindings."
      );

      if (setTargetPath) setTargetPath(chosenPath);
      executeMeshDeployment(chosenPath);

      replyText = `Dispatched deception mesh deployment for target [${chosenPath}]. Synthesizing polymorphic canary endpoints and arming behavioral tarpit beacons. Active telemetry is streaming to SQLite WAL.`;
    }
    // 2. Threat Vector Simulation Commands
    else if (lower.startsWith("/simulate") || lower.includes("simulate") || lower.includes("attack") || lower.includes("adversary") || lower.includes("probe")) {
      thoughtText = "Received adversarial simulation request. Generating synthetic intrusion headers, randomized client fingerprint, and triggering multi-agent defense chain.";
      toolCallData = {
        tool: "simulate_threat_vector",
        args: { vectorType: "automated_reconnaissance", jitterMs: "500-10000" },
      };

      appendAgentThought(
        "AGENT_EXECUTE",
        "Autonomous agent triggered synthetic attack vector. Testing multi-agent response.",
        "Simulating probe."
      );

      handleSimulateThreatVector();
      replyText = "Simulated adversarial threat vector successfully. Ingested raw request stream into Triage Agent, synthesized canary honeytoken via Deception Agent, and engaged Entanglement Agent with exponential tarpit latency.";
    }
    // 3. Tab Navigation Commands
    else if (lower.startsWith("/view") || lower.startsWith("/tab") || lower.includes("topology") || lower.includes("ghost") || lower.includes("threat feed") || lower.includes("soc")) {
      let targetTab = "deploy";
      if (lower.includes("topology") || lower.includes("ghost") || lower.includes("map")) {
        targetTab = "topology";
      } else if (lower.includes("threat") || lower.includes("soc") || lower.includes("feed")) {
        targetTab = "soc";
      }

      thoughtText = `Routing user to dashboard view [${targetTab.toUpperCase()}]. Updating UI layout container.`;
      toolCallData = {
        tool: "set_active_tab",
        args: { tab: targetTab },
      };

      setActiveTab(targetTab);
      if (targetTab === "soc") {
        handleManualRefresh();
      }

      replyText = `Switched active dashboard perspective to [${targetTab.toUpperCase()}]. Real-time telemetry synchronized.`;
    }
    // 4. Defense Mode Toggles
    else if (lower.includes("supervised") || lower.includes("approval mode")) {
      thoughtText = "Evaluating governance directive: Switching agent sentinel posture to Supervised Mode.";
      toolCallData = {
        tool: "set_defense_mode",
        args: { mode: "supervised" },
      };

      setSentinelMode("supervised");
      setSentinelStatus("Awaiting Operator Approval");
      appendAgentThought(
        "GOVERNANCE_UPDATE",
        "Agent mode set to Supervised. Deception deployment and containment playbooks require operator confirmation.",
        "Supervised lock active."
      );

      replyText = "Sentinel posture shifted to SUPERVISED MODE. Autonomous auto-mitigation paused; all future containment actions and deployment proposals will require operator sign-off.";
    } else if (lower.includes("autonomous") || lower.includes("auto mode")) {
      thoughtText = "Evaluating governance directive: Engaging Autonomous Sentinel Mode.";
      toolCallData = {
        tool: "set_defense_mode",
        args: { mode: "autonomous" },
      };

      setSentinelMode("autonomous");
      setSentinelStatus("Autonomous Defense Active");
      appendAgentThought(
        "GOVERNANCE_UPDATE",
        "Agent mode set to Autonomous. Deception deployment and behavioral tarpitting active without human bottleneck.",
        "Autonomous perimeter online."
      );

      replyText = "Sentinel posture shifted to AUTONOMOUS MODE. Multi-agent defense loop is actively detecting, tarpitting, and neutralizing adversarial probes without requiring operator intervention.";
    }
    // 5. Isolate or Tarpit Specific Attackers
    else if (lower.includes("isolate") || lower.includes("quarantine")) {
      const match = text.match(/(?:ip\s+)?((?:\d{1,3}\.){3}\d{1,3})/);
      const targetIp = match ? match[1] : (alerts[0]?.source_ip || alerts[0]?.ip || "198.51.100.44");
      const targetAlert = alerts.find((a) => (a.source_ip || a.ip) === targetIp) || alerts[0];
      const alertId = targetAlert?.id || targetAlert?.trap_id || "trap_01";

      thoughtText = `Isolating attack vector originating from IP [${targetIp}]. Severing decoy route bindings.`;
      toolCallData = {
        tool: "quarantine_vector",
        args: { ip: targetIp, alertId },
      };

      handleOperatorAction(alertId, "isolate_vector");
      replyText = `Quarantine protocol executed for IP [${targetIp}]. Decoy routing severed, threat vector isolated from core infrastructure.`;
    } else if (lower.includes("tarpit") || lower.includes("delay") || lower.includes("stall")) {
      const match = text.match(/(?:ip\s+)?((?:\d{1,3}\.){3}\d{1,3})/);
      const targetIp = match ? match[1] : (alerts[0]?.source_ip || alerts[0]?.ip || "198.51.100.44");
      const targetAlert = alerts.find((a) => (a.source_ip || a.ip) === targetIp) || alerts[0];
      const alertId = targetAlert?.id || targetAlert?.trap_id || "trap_01";

      thoughtText = `Injecting exponential latency penalty on adversarial socket for IP [${targetIp}].`;
      toolCallData = {
        tool: "approve_tarpit_matrix",
        args: { ip: targetIp, alertId, delayMs: 6400 },
      };

      handleOperatorAction(alertId, "approve_tarpit");
      replyText = `Behavioral tarpit enforced for IP [${targetIp}]. Attacker TCP connection suspended in recursive deceptive telemetry loop (6.4s injected delay).`;
    }
    // 6. Posture / Status Query
    else if (lower.includes("status") || lower.includes("posture") || lower.includes("health") || lower.includes("metrics") || lower.startsWith("/status")) {
      thoughtText = "Gathering holistic security posture telemetry from active SQLite database and memory caches.";
      toolCallData = {
        tool: "query_security_posture",
        args: { queryScope: "system_wide" },
      };

      replyText = `SPECTRESYNC SECURITY POSTURE REPORT:
- Defense Perimeter: ${sentinelStatus.toUpperCase()}
- Governance Mode: ${sentinelMode.toUpperCase()}
- Deception Constellation: ${decoys.length > 0 ? decoys.length : 190} Decoys Active (Deception Ratio: ${deceptionRatio}%)
- Adversarial Entrapment: ${alerts.length} Threats Logged
- Dwell Time Multiplier: ${dwellMultiplier}
- Multi-Agent Pipeline: 3 Active Agents (Triage, Deception, Entanglement) Online (0ms sync lag)`;
    }
    // 7. Clear History
    else if (lower === "/clear" || lower.includes("clear session") || lower.includes("clear chat")) {
      setMessages([
        {
          id: `init-${Date.now()}`,
          sender: "agent",
          timestamp: new Date().toLocaleTimeString(),
          thought: "Session memory cleared on operator request.",
          toolCall: null,
          content: "Session history cleared. Autonomous Agent ready for new directives.",
        },
      ]);
      setIsProcessing(false);
      return;
    }
    // 8. Help Menu
    else if (lower.startsWith("/help") || lower === "help" || lower === "commands") {
      thoughtText = "Compiling available command catalog and capabilities.";
      toolCallData = {
        tool: "show_command_reference",
        args: {},
      };

      replyText = `SUPPORTED COMMANDS & DIRECTIVES:
- /deploy [path] : Deploy deception mesh for repository (e.g. /deploy ./src)
- /simulate [target] : Simulate adversarial honeytoken attack
- /view [deploy|topology|soc] : Switch active dashboard view
- /mode [autonomous|supervised] : Toggle AI defense governance mode
- /isolate [ip] : Quarantine and sever routes for an adversarial IP
- /tarpit [ip] : Inject exponential response delay into attacker socket
- /status : Display full security telemetry and deception ratio briefing
- /clear : Reset copilot session history

You can also speak naturally (e.g., "scan my backend", "switch to topology", "isolate the threat").`;
    }
    // 9. Natural Language Cyber Reasoning Fallback
    else {
      thoughtText = `Analyzing natural language inquiry: "${text}". Synthesizing response grounded in active defense architecture.`;

      replyText = `Acknowledged directive. As the SpectreSync Autonomous Agent, I continuously monitor telemetry, generate high-fidelity decoys, and trap malicious scanners. 

To execute an action, try:
- "Deploy mesh for ./src"
- "Simulate threat on /api/v1/vault"
- "Show ghost topology"
- "Switch to supervised mode"
- "What is our current posture?"`;
    }

    setMessages((prev) => [
      ...prev,
      {
        id: agentMsgId,
        sender: "agent",
        timestamp: agentTimestamp,
        thought: thoughtText,
        toolCall: toolCallData,
        content: replyText,
      },
    ]);

    setIsProcessing(false);
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      processCommand(inputVal);
    }
  };

  const handlePromptChipClick = (prompt) => {
    processCommand(prompt);
  };

  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-label="SpectreSync AI Copilot"
      className="fixed inset-y-0 right-0 z-50 w-full sm:w-[480px] lg:w-[520px] shadow-2xl flex flex-col border-l backdrop-blur-2xl transition-all duration-300 animate-in slide-in-from-right duration-300"
      style={{
        backgroundColor: isLight ? "rgba(255, 255, 255, 0.96)" : "rgba(9, 13, 22, 0.96)",
        borderColor: isLight ? "rgba(226, 232, 240, 0.9)" : "rgba(30, 41, 59, 0.9)",
      }}
    >
      {/* Copilot Header */}
      <div
        className={`px-5 py-4 border-b flex items-center justify-between ${
          isLight ? "border-slate-200 bg-slate-50/80" : "border-slate-800/80 bg-black/40"
        }`}
      >
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2
                className={`text-xs font-bold uppercase font-mono tracking-wider ${
                  isLight ? "text-slate-900" : "text-white"
                }`}
              >
                Spectre AI Copilot
              </h2>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/25">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                ONLINE
              </span>
            </div>
            <p className="text-[11px] font-mono text-neutral-400">
              Autonomous Codebase & Defense Sentinel
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1">
          <button
            onClick={() => setShowThinking((v) => !v)}
            className={`p-1.5 rounded-lg border text-xs transition-colors cursor-pointer ${
              showThinking
                ? isLight
                  ? "bg-slate-200 text-slate-800 border-slate-300"
                  : "bg-slate-800 text-cyan-300 border-slate-700"
                : isLight
                ? "text-slate-500 border-transparent hover:bg-slate-100"
                : "text-neutral-400 border-transparent hover:bg-white/5"
            }`}
            title="Toggle Agent Monologue & Tool Call Display"
          >
            <Cpu className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() =>
              setMessages([
                {
                  id: `init-${Date.now()}`,
                  sender: "agent",
                  timestamp: new Date().toLocaleTimeString(),
                  thought: "Session memory reset.",
                  toolCall: null,
                  content: "Copilot session reset. Ready for directives.",
                },
              ])
            }
            className={`p-1.5 rounded-lg border border-transparent transition-colors cursor-pointer ${
              isLight
                ? "text-slate-500 hover:text-rose-600 hover:bg-rose-50"
                : "text-neutral-400 hover:text-rose-400 hover:bg-rose-500/10"
            }`}
            title="Clear Chat History"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={onClose}
            className={`p-1.5 rounded-lg border border-transparent transition-colors cursor-pointer ${
              isLight
                ? "text-slate-500 hover:text-slate-900 hover:bg-slate-100"
                : "text-neutral-400 hover:text-white hover:bg-white/5"
            }`}
            title="Close Copilot Panel"
            aria-label="Close Copilot"
          >
            <Minimize2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Quick Action Suggestion Chips */}
      <div
        className={`px-4 py-2 border-b flex items-center gap-1.5 overflow-x-auto text-[11px] font-mono no-scrollbar ${
          isLight ? "border-slate-200 bg-white" : "border-slate-800/80 bg-black/20"
        }`}
      >
        <button
          onClick={() => handlePromptChipClick("Deploy deception mesh for ./src")}
          className={`shrink-0 px-2.5 py-1 rounded-lg border transition-all cursor-pointer ${
            isLight
              ? "bg-slate-100 hover:bg-slate-200 border-slate-300 text-slate-700"
              : "bg-slate-900/80 hover:bg-slate-800 border-slate-700/80 text-cyan-300"
          }`}
        >
          Deploy Mesh
        </button>
        <button
          onClick={() => handlePromptChipClick("Simulate adversarial probe on /api/v1/vault")}
          className={`shrink-0 px-2.5 py-1 rounded-lg border transition-all cursor-pointer ${
            isLight
              ? "bg-slate-100 hover:bg-slate-200 border-slate-300 text-slate-700"
              : "bg-slate-900/80 hover:bg-slate-800 border-slate-700/80 text-cyan-300"
          }`}
        >
          Simulate Attack
        </button>
        <button
          onClick={() => handlePromptChipClick("Show security posture report")}
          className={`shrink-0 px-2.5 py-1 rounded-lg border transition-all cursor-pointer ${
            isLight
              ? "bg-slate-100 hover:bg-slate-200 border-slate-300 text-slate-700"
              : "bg-slate-900/80 hover:bg-slate-800 border-slate-700/80 text-cyan-300"
          }`}
        >
          Posture Report
        </button>
        <button
          onClick={() => handlePromptChipClick("Switch to Ghost Topology")}
          className={`shrink-0 px-2.5 py-1 rounded-lg border transition-all cursor-pointer ${
            isLight
              ? "bg-slate-100 hover:bg-slate-200 border-slate-300 text-slate-700"
              : "bg-slate-900/80 hover:bg-slate-800 border-slate-700/80 text-cyan-300"
          }`}
        >
          View Topology
        </button>
        <button
          onClick={() => handlePromptChipClick("/help")}
          className={`shrink-0 px-2.5 py-1 rounded-lg border transition-all cursor-pointer ${
            isLight
              ? "bg-slate-100 hover:bg-slate-200 border-slate-300 text-slate-700"
              : "bg-slate-900/80 hover:bg-slate-800 border-slate-700/80 text-cyan-300"
          }`}
        >
          Help Menu
        </button>
      </div>

      {/* Messages Stream */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 font-mono text-xs">
        {messages.map((msg) => (
          <div key={msg.id} className="space-y-1.5">
            {msg.sender === "user" ? (
              <div className="flex justify-end">
                <div
                  className={`max-w-[85%] rounded-2xl px-4 py-2.5 border shadow-sm ${
                    isLight
                      ? "bg-slate-100 border-slate-300 text-slate-900"
                      : "bg-slate-800/90 border-slate-700 text-white"
                  }`}
                >
                  <div className="text-[10px] text-neutral-400 mb-0.5 flex items-center justify-end gap-1.5">
                    <span>You</span>
                    <span>·</span>
                    <span>{msg.timestamp}</span>
                  </div>
                  <p className="whitespace-pre-wrap leading-relaxed">{msg.content}</p>
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <div className="w-5 h-5 rounded-md bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center shrink-0">
                    <Bot className="w-3 h-3" />
                  </div>
                  <span className="text-[11px] font-bold text-cyan-400">
                    SPECTRESYNC SENTINEL
                  </span>
                  <span className="text-[10px] text-neutral-500">{msg.timestamp}</span>
                </div>

                {/* Agent Thought / Monologue Disclosure */}
                {showThinking && msg.thought && (
                  <div
                    className={`rounded-xl border p-2.5 text-[11px] leading-relaxed transition-all ${
                      isLight
                        ? "bg-slate-50 border-slate-200 text-slate-600"
                        : "bg-black/50 border-slate-800 text-neutral-400"
                    }`}
                  >
                    <div className="flex items-center gap-1.5 text-cyan-400 font-semibold mb-1 text-[10px] uppercase tracking-wide">
                      <Cpu className="w-3 h-3" />
                      <span>Internal Reasoning</span>
                    </div>
                    <p className="italic">{msg.thought}</p>
                  </div>
                )}

                {/* Tool Call Artifact Card */}
                {showThinking && msg.toolCall && (
                  <div
                    className={`rounded-xl border p-2.5 text-[11px] ${
                      isLight
                        ? "bg-amber-500/5 border-amber-500/20 text-amber-900"
                        : "bg-cyan-950/20 border-cyan-500/30 text-cyan-300"
                    }`}
                  >
                    <div className="flex items-center justify-between font-semibold text-[10px] uppercase tracking-wider mb-1">
                      <span className="flex items-center gap-1.5">
                        <Terminal className="w-3 h-3" />
                        <span>Action Dispatched: {msg.toolCall.tool}</span>
                      </span>
                      <span className="text-[10px] text-emerald-400">SUCCESS</span>
                    </div>
                    <pre className="text-[10px] overflow-x-auto p-1.5 rounded-lg bg-black/40 text-neutral-300">
                      {JSON.stringify(msg.toolCall.args, null, 2)}
                    </pre>
                  </div>
                )}

                {/* Final Agent Response Content */}
                <div
                  className={`rounded-2xl p-3.5 border shadow-sm leading-relaxed ${
                    isLight
                      ? "bg-white border-slate-200 text-slate-800"
                      : "bg-slate-900/60 border-slate-800 text-neutral-200"
                  }`}
                >
                  <p className="whitespace-pre-wrap">{msg.content}</p>
                </div>
              </div>
            )}
          </div>
        ))}

        {isProcessing && (
          <div className="flex items-center gap-2 p-3 rounded-xl border border-cyan-500/20 bg-cyan-500/5 text-cyan-400 text-xs font-mono">
            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            <span>Agent synthesizing response and evaluating tool dispatch...</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Command Prompt Input Bar */}
      <div
        className={`p-4 border-t ${
          isLight ? "border-slate-200 bg-slate-50/90" : "border-slate-800/80 bg-black/60"
        }`}
      >
        <div
          className={`flex items-center gap-2 px-3 py-2 rounded-xl border transition-all ${
            isLight
              ? "bg-white border-slate-300 focus-within:border-cyan-500"
              : "bg-slate-950 border-slate-800 focus-within:border-cyan-500"
          }`}
        >
          <Terminal className="w-4 h-4 text-cyan-400 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={inputVal}
            onChange={(e) => setInputVal(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={isProcessing}
            placeholder="Type a command or natural language instruction..."
            className={`w-full bg-transparent text-xs font-mono outline-hidden ${
              isLight ? "text-slate-900 placeholder:text-slate-400" : "text-white placeholder:text-neutral-500"
            }`}
          />
          <button
            onClick={() => processCommand(inputVal)}
            disabled={!inputVal.trim() || isProcessing}
            className="p-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/30 transition-all disabled:opacity-40 cursor-pointer active:scale-95"
            title="Execute Command"
          >
            <CornerDownLeft className="w-3.5 h-3.5" />
          </button>
        </div>
        <div className="flex items-center justify-between text-[10px] font-mono text-neutral-500 mt-2 px-1">
          <span>Commands: /deploy, /simulate, /mode, /view, /status, /help</span>
          <span>ENTER to dispatch</span>
        </div>
      </div>
    </div>
  );
}
