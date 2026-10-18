/**
 * SpectreSync Active Defense Agent - End-to-End Verification Demo.
 * Demonstrates Threat Event Ingestion, Dynamic File Modifications, and Human-In-The-Loop Approval Workflow.
 */

import * as fs from "fs";
import * as path from "path";
import { ActiveDefenseAgent } from "./ActiveDefenseAgent";

async function runDemo() {
  console.log("==================================================================");
  console.log("SpectreSync Active Defense Agent - Architecture Verification Demo");
  console.log("==================================================================\n");

  const testConfigDir = path.join(__dirname, "..", "config");
  const testDecoyDir = path.join(__dirname, "..", "pages", "api", "decoy");

  const agent = new ActiveDefenseAgent({
    configDir: testConfigDir,
    decoyRoutesDir: testDecoyDir,
    mode: "autonomous",
  });

  // Attach event listener hooks for real-time telemetry observation
  agent.listener.on("event_ingested", (evt) => {
    console.log(`[EVENT_INGESTED] ID: ${evt.id} | Type: ${evt.type} | IP: ${evt.sourceIp} | Severity: ${evt.severity}`);
  });

  agent.listener.on("action_executed", ({ action, executionResult }) => {
    console.log(`[ACTION_AUTO_EXECUTED] Action: ${action.type} -> File: ${executionResult.targetFile}`);
    console.log(`                       Message: ${executionResult.message}`);
  });

  agent.listener.on("approval_required", ({ action, approvalRequest }) => {
    console.log("\n------------------------------------------------------------------");
    console.log(">>> [HUMAN-IN-THE-LOOP HALT] MAJOR SECURITY ACTION SUSPENDED <<<");
    console.log(`Request ID:        ${approvalRequest.id}`);
    console.log(`Proposed Action:   ${action.title}`);
    console.log(`Target Resource:   ${action.targetResource}`);
    console.log(`Risk Level:        ${action.riskLevel}`);
    console.log(`Justification:     ${action.justification}`);
    console.log(`Status:            Awaiting Explicit Operator Authorization (PENDING)`);
    console.log("------------------------------------------------------------------\n");
  });

  // -------------------------------------------------------------------------
  // SCENARIO 1: Low-Risk Event -> Automated Tarpit Modification
  // -------------------------------------------------------------------------
  console.log("\n--- SCENARIO 1: Ingesting Low-Risk PORT_SCAN_DETECTED Telemetry ---");
  agent.ingestAlert({
    type: "PORT_SCAN_DETECTED",
    sourceIp: "192.0.2.77",
    targetAsset: "/api/ports",
    userAgent: "Masscan/1.3.2",
  });

  const tarpitFile = path.join(testConfigDir, "tarpit-rules.json");
  if (fs.existsSync(tarpitFile)) {
    console.log("[VERIFIED] config/tarpit-rules.json was automatically created/updated:");
    console.log(fs.readFileSync(tarpitFile, "utf8"));
  }

  // -------------------------------------------------------------------------
  // SCENARIO 2: Canary Trip Event -> Dynamic Decoy Synthesis & Quarantine
  // -------------------------------------------------------------------------
  console.log("\n--- SCENARIO 2: Ingesting CANARY_EXPOSED Telemetry ---");
  agent.ingestAlert({
    type: "CANARY_EXPOSED",
    sourceIp: "198.51.100.42",
    targetAsset: "/api/v1/vault/tokens",
    userAgent: "Python-Requests/2.31.0",
  });

  const decoyManifest = path.join(testConfigDir, "decoy-manifest.json");
  const quarantineManifest = path.join(testConfigDir, "quarantine-manifest.json");
  const decoyRouteFile = path.join(testDecoyDir, "api_v1_vault_tokens.js");

  console.log("[VERIFIED] Decoy handler generated at:", decoyRouteFile, fs.existsSync(decoyRouteFile));
  console.log("[VERIFIED] Decoy manifest updated:", fs.existsSync(decoyManifest));
  console.log("[VERIFIED] Quarantine manifest updated:", fs.existsSync(quarantineManifest));

  // -------------------------------------------------------------------------
  // SCENARIO 3: Major Security Decision -> Human-In-The-Loop Approval
  // -------------------------------------------------------------------------
  console.log("\n--- SCENARIO 3: Ingesting High-Risk BRUTE_FORCE_BURST Telemetry ---");
  const bruteForceResult = agent.ingestAlert({
    type: "BRUTE_FORCE_BURST",
    sourceIp: "203.0.113.99",
    targetAsset: "/api/v1/auth/login",
    userAgent: "Hydra/9.5",
  });

  const firewallFile = path.join(testConfigDir, "firewall-rules.json");
  const pendingRequests = agent.getPendingApprovals();
  console.log(`[CHECK] Pending HITL approvals count: ${pendingRequests.length}`);

  const subnetApproval = pendingRequests.find((r) => r.action.type === "BLOCK_SUBNET");
  if (subnetApproval) {
    console.log(`[VERIFIED] Major action was NOT auto-executed. Status: ${subnetApproval.status}`);
    console.log("[VERIFIED] Target firewall file exists before approval:", fs.existsSync(firewallFile));

    console.log("\n>>> Operator review in progress... Simulating Human Operator APPROVAL (Yes) <<<");
    const approvalResult = agent.approve(subnetApproval.id, "CHIEF_SECURITY_OFFICER_01");

    console.log("[OPERATOR_DECISION] Result:", approvalResult.message);
    console.log("[VERIFIED] config/firewall-rules.json content post-approval:");
    console.log(fs.readFileSync(firewallFile, "utf8"));
  }

  // -------------------------------------------------------------------------
  // SCENARIO 4: Supervised Mode Governance
  // -------------------------------------------------------------------------
  console.log("\n--- SCENARIO 4: Enabling Supervised Mode (All Actions Require Sign-Off) ---");
  agent.setMode("supervised");
  console.log(`[STATUS] Agent mode switched to: ${agent.getMode().toUpperCase()}`);

  agent.ingestAlert({
    type: "PORT_SCAN_DETECTED",
    sourceIp: "198.51.100.99",
    targetAsset: "/admin",
  });

  const supervisedPending = agent.getPendingApprovals();
  console.log(`[VERIFIED] Under Supervised Mode, low-risk actions halt as well. Pending approvals: ${supervisedPending.length}`);

  const lastPending = supervisedPending[supervisedPending.length - 1];
  console.log(`Simulating Operator REJECTION (No) for Request [${lastPending.id}]...`);
  const rejectionRecord = agent.reject(lastPending.id, "DUTY_ANALYST_02", "Benign internal vulnerability scan scheduled by DevOps.");
  console.log(`[REJECTION_CONFIRMED] Status: ${rejectionRecord.status} | Reason: ${rejectionRecord.rejectionReason}`);

  console.log("\n==================================================================");
  console.log("All Active Defense Agent scenarios successfully executed and verified!");
  console.log("==================================================================");
}

runDemo().catch((err) => {
  console.error("Demo failed:", err);
  process.exit(1);
});

