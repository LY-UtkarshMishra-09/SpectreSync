/**
 * Active Defense Agent: Autonomous Core Orchestrator.
 * Connects AttackEventListener, PolicyEngine, and ToolExecutionLayer.
 */

import { AgentConfig, ThreatEvent, ThreatEventType, ApprovalRequest, ToolExecutionResult } from "./types";
import { ToolExecutionLayer } from "./ToolExecutionLayer";
import { PolicyEngine } from "./PolicyEngine";
import { AttackEventListener } from "./AttackEventListener";

export class ActiveDefenseAgent {
  public tools: ToolExecutionLayer;
  public policy: PolicyEngine;
  public listener: AttackEventListener;

  constructor(config: Partial<AgentConfig> = {}) {
    this.tools = new ToolExecutionLayer(config);
    this.policy = new PolicyEngine(this.tools, config.mode || "autonomous");
    this.listener = new AttackEventListener(this.policy);
  }

  /**
   * Ingest structured threat alert telemetry.
   */
  public ingestAlert(event: Partial<ThreatEvent> & { type: ThreatEventType; sourceIp: string }) {
    return this.listener.ingest(event);
  }

  /**
   * Human-In-The-Loop Approval: approve a pending high-privilege action.
   */
  public approve(requestId: string, operatorId = "SOC_OPERATOR"): ToolExecutionResult {
    return this.policy.approve(requestId, operatorId);
  }

  /**
   * Human-In-The-Loop Approval: reject a pending high-privilege action.
   */
  public reject(requestId: string, operatorId = "SOC_OPERATOR", reason?: string): ApprovalRequest {
    return this.policy.reject(requestId, operatorId, reason);
  }

  /**
   * Retrieve list of pending Human-In-The-Loop approval requests.
   */
  public getPendingApprovals(): ApprovalRequest[] {
    return this.policy.getPendingRequests();
  }

  /**
   * Retrieve execution audit history.
   */
  public getAuditHistory(limit = 50): ApprovalRequest[] {
    return this.policy.getAuditHistory(limit);
  }

  /**
   * Retrieve recent ingested threat telemetry events.
   */
  public getRecentEvents(limit = 50): ThreatEvent[] {
    return this.listener.getEventHistory(limit);
  }

  /**
   * Retrieve live file and resource configurations (tarpit rules, decoys, quarantine manifests).
   */
  public getLiveConfigurations() {
    return this.tools.getCurrentConfigurations();
  }

  /**
   * Set agent governance mode ("autonomous" | "supervised").
   */
  public setMode(mode: "autonomous" | "supervised"): void {
    this.policy.setMode(mode);
  }

  /**
   * Get agent governance mode.
   */
  public getMode(): "autonomous" | "supervised" {
    return this.policy.getMode();
  }
}

// Default singleton instance export
export const defaultAgent = new ActiveDefenseAgent();

