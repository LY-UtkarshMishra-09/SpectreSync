/**
 * Policy Engine: Governs Major Decisions and Human-In-The-Loop (HITL) Supervised Mode.
 * Determines privilege thresholds, halts dangerous operations, and tracks operator approvals.
 */

import {
  ActionType,
  ProposedAction,
  ThreatEvent,
  ApprovalRequest,
  RiskLevel,
  ToolExecutionResult,
} from "./types";
import { ToolExecutionLayer } from "./ToolExecutionLayer";

export class PolicyEngine {
  private mode: "autonomous" | "supervised";
  private toolLayer: ToolExecutionLayer;
  private pendingApprovals: Map<string, ApprovalRequest> = new Map();
  private auditHistory: ApprovalRequest[] = [];

  constructor(toolLayer: ToolExecutionLayer, initialMode: "autonomous" | "supervised" = "autonomous") {
    this.toolLayer = toolLayer;
    this.mode = initialMode;
  }

  public getMode(): "autonomous" | "supervised" {
    return this.mode;
  }

  public setMode(mode: "autonomous" | "supervised"): void {
    this.mode = mode;
  }

  /**
   * Determine if an action constitutes a Major Decision requiring Human-In-The-Loop sign-off.
   */
  public isMajorDecision(action: ProposedAction): boolean {
    const HIGH_PRIVILEGE_ACTIONS: ActionType[] = [
      "BLOCK_SUBNET",
      "LOCKDOWN_CORE_ROUTE",
      "ROTATE_CREDENTIALS",
      "REVOKE_TOKEN",
    ];

    if (HIGH_PRIVILEGE_ACTIONS.includes(action.type)) {
      return true;
    }

    if (action.riskLevel === "HIGH" || action.riskLevel === "CRITICAL") {
      return true;
    }

    // In Supervised Mode, all actions are subject to operator sign-off
    if (this.mode === "supervised") {
      return true;
    }

    return false;
  }

  /**
   * Evaluate a proposed action against active threat event and security policies.
   * If major decision or supervised mode is active, halts execution and queues an ApprovalRequest.
   */
  public evaluate(
    action: ProposedAction,
    event: ThreatEvent
  ): { requiresApproval: boolean; request?: ApprovalRequest; directResult?: ToolExecutionResult } {
    const requiresApproval = this.isMajorDecision(action);

    if (requiresApproval) {
      const requestId = `hitl-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
      const request: ApprovalRequest = {
        id: requestId,
        action,
        status: "PENDING",
        threatEvent: event,
        createdAt: new Date().toISOString(),
      };

      this.pendingApprovals.set(requestId, request);

      return {
        requiresApproval: true,
        request,
      };
    }

    // Low-risk action in Autonomous Mode: execute immediately
    const directResult = this.executeAction(action, "AUTONOMOUS_POLICY_ENGINE");
    const autoRecord: ApprovalRequest = {
      id: `auto-${Date.now()}`,
      action,
      status: "AUTO_EXECUTED",
      threatEvent: event,
      createdAt: new Date().toISOString(),
      decidedAt: new Date().toISOString(),
      decidedBy: "SYSTEM_AUTONOMOUS_POLICY",
      executionResult: directResult,
    };
    this.auditHistory.unshift(autoRecord);

    return {
      requiresApproval: false,
      directResult,
    };
  }

  /**
   * Operator approval trigger (Yes decision).
   */
  public approve(requestId: string, operatorId = "SOC_OPERATOR"): ToolExecutionResult {
    const request = this.pendingApprovals.get(requestId);
    if (!request) {
      throw new Error(`Approval request [${requestId}] not found or already processed.`);
    }

    const result = this.executeAction(request.action, operatorId);
    request.status = "APPROVED";
    request.decidedAt = new Date().toISOString();
    request.decidedBy = operatorId;
    request.executionResult = result;

    this.pendingApprovals.delete(requestId);
    this.auditHistory.unshift(request);

    return result;
  }

  /**
   * Operator rejection trigger (No decision).
   */
  public reject(requestId: string, operatorId = "SOC_OPERATOR", reason = "Operator rejected proposed action"): ApprovalRequest {
    const request = this.pendingApprovals.get(requestId);
    if (!request) {
      throw new Error(`Approval request [${requestId}] not found or already processed.`);
    }

    request.status = "REJECTED";
    request.decidedAt = new Date().toISOString();
    request.decidedBy = operatorId;
    request.rejectionReason = reason;

    this.pendingApprovals.delete(requestId);
    this.auditHistory.unshift(request);

    return request;
  }

  /**
   * Internal dispatcher to ToolExecutionLayer based on action type.
   */
  private executeAction(action: ProposedAction, operator: string): ToolExecutionResult {
    switch (action.type) {
      case "UPDATE_TARPIT_RULES": {
        const ip = String(action.parameters.ip || "127.0.0.1");
        const delayMs = Number(action.parameters.delayMs || 3500);
        return this.toolLayer.updateTarpitRules(ip, delayMs);
      }
      case "GENERATE_DECOY_CONFIG": {
        const route = String(action.parameters.route || "/api/v1/auth/keys");
        return this.toolLayer.generateDecoyConfig(route, action.parameters);
      }
      case "QUARANTINE_ASSET": {
        const assetId = String(action.parameters.assetId || action.targetResource);
        const reason = String(action.justification);
        return this.toolLayer.quarantineAsset(assetId, reason);
      }
      case "BLOCK_SUBNET": {
        const cidr = String(action.parameters.cidr || `${action.parameters.ip}/24`);
        return this.toolLayer.blockSubnet(cidr, action.justification, operator);
      }
      case "LOCKDOWN_CORE_ROUTE": {
        const route = String(action.parameters.route || action.targetResource);
        return this.toolLayer.lockdownCoreRoute(route, action.justification, operator);
      }
      default:
        return {
          success: false,
          actionId: action.id,
          actionType: action.type,
          targetFile: action.targetResource,
          timestamp: new Date().toISOString(),
          message: `Unknown action type [${action.type}]`,
          error: `Unsupported action type: ${action.type}`,
        };
    }
  }

  public getPendingRequests(): ApprovalRequest[] {
    return Array.from(this.pendingApprovals.values());
  }

  public getRequest(id: string): ApprovalRequest | undefined {
    return this.pendingApprovals.get(id);
  }

  public getAuditHistory(limit = 50): ApprovalRequest[] {
    return this.auditHistory.slice(0, limit);
  }
}

