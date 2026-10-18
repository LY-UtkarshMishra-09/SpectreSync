/**
 * Active Defense Agent: Autonomous Core Orchestrator.
 * Connects AttackEventListener, PolicyEngine, and ToolExecutionLayer.
 */
import { AgentConfig, ThreatEvent, ThreatEventType, ApprovalRequest, ToolExecutionResult } from "./types";
import { ToolExecutionLayer } from "./ToolExecutionLayer";
import { PolicyEngine } from "./PolicyEngine";
import { AttackEventListener } from "./AttackEventListener";
export declare class ActiveDefenseAgent {
    tools: ToolExecutionLayer;
    policy: PolicyEngine;
    listener: AttackEventListener;
    constructor(config?: Partial<AgentConfig>);
    /**
     * Ingest structured threat alert telemetry.
     */
    ingestAlert(event: Partial<ThreatEvent> & {
        type: ThreatEventType;
        sourceIp: string;
    }): {
        event: ThreatEvent;
        actions: import("./types").ProposedAction[];
        results: (ToolExecutionResult | ApprovalRequest)[];
    };
    /**
     * Human-In-The-Loop Approval: approve a pending high-privilege action.
     */
    approve(requestId: string, operatorId?: string): ToolExecutionResult;
    /**
     * Human-In-The-Loop Approval: reject a pending high-privilege action.
     */
    reject(requestId: string, operatorId?: string, reason?: string): ApprovalRequest;
    /**
     * Retrieve list of pending Human-In-The-Loop approval requests.
     */
    getPendingApprovals(): ApprovalRequest[];
    /**
     * Retrieve execution audit history.
     */
    getAuditHistory(limit?: number): ApprovalRequest[];
    /**
     * Retrieve recent ingested threat telemetry events.
     */
    getRecentEvents(limit?: number): ThreatEvent[];
    /**
     * Retrieve live file and resource configurations (tarpit rules, decoys, quarantine manifests).
     */
    getLiveConfigurations(): {
        tarpitRules: {};
        decoyManifest: {};
        quarantineManifest: {};
        firewallRules: {};
        routeLockdowns: {};
    };
    /**
     * Set agent governance mode ("autonomous" | "supervised").
     */
    setMode(mode: "autonomous" | "supervised"): void;
    /**
     * Get agent governance mode.
     */
    getMode(): "autonomous" | "supervised";
}
export declare const defaultAgent: ActiveDefenseAgent;
