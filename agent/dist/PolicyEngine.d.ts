/**
 * Policy Engine: Governs Major Decisions and Human-In-The-Loop (HITL) Supervised Mode.
 * Determines privilege thresholds, halts dangerous operations, and tracks operator approvals.
 */
import { ProposedAction, ThreatEvent, ApprovalRequest, ToolExecutionResult } from "./types";
import { ToolExecutionLayer } from "./ToolExecutionLayer";
export declare class PolicyEngine {
    private mode;
    private toolLayer;
    private pendingApprovals;
    private auditHistory;
    constructor(toolLayer: ToolExecutionLayer, initialMode?: "autonomous" | "supervised");
    getMode(): "autonomous" | "supervised";
    setMode(mode: "autonomous" | "supervised"): void;
    /**
     * Determine if an action constitutes a Major Decision requiring Human-In-The-Loop sign-off.
     */
    isMajorDecision(action: ProposedAction): boolean;
    /**
     * Evaluate a proposed action against active threat event and security policies.
     * If major decision or supervised mode is active, halts execution and queues an ApprovalRequest.
     */
    evaluate(action: ProposedAction, event: ThreatEvent): {
        requiresApproval: boolean;
        request?: ApprovalRequest;
        directResult?: ToolExecutionResult;
    };
    /**
     * Operator approval trigger (Yes decision).
     */
    approve(requestId: string, operatorId?: string): ToolExecutionResult;
    /**
     * Operator rejection trigger (No decision).
     */
    reject(requestId: string, operatorId?: string, reason?: string): ApprovalRequest;
    /**
     * Internal dispatcher to ToolExecutionLayer based on action type.
     */
    private executeAction;
    getPendingRequests(): ApprovalRequest[];
    getRequest(id: string): ApprovalRequest | undefined;
    getAuditHistory(limit?: number): ApprovalRequest[];
}
