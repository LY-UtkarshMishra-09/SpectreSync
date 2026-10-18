/**
 * Types and interfaces for SpectreSync Active Defense Agent.
 */
export type ThreatEventType = "CANARY_EXPOSED" | "PORT_SCAN_DETECTED" | "BRUTE_FORCE_BURST" | "CREDENTIAL_STUFFING" | "DIRECTORY_ENUMERATION" | "SQLI_PROBE" | "UNAUTHORIZED_ADMIN_ACCESS";
export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type ActionType = "UPDATE_TARPIT_RULES" | "GENERATE_DECOY_CONFIG" | "QUARANTINE_ASSET" | "BLOCK_SUBNET" | "LOCKDOWN_CORE_ROUTE" | "ROTATE_CREDENTIALS" | "REVOKE_TOKEN";
export type ApprovalStatus = "PENDING" | "APPROVED" | "REJECTED" | "AUTO_EXECUTED";
export interface ThreatEvent {
    id: string;
    type: ThreatEventType;
    timestamp: string;
    sourceIp: string;
    targetAsset: string;
    severity: RiskLevel;
    userAgent?: string;
    metadata?: Record<string, unknown>;
}
export interface ProposedAction {
    id: string;
    type: ActionType;
    title: string;
    targetResource: string;
    parameters: Record<string, unknown>;
    riskLevel: RiskLevel;
    justification: string;
    threatEventId: string;
    createdAt: string;
}
export interface ApprovalRequest {
    id: string;
    action: ProposedAction;
    status: ApprovalStatus;
    threatEvent: ThreatEvent;
    createdAt: string;
    decidedAt?: string;
    decidedBy?: string;
    rejectionReason?: string;
    executionResult?: ToolExecutionResult;
}
export interface ToolExecutionResult {
    success: boolean;
    actionId: string;
    actionType: ActionType;
    targetFile: string;
    timestamp: string;
    message: string;
    diffSummary?: string;
    details?: Record<string, unknown>;
    error?: string;
}
export interface TarpitRuleEntry {
    ip: string;
    delayMs: number;
    addedAt: string;
    lastTriggeredAt: string;
    hitsCount: number;
    status: "ACTIVE" | "EXPIRED";
}
export interface DecoyRouteManifest {
    route: string;
    handlerPath: string;
    category: string;
    createdAt: string;
    lastAccessed?: string;
    syntheticPayloadType: string;
}
export interface QuarantineEntry {
    assetId: string;
    quarantinedAt: string;
    reason: string;
    originalRoute?: string;
    redirectionTarget?: string;
    status: "ISOLATED" | "RELEASED";
}
export interface FirewallRuleEntry {
    cidr: string;
    action: "DROP" | "REJECT" | "TARPIT";
    justification: string;
    addedAt: string;
    approvedBy: string;
}
export interface AgentConfig {
    workspaceRoot: string;
    configDir: string;
    decoyRoutesDir: string;
    mode: "autonomous" | "supervised";
    maxAutoTarpitDelayMs: number;
    enableFilePersistence: boolean;
}
