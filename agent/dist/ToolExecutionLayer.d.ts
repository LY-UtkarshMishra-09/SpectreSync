/**
 * Tool Execution Layer: Dynamic File and Resource Modifier.
 * Handles automatic and approved filesystem modifications with atomic writes and audit trails.
 */
import { AgentConfig, ToolExecutionResult } from "./types";
export declare class ToolExecutionLayer {
    private config;
    constructor(config?: Partial<AgentConfig>);
    /**
     * Ensure required configuration and decoy directories exist.
     */
    private ensureDirectories;
    /**
     * Helper to write JSON files safely with pretty formatting.
     */
    private writeJsonAtomic;
    /**
     * Helper to read JSON files safely with fallback.
     */
    private readJsonSafe;
    /**
     * Low-risk action: update rate-limit/proxy config to slow down malicious requests.
     */
    updateTarpitRules(ip: string, delayMs: number): ToolExecutionResult;
    /**
     * Low-risk action: dynamically synthesize mock route handler under /pages/api/decoy/.
     */
    generateDecoyConfig(route: string, metadata?: Record<string, unknown>): ToolExecutionResult;
    /**
     * Low-risk action: quarantine compromised asset by updating environment flags or route configs.
     */
    quarantineAsset(assetId: string, reason?: string): ToolExecutionResult;
    /**
     * Major Decision Action (Requires Human Approval): Block an entire subnet in firewall rules.
     */
    blockSubnet(cidr: string, justification: string, approvedBy: string): ToolExecutionResult;
    /**
     * Major Decision Action (Requires Human Approval): Lockdown or sever access to core API route.
     */
    lockdownCoreRoute(route: string, justification: string, approvedBy: string): ToolExecutionResult;
    /**
     * Get all current configurations for telemetry and auditing.
     */
    getCurrentConfigurations(): {
        tarpitRules: {};
        decoyManifest: {};
        quarantineManifest: {};
        firewallRules: {};
        routeLockdowns: {};
    };
}
