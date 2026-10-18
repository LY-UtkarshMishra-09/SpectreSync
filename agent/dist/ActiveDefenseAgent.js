"use strict";
/**
 * Active Defense Agent: Autonomous Core Orchestrator.
 * Connects AttackEventListener, PolicyEngine, and ToolExecutionLayer.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.defaultAgent = exports.ActiveDefenseAgent = void 0;
const ToolExecutionLayer_1 = require("./ToolExecutionLayer");
const PolicyEngine_1 = require("./PolicyEngine");
const AttackEventListener_1 = require("./AttackEventListener");
class ActiveDefenseAgent {
    tools;
    policy;
    listener;
    constructor(config = {}) {
        this.tools = new ToolExecutionLayer_1.ToolExecutionLayer(config);
        this.policy = new PolicyEngine_1.PolicyEngine(this.tools, config.mode || "autonomous");
        this.listener = new AttackEventListener_1.AttackEventListener(this.policy);
    }
    /**
     * Ingest structured threat alert telemetry.
     */
    ingestAlert(event) {
        return this.listener.ingest(event);
    }
    /**
     * Human-In-The-Loop Approval: approve a pending high-privilege action.
     */
    approve(requestId, operatorId = "SOC_OPERATOR") {
        return this.policy.approve(requestId, operatorId);
    }
    /**
     * Human-In-The-Loop Approval: reject a pending high-privilege action.
     */
    reject(requestId, operatorId = "SOC_OPERATOR", reason) {
        return this.policy.reject(requestId, operatorId, reason);
    }
    /**
     * Retrieve list of pending Human-In-The-Loop approval requests.
     */
    getPendingApprovals() {
        return this.policy.getPendingRequests();
    }
    /**
     * Retrieve execution audit history.
     */
    getAuditHistory(limit = 50) {
        return this.policy.getAuditHistory(limit);
    }
    /**
     * Retrieve recent ingested threat telemetry events.
     */
    getRecentEvents(limit = 50) {
        return this.listener.getEventHistory(limit);
    }
    /**
     * Retrieve live file and resource configurations (tarpit rules, decoys, quarantine manifests).
     */
    getLiveConfigurations() {
        return this.tools.getCurrentConfigurations();
    }
    /**
     * Set agent governance mode ("autonomous" | "supervised").
     */
    setMode(mode) {
        this.policy.setMode(mode);
    }
    /**
     * Get agent governance mode.
     */
    getMode() {
        return this.policy.getMode();
    }
}
exports.ActiveDefenseAgent = ActiveDefenseAgent;
// Default singleton instance export
exports.defaultAgent = new ActiveDefenseAgent();
