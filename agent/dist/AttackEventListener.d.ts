/**
 * Threat Event Listener: Event-driven ingestion service for structured alert telemetry.
 * Ingests threat signals, detects velocity anomalies, and routes proposed actions to Policy Engine.
 */
import { EventEmitter } from "events";
import { ThreatEvent, ThreatEventType, ProposedAction, ApprovalRequest, ToolExecutionResult } from "./types";
import { PolicyEngine } from "./PolicyEngine";
export interface EventListenerOptions {
    windowSeconds?: number;
    burstThreshold?: number;
}
export declare class AttackEventListener extends EventEmitter {
    private policyEngine;
    private eventHistory;
    private ipVelocityMap;
    private windowSeconds;
    private burstThreshold;
    constructor(policyEngine: PolicyEngine, options?: EventListenerOptions);
    /**
     * Primary ingestion entrypoint for structured threat telemetry.
     */
    ingest(rawEvent: Partial<ThreatEvent> & {
        type: ThreatEventType;
        sourceIp: string;
    }): {
        event: ThreatEvent;
        actions: ProposedAction[];
        results: (ToolExecutionResult | ApprovalRequest)[];
    };
    /**
     * Infer default threat severity if not explicitly provided.
     */
    private inferSeverity;
    /**
     * Track velocity and detect bursts from identical IP addresses.
     */
    private recordEvent;
    /**
     * Synthesize defensive countermeasure actions for an ingested threat event.
     */
    private synthesizeActions;
    getEventHistory(limit?: number): ThreatEvent[];
    getIpVelocity(ip: string): number;
}
