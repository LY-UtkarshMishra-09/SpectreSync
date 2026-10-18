/**
 * Threat Event Listener: Event-driven ingestion service for structured alert telemetry.
 * Ingests threat signals, detects velocity anomalies, and routes proposed actions to Policy Engine.
 */

import { EventEmitter } from "events";
import {
  ThreatEvent,
  ThreatEventType,
  ProposedAction,
  RiskLevel,
  ActionType,
  ApprovalRequest,
  ToolExecutionResult,
} from "./types";
import { PolicyEngine } from "./PolicyEngine";

export interface EventListenerOptions {
  windowSeconds?: number;
  burstThreshold?: number;
}

export class AttackEventListener extends EventEmitter {
  private policyEngine: PolicyEngine;
  private eventHistory: ThreatEvent[] = [];
  private ipVelocityMap: Map<string, number[]> = new Map();
  private windowSeconds: number;
  private burstThreshold: number;

  constructor(policyEngine: PolicyEngine, options: EventListenerOptions = {}) {
    super();
    this.policyEngine = policyEngine;
    this.windowSeconds = options.windowSeconds || 60;
    this.burstThreshold = options.burstThreshold || 5;
  }

  /**
   * Primary ingestion entrypoint for structured threat telemetry.
   */
  public ingest(rawEvent: Partial<ThreatEvent> & { type: ThreatEventType; sourceIp: string }): {
    event: ThreatEvent;
    actions: ProposedAction[];
    results: (ToolExecutionResult | ApprovalRequest)[];
  } {
    const event: ThreatEvent = {
      id: rawEvent.id || `evt-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      type: rawEvent.type,
      timestamp: rawEvent.timestamp || new Date().toISOString(),
      sourceIp: rawEvent.sourceIp,
      targetAsset: rawEvent.targetAsset || "/unknown",
      severity: rawEvent.severity || this.inferSeverity(rawEvent.type),
      userAgent: rawEvent.userAgent || "Automated Prober",
      metadata: rawEvent.metadata || {},
    };

    // Track event history and IP velocity
    this.recordEvent(event);
    this.emit("event_ingested", event);

    // Synthesize proposed defensive action(s) based on threat classification
    const proposedActions = this.synthesizeActions(event);
    const results: (ToolExecutionResult | ApprovalRequest)[] = [];

    for (const action of proposedActions) {
      this.emit("action_proposed", { event, action });

      const evaluation = this.policyEngine.evaluate(action, event);

      if (evaluation.requiresApproval && evaluation.request) {
        results.push(evaluation.request);
        this.emit("approval_required", {
          event,
          action,
          approvalRequest: evaluation.request,
        });
      } else if (evaluation.directResult) {
        results.push(evaluation.directResult);
        this.emit("action_executed", {
          event,
          action,
          executionResult: evaluation.directResult,
        });
      }
    }

    return {
      event,
      actions: proposedActions,
      results,
    };
  }

  /**
   * Infer default threat severity if not explicitly provided.
   */
  private inferSeverity(type: ThreatEventType): RiskLevel {
    switch (type) {
      case "UNAUTHORIZED_ADMIN_ACCESS":
        return "CRITICAL";
      case "BRUTE_FORCE_BURST":
      case "CREDENTIAL_STUFFING":
        return "HIGH";
      case "DIRECTORY_ENUMERATION":
      case "SQLI_PROBE":
        return "MEDIUM";
      case "CANARY_EXPOSED":
      case "PORT_SCAN_DETECTED":
      default:
        return "LOW";
    }
  }

  /**
   * Track velocity and detect bursts from identical IP addresses.
   */
  private recordEvent(event: ThreatEvent): void {
    this.eventHistory.unshift(event);
    if (this.eventHistory.length > 500) {
      this.eventHistory.pop();
    }

    const now = Date.now();
    const timestamps = this.ipVelocityMap.get(event.sourceIp) || [];
    const windowStart = now - this.windowSeconds * 1000;
    const recent = timestamps.filter((t) => t >= windowStart);
    recent.push(now);
    this.ipVelocityMap.set(event.sourceIp, recent);
  }

  /**
   * Synthesize defensive countermeasure actions for an ingested threat event.
   */
  private synthesizeActions(event: ThreatEvent): ProposedAction[] {
    const actions: ProposedAction[] = [];
    const timestamps = this.ipVelocityMap.get(event.sourceIp) || [];
    const isBurst = timestamps.length >= this.burstThreshold;

    switch (event.type) {
      case "PORT_SCAN_DETECTED": {
        // Low-risk: inject tarpit delay to slow port enumeration
        actions.push({
          id: `act-${Date.now()}-1`,
          type: "UPDATE_TARPIT_RULES",
          title: `Apply Tarpit Rate Limit to Scanner [${event.sourceIp}]`,
          targetResource: "config/tarpit-rules.json",
          parameters: { ip: event.sourceIp, delayMs: 4500 },
          riskLevel: "LOW",
          justification: `Port scanning activity detected from IP ${event.sourceIp}. Tarpitting socket by 4.5s.`,
          threatEventId: event.id,
          createdAt: new Date().toISOString(),
        });
        break;
      }

      case "CANARY_EXPOSED": {
        // Low-risk: synthesize fresh mock decoy route around the breached asset
        actions.push({
          id: `act-${Date.now()}-1`,
          type: "GENERATE_DECOY_CONFIG",
          title: `Synthesize Dynamic Honeytoken Route for [${event.targetAsset}]`,
          targetResource: `pages/api/decoy/${event.targetAsset.replace(/^\//, "").replace(/\//g, "_")}.js`,
          parameters: {
            route: event.targetAsset,
            category: "canary_replenishment",
          },
          riskLevel: "LOW",
          justification: `Canary asset [${event.targetAsset}] hit by ${event.sourceIp}. Synthesizing replacement decoy fabric.`,
          threatEventId: event.id,
          createdAt: new Date().toISOString(),
        });

        // Also quarantine the breached canary asset
        actions.push({
          id: `act-${Date.now()}-2`,
          type: "QUARANTINE_ASSET",
          title: `Quarantine Compromised Canary Asset [${event.targetAsset}]`,
          targetResource: "config/quarantine-manifest.json",
          parameters: { assetId: event.targetAsset },
          riskLevel: "LOW",
          justification: `Asset [${event.targetAsset}] tripped. Tagging as quarantined and redirecting probe traffic.`,
          threatEventId: event.id,
          createdAt: new Date().toISOString(),
        });
        break;
      }

      case "BRUTE_FORCE_BURST":
      case "CREDENTIAL_STUFFING": {
        // Step 1: Low-risk immediate tarpit penalty
        actions.push({
          id: `act-${Date.now()}-1`,
          type: "UPDATE_TARPIT_RULES",
          title: `Inject Maximum Tarpit Delay on Attacker [${event.sourceIp}]`,
          targetResource: "config/tarpit-rules.json",
          parameters: { ip: event.sourceIp, delayMs: 8500 },
          riskLevel: "LOW",
          justification: `Brute force burst (${timestamps.length} hits/min) from IP ${event.sourceIp}.`,
          threatEventId: event.id,
          createdAt: new Date().toISOString(),
        });

        // Step 2: Major Decision (High Risk) -> Block entire subnet in firewall rules
        const subnetCidr = `${event.sourceIp.split(".").slice(0, 3).join(".")}.0/24`;
        actions.push({
          id: `act-${Date.now()}-2`,
          type: "BLOCK_SUBNET",
          title: `Block Entire Subnet [${subnetCidr}] in Firewall Rules`,
          targetResource: "config/firewall-rules.json",
          parameters: { cidr: subnetCidr, ip: event.sourceIp },
          riskLevel: "HIGH",
          justification: `Critical brute force signature from ${event.sourceIp}. Blocking /24 subnet requires Human-In-The-Loop approval to prevent collateral disruption.`,
          threatEventId: event.id,
          createdAt: new Date().toISOString(),
        });
        break;
      }

      case "DIRECTORY_ENUMERATION": {
        // Low-risk: generate honeytoken decoy at the probed path
        actions.push({
          id: `act-${Date.now()}-1`,
          type: "GENERATE_DECOY_CONFIG",
          title: `Deploy Decoy Route for Probed Path [${event.targetAsset}]`,
          targetResource: `pages/api/decoy/probed_path.js`,
          parameters: { route: event.targetAsset, category: "directory_trap" },
          riskLevel: "LOW",
          justification: `Automated directory scanner probing path [${event.targetAsset}]. Entrapping scanner in mock JSON route.`,
          threatEventId: event.id,
          createdAt: new Date().toISOString(),
        });
        break;
      }

      case "UNAUTHORIZED_ADMIN_ACCESS": {
        // Major Decision (Critical Risk) -> Lock down core route
        actions.push({
          id: `act-${Date.now()}-1`,
          type: "LOCKDOWN_CORE_ROUTE",
          title: `Emergency Lockdown of Core Route [${event.targetAsset}]`,
          targetResource: "config/route-lockdown.json",
          parameters: { route: event.targetAsset },
          riskLevel: "CRITICAL",
          justification: `Unauthorized administrative penetration attempt on [${event.targetAsset}] from IP ${event.sourceIp}. Major action requires operator authorization.`,
          threatEventId: event.id,
          createdAt: new Date().toISOString(),
        });
        break;
      }

      default: {
        actions.push({
          id: `act-${Date.now()}-1`,
          type: "UPDATE_TARPIT_RULES",
          title: `Standard Rate Throttling for [${event.sourceIp}]`,
          targetResource: "config/tarpit-rules.json",
          parameters: { ip: event.sourceIp, delayMs: 3000 },
          riskLevel: "LOW",
          justification: `Generic anomaly detected from ${event.sourceIp}. Applying baseline rate dampening.`,
          threatEventId: event.id,
          createdAt: new Date().toISOString(),
        });
      }
    }

    return actions;
  }

  public getEventHistory(limit = 50): ThreatEvent[] {
    return this.eventHistory.slice(0, limit);
  }

  public getIpVelocity(ip: string): number {
    const timestamps = this.ipVelocityMap.get(ip) || [];
    const windowStart = Date.now() - this.windowSeconds * 1000;
    return timestamps.filter((t) => t >= windowStart).length;
  }
}

