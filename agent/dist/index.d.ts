/**
 * SpectreSync Active Defense Agent Module.
 * Event-driven telemetry ingestion, dynamic file modifiers, and human-in-the-loop supervised governance.
 */
export * from "./types";
export * from "./ToolExecutionLayer";
export * from "./PolicyEngine";
export * from "./AttackEventListener";
export * from "./ActiveDefenseAgent";
import { defaultAgent } from "./ActiveDefenseAgent";
export default defaultAgent;
