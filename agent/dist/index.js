"use strict";
/**
 * SpectreSync Active Defense Agent Module.
 * Event-driven telemetry ingestion, dynamic file modifiers, and human-in-the-loop supervised governance.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
__exportStar(require("./types"), exports);
__exportStar(require("./ToolExecutionLayer"), exports);
__exportStar(require("./PolicyEngine"), exports);
__exportStar(require("./AttackEventListener"), exports);
__exportStar(require("./ActiveDefenseAgent"), exports);
const ActiveDefenseAgent_1 = require("./ActiveDefenseAgent");
exports.default = ActiveDefenseAgent_1.defaultAgent;
