/**
 * Tool Execution Layer: Dynamic File and Resource Modifier.
 * Handles automatic and approved filesystem modifications with atomic writes and audit trails.
 */

import * as fs from "fs";
import * as path from "path";
import {
  AgentConfig,
  TarpitRuleEntry,
  DecoyRouteManifest,
  QuarantineEntry,
  FirewallRuleEntry,
  ToolExecutionResult,
} from "./types";

export class ToolExecutionLayer {
  private config: AgentConfig;

  constructor(config: Partial<AgentConfig> = {}) {
    const workspaceRoot = config.workspaceRoot || path.resolve(__dirname, "..");
    this.config = {
      workspaceRoot,
      configDir: config.configDir || path.join(workspaceRoot, "config"),
      decoyRoutesDir: config.decoyRoutesDir || path.join(workspaceRoot, "pages", "api", "decoy"),
      mode: config.mode || "autonomous",
      maxAutoTarpitDelayMs: config.maxAutoTarpitDelayMs || 10000,
      enableFilePersistence: config.enableFilePersistence !== false,
    };

    this.ensureDirectories();
  }

  /**
   * Ensure required configuration and decoy directories exist.
   */
  private ensureDirectories(): void {
    if (!this.config.enableFilePersistence) return;

    try {
      if (!fs.existsSync(this.config.configDir)) {
        fs.mkdirSync(this.config.configDir, { recursive: true });
      }
      if (!fs.existsSync(this.config.decoyRoutesDir)) {
        fs.mkdirSync(this.config.decoyRoutesDir, { recursive: true });
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("Failed to initialize defense directories:", msg);
    }
  }

  /**
   * Helper to write JSON files safely with pretty formatting.
   */
  private writeJsonAtomic(filePath: string, data: unknown): void {
    if (!this.config.enableFilePersistence) return;

    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const tempPath = `${filePath}.${Date.now()}.tmp`;
    const serialized = JSON.stringify(data, null, 2);
    fs.writeFileSync(tempPath, serialized, "utf8");
    fs.renameSync(tempPath, filePath);
  }

  /**
   * Helper to read JSON files safely with fallback.
   */
  private readJsonSafe<T>(filePath: string, fallback: T): T {
    if (!fs.existsSync(filePath)) {
      return fallback;
    }
    try {
      const content = fs.readFileSync(filePath, "utf8");
      return JSON.parse(content) as T;
    } catch {
      return fallback;
    }
  }

  /**
   * Low-risk action: update rate-limit/proxy config to slow down malicious requests.
   */
  public updateTarpitRules(ip: string, delayMs: number): ToolExecutionResult {
    const targetFile = path.join(this.config.configDir, "tarpit-rules.json");
    const boundedDelay = Math.min(Math.max(delayMs, 500), this.config.maxAutoTarpitDelayMs);
    const now = new Date().toISOString();

    try {
      const existing = this.readJsonSafe<Record<string, TarpitRuleEntry>>(targetFile, {});
      const previous = existing[ip];

      const entry: TarpitRuleEntry = {
        ip,
        delayMs: boundedDelay,
        addedAt: previous?.addedAt || now,
        lastTriggeredAt: now,
        hitsCount: (previous?.hitsCount || 0) + 1,
        status: "ACTIVE",
      };

      existing[ip] = entry;
      this.writeJsonAtomic(targetFile, existing);

      return {
        success: true,
        actionId: `tarpit-${Date.now()}`,
        actionType: "UPDATE_TARPIT_RULES",
        targetFile,
        timestamp: now,
        message: `Tarpit rule applied to IP [${ip}]. Injected response delay: ${boundedDelay}ms. Total hits throttled: ${entry.hitsCount}.`,
        diffSummary: `IP ${ip} -> delayMs: ${boundedDelay}`,
        details: { entry },
      };
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        actionId: `tarpit-err-${Date.now()}`,
        actionType: "UPDATE_TARPIT_RULES",
        targetFile,
        timestamp: now,
        message: `Failed to update tarpit rules for IP [${ip}]`,
        error: errorMsg,
      };
    }
  }

  /**
   * Low-risk action: dynamically synthesize mock route handler under /pages/api/decoy/.
   */
  public generateDecoyConfig(
    route: string,
    metadata: Record<string, unknown> = {}
  ): ToolExecutionResult {
    const cleanRouteName = route
      .replace(/^\/+/, "")
      .replace(/[\/\\]/g, "_")
      .replace(/[^a-zA-Z0-9_-]/g, "");

    const handlerFileName = `${cleanRouteName || "endpoint"}.js`;
    const targetHandlerFile = path.join(this.config.decoyRoutesDir, handlerFileName);
    const manifestFile = path.join(this.config.configDir, "decoy-manifest.json");
    const now = new Date().toISOString();

    try {
      // 1. Generate standalone Node.js / Next.js mock API route file
      const handlerContent = `// Auto-generated synthetic decoy route handler by SpectreSync Active Defense Agent
// Target route: ${route}
// Generated at: ${now}

export default async function handler(req, res) {
  const sourceIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "127.0.0.1";
  const userAgent = req.headers["user-agent"] || "unknown";

  // Simulate artificial jitter delay (2000ms - 4500ms) to entrap crawlers
  const jitter = Math.floor(2000 + Math.random() * 2500);
  await new Promise((resolve) => setTimeout(resolve, jitter));

  res.status(200).json({
    status: "ok",
    warning: "SYNTHETIC_CANARY_ACTIVE",
    service: "${cleanRouteName}",
    tokens: {
      auth_token: "ss_live_" + Buffer.from(sourceIp).toString("hex"),
      expires_in: 3600,
      scope: "internal:read"
    },
    fingerprint: Buffer.from(userAgent).toString("base64").slice(0, 16)
  });
}
`;

      if (this.config.enableFilePersistence) {
        fs.writeFileSync(targetHandlerFile, handlerContent, "utf8");
      }

      // 2. Update decoy manifest registry
      const manifest = this.readJsonSafe<Record<string, DecoyRouteManifest>>(manifestFile, {});
      manifest[route] = {
        route,
        handlerPath: path.relative(this.config.workspaceRoot, targetHandlerFile),
        category: (metadata.category as string) || "dynamic_decoy",
        createdAt: now,
        lastAccessed: now,
        syntheticPayloadType: "MOCK_CANARY_JWT",
      };

      this.writeJsonAtomic(manifestFile, manifest);

      return {
        success: true,
        actionId: `decoy-${Date.now()}`,
        actionType: "GENERATE_DECOY_CONFIG",
        targetFile: targetHandlerFile,
        timestamp: now,
        message: `Synthesized dynamic canary route handler at [${path.relative(this.config.workspaceRoot, targetHandlerFile)}] for target route [${route}].`,
        diffSummary: `Created decoy handler ${handlerFileName} and updated manifest registry`,
        details: { route, handlerPath: targetHandlerFile },
      };
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        actionId: `decoy-err-${Date.now()}`,
        actionType: "GENERATE_DECOY_CONFIG",
        targetFile: targetHandlerFile,
        timestamp: now,
        message: `Failed to synthesize decoy route for [${route}]`,
        error: errorMsg,
      };
    }
  }

  /**
   * Low-risk action: quarantine compromised asset by updating environment flags or route configs.
   */
  public quarantineAsset(assetId: string, reason = "Canary trip detected"): ToolExecutionResult {
    const targetFile = path.join(this.config.configDir, "quarantine-manifest.json");
    const now = new Date().toISOString();

    try {
      const manifest = this.readJsonSafe<Record<string, QuarantineEntry>>(targetFile, {});

      manifest[assetId] = {
        assetId,
        quarantinedAt: now,
        reason,
        status: "ISOLATED",
        redirectionTarget: "/api/canary?quarantined=true",
      };

      this.writeJsonAtomic(targetFile, manifest);

      return {
        success: true,
        actionId: `quarantine-${Date.now()}`,
        actionType: "QUARANTINE_ASSET",
        targetFile,
        timestamp: now,
        message: `Asset [${assetId}] isolated. Route redirection and environment quarantine flags active.`,
        diffSummary: `Asset ${assetId} -> status: ISOLATED`,
        details: { asset: manifest[assetId] },
      };
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        actionId: `quarantine-err-${Date.now()}`,
        actionType: "QUARANTINE_ASSET",
        targetFile,
        timestamp: now,
        message: `Failed to quarantine asset [${assetId}]`,
        error: errorMsg,
      };
    }
  }

  /**
   * Major Decision Action (Requires Human Approval): Block an entire subnet in firewall rules.
   */
  public blockSubnet(cidr: string, justification: string, approvedBy: string): ToolExecutionResult {
    const targetFile = path.join(this.config.configDir, "firewall-rules.json");
    const now = new Date().toISOString();

    try {
      const rules = this.readJsonSafe<Record<string, FirewallRuleEntry>>(targetFile, {});

      rules[cidr] = {
        cidr,
        action: "DROP",
        justification,
        addedAt: now,
        approvedBy,
      };

      this.writeJsonAtomic(targetFile, rules);

      return {
        success: true,
        actionId: `firewall-${Date.now()}`,
        actionType: "BLOCK_SUBNET",
        targetFile,
        timestamp: now,
        message: `Subnet [${cidr}] blocked in firewall rules upon human approval from operator [${approvedBy}].`,
        diffSummary: `Subnet ${cidr} -> DROP (Approved by ${approvedBy})`,
        details: { entry: rules[cidr] },
      };
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        actionId: `firewall-err-${Date.now()}`,
        actionType: "BLOCK_SUBNET",
        targetFile,
        timestamp: now,
        message: `Failed to block subnet [${cidr}]`,
        error: errorMsg,
      };
    }
  }

  /**
   * Major Decision Action (Requires Human Approval): Lockdown or sever access to core API route.
   */
  public lockdownCoreRoute(route: string, justification: string, approvedBy: string): ToolExecutionResult {
    const targetFile = path.join(this.config.configDir, "route-lockdown.json");
    const now = new Date().toISOString();

    try {
      const lockdowns = this.readJsonSafe<Record<string, Record<string, unknown>>>(targetFile, {});

      lockdowns[route] = {
        route,
        status: "LOCKED_DOWN",
        justification,
        enforcedAt: now,
        approvedBy,
      };

      this.writeJsonAtomic(targetFile, lockdowns);

      return {
        success: true,
        actionId: `lockdown-${Date.now()}`,
        actionType: "LOCKDOWN_CORE_ROUTE",
        targetFile,
        timestamp: now,
        message: `Core route [${route}] locked down. All external ingress severed. Approved by operator [${approvedBy}].`,
        diffSummary: `Route ${route} -> LOCKED_DOWN`,
        details: { lockdown: lockdowns[route] },
      };
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        actionId: `lockdown-err-${Date.now()}`,
        actionType: "LOCKDOWN_CORE_ROUTE",
        targetFile,
        timestamp: now,
        message: `Failed to lock down core route [${route}]`,
        error: errorMsg,
      };
    }
  }

  /**
   * Get all current configurations for telemetry and auditing.
   */
  public getCurrentConfigurations() {
    return {
      tarpitRules: this.readJsonSafe(path.join(this.config.configDir, "tarpit-rules.json"), {}),
      decoyManifest: this.readJsonSafe(path.join(this.config.configDir, "decoy-manifest.json"), {}),
      quarantineManifest: this.readJsonSafe(path.join(this.config.configDir, "quarantine-manifest.json"), {}),
      firewallRules: this.readJsonSafe(path.join(this.config.configDir, "firewall-rules.json"), {}),
      routeLockdowns: this.readJsonSafe(path.join(this.config.configDir, "route-lockdown.json"), {}),
    };
  }
}

