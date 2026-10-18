const express = require("express");
const cors = require("cors");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = 5000;

// Enable proxy header trust for accurate IP resolution behind reverse proxies
app.set("trust proxy", true);

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("SpectreSync Backend API is online and listening.");
});

// -- Active Defense Agent Module ---------------------------------------------
let activeDefenseAgent = null;
try {
  const { defaultAgent } = require("./agent/dist/ActiveDefenseAgent");
  activeDefenseAgent = defaultAgent;
  console.log("SpectreSync Active Defense Agent successfully loaded into backend.");
} catch (err) {
  console.warn("Active Defense Agent module not pre-compiled, fallback initialized:", err.message);
}

// -- Database initialization --------------------------------------------------

const DB_PATH = path.join(__dirname, "spectresync.db");
const db = new Database(DB_PATH);

// Enable WAL mode for concurrent read access without locking
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

// Create tables if they do not exist
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    file_count  INTEGER DEFAULT 0,
    env_vars    INTEGER DEFAULT 0,
    config_keys INTEGER DEFAULT 0,
    created_at  TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS traps (
    id           TEXT PRIMARY KEY,
    scan_id      TEXT NOT NULL REFERENCES scans(id),
    trap_name    TEXT NOT NULL,
    category     TEXT NOT NULL,
    decoy_value  TEXT NOT NULL,
    endpoint_url TEXT NOT NULL,
    created_at   TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS alerts (
    id              TEXT PRIMARY KEY,
    trap_id         TEXT,
    timestamp       TEXT NOT NULL,
    ip              TEXT NOT NULL,
    type            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'Triggered',
    tarpit_duration INTEGER DEFAULT 0
  );
`);

// Ensure tarpit_duration column exists on pre-existing databases
try {
  db.exec("ALTER TABLE alerts ADD COLUMN tarpit_duration INTEGER DEFAULT 0;");
} catch (_) {
  // Column already present
}

// -- Prepared statements ------------------------------------------------------

const insertScan = db.prepare(`
  INSERT INTO scans (id, target, file_count, env_vars, config_keys, created_at)
  VALUES (?, ?, ?, ?, ?, ?)
`);

const insertTrap = db.prepare(`
  INSERT INTO traps (id, scan_id, trap_name, category, decoy_value, endpoint_url, created_at)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);

const insertAlert = db.prepare(`
  INSERT INTO alerts (id, trap_id, timestamp, ip, type, status, tarpit_duration)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);

const selectAllAlerts = db.prepare(`
  SELECT id, trap_id, timestamp, ip, ip AS source_ip, type, type AS user_agent, status, tarpit_duration
  FROM alerts ORDER BY timestamp DESC
`);

const selectAllTraps = db.prepare(`
  SELECT id, scan_id, trap_name, category, decoy_value, endpoint_url, created_at
  FROM traps ORDER BY created_at DESC
`);

// -- Decoy synthesis helpers --------------------------------------------------

const SUFFIX_POOLS = {
  secret:   ["SECRET_KEY", "SECRET_ACCESS_KEY", "SECRET_TOKEN", "PRIVATE_KEY"],
  database: ["DB_URI", "DB_URL", "DB_PASSWORD", "DB_CONNECTION_STRING"],
  token:    ["API_TOKEN", "AUTH_TOKEN", "ACCESS_TOKEN", "REFRESH_TOKEN"],
  key:      ["API_KEY", "ACCESS_KEY", "ENCRYPTION_KEY", "SIGNING_KEY"],
  generic:  ["BACKUP_CREDENTIALS", "ADMIN_PASSWORD", "SERVICE_ACCOUNT_KEY"],
};

const VALUE_TEMPLATES = {
  secret:   (r) => `wJalrXUtnFEMI/${r}`,
  database: (r) => `postgresql://admin:${r}@staging-db.internal:5432/app`,
  token:    (r) => `ghp_${r}`,
  key:      (r) => `AKIA${r}`,
  generic:  (r) => r,
};

const PREFIXES = ["APP", "SVC", "INTERNAL", "STAGING", "BACKUP"];
const MIDDLES  = ["BACKUP", "STAGING", "LEGACY", "INTERNAL", "TEMP", "OLD"];

function randomHex(len) {
  return crypto.randomBytes(len).toString("hex").slice(0, len);
}

function generateId() {
  return crypto.randomUUID();
}

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// Build context-aware decoy traps for the target path
function synthesizeTraps(targetPath) {
  const categories = Object.keys(SUFFIX_POOLS);
  const traps = [];

  for (let i = 1; i <= 5; i++) {
    const cat = pick(categories);
    const prefix = pick(PREFIXES);
    const suffix = pick(SUFFIX_POOLS[cat]);
    const useMid = Math.random() < 0.5;
    const varName = useMid
      ? `${prefix}_${pick(MIDDLES)}_${suffix}`
      : `${prefix}_${suffix}`;

    const randPart = randomHex(20);
    const value = VALUE_TEMPLATES[cat](randPart);
    const trapId = `trap_${String(i).padStart(2, "0")}`;

    traps.push({
      trap_id: trapId,
      variable_name: varName,
      decoy_value: value,
      category: cat,
      endpoint: `/api/canary?id=${trapId}`,
    });
  }

  return traps;
}

// Calculate randomized exponential delay between 2000ms and 6000ms
function calculateTarpitDelay() {
  const minMs = 2000;
  const maxMs = 6000;
  const lambda = 1.8;
  const randFactor = (1 - Math.exp(-lambda * Math.random())) / (1 - Math.exp(-lambda));
  return Math.floor(minMs + randFactor * (maxMs - minMs));
}

// Generate realistic high-value mock credentials to entangle scrapers
function generateHighValueDecoyPayload(trapId) {
  const randAws = crypto.randomBytes(16).toString("hex").toUpperCase();
  const randSecret = crypto.randomBytes(30).toString("base64");
  const randToken = crypto.randomBytes(24).toString("hex");
  const randDbPass = crypto.randomBytes(12).toString("base64url");

  return {
    status: "success",
    code: 200,
    message: "Session authenticated. Staging environment profile synchronized.",
    data: {
      account_id: "847291049281",
      iam_role: "arn:aws:iam::847291049281:role/ProductionDataPipelineService",
      credentials: {
        aws_access_key_id: `AKIA${randAws}`,
        aws_secret_access_key: randSecret,
        session_token: `AQoDYXdzEE8${randToken}`,
        expires_at: new Date(Date.now() + 7200000).toISOString(),
      },
      infrastructure: {
        staging_db_uri: `postgresql://prod_vault:${randDbPass}@staging-db.internal.spectre.local:5432/corp_data`,
        redis_cluster: `rediss://default:${randDbPass}@staging-redis.internal.spectre.local:6379`,
        kms_key_endpoint: "https://kms.us-east-1.internal.spectre.corp/v1/keys",
      },
      audit: {
        trap_identifier: trapId,
        session_id: crypto.randomUUID(),
        issued_at: new Date().toISOString(),
      },
    },
  };
}

// Extract and normalize real client IP address
function getClientIp(req) {
  let ip = null;

  // Check X-Forwarded-For header (handles multi-proxy chains)
  const forwardedFor = req.headers["x-forwarded-for"];
  if (forwardedFor && typeof forwardedFor === "string") {
    ip = forwardedFor.split(",")[0].trim();
  }

  // Fallback to socket remoteAddress, Express req.ip, or connection
  if (!ip) {
    ip = req.socket?.remoteAddress || req.ip || req.connection?.remoteAddress;
  }

  if (!ip || typeof ip !== "string") {
    return "Unknown";
  }

  // Normalize IPv6-mapped IPv4 addresses (::ffff:127.0.0.1)
  if (ip.startsWith("::ffff:")) {
    ip = ip.replace("::ffff:", "");
  }

  // Normalize local loopback addresses for clean display in SOC feed
  if (ip === "::1" || ip === "127.0.0.1") {
    return "127.0.0.1 (Local)";
  }

  return ip;
}

// -- Routes -------------------------------------------------------------------

// POST /api/scan -- scan target path, persist scan and generated decoys
app.post("/api/scan", (req, res) => {
  const { targetPath } = req.body;

  if (!targetPath || !targetPath.trim()) {
    return res.status(400).json({ error: "targetPath is required" });
  }

  try {
    const scanId = generateId();
    const now = new Date().toISOString();

    // Persist scan record
    insertScan.run(scanId, targetPath.trim(), 0, 0, 0, now);

    // Generate and persist decoy traps transactionally
    const traps = synthesizeTraps(targetPath.trim());
    const persistTrap = db.transaction((trapList) => {
      for (const t of trapList) {
        insertTrap.run(
          generateId(), scanId, t.variable_name,
          t.category, t.decoy_value, t.endpoint, now
        );
      }
    });
    persistTrap(traps);

    res.json({
      scan_id: scanId,
      target: targetPath.trim(),
      trap_count: traps.length,
      traps,
    });
  } catch (err) {
    console.error("Scan error:", err.message);
    res.status(500).json({ error: "Internal server error during scan" });
  }
});

// GET & POST /api/canary -- behavioral tarpitting, delay injection, alert recording, and fake data payload
const handleCanaryHit = async (req, res) => {
  const trapId = req.query.id || req.body?.id || "unknown";
  const sourceIp = getClientIp(req);
  const userAgent = req.headers["user-agent"] || "Automated Scraper";

  // Calculate adaptive randomized exponential tarpit delay (2000ms - 6000ms)
  const delayMs = calculateTarpitDelay();
  const suspensionStatus = `Suspended (${(delayMs / 1000).toFixed(1)}s Tarpit)`;

  try {
    const alertId = generateId();
    const now = new Date().toISOString();

    // Insert alert recording tarpit duration and bot suspension status
    insertAlert.run(
      alertId,
      trapId,
      now,
      sourceIp,
      userAgent,
      suspensionStatus,
      delayMs
    );

    // Ingest threat event into Active Defense Agent
    if (activeDefenseAgent) {
      try {
        activeDefenseAgent.ingestAlert({
          type: "CANARY_EXPOSED",
          sourceIp,
          targetAsset: trapId,
          userAgent,
          metadata: { delayMs, alertId, suspensionStatus },
        });
      } catch (agentErr) {
        console.warn("Active Defense Agent ingestion warning:", agentErr.message);
      }
    }

    // Inject delay to slow down automated crawlers and bots
    await new Promise((resolve) => setTimeout(resolve, delayMs));

    // Return fake high-value mock credentials to trap the attacker in a verification loop
    const decoyData = generateHighValueDecoyPayload(trapId);
    res.status(200).json(decoyData);
  } catch (err) {
    console.error("Canary alert error:", err.message);
    res.status(500).json({ error: "Internal error during canary processing" });
  }
};

app.get("/api/canary", handleCanaryHit);
app.post("/api/canary", handleCanaryHit);

// -- Active Defense Agent REST Endpoints ---------------------------------------

// POST /api/defense/events -- Ingest structured threat alert telemetry
app.post("/api/defense/events", (req, res) => {
  if (!activeDefenseAgent) {
    return res.status(503).json({ error: "Active Defense Agent unavailable" });
  }
  try {
    const { type, sourceIp, targetAsset, severity, userAgent, metadata } = req.body;
    if (!type || !sourceIp) {
      return res.status(400).json({ error: "Missing required fields: type, sourceIp" });
    }
    const result = activeDefenseAgent.ingestAlert({
      type,
      sourceIp,
      targetAsset: targetAsset || "/unknown",
      severity,
      userAgent,
      metadata,
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/defense/approvals -- Retrieve pending Human-In-The-Loop approvals
app.get("/api/defense/approvals", (_req, res) => {
  if (!activeDefenseAgent) {
    return res.status(503).json({ error: "Active Defense Agent unavailable" });
  }
  res.json(activeDefenseAgent.getPendingApprovals());
});

// POST /api/defense/approvals/:id/decide -- Operator decision (APPROVED or REJECTED)
app.post("/api/defense/approvals/:id/decide", (req, res) => {
  if (!activeDefenseAgent) {
    return res.status(503).json({ error: "Active Defense Agent unavailable" });
  }
  const { id } = req.params;
  const { decision, operator = "SOC_OPERATOR", reason } = req.body;

  try {
    if (decision === "APPROVED") {
      const result = activeDefenseAgent.approve(id, operator);
      return res.json({ status: "APPROVED", result });
    } else if (decision === "REJECTED") {
      const result = activeDefenseAgent.reject(id, operator, reason);
      return res.json({ status: "REJECTED", result });
    } else {
      return res.status(400).json({ error: "Decision must be 'APPROVED' or 'REJECTED'" });
    }
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

// GET /api/defense/config -- Retrieve live dynamic file & resource configs
app.get("/api/defense/config", (_req, res) => {
  if (!activeDefenseAgent) {
    return res.status(503).json({ error: "Active Defense Agent unavailable" });
  }
  res.json(activeDefenseAgent.getLiveConfigurations());
});

// GET /api/defense/status -- Retrieve agent operational telemetry
app.get("/api/defense/status", (_req, res) => {
  if (!activeDefenseAgent) {
    return res.status(503).json({ error: "Active Defense Agent unavailable" });
  }
  res.json({
    mode: activeDefenseAgent.getMode(),
    pendingApprovalsCount: activeDefenseAgent.getPendingApprovals().length,
    recentEvents: activeDefenseAgent.getRecentEvents(10),
    auditHistory: activeDefenseAgent.getAuditHistory(10),
    configurations: activeDefenseAgent.getLiveConfigurations(),
  });
});

// POST /api/defense/mode -- Update agent governance mode
app.post("/api/defense/mode", (req, res) => {
  if (!activeDefenseAgent) {
    return res.status(503).json({ error: "Active Defense Agent unavailable" });
  }
  const { mode } = req.body;
  if (mode !== "autonomous" && mode !== "supervised") {
    return res.status(400).json({ error: "Mode must be 'autonomous' or 'supervised'" });
  }
  activeDefenseAgent.setMode(mode);
  res.json({ status: "ok", mode: activeDefenseAgent.getMode() });
});

// GET /api/alerts -- return all stored alerts, newest first
app.get("/api/alerts", (_req, res) => {
  try {
    const rows = selectAllAlerts.all();
    res.json(rows);
  } catch (err) {
    console.error("Alert query error:", err.message);
    res.status(500).json({ error: "Failed to retrieve alerts" });
  }
});

// GET /api/traps -- return all stored traps
app.get("/api/traps", (_req, res) => {
  try {
    const rows = selectAllTraps.all();
    res.json(rows);
  } catch (err) {
    console.error("Trap query error:", err.message);
    res.status(500).json({ error: "Failed to retrieve traps" });
  }
});

// GET /health -- liveness probe
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// -- Graceful shutdown --------------------------------------------------------

process.on("SIGINT", () => {
  db.close();
  process.exit(0);
});

process.on("SIGTERM", () => {
  db.close();
  process.exit(0);
});

// -- Start server -------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`SpectreSync backend running on http://localhost:${PORT}`);
});
