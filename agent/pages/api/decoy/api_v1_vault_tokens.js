// Auto-generated synthetic decoy route handler by SpectreSync Active Defense Agent
// Target route: /api/v1/vault/tokens
// Generated at: 2026-10-18T16:36:31.787Z

export default async function handler(req, res) {
  const sourceIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "127.0.0.1";
  const userAgent = req.headers["user-agent"] || "unknown";

  // Simulate artificial jitter delay (2000ms - 4500ms) to entrap crawlers
  const jitter = Math.floor(2000 + Math.random() * 2500);
  await new Promise((resolve) => setTimeout(resolve, jitter));

  res.status(200).json({
    status: "ok",
    warning: "SYNTHETIC_CANARY_ACTIVE",
    service: "api_v1_vault_tokens",
    tokens: {
      auth_token: "ss_live_" + Buffer.from(sourceIp).toString("hex"),
      expires_in: 3600,
      scope: "internal:read"
    },
    fingerprint: Buffer.from(userAgent).toString("base64").slice(0, 16)
  });
}
