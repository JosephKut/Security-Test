const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const JWT_PATTERN = /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g;

function fetchURL(url, timeout = 10000) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const lib    = parsed.protocol === "https:" ? https : http;
      const req    = lib.get(url, { timeout, rejectUnauthorized: false }, (res) => {
        let data = "";
        res.on("data", (c) => { data += c; if (data.length > 500000) req.destroy(); });
        res.on("end", () => resolve({ status: res.statusCode, body: data, headers: res.headers }));
      });
      req.on("error",   () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
    } catch { resolve(null); }
  });
}

function decodeBase64(str) {
  try {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(Buffer.from(str, "base64").toString("utf8"));
  } catch { return null; }
}

async function testJWT(target, siteMap) {
  const result  = { name: "JWT Token Security", passed: true, issues: [] };
  const base    = target.replace(/\/$/, "");

  const pages = siteMap?.pages?.map(p => p.url) || [base, `${base}/api`, `${base}/api/users`];

  for (const page of pages) {
    try {
      const res = await fetchURL(page);
      if (!res || res.status === 404) continue;
      await delay(100);

      const body = res.body;
      const headers = res.headers;

      let tokens = [];
      const bodyMatches = body.match(JWT_PATTERN);
      if (bodyMatches) tokens.push(...bodyMatches);

      const authHeader = headers["authorization"] || headers["x-auth-token"] || "";
      const headerMatch = authHeader.match(JWT_PATTERN);
      if (headerMatch) tokens.push(...headerMatch);

      if (tokens.length === 0) continue;

      for (const token of [...new Set(tokens)]) {
        const parts = token.split(".");
        if (parts.length !== 3) continue;

        const header = decodeBase64(parts[0]);
        const payload = decodeBase64(parts[1]);

        if (!header || !payload) continue;

        const tokenIssues = [];

        if (header.alg === "none") {
          tokenIssues.push({
            title:    "JWT — 'none' Algorithm Accepted",
            location: page,
            detail:   `JWT with algorithm "none" found — server may accept unsigned tokens. Token: ${token.slice(0, 40)}...`,
            severity: "CRITICAL",
            risk:     "Attackers can forge arbitrary tokens by setting alg to 'none' — full account impersonation.",
            fixes: [
              { label: "Reject 'none' algorithm in JWT verification",
                code:  "// ❌ VULNERABLE — accepts 'none' algorithm\njwt.verify(token, secret);\n\n// ✅ SAFE — explicitly require a valid algorithm\njwt.verify(token, secret, { algorithms: ['HS256'] });" }
            ]
          });
        }

        if (payload.exp) {
          const now = Math.floor(Date.now() / 1000);
          if (payload.exp < now) {
            tokenIssues.push({
              title:    "JWT — Token Already Expired",
              location: page,
              detail:   `JWT expired at ${new Date(payload.exp * 1000).toISOString()}.`,
              severity: "LOW",
              risk:     "No immediate risk, but expired tokens in responses suggest improper token lifecycle handling.",
              fixes: []
            });
          }
        }

        if (payload.iat && payload.exp && (payload.exp - payload.iat > 86400 * 7)) {
          tokenIssues.push({
            title:    "JWT — Excessive Token Lifetime",
            location: page,
            detail:   `Token valid for ${Math.round((payload.exp - payload.iat) / 86400)} days. Should be hours, not days.`,
            severity: "MEDIUM",
            risk:     "Long-lived tokens increase the window of opportunity if a token is leaked.",
            fixes: [
              { label: "Set short expiration times (15-60 minutes)",
                code:  "jwt.sign(payload, secret, { expiresIn: '1h' });\n// Use refresh tokens for long-lived sessions." }
            ]
          });
        }

        if (!payload.iat && !payload.exp) {
          tokenIssues.push({
            title:    "JWT — Missing Expiration Claim",
            location: page,
            detail:   "JWT has no 'exp' or 'iat' claim — token never expires.",
            severity: "HIGH",
            risk:     "Stolen tokens can be used forever — no window of compromise.",
            fixes: [
              { label: "Always set expiration on JWT tokens",
                code:  "jwt.sign(payload, secret, { expiresIn: '1h' });" }
            ]
          });
        }

        for (const issue of tokenIssues) {
          result.passed = false;
          result.issues.push(issue);
        }
      }
    } catch { }
  }

  return result;
}

module.exports = testJWT;
