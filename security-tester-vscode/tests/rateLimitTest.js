const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const RATE_LIMIT_HEADERS = [
  "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
  "x-rate-limit-limit", "x-rate-limit-remaining", "x-rate-limit-reset",
  "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
  "retry-after", "x-retry-after",
];

function fetchURL(url, timeout = 5000) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const lib    = parsed.protocol === "https:" ? https : http;
      const req    = lib.get(url, { timeout, rejectUnauthorized: false }, (res) => {
        let data = "";
        res.on("data", (c) => { data += c; if (data.length > 500000) req.destroy(); });
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
      });
      req.on("error",   () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
    } catch { resolve(null); }
  });
}

async function testRateLimit(target, siteMap) {
  const result  = { name: "Rate Limiting / DoS", passed: true, issues: [] };
  const base    = target.replace(/\/$/, "");

  const testEndpoints = [base, `${base}/api`, `${base}/login`, `${base}/search`];
  if (siteMap?.endpoints && siteMap.endpoints.length > 0) {
    testEndpoints.push(siteMap.endpoints[0]);
  }

  const rapidRequests = 6;

  for (const endpoint of testEndpoints.slice(0, 3)) {
    try {
      const responses = [];
      for (let i = 0; i < rapidRequests; i++) {
        const res = await fetchURL(endpoint);
        if (res) responses.push(res);
      }

      await delay(100);

      const headersPresent = RATE_LIMIT_HEADERS.filter(h =>
        responses.some(r => r.headers && Object.keys(r.headers).some(k => k.toLowerCase() === h))
      );

      if (headersPresent.length > 0) {
        result.issues.push({
          title:    "Rate Limiting Headers Detected",
          location: endpoint,
          detail:   `Rate limit headers found: ${headersPresent.join(", ")}. Rate limiting appears to be configured.`,
          severity: "INFO",
          risk:     "Rate limiting is configured — good protection against brute force and DoS.",
          fixes: []
        });
        continue;
      }

      const allOk = responses.every(r => r.status === 200);
      const rateLimited = responses.some(r => r.status === 429);

      if (allOk) {
        result.issues.push({
          title:    "No Rate Limiting Detected",
          location: endpoint,
          detail:   `Sent ${rapidRequests} rapid requests to ${endpoint} — all returned HTTP 200. No rate limiting or throttling observed.`,
          severity: "MEDIUM",
          risk:     "Without rate limiting, attackers can brute force passwords, enumerate resources, or DoS the server with unlimited requests.",
          fixes: [
            { label: "Implement rate limiting on all API endpoints",
              code:  "// Express.js with express-rate-limit\nconst rateLimit = require('express-rate-limit');\n\nconst limiter = rateLimit({\n  windowMs: 15 * 60 * 1000,  // 15 minutes\n  max: 100,                   // limit each IP to 100 requests per window\n  message: 'Too many requests, please try again later.'\n});\n\napp.use('/api/', limiter);\n\n// Stricter limit for login\nconst loginLimiter = rateLimit({\n  windowMs: 15 * 60 * 1000,\n  max: 5,\n  message: 'Too many login attempts.'\n});\napp.post('/login', loginLimiter);" },
            { label: "Use Reverse Proxy for Rate Limiting",
              code:  "# Nginx rate limiting\nlimit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;\nserver {\n  location /api/ {\n    limit_req zone=mylimit burst=20 nodelay;\n  }\n}" }
          ]
        });
        break;
      }

      if (rateLimited) {
        result.issues.push({
          title:    "Rate Limiting Active",
          location: endpoint,
          detail:   `Rate limiting detected — HTTP 429 returned on ${endpoint}. Good configuration.`,
          severity: "INFO",
          risk:     "No issue — rate limiting is properly configured.",
          fixes: []
        });
      }
    } catch { }
  }

  return result;
}

module.exports = testRateLimit;
