const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const PATTERNS = [
  { name: "Plain-text Password",      pattern: /["']?password["']?\s*[:=]\s*["'][^"']{3,}["']/i },
  { name: "Credit Card Number",       pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/ },
  { name: "Stack Trace / File Path",  pattern: /at\s+\w+.*\.(?:cs|js):\d+|(?:\/home\/|\/var\/www\/|C:\\Users\\)/i },
  { name: "Database Connection String", pattern: /mongodb:\/\/|mysql:\/\/|postgres:\/\/|Server=.*;Database=/i },
  { name: "Internal IP Address",      pattern: /\b(?:192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)\d+\.\d+\b/ },
  { name: "JWT Token in Response",    pattern: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/ },
];

const COOKIE_FLAGS = ["httponly", "secure"];

function fetchURL(url, timeout = 10000) {
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

async function testSensitiveData(target, siteMap) {
  const result  = { name: "Sensitive Data Exposure", passed: true, issues: [] };
  const baseUrl = target.replace(/\/$/, "");

  const pages = siteMap?.pages?.map(p => p.url) || [
    baseUrl, `${baseUrl}/api`, `${baseUrl}/api/users`, `${baseUrl}/login`
  ];

  for (const page of pages) {
    try {
      const res = await fetchURL(page);
      if (!res || res.status === 404) continue;
      await delay(100);

      const body = res.body;

      for (const p of PATTERNS) {
        const match = body.match(p.pattern);
        if (!match) continue;

        const raw    = match[0];
        const masked = raw.length > 10 ? raw.slice(0, 6) + "..." + raw.slice(-4) : "****";

        result.passed = false;
        result.issues.push({
          title:    `Sensitive Data Exposed: ${p.name}`,
          location: page,
          detail:   `Pattern matched in response: "${masked}"`,
          severity: p.name.includes("Password") || p.name.includes("Card") ? "CRITICAL" : "HIGH",
          risk:     `Exposing ${p.name.toLowerCase()} gives attackers direct access to credentials or system internals.`,
          fixes: [
            { label: "Never return sensitive fields in API responses",
              code:  "// ❌ VULNERABLE — returns everything including password hash\nres.json(user);\n\n// ✅ SAFE — use a DTO\nres.json({ id: user.id, name: user.name, email: user.email });" },
            { label: "Never expose stack traces in production",
              code:  "// In Express:\napp.use((err, req, res, next) => {\n  if (req.app.get('env') === 'development') {\n    return res.status(500).json({ error: err.stack });\n  }\n  res.status(500).json({ error: 'An error occurred' });\n});" }
          ]
        });
      }

      const setCookie = res.headers["set-cookie"];
      if (setCookie) {
        const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
        for (const cookie of cookies) {
          const cl = cookie.toLowerCase();
          for (const flag of COOKIE_FLAGS) {
            if (!cl.includes(flag)) {
              result.passed = false;
              result.issues.push({
                title:    `Cookie Missing "${flag}" Flag`,
                location: `Set-Cookie header at ${page}`,
                detail:   `Cookie set without "${flag}": ${cookie.split(";")[0]}`,
                severity: "MEDIUM",
                risk:     flag === "httponly"
                  ? "JavaScript can read the cookie — XSS can steal session tokens."
                  : "Cookie sent over plain HTTP — can be intercepted.",
                fixes: [
                  { label: "Set all security flags on cookies",
                    code:  "res.cookie('session', token, {\n  httpOnly: true,\n  secure:   true,\n  sameSite: 'strict'\n});" }
                ]
              });
            }
          }
        }
      }
    } catch { }
  }

  return result;
}

module.exports = testSensitiveData;
