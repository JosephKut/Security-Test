const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const DEFAULT_CREDS = [
  ["admin", "admin"], ["admin", "password"], ["admin", "123456"],
  ["admin", "admin123"], ["admin", "root"], ["root", "root"],
  ["root", "toor"], ["user", "user"], ["test", "test"],
  ["guest", "guest"], ["administrator", "password"],
];

const LOGIN_PATHS = ["/login", "/signin", "/auth", "/api/login", "/admin",
                     "/wp-login", "/administrator", "/user/login"];

function sendPost(url, bodyContent, timeout = 10000) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const lib    = parsed.protocol === "https:" ? https : http;
      const body   = typeof bodyContent === "string" ? bodyContent : new URLSearchParams(bodyContent).toString();
      const ct     = typeof bodyContent === "string" && bodyContent.includes("xml") ? "application/xml"
                   : typeof bodyContent === "string" ? "text/plain"
                   : "application/x-www-form-urlencoded";
      const opts = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: "POST",
        headers: { "Content-Type": ct, "Content-Length": Buffer.byteLength(body) },
        rejectUnauthorized: false,
        timeout,
      };
      const req = lib.request(opts, (res) => {
        let data = "";
        res.on("data", (c) => { data += c; if (data.length > 500000) req.destroy(); });
        res.on("end", () => resolve({ status: res.statusCode, body: data, headers: res.headers }));
      });
      req.on("error",   () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
      req.write(body);
      req.end();
    } catch { resolve(null); }
  });
}

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

async function testBruteForce(target, siteMap) {
  const result  = { name: "Brute Force & Default Creds", passed: true, issues: [] };
  const base    = target.replace(/\/$/, "");

  const loginEndpoints = new Set();
  if (siteMap?.forms) {
    for (const form of siteMap.forms) {
      loginEndpoints.add(form.action);
    }
  }
  if (loginEndpoints.size === 0) {
    for (const p of LOGIN_PATHS) {
      try {
        const res = await fetchURL(`${base}${p}`);
        if (res && res.status !== 404) loginEndpoints.add(`${base}${p}`);
        await delay(100);
      } catch { }
    }
  }
  if (loginEndpoints.size === 0) loginEndpoints.add(`${base}/login`);

  let attempts = 0;
  const MAX_ATTEMPTS = 10;

  for (const endpoint of loginEndpoints) {
    for (const [user, pass] of DEFAULT_CREDS) {
      if (attempts >= MAX_ATTEMPTS) break;
      try {
        const body = new URLSearchParams();
        body.append("username", user);
        body.append("password", pass);
        body.append("email", user);
        body.append("user", user);
        body.append("pass", pass);
        body.append("login", user);

        const res = await sendPost(endpoint, body);
        attempts++;
        if (!res) continue;
        await delay(200);

        if (res.status === 302 || res.status === 200) {
          const setCookie = res.headers && res.headers["set-cookie"];
          const bodyLower = res.body.toLowerCase();
          const success = setCookie || 
                         bodyLower.includes("welcome") ||
                         bodyLower.includes("dashboard") ||
                         bodyLower.includes("logout") ||
                         bodyLower.includes("redirect");

          if (success && !bodyLower.includes("invalid") && !bodyLower.includes("incorrect")) {
            result.passed = false;
            result.issues.push({
              title:    "Default Credentials Accepted",
              location: `POST ${endpoint}`,
              detail:   `Login succeeded with credentials "${user}:${pass}" — default or weak credentials in use.`,
              severity: "CRITICAL",
              risk:     "Attackers can gain unauthorized access using known default/weak username and password combinations.",
              fixes: [
                { label: "Change all default credentials immediately",
                  code:  "// Enforce strong password policy:\n// - Minimum 12 characters\n// - At least one uppercase, lowercase, digit, special char\n// - No common patterns (admin, password, 123456)\nconst passwordValidator = require('password-validator');\nconst schema = new passwordValidator();\nschema.is().min(12).has().uppercase().has().lowercase().has().digits().has().symbols();" },
                { label: "Implement account lockout after 5 failed attempts",
                  code:  "// Example rate limiting with express-rate-limit\nconst rateLimit = require('express-rate-limit');\nconst loginLimiter = rateLimit({\n  windowMs: 15 * 60 * 1000,  // 15 minutes\n  max: 5,                     // 5 attempts per window\n  message: 'Too many attempts — try again later'\n});\napp.post('/login', loginLimiter, (req, res) => { ... });" }
              ]
            });
            break;
          }
        }
      } catch { }
    }
    if (result.issues.length > 0) break;
  }

  return result;
}

module.exports = testBruteForce;
