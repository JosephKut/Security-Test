const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const EXTRA_PARAMS = [
  { key: "admin", value: "true" },
  { key: "role", value: "admin" },
  { key: "isAdmin", value: "true" },
  { key: "is_admin", value: "1" },
  { key: "permissions", value: "*" },
  { key: "access_level", value: "999" },
  { key: "verified", value: "true" },
  { key: "email_verified", value: "true" },
  { key: "balance", value: "999999" },
  { key: "credit", value: "1000000" },
];

function sendPost(url, bodyContent, timeout = 10000) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const lib    = parsed.protocol === "https:" ? https : http;
      const body   = JSON.stringify(bodyContent);
      const opts = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) },
        rejectUnauthorized: false,
        timeout,
      };
      const req = lib.request(opts, (res) => {
        let data = "";
        res.on("data", (c) => { data += c; if (data.length > 500000) req.destroy(); });
        res.on("end", () => resolve({ status: res.statusCode, body: data }));
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
        res.on("end", () => resolve({ status: res.statusCode, body: data }));
      });
      req.on("error",   () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
    } catch { resolve(null); }
  });
}

async function testMassAssignment(target, siteMap) {
  const result  = { name: "Mass Assignment", passed: true, issues: [] };
  const base    = target.replace(/\/$/, "");

  const endpoints = new Set([`${base}/api/users`, `${base}/api/user`, `${base}/api/register`,
                             `${base}/api/signup`, `${base}/api/profile`, `${base}/api/update`]);
  if (siteMap?.endpoints) {
    for (const ep of siteMap.endpoints) {
      const lower = ep.toLowerCase();
      if (lower.includes("api") || lower.includes("user") || lower.includes("register") ||
          lower.includes("signup") || lower.includes("profile") || lower.includes("update")) {
        endpoints.add(ep.replace(/\/$/, ""));
      }
    }
  }

  if (siteMap?.forms) {
    for (const form of siteMap.forms) {
      if (form.method.toUpperCase() === "POST") endpoints.add(form.action);
    }
  }

  for (const endpoint of Array.from(endpoints).slice(0, 10)) {
    for (const { key, value } of EXTRA_PARAMS) {
      try {
        const bodyData = { username: "test", email: "test@test.com", password: "test123", [key]: value };
        const res = await sendPost(endpoint, bodyData);
        if (!res) continue;
        await delay(100);

        const bodyLower = res.body.toLowerCase();
        if (bodyLower.includes(value.toLowerCase()) && 
            (bodyLower.includes(key.toLowerCase()) || bodyLower.includes("admin") || bodyLower.includes("role"))) {
          result.passed = false;
          result.issues.push({
            title:    "Potential Mass Assignment — Extra Parameter Accepted",
            location: `POST ${endpoint}`,
            detail:   `Sent extra parameter "${key}: ${value}" and it was reflected in the response — server may be binding user input directly to models.`,
            severity: "HIGH",
            risk:     "Attackers can set sensitive properties (isAdmin, role, balance) by adding extra parameters to API requests.",
            fixes: [
              { label: "Use a whitelist of allowed fields (Data Transfer Objects)",
                code:  "// ❌ VULNERABLE — binds all request body to model\napp.post('/api/user', (req, res) => {\n  const user = new User(req.body);  // Mass assignment!\n  await user.save();\n});\n\n// ✅ SAFE — only allow specific fields\nconst ALLOWED_FIELDS = ['username', 'email', 'password'];\nconst safeData = {};\nfor (const field of ALLOWED_FIELDS) {\n  if (req.body[field] !== undefined) safeData[field] = req.body[field];\n}\nconst user = new User(safeData);" },
              { label: "Use a library like express-validator to filter input",
                code:  "const { body, validationResult } = require('express-validator');\napp.post('/api/user', [\n  body('username').isString(),\n  body('email').isEmail(),\n  body('password').isLength({ min: 8 }),\n  body('isAdmin').custom(() => false), // reject admin field\n], handler);" }
            ]
          });
          break;
        }
      } catch { }
    }
    if (result.issues.length > 0) break;
  }

  return result;
}

module.exports = testMassAssignment;
