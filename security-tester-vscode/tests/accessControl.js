const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const PROTECTED_PATHS = ["/admin", "/admin/users", "/admin/config", "/api/admin",
                         "/api/users", "/api/users/1", "/api/users/2", "/api/keys",
                         "/api/config", "/api/db", "/api/logs", "/.env", "/backup",
                         "/config", "/dashboard", "/wp-admin", "/administrator"];

const IDOR_PATTERNS = [
  { template: "/api/users/{id}", ids: [1, 2, 3, 100, 1000] },
  { template: "/api/orders/{id}", ids: [1, 2, 3] },
  { template: "/api/documents/{id}", ids: [1, 2, 3] },
  { template: "/user/{id}", ids: [1, 2, 3] },
  { template: "/profile/{id}", ids: [1, 2, 3] },
  { template: "?id={id}", ids: [1, 2, 3, 100] },
  { template: "?user_id={id}", ids: [1, 2, 3] },
  { template: "?document_id={id}", ids: [1, 2, 3] },
];

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

async function testAccessControl(target, siteMap) {
  const result  = { name: "Broken Access Control & IDOR", passed: true, issues: [] };
  const base    = target.replace(/\/$/, "");

  for (const path of PROTECTED_PATHS) {
    try {
      const testURL = `${base}${path}`;
      const res     = await fetchURL(testURL);
      if (!res) continue;
      await delay(100);

      if (res.status === 200) {
        const body = res.body.toLowerCase();
        if (body.includes("login") || body.includes("sign in") || body.includes("unauthorized")) continue;

        result.passed = false;
        result.issues.push({
          title:    "Potentially Exposed Protected Path",
          location: testURL,
          detail:   `Path "${path}" returned HTTP 200 (not a login page) — may be accessible without authentication.`,
          severity: "HIGH",
          risk:     "Unauthorized users may access admin panels, API endpoints, or sensitive files.",
          fixes: [
            { label: "Implement proper authentication checks on all protected routes",
              code:  "// Express.js middleware:\nfunction requireAuth(req, res, next) {\n  if (!req.session.userId) {\n    return res.status(401).json({ error: 'Unauthorized' });\n  }\n  next();\n}\napp.use('/admin', requireAuth, adminRouter);\napp.use('/api', requireAuth, apiRouter);" },
            { label: "Use role-based access control (RBAC)",
              code:  "function requireRole(role) {\n  return (req, res, next) => {\n    if (req.session.role !== role) {\n      return res.status(403).json({ error: 'Forbidden' });\n    }\n    next();\n  };\n}\napp.get('/admin/users', requireAuth, requireRole('admin'), handler);" }
          ]
        });
        break;
      } else if (res.status === 403) {
        result.issues.push({
          title:    "Protected Path Returns 403",
          location: testURL,
          detail:   `Path "${path}" returned HTTP 403. Access is denied, which is proper behavior.`,
          severity: "INFO",
          risk:     "No risk detected — access control appears to be in place.",
          fixes: []
        });
      }
    } catch { }
  }

  for (const { template, ids } of IDOR_PATTERNS) {
    const results = [];
    for (const id of ids) {
      try {
        const path = template.replace("{id}", id);
        const testURL = path.startsWith("?") ? `${base}${path}` : `${base}${path}`;
        const res = await fetchURL(testURL);
        if (res) { results.push({ id, status: res.status, body: res.body }); }
        await delay(100);
      } catch { }
    }

    const successResults = results.filter(r => r.status === 200);
    if (successResults.length >= 2 && successResults.length === ids.length) {
      const preview = successResults.slice(0, 2).map(r => `ID ${r.id} -> ${r.status}`).join(", ");
      result.passed = false;
      result.issues.push({
        title:    "Potential IDOR — Sequential IDs Return Data",
        location: `${base}${template}`,
        detail:   `Multiple sequential IDs returned HTTP 200: ${preview}. Users may access each other's data by changing the ID.`,
        severity: "HIGH",
        risk:     "Attackers can enumerate and access other users' private data (accounts, orders, documents) by guessing sequential IDs.",
        fixes: [
          { label: "Use UUIDs or random tokens instead of sequential IDs",
            code:  "// ❌ VULNERABLE — sequential integer IDs\napp.get('/api/users/:id', (req, res) => { ... });\n\n// ✅ SAFE — use UUIDs (non-guessable)\nconst { v4: uuidv4 } = require('uuid');\napp.get('/api/users/:uuid', (req, res) => {\n  const user = db.find(u => u.uuid === req.params.uuid);\n  if (!user || user.owner !== req.session.userId) {\n    return res.status(403).send('Forbidden');\n  }\n  res.json(user);\n});" },
          { label: "Verify object ownership",
            code:  "// Always check that the requester owns the resource\napp.get('/api/orders/:id', (req, res) => {\n  const order = db.orders.find(o => o.id === req.params.id);\n  if (!order) return res.status(404).send('Not found');\n  if (order.userId !== req.session.userId) {\n    return res.status(403).send('Forbidden');\n  }\n  res.json(order);\n});" }
        ]
      });
    }
  }

  return result;
}

module.exports = testAccessControl;
