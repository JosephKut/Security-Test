const https = require("https");
const http  = require("http");
const { URL } = require("url");

const SQL_PAYLOADS = [
  "' OR '1'='1",
  "'; DROP TABLE users; --",
  "' UNION SELECT null, username, password FROM users --",
  "1' AND SLEEP(3) --",
  "admin'--"
];

const SQL_ERROR_SIGNATURES = [
  "sql syntax", "mysql_fetch", "ora-", "syntax error",
  "unclosed quotation", "sqlite", "pg_query"
];

async function fetchURL(url, timeout = 5000) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const lib    = parsed.protocol === "https:" ? https : http;
      const req    = lib.get(url, { timeout, rejectUnauthorized: false }, (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode, body: data }));
      });
      req.on("error",   () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
    } catch { resolve(null); }
  });
}

// Build all URLs to test — root + all crawled param URLs
function buildTestTargets(target, siteMap) {
  const targets = new Set();

  // Always test root with common params
  const common = ["id", "search", "q", "user", "page", "cat"];
  for (const p of common) targets.add(`${target}?${p}=1`);

  // Add every crawled URL that has query params
  if (siteMap?.paramUrls) {
    for (const { url } of siteMap.paramUrls) targets.add(url);
  }

  // Add every crawled endpoint with injected params
  if (siteMap?.endpoints) {
    for (const ep of siteMap.endpoints) {
      for (const p of common) targets.add(`${ep}?${p}=1`);
    }
  }

  return [...targets];
}

async function testSQLInjection(target, siteMap) {
  const result  = { name: "SQL Injection", passed: true, issues: [] };
  const targets = buildTestTargets(target, siteMap);

  for (const baseTestUrl of targets) {
    for (const payload of SQL_PAYLOADS) {
      try {
        const parsed = new URL(baseTestUrl);
        // Inject payload into every existing param
        for (const key of parsed.searchParams.keys()) {
          parsed.searchParams.set(key, payload);
        }
        const testURL = parsed.toString();
        const res     = await fetchURL(testURL);
        if (!res) continue;

        const body = res.body.toLowerCase();
        for (const sig of SQL_ERROR_SIGNATURES) {
          if (body.includes(sig)) {
            result.passed = false;
            result.issues.push({
              title:    "SQL Injection Vulnerability Detected",
              location: `URL: ${testURL}`,
              detail:   `DB error signature "${sig}" exposed with payload: ${payload}`,
              severity: "CRITICAL",
              risk:     "Attackers can read, modify, or delete your entire database.",
              fixes: [
                { label: "Node.js — use parameterized queries",
                  code:  "// ❌ VULNERABLE\ndb.query(\"SELECT * FROM users WHERE id = \" + userInput);\n\n// ✅ SAFE\ndb.query(\"SELECT * FROM users WHERE id = ?\", [userInput]);" },
                { label: "Never concatenate user input into SQL",
                  code:  "Always use prepared statements or an ORM." }
              ]
            });
            break;
          }
        }
      } catch { }
    }
  }

  return result;
}

module.exports = testSQLInjection;
