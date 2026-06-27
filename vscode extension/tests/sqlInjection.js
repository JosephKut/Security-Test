const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const PAYLOADS = [
  "' OR '1'='1",
  "' UNION SELECT null, username, password FROM users --",
  "admin'--",
  "' OR '1'='1' --",
  "'"
];

const ERROR_SIGNATURES = [
  "sql syntax", "mysql_fetch", "ora-", "syntax error",
  "unclosed quotation", "sqlite", "pg_query"
];

const COMMON_PARAMS = ["id", "search", "q", "user", "page", "cat", "item", "ref"];

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

function buildTargets(target, siteMap) {
  const targets = new Set();
  for (const p of COMMON_PARAMS) targets.add(`${target}?${p}=1`);
  if (siteMap?.paramUrls) { for (const { url } of siteMap.paramUrls) targets.add(url); }
  if (siteMap?.endpoints) {
    for (const ep of siteMap.endpoints) {
      for (const p of COMMON_PARAMS) targets.add(`${ep}?${p}=1`);
    }
  }
  return [...targets];
}

async function testSQLInjection(target, siteMap) {
  const result  = { name: "SQL Injection", passed: true, issues: [] };
  const targets = buildTargets(target.replace(/\/$/, ""), siteMap);

  for (const baseUrl of targets) {
    for (const payload of PAYLOADS) {
      try {
        const parsed = new URL(baseUrl);
        for (const key of parsed.searchParams.keys()) parsed.searchParams.set(key, payload);
        const testURL = parsed.toString();
        const res     = await fetchURL(testURL);
        if (!res) continue;
        await delay(100);

        const body = res.body.toLowerCase();
        for (const sig of ERROR_SIGNATURES) {
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
