const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const PAYLOADS = [
  { payload: "; echo pong", desc: "Semicolon injection" },
  { payload: "| echo pong", desc: "Pipe injection" },
  { payload: "`echo pong`", desc: "Backtick injection" },
  { payload: "$(echo pong)", desc: "Subshell injection" },
  { payload: "& echo pong &", desc: "Background injection" },
];

const COMMON_PARAMS = ["host", "hostname", "server", "domain", "ip", "ping", "traceroute",
                       "nslookup", "dig", "cmd", "command", "exec", "run", "shell",
                       "file", "dir", "folder", "path", "dest", "output"];

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

async function testCommandInjection(target, siteMap) {
  const result  = { name: "Command Injection", passed: true, issues: [] };
  const base    = target.replace(/\/$/, "");

  const allEndpoints = new Set([base]);
  if (siteMap?.endpoints) {
    for (const ep of siteMap.endpoints) allEndpoints.add(ep.replace(/\/$/, ""));
  }

  for (const endpoint of allEndpoints) {
    for (const param of COMMON_PARAMS) {
      for (const { payload, desc } of PAYLOADS) {
        try {
          const testURL = `${endpoint}?${param}=${encodeURIComponent(payload)}`;
          const res     = await fetchURL(testURL);
          if (!res) continue;
          await delay(100);

          if (res.body.includes("pong") || res.body.includes("Pong")) {
            result.passed = false;
            result.issues.push({
              title:    "Command Injection Vulnerability Detected",
              location: `${endpoint}?${param}=...`,
              detail:   `Payload "${payload}" (${desc}) executed — "pong" reflected in response at HTTP ${res.status}.`,
              severity: "CRITICAL",
              risk:     "Attackers can execute arbitrary OS commands on your server — full takeover, data theft, lateral movement.",
              fixes: [
                { label: "Never pass user input to shell functions",
                  code:  "// ❌ VULNERABLE\nconst exec = require('child_process').exec;\nexec('ping ' + userInput);\n\n// ✅ SAFE — use execFile with arguments array\nconst { execFile } = require('child_process');\nexecFile('ping', [userInput]);" },
                { label: "Validate input against strict allowlist",
                  code:  "const ALLOWED_HOSTS = ['10.0.0.1', '10.0.0.2'];\nif (!ALLOWED_HOSTS.includes(userInput)) {\n  return res.status(400).send('Invalid host');\n}" }
              ]
            });
            break;
          }
        } catch { }
      }
    }

    if (result.issues.length > 0) break;

    try {
      for (const { payload, desc } of PAYLOADS) {
        const bodyObj = {};
        for (const p of COMMON_PARAMS.slice(0, 5)) bodyObj[p] = payload;
        const res = await sendPost(endpoint, bodyObj);
        if (!res) continue;
        await delay(100);

        if (res.body.includes("pong")) {
          result.passed = false;
          result.issues.push({
            title:    "Command Injection via POST Body Detected",
            location: `POST ${endpoint}`,
            detail:   `Payload "${payload}" (${desc}) in POST body executed — "pong" reflected in response.`,
            severity: "CRITICAL",
            risk:     "Attackers can execute arbitrary OS commands on your server.",
            fixes: [
              { label: "Never pass user input to shell functions",
                code:  "// ❌ VULNERABLE\nconst { exec } = require('child_process');\nexec('ping ' + req.body.host);\n\n// ✅ SAFE\nconst { execFile } = require('child_process');\nexecFile('ping', [req.body.host]);" }
            ]
          });
          break;
        }
      }
    } catch { }
  }

  return result;
}

module.exports = testCommandInjection;
