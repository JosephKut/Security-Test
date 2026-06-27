const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const PAYLOADS = [
  { payload: "{{7*7}}",      engine: "Jinja2 / Twig / Django" },
  { payload: "${7*7}",       engine: "Freemarker / MVEL" },
  { payload: "#{7*7}",       engine: "Velocity" },
  { payload: "*{7*7}",       engine: "Spring EL" },
  { payload: "{{7*'7'}}",    engine: "Jinja2 (math)" },
  { payload: "${7*7}",       engine: "JSP EL / Freemarker" },
];

const COMMON_PARAMS = ["name", "username", "user", "search", "q", "page", "template",
                       "view", "file", "path", "input", "msg", "message", "error"];

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

function buildTargets(target, siteMap) {
  const targets = new Set();
  for (const p of COMMON_PARAMS) targets.add(`${target}?${p}=test`);
  if (siteMap?.paramUrls) { for (const { url } of siteMap.paramUrls) targets.add(url); }
  if (siteMap?.endpoints) {
    for (const ep of siteMap.endpoints) {
      for (const p of COMMON_PARAMS) targets.add(`${ep}?${p}=test`);
    }
  }
  return [...targets];
}

async function testSSTI(target, siteMap) {
  const result  = { name: "SSTI (Template Injection)", passed: true, issues: [] };
  const base    = target.replace(/\/$/, "");
  const targets = buildTargets(base, siteMap);

  for (const baseUrl of targets) {
    for (const { payload, engine } of PAYLOADS) {
      try {
        const parsed = new URL(baseUrl);
        for (const key of parsed.searchParams.keys()) parsed.searchParams.set(key, payload);
        const testURL = parsed.toString();
        const res     = await fetchURL(testURL);
        if (!res) continue;
        await delay(100);

        if (res.body.includes("49") || res.body.includes("7777777")) {
          result.passed = false;
          result.issues.push({
            title:    `SSTI Vulnerability — ${engine}`,
            location: `URL: ${testURL}`,
            detail:   `Payload "${payload}" evaluated to "49" in response — template engine (${engine}) is processing user input.`,
            severity: "CRITICAL",
            risk:     "Attackers can execute arbitrary code on your server by injecting template directives — full server takeover.",
            fixes: [
              { label: "Never render user input as templates",
                code:  "// ❌ VULNERABLE — user input compiled as template\nconst output = templateEngine.compile(userInput);\n\n// ✅ SAFE — pass user input as data, not as template\nconst output = templateEngine.render(template, { userInput });" },
              { label: "Sandbox the template engine",
                code:  "// Restrict available functions/objects\nconst env = nunjucks.configure({ autoescape: true });\nconst output = nunjucks.renderString(template, { userInput });" }
            ]
          });
          break;
        }
      } catch { }
    }
    if (result.issues.length > 0) break;
  }

  if (!result.issues.length && siteMap?.endpoints) {
    for (const endpoint of siteMap.endpoints) {
      for (const { payload, engine } of PAYLOADS) {
        try {
          const bodyData = {};
          for (const p of COMMON_PARAMS.slice(0, 3)) bodyData[p] = payload;
          const res = await sendPost(endpoint, bodyData);
          if (!res) continue;
          await delay(100);

          if (res.body.includes("49")) {
            result.passed = false;
            result.issues.push({
              title:    `SSTI via POST Body — ${engine}`,
              location: `POST ${endpoint}`,
              detail:   `Payload "${payload}" evaluated to "49" in POST response — template engine processing user input.`,
              severity: "CRITICAL",
              risk:     "Attackers can execute arbitrary code via POST data.",
              fixes: [
                { label: "Never render user input as templates",
                  code:  "✅ Pass user input as template data, not as template source." }
              ]
            });
            break;
          }
        } catch { }
      }
      if (result.issues.length > 0) break;
    }
  }

  return result;
}

module.exports = testSSTI;
