const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const PAYLOADS = [
  "<script>alert('xss')</script>",
  "<img src=x onerror=alert(1)>",
  "javascript:alert(1)",
  "'><svg onload=alert(1)>",
  "<body onload=alert(1)>"
];

const COMMON_PARAMS = ["q", "search", "name", "msg", "input", "query", "text", "s"];

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
  for (const p of COMMON_PARAMS) targets.add(`${target}?${p}=test`);
  if (siteMap?.paramUrls) { for (const { url } of siteMap.paramUrls) targets.add(url); }
  if (siteMap?.endpoints) {
    for (const ep of siteMap.endpoints) {
      for (const p of COMMON_PARAMS) targets.add(`${ep}?${p}=test`);
    }
  }
  return [...targets];
}

async function testXSS(target, siteMap) {
  const result  = { name: "Cross-Site Scripting (XSS)", passed: true, issues: [] };
  const targets = buildTargets(target.replace(/\/$/, ""), siteMap);

  for (const baseUrl of targets) {
    for (const payload of PAYLOADS) {
      try {
        const parsed = new URL(baseUrl);
        for (const key of parsed.searchParams.keys()) parsed.searchParams.set(key, payload);
        const testURL = parsed.toString();
        const res     = await fetchURL(testURL);
        await delay(100);

        if (res && res.body.includes(payload)) {
          result.passed = false;
          result.issues.push({
            title:    "Reflected XSS Vulnerability",
            location: `URL: ${testURL}`,
            detail:   `Payload "${payload}" returned unescaped in HTML response.`,
            severity: "HIGH",
            risk:     "Attackers inject scripts that run in victims' browsers — stealing cookies or session tokens.",
            fixes: [
              { label: "Node.js — HTML-encode all output",
                code:  "const he = require('he');\nres.send('<p>' + he.encode(userInput) + '</p>');" },
              { label: "React — never use dangerouslySetInnerHTML",
                code:  "// ✅ Safe — React escapes by default\n<p>{userInput}</p>" }
            ]
          });
          break;
        }
      } catch { }
    }
  }

  return result;
}

module.exports = testXSS;
