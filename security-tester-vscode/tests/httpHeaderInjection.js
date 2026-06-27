const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const CRLF_PAYLOADS = [
  "%0d%0aX-Injected:%20true",
  "%0aX-Injected:%20true",
  "%0d%0aLocation:%20http://evil.com",
  "%0d%0aSet-Cookie:%20session=injected",
];

const COMMON_PARAMS = ["redirect", "url", "uri", "path", "file", "page", "view",
                       "return", "next", "dest", "destination", "ref"];

function fetchWithHeaders(url, timeout = 10000) {
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

async function testHTTPHeaderInjection(target, siteMap) {
  const result  = { name: "HTTP Header Injection / CRLF", passed: true, issues: [] };
  const base    = target.replace(/\/$/, "");
  const targets = buildTargets(base, siteMap);

  for (const baseUrl of targets) {
    for (const payload of CRLF_PAYLOADS) {
      try {
        const parsed = new URL(baseUrl);
        const firstKey = [...parsed.searchParams.keys()][0] || "redirect";
        parsed.searchParams.set(firstKey, payload);
        const testURL = parsed.toString();
        const res     = await fetchWithHeaders(testURL);
        if (!res) continue;
        await delay(100);

        if (res.headers && (res.headers["x-injected"] !== undefined || 
            res.body.includes("X-Injected: true") ||
            res.body.includes("Location: http://evil.com"))) {
          result.passed = false;
          result.issues.push({
            title:    "HTTP Header Injection / CRLF Detected",
            location: `URL: ${testURL}`,
            detail:   `CRLF payload "${payload}" injected a custom header or split the response.`,
            severity: "HIGH",
            risk:     "Attackers can inject arbitrary HTTP headers — session fixation, XSS, cache poisoning, or response splitting.",
            fixes: [
              { label: "Remove all CR/LF characters from user input",
                code:  "// ❌ VULNERABLE\nres.redirect(userInput);\n\n// ✅ SAFE — strip CR/LF characters\nconst safe = userInput.replace(/[\\r\\n]/g, '');\nres.redirect(safe);" },
              { label: "Validate redirect targets against allowlist",
                code:  "const ALLOWED = ['/home', '/profile'];\nif (!ALLOWED.includes(userInput)) {\n  return res.status(400).send('Invalid redirect');\n}" }
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

module.exports = testHTTPHeaderInjection;
