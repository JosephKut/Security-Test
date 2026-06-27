const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const REDIRECT_PARAMS = ["url", "redirect", "redirect_uri", "redirect_url", "return",
                         "return_url", "return_to", "next", "dest", "destination",
                         "target", "goto", "link", "href", "ref", "referrer", "page"];

const EXTERNAL_URLS = [
  "http://evil.com",
  "https://evil.com",
  "//evil.com",
  "http://evil.com/phish",
];

function fetchNoRedirect(url, timeout = 10000) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const lib    = parsed.protocol === "https:" ? https : http;
      const req    = lib.get(url, { timeout, rejectUnauthorized: false, followRedirect: false }, (res) => {
        let data = "";
        res.on("data", (c) => { data += c; if (data.length > 500000) req.destroy(); });
        res.on("end", () => resolve({ status: res.statusCode, body: data, headers: res.headers }));
      });
      req.on("error",   () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
    } catch { resolve(null); }
  });
}

function buildTargets(target, siteMap) {
  const targets = new Set([target]);
  if (siteMap?.paramUrls) { for (const { url } of siteMap.paramUrls) targets.add(url); }
  if (siteMap?.endpoints) {
    for (const ep of siteMap.endpoints) {
      for (const p of REDIRECT_PARAMS) targets.add(`${ep}?${p}=test`);
    }
  }
  return [...targets];
}

async function testOpenRedirect(target, siteMap) {
  const result  = { name: "Open Redirect", passed: true, issues: [] };
  const base    = target.replace(/\/$/, "");
  const targets = buildTargets(base, siteMap);

  for (const baseUrl of targets) {
    for (const param of REDIRECT_PARAMS) {
      for (const externalUrl of EXTERNAL_URLS) {
        try {
          const testURL = `${baseUrl.split("?")[0]}?${param}=${encodeURIComponent(externalUrl)}`;
          const res = await fetchNoRedirect(testURL);
          if (!res) continue;
          await delay(100);

          const location = res.headers && res.headers["location"];

          if (res.status >= 300 && res.status < 400 && location) {
            if (location.includes("evil.com") || location.startsWith("//") || 
                (!location.startsWith("/") && !location.includes(base.replace(/https?:\/\//, "")))) {
              result.passed = false;
              result.issues.push({
                title:    "Open Redirect Vulnerability",
                location: `?${param}= at ${baseUrl.split("?")[0]}`,
                detail:   `Server redirects to "${location}" via parameter "${param}" (HTTP ${res.status}). External URL "${externalUrl}" accepted.`,
                severity: "HIGH",
                risk:     "Attackers can trick users into clicking legitimate-looking links that redirect to phishing sites — credential theft, malware.",
                fixes: [
                  { label: "Validate redirect URLs against an allowlist",
                    code:  "const ALLOWED_DOMAINS = ['yoursite.com'];\n\nfunction safeRedirect(url) {\n  try {\n    const parsed = new URL(url, 'https://yoursite.com');\n    if (!ALLOWED_DOMAINS.includes(parsed.hostname)) {\n      return '/default';\n    }\n    return url;\n  } catch { return '/default'; }\n}" },
                  { label: "Use indirect references instead of raw URLs",
                    code:  "// ❌ VULNERABLE\nres.redirect(req.query.url);\n\n// ✅ SAFE — use named routes\nconst ROUTES = { 'home': '/', 'profile': '/profile' };\nres.redirect(ROUTES[req.query.return] || '/');" }
                ]
              });
              break;
            }
          }

          if (res.body.toLowerCase().includes("evil.com") && res.body.includes("window.location")) {
            result.passed = false;
            result.issues.push({
              title:    "Open Redirect via JavaScript",
              location: `?${param}= at ${baseUrl.split("?")[0]}`,
              detail:   `External URL reflected in JavaScript redirect code.`,
              severity: "HIGH",
              risk:     "Same as HTTP redirect — users can be sent to phishing sites.",
              fixes: [
                { label: "Sanitize all URL parameters before using in JS",
                  code:  "// Never trust user input in window.location\nconst safe = validateUrl(userInput);\nwindow.location.href = safe;" }
              ]
            });
            break;
          }
        } catch { }
      }
      if (result.issues.length > 0) break;
    }
    if (result.issues.length > 0) break;
  }

  return result;
}

module.exports = testOpenRedirect;
