const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const ENDPOINTS = ["", "/api", "/api/users", "/api/data"];
const EVIL_ORIGIN = "https://evil-attacker.com";

function fetchOptions(url, origin) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const lib    = parsed.protocol === "https:" ? https : http;
      const opts = {
        method: "OPTIONS",
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
        path: parsed.pathname + parsed.search,
        headers: {
          "Origin": origin,
          "Access-Control-Request-Method": "GET",
        },
        rejectUnauthorized: false,
        timeout: 10000,
      };
      const req = lib.request(opts, (res) => {
        const acao = res.headers["access-control-allow-origin"] || "";
        const acac = res.headers["access-control-allow-credentials"] || "";
        res.resume();
        res.on("end", () => resolve({ acao, acac }));
      });
      req.on("error",   () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
      req.end();
    } catch { resolve(null); }
  });
}

async function testCORS(target, siteMap) {
  const result  = { name: "CORS Misconfiguration", passed: true, issues: [] };
  const baseUrl = target.replace(/\/$/, "");

  for (const endpoint of ENDPOINTS) {
    const url = `${baseUrl}${endpoint}`;
    try {
      const res = await fetchOptions(url, EVIL_ORIGIN);
      if (!res) continue;
      await delay(100);

      const origin      = res.acao;
      const credentials = res.acac;

      if ((origin === "*" || origin === EVIL_ORIGIN) && credentials === "true") {
        result.passed = false;
        result.issues.push({
          title:    "CRITICAL CORS — Any Origin + Credentials Allowed",
          location: url,
          detail:   `Access-Control-Allow-Origin: ${origin}\nAccess-Control-Allow-Credentials: true`,
          severity: "CRITICAL",
          risk:     "Any website can make authenticated requests to your API — reading private data or taking over accounts.",
          fixes: [
            { label: "Whitelist specific origins",
              code:  "// Never combine wildcard with credentials\n// ❌ DANGEROUS\napp.use(cors({ origin: '*', credentials: true }));\n\n// ✅ SAFE\napp.use(cors({ origin: ['https://yoursite.com'], credentials: true }));" }
          ]
        });
      } else if (origin === "*") {
        result.issues.push({
          title:    "CORS Allows All Origins (Wildcard)",
          location: url,
          detail:   "Access-Control-Allow-Origin: * — any website can read this API's responses.",
          severity: "MEDIUM",
          risk:     "Fine for public APIs. Dangerous if any sensitive data is returned.",
          fixes: [
            { label: "Restrict to known origins if response has sensitive data",
              code:  "app.use(cors({ origin: ['https://yoursite.com'] }));" }
          ]
        });
      } else if (origin === EVIL_ORIGIN) {
        result.passed = false;
        result.issues.push({
          title:    "CORS Reflects Arbitrary Origin",
          location: url,
          detail:   `Server reflected evil origin: Access-Control-Allow-Origin: ${origin}`,
          severity: "HIGH",
          risk:     "Server blindly allows any origin — effectively wildcard but works with credentials too.",
          fixes: [
            { label: "Validate origin strictly before reflecting",
              code:  "const allowed = new Set(['https://yoursite.com']);\nif (allowed.has(req.headers.origin)) {\n  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n}" }
          ]
        });
      }
    } catch { }
  }

  return result;
}

module.exports = testCORS;
