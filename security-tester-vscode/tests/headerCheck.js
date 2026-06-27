const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const SECURITY_HEADERS = [
  { name: "Strict-Transport-Security", severity: "HIGH",
    desc: "Enforces HTTPS connections and prevents downgrade attacks.",
    risk: "Without HSTS, users can be downgraded to HTTP via SSL stripping.",
    fixLabel: "Add Strict-Transport-Security header",
    fixCode: "// Nginx:\nadd_header Strict-Transport-Security 'max-age=63072000; includeSubDomains; preload';" },
  { name: "Content-Security-Policy", severity: "HIGH",
    desc: "Controls which resources can be loaded — prevents XSS and data injection.",
    risk: "Without CSP, XSS payloads can load external scripts and exfiltrate data.",
    fixLabel: "Add Content-Security-Policy header",
    fixCode: "// Nginx:\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'\";" },
  { name: "X-Frame-Options", severity: "MEDIUM",
    desc: "Prevents clickjacking by blocking your site from being loaded in iframes.",
    risk: "Attacker can embed your site in a transparent iframe and trick users into clicking.",
    fixLabel: "Add X-Frame-Options header",
    fixCode: "// Nginx:\nadd_header X-Frame-Options SAMEORIGIN;" },
  { name: "X-Content-Type-Options", severity: "MEDIUM",
    desc: "Prevents MIME type sniffing — browsers won't interpret files as a different type.",
    risk: "Attacker can upload a fake .jpg containing script that gets executed as JavaScript.",
    fixLabel: "Add X-Content-Type-Options header",
    fixCode: "// Nginx:\nadd_header X-Content-Type-Options nosniff;" },
  { name: "Referrer-Policy", severity: "LOW",
    desc: "Controls how much referrer information is sent to other sites.",
    risk: "Sensitive URL parameters (tokens, session IDs) may leak in the Referer header.",
    fixLabel: "Add Referrer-Policy header",
    fixCode: "// Nginx:\nadd_header Referrer-Policy 'strict-origin-when-cross-origin';" },
  { name: "Permissions-Policy", severity: "LOW",
    desc: "Controls which browser APIs (camera, mic, location) the site can access.",
    risk: "Reduces attack surface by disabling unused sensitive features.",
    fixLabel: "Add Permissions-Policy header",
    fixCode: "// Nginx:\nadd_header Permissions-Policy 'camera=(), microphone=(), geolocation=()';" },
  { name: "X-XSS-Protection", severity: "LOW",
    desc: "Legacy XSS filter (largely obsolete but still recommended).",
    risk: "Older browsers may benefit from the XSS filter.",
    fixLabel: "Add X-XSS-Protection header",
    fixCode: "// Nginx:\nadd_header X-XSS-Protection '1; mode=block';" },
];

const safeHeaderNames = SECURITY_HEADERS.map(h => h.name.toLowerCase());

function fetchURL(url, timeout = 10000) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const lib    = parsed.protocol === "https:" ? https : http;
      const req    = lib.get(url, { timeout, rejectUnauthorized: false }, (res) => {
        let data = "";
        res.on("data", (c) => { data += c; if (data.length > 500000) req.destroy(); });
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers }));
      });
      req.on("error",   () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
    } catch { resolve(null); }
  });
}

async function testHeaders(target, siteMap) {
  const result  = { name: "Security Headers", passed: true, issues: [] };
  const base    = target.replace(/\/$/, "");

  const pages = siteMap?.pages?.map(p => p.url) || [base, `${base}/api`, `${base}/login`];

  const checkedHeaders = new Set();

  for (const page of pages) {
    try {
      const res = await fetchURL(page);
      if (!res || res.status === 404) continue;
      await delay(100);

      const responseHeaders = res.headers;

      for (const sh of SECURITY_HEADERS) {
        const headerKey = sh.name.toLowerCase();
        if (checkedHeaders.has(headerKey)) continue;

        const found = Object.keys(responseHeaders).some(h => h.toLowerCase() === headerKey);

        if (!found) {
          result.passed = false;
          result.issues.push({
            title:    `Missing Security Header: ${sh.name}`,
            location: page,
            detail:   `${sh.desc}`,
            severity: sh.severity,
            risk:     sh.risk,
            fixes:    [{ label: sh.fixLabel, code: sh.fixCode }]
          });
        }

        checkedHeaders.add(headerKey);
      }
    } catch { }
  }

  if (checkedHeaders.size > 0 && result.issues.length === 0) {
    result.issues.push({
      title:    "All Security Headers Present",
      location: base,
      detail:   `Headers checked: ${[...checkedHeaders].join(", ")}. All present and configured.`,
      severity: "INFO",
      risk:     "Good security header configuration.",
      fixes:    []
    });
  }

  return result;
}

module.exports = testHeaders;
