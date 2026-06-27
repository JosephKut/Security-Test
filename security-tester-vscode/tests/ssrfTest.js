const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const SSRF_PARAMS = ["url", "uri", "src", "source", "dest", "destination",
                     "redirect", "proxy", "fetch", "load", "link", "host",
                     "callback", "return", "next", "data", "reference"];

const SSRF_TARGETS = [
  { url: "http://169.254.169.254/latest/meta-data/",            label: "AWS Metadata Service",    marker: "ami-id" },
  { url: "http://169.254.169.254/latest/meta-data/iam/",        label: "AWS IAM Credentials",     marker: "security-credentials" },
  { url: "http://metadata.google.internal/computeMetadata/v1/", label: "GCP Metadata Service",    marker: "computeMetadata" },
  { url: "http://localhost/",                                    label: "Localhost Internal",       marker: null },
  { url: "http://127.0.0.1/",                                   label: "Loopback Internal",        marker: null },
  { url: "http://localhost:27017/",                              label: "Local MongoDB",            marker: "mongodb" },
  { url: "http://localhost:6379/",                               label: "Local Redis",              marker: "redis" },
];

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

async function testSSRF(target, siteMap) {
  const result    = { name: "Server-Side Request Forgery (SSRF)", passed: true, issues: [] };
  const base      = target.replace(/\/$/, "");

  const probeBases = new Set([base]);
  if (siteMap?.paramUrls) {
    for (const { url } of siteMap.paramUrls) {
      try { probeBases.add(new URL(url).origin + new URL(url).pathname); }
      catch { }
    }
  }

  for (const probeBase of probeBases) {
    for (const param of SSRF_PARAMS) {
      for (const { url: ssrfUrl, label, marker } of SSRF_TARGETS) {
        const testURL = `${probeBase}?${param}=${encodeURIComponent(ssrfUrl)}`;
        const res     = await fetchURL(testURL);
        if (!res || res.status === 404) continue;
        await delay(100);

        const bodyLower = res.body.toLowerCase();
        const triggered = marker
          ? bodyLower.includes(marker.toLowerCase())
          : (res.status === 200 && res.body.length > 100 &&
             (bodyLower.includes("localhost") || bodyLower.includes("html")));

        if (triggered) {
          result.passed = false;
          result.issues.push({
            title:    `SSRF Vulnerability — ${label} Accessible`,
            location: `Parameter "?${param}=" at ${probeBase}`,
            detail:   `Server fetched internal URL "${ssrfUrl}" and returned its contents (HTTP ${res.status}).`,
            severity: label.includes("AWS") || label.includes("GCP") ? "CRITICAL" : "HIGH",
            risk:     "Attackers trick your server into fetching internal systems — stealing cloud credentials or mapping your private network.",
            fixes: [
              { label: "Validate URLs against a strict allowlist",
                code:  "const ALLOWED_HOSTS = ['api.yourservice.com'];\n\nfunction isSafeURL(inputUrl) {\n  try {\n    const parsed = new URL(inputUrl);\n    const blocked = ['localhost','127.0.0.1','0.0.0.0','169.254.169.254'];\n    if (blocked.some(b => parsed.hostname.startsWith(b))) return false;\n    return ALLOWED_HOSTS.includes(parsed.hostname);\n  } catch { return false; }\n}" },
              { label: "Block metadata IP at network level",
                code:  "iptables -A OUTPUT -d 169.254.169.254 -j DROP" }
            ]
          });
          break;
        }
      }
    }
  }

  return result;
}

module.exports = testSSRF;
