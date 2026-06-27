const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const API_KEY_PATTERNS = [
  { pattern: /AKIA[0-9A-Z]{16}/, name: "AWS Access Key ID", severity: "CRITICAL",
    risk: "AWS keys grant full or limited access to AWS services and resources." },
  { pattern: /["']sk[-_]live[-_][a-zA-Z0-9]{10,}["']/i, name: "Stripe Live Secret Key", severity: "CRITICAL",
    risk: "Stripe live keys allow real payment processing and refunds." },
  { pattern: /ghp_[a-zA-Z0-9]{36}/, name: "GitHub Personal Access Token", severity: "HIGH",
    risk: "GitHub tokens allow access to repositories and actions." },
  { pattern: /xox[baprs]-[a-zA-Z0-9-]{10,}/, name: "Slack API Token", severity: "HIGH",
    risk: "Slack tokens grant access to Slack workspaces and messages." },
  { pattern: /["']AIza[0-9A-Za-z_-]{35}["']/, name: "Google API Key", severity: "HIGH",
    risk: "Google API keys provide access to Google Cloud services." },
  { pattern: /["']sk-[a-zA-Z0-9]{20,}["']/, name: "OpenAI / Generic Secret Key", severity: "HIGH",
    risk: "Secret keys can be used to access paid API services." },
  { pattern: /["'](?:pk|sk|test|live)_[a-zA-Z0-9]{10,}["']/i, name: "Stripe/Payment Key", severity: "CRITICAL",
    risk: "Payment processor keys can be abused for financial transactions." },
  { pattern: /-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----/i, name: "Private Key", severity: "CRITICAL",
    risk: "Private keys allow decryption of traffic and impersonation of the server." },
  { pattern: /["'](?:api_key|apikey|api-secret|apiSecret|secret_key|secretKey)["']\s*[:=]\s*["'][^"']+["']/i,
    name: "Generic API Key/Secret Assignment", severity: "HIGH",
    risk: "Hardcoded API secrets in source code or responses can be used to access protected services." },
];

const KEY_ASSIGNMENT_PATTERN = /["'](?:api_key|apikey|api-secret|apiSecret|secret_key|secretKey)["']\s*[:=]\s*["'][^"']+["']/gi;

function fetchURL(url, timeout = 10000) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const lib    = parsed.protocol === "https:" ? https : http;
      const req    = lib.get(url, { timeout, rejectUnauthorized: false }, (res) => {
        let data = "";
        res.on("data", (c) => { data += c; if (data.length > 500000) req.destroy(); });
        res.on("end", () => resolve({ status: res.statusCode, body: data, headers: res.headers }));
      });
      req.on("error",   () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
    } catch { resolve(null); }
  });
}

async function testAPIKeyLeaks(target, siteMap) {
  const result  = { name: "API Key / Secret Leaks", passed: true, issues: [] };
  const base    = target.replace(/\/$/, "");

  const pages = siteMap?.pages?.map(p => p.url) || [base, `${base}/api`, `${base}/.env`, `${base}/config`];

  for (const page of pages) {
    try {
      const res = await fetchURL(page);
      if (!res || res.status === 404) continue;
      await delay(100);

      const body = res.body;

      for (const { pattern, name, severity, risk } of API_KEY_PATTERNS) {
        const matches = body.match(pattern);
        if (!matches) continue;

        for (const match of matches.slice(0, 3)) {
          const masked = match.length > 12 ? match.slice(0, 8) + "..." + match.slice(-4) : "****";

          result.passed = false;
          result.issues.push({
            title:    `API Key / Secret Leaked: ${name}`,
            location: page,
            detail:   `Matched pattern: "${masked}". ${name} found in response body.`,
            severity: severity,
            risk:     risk,
            fixes: [
              { label: "Remove secrets from source code and API responses",
                code:  "// ❌ DANGEROUS — hardcoded in source\nconst apiKey = 'AKIA1234567890ABCDEF';\n\n// ✅ SAFE — use environment variables\nconst apiKey = process.env.AWS_ACCESS_KEY_ID;" },
              { label: "Use a secrets scanner in CI/CD pipeline",
                code:  "// Add to GitHub Actions:\n// - name: Secret Scanning\n//   uses: trufflesecurity/trufflehog@main\n//   with:\n//     path: ./" }
            ]
          });
          break;
        }
      }
    } catch { }
  }

  return result;
}

module.exports = testAPIKeyLeaks;
