const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const CSRF_TOKEN_FIELDS = ["csrf", "csrf_token", "_token", "authenticity_token", "csrfmiddlewaretoken",
                           "__RequestVerificationToken", "xsrf", "xsrf-token", "token", "_csrf"];

const CSRF_HEADERS = ["x-csrf-token", "x-xsrf-token", "x-csrf-protection", "x-csrf"];

const CSRF_META = ["csrf-token", "csrf-param", "xsrf-token"];

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

async function testCSRF(target, siteMap) {
  const result  = { name: "CSRF", passed: true, issues: [] };
  const base    = target.replace(/\/$/, "");

  const forms = siteMap?.forms || [];

  if (forms.length === 0) {
    return result;
  }

  for (const form of forms) {
    try {
      const res = await fetchURL(form.foundOn || form.action);
      if (!res || res.status === 404) continue;
      await delay(100);

      const body = res.body;
      const hasCSRFToken = CSRF_TOKEN_FIELDS.some(f => body.includes(f));
      const hasCSRFMeta = CSRF_META.some(m => body.includes(m));

      const responseHeaders = res.headers;
      const hasCSRFHeader = CSRF_HEADERS.some(h => responseHeaders[h] !== undefined);

      if (!hasCSRFToken && !hasCSRFMeta && !hasCSRFHeader && form.method.toUpperCase() === "POST") {
        result.passed = false;
        result.issues.push({
          title:    "Missing CSRF Protection",
          location: `Form action: ${form.action} (on ${form.foundOn})`,
          detail:   `POST form ${form.action} has no CSRF token field, meta tag, or X-CSRF header. Fields: ${form.fields.join(", ")}`,
          severity: "HIGH",
          risk:     "Attackers can forge cross-site requests on behalf of authenticated users — account takeover, data modification.",
          fixes: [
            { label: "Add CSRF token to all POST forms",
              code:  "// Express.js with csurf middleware:\nconst csrf = require('csurf');\napp.use(csrf({ cookie: true }));\n\n// In your form template:\n<input type=\"hidden\" name=\"_csrf\" value=\"<%= csrfToken %>\">" },
            { label: "Set SameSite cookie attribute",
              code:  "res.cookie('session', token, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'strict'  // Prevents CSRF\n});" }
          ]
        });
      }
    } catch { }
  }

  return result;
}

module.exports = testCSRF;
