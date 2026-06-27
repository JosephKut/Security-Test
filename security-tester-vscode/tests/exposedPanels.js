const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const COMMON_PATHS = [
  "/admin", "/administrator", "/admin.php", "/admin/", "/admin/login", "/admin/login.php",
  "/wp-admin", "/wp-login.php", "/dashboard", "/cpanel", "/plesk",
  "/login", "/signin", "/auth", "/signup", "/register",
  "/.git", "/.git/config", "/.env", "/.env.example", "/.htaccess",
  "/backup", "/backups", "/db_backup", "/backup.sql", "/db.sql",
  "/phpinfo.php", "/info.php", "/test.php", "/debug",
  "/api", "/api/", "/api/v1", "/api/docs", "/swagger", "/api-docs",
  "/config", "/config.php", "/configuration", "/settings",
  "/logs", "/error.log", "/access.log", "/debug.log",
  "/phpmyadmin", "/pma", "/mysql", "/adminer.php",
  "/server-status", "/server-info", "/actuator/health", "/actuator/info",
  "/console", "/manager/html", "/jmx-console",
  "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
  "/.aws/credentials", "/.ssh/id_rsa",
];

const SENSITIVE_PATTERNS = [
  { pattern: /DB_HOST|DB_USER|DB_PASSWORD|DB_NAME/i, name: "Database credentials" },
  { pattern: /password\s*[:=]\s*["'][^"']+/i, name: "Plain-text password" },
  { pattern: /AWS_ACCESS_KEY|AWS_SECRET_KEY|AKIA[0-9A-Z]{16}/i, name: "AWS access key" },
  { pattern: /-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----/i, name: "Private key" },
  { pattern: /admin:|root:/, name: "Shadow file entry" },
];

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

async function testExposedPanels(target, siteMap) {
  const result  = { name: "Exposed Admin Panels & Files", passed: true, issues: [] };
  const base    = target.replace(/\/$/, "");

  for (const path of COMMON_PATHS) {
    try {
      const testURL = `${base}${path}`;
      const res     = await fetchURL(testURL);
      if (!res) continue;
      await delay(100);

      if (res.status === 200 || res.status === 401 || res.status === 403) {
        const body = res.body;

        if (res.status === 200) {
          const bodyLower = body.toLowerCase();

          let foundSensitive = null;
          for (const { pattern, name } of SENSITIVE_PATTERNS) {
            if (pattern.test(body)) {
              foundSensitive = name;
              break;
            }
          }

          const isLoginPage = bodyLower.includes("login") || bodyLower.includes("sign in") ||
                              bodyLower.includes("username") || bodyLower.includes("password");

          if (foundSensitive) {
            result.passed = false;
            result.issues.push({
              title:    `Sensitive File Exposed — ${path}`,
              location: testURL,
              detail:   `Path "${path}" returned HTTP 200 with content matching "${foundSensitive}". This file should not be publicly accessible.`,
              severity: "CRITICAL",
              risk:     "Attackers can read sensitive configuration files, credentials, or source code exposed to the public.",
              fixes: [
                { label: "Block access to sensitive paths in web server config",
                  code:  "# Nginx — block sensitive files\nlocation ~* (\\.git|\\.env|backup|config|logs) {\n    deny all;\n    return 404;\n}" },
                { label: "Move sensitive files outside web root",
                  code:  "// ❌ DANGEROUS — .env in public web root\n// ✅ SAFE — .env in parent directory, not served by web server" }
              ]
            });
            break;
          }

          if (isLoginPage) {
            result.issues.push({
              title:    "Admin/Login Panel Exposed",
              location: testURL,
              detail:   `Path "${path}" returned HTTP 200 — admin or login panel is publicly accessible.`,
              severity: "MEDIUM",
              risk:     "Exposed admin panels give attackers a target for brute force and vulnerability scanning.",
              fixes: [
                { label: "Restrict admin panels by IP or VPN",
                  code:  "# Nginx — restrict by IP\nlocation /admin {\n    allow 10.0.0.0/8;\n    allow 192.168.0.0/16;\n    deny all;\n}" }
              ]
            });
          }
        }
      } else if (res.status === 200) {
        const ct = (res.headers && res.headers["content-type"]) || "";
        if (ct.includes("application/octet-stream") || ct.includes("text/plain")) {
          result.issues.push({
            title:    `Potential File Exposure — ${path}`,
            location: testURL,
            detail:   `Path "${path}" returned HTTP 200 with content-type "${ct}". May be serving raw files.`,
            severity: "LOW",
            risk:     "Sensitive files may be downloadable if they exist at the exposed path.",
            fixes: [
              { label: "Verify no sensitive files are in web root",
                code:  "Check for backup files, .env, .git, config files in the public directory." }
            ]
          });
        }
      }
    } catch { }
  }

  return result;
}

module.exports = testExposedPanels;
