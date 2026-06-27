const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const TRAVERSAL_PATHS = [
  { path: "/../../../etc/passwd",             desc: "Linux system user file" },
  { path: "/../../windows/win.ini",           desc: "Windows config file" },
  { path: "/?file=../../../../etc/passwd",    desc: "Query param file inclusion" },
  { path: "/?page=../../../etc/shadow",       desc: "Linux shadow password file" },
  { path: "/static/../../../etc/passwd",      desc: "Static folder bypass" },
  { path: "/%2e%2e%2f%2e%2e%2fetc%2fpasswd", desc: "URL-encoded traversal" },
];

const SENSITIVE_SIGNATURES = [
  { sig: "root:x:0:0",   file: "/etc/passwd" },
  { sig: "[extensions]", file: "windows/win.ini" },
  { sig: "daemon:",      file: "/etc/passwd" },
  { sig: "/bin/bash",    file: "/etc/passwd" },
  { sig: "nobody:x:",    file: "/etc/passwd" },
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

async function testDirectoryTraversal(target, siteMap) {
  const result  = { name: "Directory Traversal", passed: true, issues: [] };
  const base    = target.replace(/\/$/, "");

  const allBases = new Set([base]);
  if (siteMap?.endpoints) {
    for (const ep of siteMap.endpoints) allBases.add(ep.replace(/\/$/, ""));
  }

  for (const currentBase of allBases) {
    for (const { path, desc } of TRAVERSAL_PATHS) {
      const testURL = `${currentBase}${path}`;
      const res     = await fetchURL(testURL);
      if (!res) continue;
      await delay(100);

      const body = res.body.toLowerCase();
      for (const { sig, file } of SENSITIVE_SIGNATURES) {
        if (body.includes(sig.toLowerCase())) {
          result.passed = false;
          result.issues.push({
            title:    "Directory Traversal — Sensitive File Exposed",
            location: `Traversal path : ${path}\n   Full URL     : ${testURL}\n   Exposed file : ${file} (${desc})`,
            detail:   `Signature "${sig}" found in response — server returned contents of "${file}".`,
            severity: "CRITICAL",
            risk:     "Attackers can read any file on your server — passwords, private keys, config files, source code.",
            fixes: [
              { label: "Node.js — validate and sanitize file paths",
                code:  "const path = require('path');\n\nconst BASE_DIR  = path.resolve('./public');\nconst requested = path.resolve(BASE_DIR, req.query.file);\n\nif (!requested.startsWith(BASE_DIR)) {\n  return res.status(403).send('Access denied');\n}\nfs.readFile(requested, ...);" },
              { label: "Use a whitelist of allowed files",
                code:  "const ALLOWED = { 'report': './files/report.pdf' };\nconst file = ALLOWED[req.query.name];\nif (!file) return res.status(404).send('Not found');\nres.sendFile(file);" },
              { label: "Nginx — block traversal patterns",
                code:  "location ~* (\\.\\./|%2e%2e) {\n    return 403;\n}" }
            ]
          });
          break;
        }
      }
    }
  }

  return result;
}

module.exports = testDirectoryTraversal;
