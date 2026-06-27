const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

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

function uploadFile(url, fieldName, fileName, fileContent, timeout = 10000) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const lib    = parsed.protocol === "https:" ? https : http;
      const boundary = "----FormBoundary" + Math.random().toString(36).slice(2);
      const bodyParts = [
        `--${boundary}\r\nContent-Disposition: form-data; name="${fieldName}"; filename="${fileName}"\r\nContent-Type: application/octet-stream\r\n\r\n${fileContent}\r\n--${boundary}--\r\n`
      ];
      const body = bodyParts.join("");

      const opts = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: "POST",
        headers: {
          "Content-Type": `multipart/form-data; boundary=${boundary}`,
          "Content-Length": Buffer.byteLength(body),
        },
        rejectUnauthorized: false,
        timeout,
      };

      const req = lib.request(opts, (res) => {
        let data = "";
        res.on("data", (c) => { data += c; if (data.length > 500000) req.destroy(); });
        res.on("end", () => resolve({ status: res.statusCode, body: data }));
      });
      req.on("error",   () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
      req.write(body);
      req.end();
    } catch { resolve(null); }
  });
}

async function testFileUpload(target, siteMap) {
  const result  = { name: "File Upload Vulnerabilities", passed: true, issues: [] };
  const base    = target.replace(/\/$/, "");

  const uploadEndpoints = new Set();
  if (siteMap?.forms) {
    for (const form of siteMap.forms) {
      const hasFileField = form.fields.some(f => 
        f.toLowerCase().includes("file") || f.toLowerCase().includes("upload") ||
        f.toLowerCase().includes("avatar") || f.toLowerCase().includes("image") ||
        f.toLowerCase().includes("photo") || f.toLowerCase().includes("resume") ||
        f.toLowerCase().includes("attachment") || f.toLowerCase().includes("pdf") ||
        f.toLowerCase().includes("document") || f.toLowerCase().includes("csv") ||
        f.toLowerCase().includes("import") || f.toLowerCase().includes("excel"));
      if (hasFileField) {
        uploadEndpoints.add(form.action);
      }
    }
  }

  const commonUploadPaths = ["/upload", "/api/upload", "/file/upload", "/media/upload",
                             "/images/upload", "/api/files", "/import", "/api/import",
                             "/avatar", "/api/avatar"];
  for (const p of commonUploadPaths) uploadEndpoints.add(`${base}${p}`);

  if (uploadEndpoints.size === 0) return result;

  for (const endpoint of Array.from(uploadEndpoints).slice(0, 5)) {
    try {
      const res = await uploadFile(endpoint, "file", "test.txt", "Security test file - safe content");
      if (!res) continue;
      await delay(100);

      if (res.status === 200 || res.status === 201 || res.status === 302) {
        const bodyLower = res.body.toLowerCase();
        if (bodyLower.includes("success") || bodyLower.includes("uploaded") ||
            bodyLower.includes("accepted") || bodyLower.includes("saved") ||
            bodyLower.includes("test.txt")) {
          result.passed = false;
          result.issues.push({
            title:    "File Upload Endpoint Detected",
            location: `POST ${endpoint}`,
            detail:   `Upload endpoint accepted file "test.txt" with HTTP ${res.status}. Verify it restricts file types and sizes.`,
            severity: "MEDIUM",
            risk:     "File upload endpoints without proper restrictions allow attackers to upload webshells, malware, or fill storage.",
            fixes: [
              { label: "Restrict file types by extension and MIME type",
                code:  "const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'application/pdf'];\nconst ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.pdf'];\n\nfunction validateFile(file) {\n  if (!ALLOWED_TYPES.includes(file.mimetype)) return false;\n  const ext = path.extname(file.name).toLowerCase();\n  if (!ALLOWED_EXTENSIONS.includes(ext)) return false;\n  return true;\n}" },
              { label: "Store uploaded files outside web root",
                code:  "// ❌ DANGEROUS — saves to public path\nfile.mv('./public/uploads/' + file.name);\n\n// ✅ SAFE — saves outside web root, serve via download endpoint\nfile.mv('/data/uploads/' + uuid + ext);" },
              { label: "Scan uploaded files for malware",
                code:  "const clamav = require('clamav.js');\nconst isInfected = await clamav.scan(filePath);" }
            ]
          });
          break;
        }
      }
    } catch { }
  }

  return result;
}

module.exports = testFileUpload;
