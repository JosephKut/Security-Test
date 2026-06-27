const https = require("https");
const http  = require("http");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const COMMON_PATHS = ["/package.json", "/bower.json", "/composer.json", "/Gemfile",
                      "/requirements.txt", "/Pipfile", "/yarn.lock", "/package-lock.json",
                      "/go.mod", "/Cargo.toml", "/build.gradle", "/pom.xml",
                      "/mix.exs", "/shard.yml", "/pubspec.yaml"];

const COMMON_CDN_PATHS = [
  "/wp-content", "/node_modules", "/vendor", "/lib", "/assets/vendor",
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

const OLD_VERSIONS = [
  { pattern: /"jquery":\s*"([^"]+)"/, name: "jQuery", maxSafe: "3.5.0" },
  { pattern: /"lodash":\s*"([^"]+)"/, name: "Lodash", maxSafe: "4.17.21" },
  { pattern: /"express":\s*"([^"]+)"/, name: "Express", maxSafe: "4.18.0" },
  { pattern: /"react":\s*"([^"]+)"/, name: "React", maxSafe: "18.0.0" },
  { pattern: /"angular":\s*"([^"]+)"/, name: "Angular", maxSafe: "15.0.0" },
  { pattern: /"vue":\s*"([^"]+)"/, name: "Vue", maxSafe: "3.3.0" },
  { pattern: /"axios":\s*"([^"]+)"/, name: "Axios", maxSafe: "1.6.0" },
  { pattern: /"moment":\s*"([^"]+)"/, name: "Moment.js", maxSafe: "2.29.4" },
];

async function testDependencies(target, siteMap) {
  const result  = { name: "Vulnerable Dependencies", passed: true, issues: [] };
  const base    = target.replace(/\/$/, "");

  let foundManifest = false;

  for (const path of COMMON_PATHS) {
    try {
      const testURL = `${base}${path}`;
      const res     = await fetchURL(testURL);
      if (!res || res.status !== 200) continue;
      await delay(100);

      foundManifest = true;
      const body = res.body;

      result.issues.push({
        title:    `Dependency Manifest Exposed: ${path}`,
        location: testURL,
        detail:   `File "${path}" is publicly accessible — attackers can see your exact dependency versions and look up known vulnerabilities.`,
        severity: "MEDIUM",
        risk:     "Exposed dependency manifests allow attackers to identify vulnerable libraries and craft targeted exploits.",
        fixes: [
          { label: "Block access to dependency manifest files",
            code:  "# Nginx — block package manifests\nlocation ~* (package\\.json|composer\\.lock|yarn\\.lock|Gemfile\\.lock) {\n    deny all;\n    return 404;\n}" }
        ]
      });

      for (const { pattern, name, maxSafe } of OLD_VERSIONS) {
        const match = body.match(pattern);
        if (match) {
          const version = match[1].replace(/[\^~]/g, "");
          result.issues.push({
            title:    `Dependency Found: ${name} ${version}`,
            location: testURL,
            detail:   `${name} version ${version} found in ${path}. Check if this version has known CVEs.`,
            severity: "INFO",
            risk:     `Dependencies with known vulnerabilities (CVEs) can be exploited. Keep all dependencies updated.`,
            fixes: [
              { label: `Update ${name} to the latest version`,
                code:  `# Check for known vulnerabilities:\nnpm audit\n\n# Update the package:\nnpm install ${name.toLowerCase()}@latest\n\n# Or use a specific safe version:\nnpm install ${name.toLowerCase()}@${maxSafe}` }
            ]
          });
          result.passed = false;
        }
      }

      if (path === "/package.json" && !result.issues.some(i => i.title.startsWith("Dependency Found"))) {
        result.passed = false;
        result.issues.push({
          title:    "Dependencies Found — No Version Analysis Available",
          location: testURL,
          detail:   "package.json is exposed but no known-vulnerable versions were detected. Review the manifest and run `npm audit` for a full security audit.",
          severity: "LOW",
          risk:     "Without auditing, vulnerable dependencies may go unnoticed.",
          fixes: [
            { label: "Run npm audit regularly",
              code:  "npm audit\n# Or generate a detailed report:\nnpm audit --json > audit-report.json" }
          ]
        });
      }
    } catch { }
  }

  if (!foundManifest) {
    for (const cdnPath of COMMON_CDN_PATHS) {
      try {
        const testURL = `${base}${cdnPath}`;
        const res     = await fetchURL(testURL);
        if (!res || res.status === 404) continue;
        await delay(100);

        result.issues.push({
          title:    `Vendor Directory Exposed: ${cdnPath}`,
          location: testURL,
          detail:   `Vendor/third-party directory "${cdnPath}" is publicly accessible. May expose client-side library versions.`,
          severity: "MEDIUM",
          risk:     "Exposed vendor directories reveal library versions, helping attackers identify known client-side vulnerabilities.",
          fixes: [
            { label: "Block access to vendor/3rd-party directories",
              code:  "# Nginx\nlocation ~* /(vendor|node_modules|bower_components)/ {\n    deny all;\n    return 404;\n}" }
          ]
        });
        break;
      } catch { }
    }
  }

  return result;
}

module.exports = testDependencies;
