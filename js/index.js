/**
 * =============================================
 *  SECURITY TESTER v5 - Node.js
 *  Educational Use Only
 *  Only test systems you own or have permission
 * =============================================
 *
 *  Usage:
 *    node index.js https://yoursite.com
 *
 *  Options:
 *    --no-crawl   Skip crawler, test root URL only
 *    --depth=N    Set crawl depth (default: 4)
 *    --pages=N    Max pages to crawl (default: 100)
 *
 *  Examples:
 *    node index.js https://yoursite.com
 *    node index.js https://yoursite.com --depth=2
 *    node index.js https://yoursite.com --no-crawl
 * =============================================
 */

const config  = require("./config");
const { crawl } = require("./crawler");

// ── Injection Tests ───────────────────────────────────────────
const testSQLInjection        = require("./tests/sqlInjection");
const testXSS                 = require("./tests/xssTest");
const testCommandInjection    = require("./tests/commandInjection");
const testDirectoryTraversal  = require("./tests/directoryTraversal");
const testXXE                 = require("./tests/xxeTest");
const testSSTI                = require("./tests/sstiTest");
const testHTTPHeaderInjection = require("./tests/httpHeaderInjection");

// ── Authentication & Session ──────────────────────────────────
const testBruteForce          = require("./tests/bruteForce");
const testJWT                 = require("./tests/jwtTest");
const testCSRF                = require("./tests/csrfTest");

// ── Access Control ────────────────────────────────────────────
const testAccessControl       = require("./tests/accessControl");
const testMassAssignment      = require("./tests/massAssignmentTest");
const testOpenRedirect        = require("./tests/openRedirect");

// ── Infrastructure & Network ──────────────────────────────────
const testExposedPanels       = require("./tests/exposedPanels");
const testSSLTLS              = require("./tests/sslTlsTest");
const testSubdomains          = require("./tests/subdomainTest");
const testSSRF                = require("./tests/ssrfTest");

// ── Data & Configuration ──────────────────────────────────────
const testHeaders             = require("./tests/headerCheck");
const testCORS                = require("./tests/corsTest");
const testSensitiveData       = require("./tests/sensitiveDataTest");
const testAPIKeyLeaks         = require("./tests/apiKeyLeaks");
const testFileUpload          = require("./tests/fileUploadTest");
const testRateLimit           = require("./tests/rateLimitTest");
const testDependencies        = require("./tests/dependencyCheck");

const generateReport          = require("./report/generateReport");

// ── Parse CLI options ─────────────────────────────────────────
const args     = process.argv.slice(2);
const target   = config.target;
const noCrawl  = args.includes("--no-crawl");
const depthArg = args.find(a => a.startsWith("--depth="));
const pagesArg = args.find(a => a.startsWith("--pages="));
const maxDepth = depthArg ? parseInt(depthArg.split("=")[1]) : 4;
const maxPages = pagesArg ? parseInt(pagesArg.split("=")[1]) : 100;

async function runAllTests() {
  console.log("\n🔍 Security Tester v5 — Full Scan with Crawler");
  console.log(`   Target : ${target}`);
  console.log(`   Mode   : ${noCrawl ? "No crawl (root URL only)" : `Crawl enabled (depth=${maxDepth}, max=${maxPages} pages)`}`);
  console.log(`   Tests  : 24\n`);

  // ── Step 1: Crawl the site ──────────────────────────────────
  let siteMap = null;

  if (!noCrawl) {
    siteMap = await crawl(target, { maxDepth, maxPages, verbose: true });

    console.log(`   📋 Site map summary:`);
    console.log(`      Pages found    : ${siteMap.pages.length}`);
    console.log(`      Forms found    : ${siteMap.forms.length}`);
    console.log(`      Endpoints      : ${siteMap.endpoints.length}`);
    console.log(`      URLs with params: ${siteMap.paramUrls.length}`);
    console.log();
  }

  // ── Step 2: Run all 24 security tests ──────────────────────
  console.log("   🛡️  Running security tests...\n");

  const tests = [
    // Injection
    { name: "SQL Injection",                  fn: (t, s) => testSQLInjection(t, s) },
    { name: "XSS (Cross-Site Scripting)",     fn: (t, s) => testXSS(t, s) },
    { name: "Command Injection",              fn: (t, s) => testCommandInjection(t, s) },
    { name: "Directory Traversal",            fn: (t, s) => testDirectoryTraversal(t, s) },
    { name: "XXE (XML External Entity)",      fn: (t, s) => testXXE(t, s) },
    { name: "SSTI (Template Injection)",      fn: (t, s) => testSSTI(t, s) },
    { name: "HTTP Header Injection / CRLF",   fn: (t, s) => testHTTPHeaderInjection(t, s) },

    // Authentication & Session
    { name: "Brute Force & Default Creds",    fn: (t, s) => testBruteForce(t, s) },
    { name: "JWT Token Security",             fn: (t, s) => testJWT(t, s) },
    { name: "CSRF",                           fn: (t, s) => testCSRF(t, s) },

    // Access Control
    { name: "Broken Access Control & IDOR",   fn: (t, s) => testAccessControl(t, s) },
    { name: "Mass Assignment",                fn: (t, s) => testMassAssignment(t, s) },
    { name: "Open Redirect",                  fn: (t, s) => testOpenRedirect(t, s) },

    // Infrastructure & Network
    { name: "Exposed Admin Panels & Files",   fn: (t, s) => testExposedPanels(t, s) },
    { name: "SSL / TLS Security",             fn: (t, s) => testSSLTLS(t, s) },
    { name: "Subdomain Enumeration",          fn: (t, s) => testSubdomains(t, s) },
    { name: "SSRF",                           fn: (t, s) => testSSRF(t, s) },

    // Data & Configuration
    { name: "Security Headers",               fn: (t, s) => testHeaders(t, s) },
    { name: "CORS Misconfiguration",          fn: (t, s) => testCORS(t, s) },
    { name: "Sensitive Data Exposure",        fn: (t, s) => testSensitiveData(t, s) },
    { name: "API Key / Secret Leaks",         fn: (t, s) => testAPIKeyLeaks(t, s) },
    { name: "File Upload Vulnerabilities",    fn: (t, s) => testFileUpload(t, s) },
    { name: "Rate Limiting / DoS",            fn: (t, s) => testRateLimit(t, s) },
    { name: "Vulnerable Dependencies",        fn: (t, s) => testDependencies(t, s) },
  ];

  const results = [];

  for (const test of tests) {
    const num = `[${String(results.length + 1).padStart(2, "0")}/${tests.length}]`;
    process.stdout.write(`   ${num} ${test.name}...`);
    try {
      const result = await test.fn(target, siteMap);
      results.push(result);
      console.log(result.passed ? " ✅" : " ❌");
    } catch (err) {
      console.log(" ⚠️  Error");
      results.push({
        name:   test.name,
        passed: false,
        issues: [{
          title:    "Test threw an error",
          location: target,
          detail:   err.message,
          severity: "N/A",
          risk:     "Could not complete this test.",
          fixes:    []
        }],
      });
    }
  }

  // ── Step 3: Generate report ─────────────────────────────────
  generateReport(target, results, siteMap);
}

runAllTests();
