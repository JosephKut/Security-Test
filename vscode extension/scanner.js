/**
 * scanner.js
 * Orchestrates the crawler + all 24 security tests.
 * Called by extension.js — returns { results, siteMap }
 */

const { crawl } = require("./crawler");

// ── All 24 tests ──────────────────────────────────────────────
const testSQLInjection        = require("./tests/sqlInjection");
const testXSS                 = require("./tests/xssTest");
const testCommandInjection    = require("./tests/commandInjection");
const testDirectoryTraversal  = require("./tests/directoryTraversal");
const testXXE                 = require("./tests/xxeTest");
const testSSTI                = require("./tests/sstiTest");
const testHTTPHeaderInjection = require("./tests/httpHeaderInjection");
const testBruteForce          = require("./tests/bruteForce");
const testJWT                 = require("./tests/jwtTest");
const testCSRF                = require("./tests/csrfTest");
const testAccessControl       = require("./tests/accessControl");
const testMassAssignment      = require("./tests/massAssignmentTest");
const testOpenRedirect        = require("./tests/openRedirect");
const testExposedPanels       = require("./tests/exposedPanels");
const testSSLTLS              = require("./tests/sslTlsTest");
const testSubdomains          = require("./tests/subdomainTest");
const testSSRF                = require("./tests/ssrfTest");
const testHeaders             = require("./tests/headerCheck");
const testCORS                = require("./tests/corsTest");
const testSensitiveData       = require("./tests/sensitiveDataTest");
const testAPIKeyLeaks         = require("./tests/apiKeyLeaks");
const testFileUpload          = require("./tests/fileUploadTest");
const testRateLimit           = require("./tests/rateLimitTest");
const testDependencies        = require("./tests/dependencyCheck");

const TESTS = [
  // Injection
  { name: "SQL Injection",                 fn: testSQLInjection },
  { name: "XSS (Cross-Site Scripting)",    fn: testXSS },
  { name: "Command Injection",             fn: testCommandInjection },
  { name: "Directory Traversal",           fn: testDirectoryTraversal },
  { name: "XXE (XML External Entity)",     fn: testXXE },
  { name: "SSTI (Template Injection)",     fn: testSSTI },
  { name: "HTTP Header Injection / CRLF",  fn: testHTTPHeaderInjection },
  // Auth & Session
  { name: "Brute Force & Default Creds",   fn: testBruteForce },
  { name: "JWT Token Security",            fn: testJWT },
  { name: "CSRF",                          fn: testCSRF },
  // Access Control
  { name: "Broken Access Control & IDOR",  fn: testAccessControl },
  { name: "Mass Assignment",               fn: testMassAssignment },
  { name: "Open Redirect",                 fn: testOpenRedirect },
  // Infrastructure
  { name: "Exposed Admin Panels & Files",  fn: testExposedPanels },
  { name: "SSL / TLS Security",            fn: testSSLTLS },
  { name: "Subdomain Enumeration",         fn: testSubdomains },
  { name: "SSRF",                          fn: testSSRF },
  // Data & Config
  { name: "Security Headers",              fn: testHeaders },
  { name: "CORS Misconfiguration",         fn: testCORS },
  { name: "Sensitive Data Exposure",       fn: testSensitiveData },
  { name: "API Key / Secret Leaks",        fn: testAPIKeyLeaks },
  { name: "File Upload Vulnerabilities",   fn: testFileUpload },
  { name: "Rate Limiting / DoS",           fn: testRateLimit },
  { name: "Vulnerable Dependencies",       fn: testDependencies },
];

/**
 * Main scan function.
 * @param {string}   target   - URL to scan
 * @param {object}   options  - crawl, maxPages, maxDepth, timeout
 * @param {object}   hooks    - onCrawlStart, onCrawlDone, onTestStart, onTestDone
 * @returns {{ results, siteMap }}
 */
async function runScan(target, options = {}, hooks = {}) {
  const {
    crawl:    doCrawl  = true,
    maxPages           = 100,
    maxDepth           = 4,
  } = options;

  const {
    onCrawlStart = () => {},
    onCrawlDone  = () => {},
    onTestStart  = () => {},
    onTestDone   = () => {},
  } = hooks;

  // ── Step 1: Crawl ───────────────────────────────────────────
  let siteMap = null;
  if (doCrawl) {
    onCrawlStart();
    siteMap = await crawl(target, { maxPages, maxDepth, verbose: false });
    onCrawlDone(siteMap);
  }

  // ── Step 2: Run all tests ───────────────────────────────────
  const results = [];

  for (let i = 0; i < TESTS.length; i++) {
    const test = TESTS[i];
    onTestStart(test.name, i + 1, TESTS.length);

    let result;
    try {
      result = await test.fn(target, siteMap);
    } catch (err) {
      result = {
        name:   test.name,
        passed: false,
        issues: [{
          title:    "Test threw an error",
          location: target,
          detail:   err.message,
          severity: "N/A",
          risk:     "Could not complete this test.",
          fixes:    []
        }]
      };
    }

    results.push(result);
    onTestDone(result);
  }

  return { results, siteMap };
}

module.exports = { runScan };
