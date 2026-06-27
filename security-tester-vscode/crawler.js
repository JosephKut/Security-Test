const https = require("https");
const http  = require("http");
const { URL } = require("url");

/**
 * Web Crawler
 * - Visits root URL and all internal links recursively
 * - Respects depth limit and max pages to avoid infinite loops
 * - Extracts: page URLs, form actions, API endpoints, query params
 * - Returns structured site map for security tests to consume
 */

const IGNORED_EXTENSIONS = [
  ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
  ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3", ".woff",
  ".woff2", ".ttf", ".eot", ".css", ".map"
];

const MAX_PAGES  = 100;  // max pages to crawl
const MAX_DEPTH  = 4;    // max link depth from root
const TIMEOUT    = 6000;
const DELAY_MS   = 100;  // polite delay between requests

async function fetchPage(url) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const lib    = parsed.protocol === "https:" ? https : http;
      const req    = lib.get(url, {
        timeout: TIMEOUT,
        rejectUnauthorized: false,
        headers: { "User-Agent": "SecurityTester-Crawler/1.0 (Educational)" }
      }, (res) => {
        // Only parse HTML pages
        const ct = res.headers["content-type"] || "";
        if (!ct.includes("text/html") && !ct.includes("application/json")) {
          res.resume();
          resolve({ status: res.statusCode, body: "", headers: res.headers, contentType: ct });
          return;
        }
        let body = "";
        res.on("data", (c) => {
          body += c;
          if (body.length > 500000) { req.destroy(); } // cap at 500KB
        });
        res.on("end", () => resolve({ status: res.statusCode, body, headers: res.headers, contentType: ct }));
      });
      req.on("error",   () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
    } catch { resolve(null); }
  });
}

function extractLinks(baseUrl, html) {
  const links = new Set();
  const base  = new URL(baseUrl);

  // href links
  const hrefMatches = html.matchAll(/href=["']([^"'#>]+)["']/gi);
  for (const m of hrefMatches) links.add(m[1].trim());

  // form actions
  const actionMatches = html.matchAll(/action=["']([^"'>]+)["']/gi);
  for (const m of actionMatches) links.add(m[1].trim());

  // src attributes (scripts, iframes)
  const srcMatches = html.matchAll(/src=["']([^"'>]+)["']/gi);
  for (const m of srcMatches) links.add(m[1].trim());

  // API endpoints in JS (fetch, axios, XMLHttpRequest)
  const apiMatches = html.matchAll(/(?:fetch|get|post|put|delete|axios)\s*\(\s*["'`]([/][^"'`\s]+)["'`]/gi);
  for (const m of apiMatches) links.add(m[1].trim());

  // Resolve to absolute URLs, filter to same origin
  const resolved = new Set();
  for (const link of links) {
    try {
      const abs = new URL(link, baseUrl);
      // Same host only
      if (abs.hostname !== base.hostname) continue;
      // Skip ignored extensions
      const path = abs.pathname.toLowerCase();
      if (IGNORED_EXTENSIONS.some(ext => path.endsWith(ext))) continue;
      // Clean URL (remove fragment)
      abs.hash = "";
      resolved.add(abs.toString());
    } catch { }
  }

  return resolved;
}

function extractForms(url, html) {
  const forms = [];
  const formMatches = html.matchAll(/<form[^>]*>([\s\S]*?)<\/form>/gi);

  for (const formMatch of formMatches) {
    const formHtml = formMatch[0];

    // Get action
    const actionMatch = formHtml.match(/action=["']([^"'>]+)["']/i);
    const methodMatch = formHtml.match(/method=["']([^"'>]+)["']/i);

    const action = actionMatch
      ? new URL(actionMatch[1], url).toString()
      : url;
    const method = methodMatch ? methodMatch[1].toUpperCase() : "GET";

    // Get input fields
    const fields = [];
    const inputMatches = formHtml.matchAll(/<input[^>]*name=["']([^"'>]+)["'][^>]*>/gi);
    for (const m of inputMatches) fields.push(m[1]);

    const selectMatches = formHtml.matchAll(/<select[^>]*name=["']([^"'>]+)["'][^>]*>/gi);
    for (const m of selectMatches) fields.push(m[1]);

    const textareaMatches = formHtml.matchAll(/<textarea[^>]*name=["']([^"'>]+)["'][^>]*>/gi);
    for (const m of textareaMatches) fields.push(m[1]);

    forms.push({ action, method, fields, foundOn: url });
  }

  return forms;
}

function extractQueryParams(url) {
  try {
    const parsed = new URL(url);
    return [...parsed.searchParams.keys()];
  } catch { return []; }
}

async function crawl(startUrl, options = {}) {
  const {
    maxPages = MAX_PAGES,
    maxDepth = MAX_DEPTH,
    verbose  = true,
  } = options;

  const visited    = new Set();
  const queue      = [{ url: startUrl, depth: 0 }];
  const pages      = [];   // all discovered pages
  const forms      = [];   // all discovered forms
  const endpoints  = new Set(); // unique endpoints (URL without params)
  const paramUrls  = [];   // URLs that have query parameters

  if (verbose) {
    console.log(`\n   🕷️  Crawler starting...`);
    console.log(`   Max pages : ${maxPages}`);
    console.log(`   Max depth : ${maxDepth}\n`);
  }

  while (queue.length > 0 && visited.size < maxPages) {
    const { url, depth } = queue.shift();

    if (visited.has(url))   continue;
    if (depth > maxDepth)   continue;

    visited.add(url);

    if (verbose) process.stdout.write(`   Crawling [${visited.size}/${maxPages}]: ${url.slice(0, 70)}...\r`);

    const res = await fetchPage(url);
    if (!res || res.status === 404) continue;

    // Record this page
    const pageData = {
      url,
      status:      res.status,
      depth,
      contentType: res.contentType,
      queryParams: extractQueryParams(url),
      hasForms:    false,
    };

    // Track endpoint (path without query params)
    try {
      const parsed = new URL(url);
      parsed.search = "";
      endpoints.add(parsed.toString());
    } catch { }

    // Track URLs with query params for injection testing
    if (pageData.queryParams.length > 0) {
      paramUrls.push({ url, params: pageData.queryParams });
    }

    // Extract forms
    if (res.body && res.contentType.includes("text/html")) {
      const pageForms = extractForms(url, res.body);
      if (pageForms.length > 0) {
        pageData.hasForms = true;
        forms.push(...pageForms);
      }

      // Extract and queue new links
      if (depth < maxDepth) {
        const links = extractLinks(url, res.body);
        for (const link of links) {
          if (!visited.has(link)) {
            queue.push({ url: link, depth: depth + 1 });
          }
        }
      }
    }

    pages.push(pageData);

    if (DELAY_MS > 0 && queue.length > 0) {
      await new Promise(r => setTimeout(r, DELAY_MS));
    }
  }

  if (verbose) {
    console.log(`\n   ✅ Crawl complete: ${pages.length} pages, ${forms.length} forms, ${endpoints.size} endpoints\n`);
  }

  return {
    startUrl,
    pages,
    forms,
    endpoints:  [...endpoints],
    paramUrls,
    totalFound: pages.length,
  };
}

module.exports = { crawl };
