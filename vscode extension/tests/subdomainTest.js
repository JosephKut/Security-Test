const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const COMMON_SUBDOMAINS = [
  "www", "mail", "ftp", "admin", "blog", "api", "dev", "test", "stage",
  "staging", "app", "m", "mobile", "webmail", "cpanel", "whm",
  "vpn", "remote", "secure", "portal", "help", "support", "docs",
  "status", "cdn", "static", "assets", "images", "media", "video",
  "download", "downloads", "upload", "uploads", "files", "file",
  "shop", "store", "billing", "payment", "pay", "checkout",
  "git", "jenkins", "jira", "confluence", "wiki", "grafana",
  "monitor", "kibana", "elastic", "redis", "mysql", "db",
  "mail2", "admin2", "server", "ns1", "ns2", "mx", "pop3",
  "smtp", "imap", "webdisk", "autodiscover", "cpanel",
];

function checkSubdomain(subdomain, domain, timeout = 5000) {
  return new Promise((resolve) => {
    const hostname = `${subdomain}.${domain}`;
    const lookup = (cb) => {
      const dns = require("dns");
      dns.resolve(hostname, "A", (err, addresses) => {
        if (err) cb(false, null);
        else cb(true, addresses);
      });
    };
    setTimeout(() => resolve({ hostname, exists: false }), timeout);
    lookup((exists, addresses) => {
      resolve({ hostname, exists, addresses: exists ? addresses : null });
    });
  });
}

async function testSubdomains(target, siteMap) {
  const result = { name: "Subdomain Enumeration", passed: true, issues: [] };

  let domain;
  try {
    const parsed = new URL(target);
    domain = parsed.hostname.replace(/^www\./, "");
    if (domain.startsWith("localhost") || domain.startsWith("127.") || domain.startsWith("192.168.") || domain.startsWith("10.") || domain === "0.0.0.0") {
      return result;
    }
  } catch {
    return result;
  }

  const foundSubdomains = [];
  const batchSize = 5;

  for (let i = 0; i < COMMON_SUBDOMAINS.length; i += batchSize) {
    const batch = COMMON_SUBDOMAINS.slice(i, i + batchSize);
    const results = await Promise.all(batch.map(sub => checkSubdomain(sub, domain)));
    await delay(100);

    for (const r of results) {
      if (r.exists) {
        foundSubdomains.push(r.hostname);
      }
    }

    if (foundSubdomains.length >= 10) break;
  }

  if (foundSubdomains.length > 0) {
    result.issues.push({
      title:    `Discovered ${foundSubdomains.length} Subdomain(s)`,
      location: domain,
      detail:   `Found subdomains: ${foundSubdomains.join(", ")}`,
      severity: "MEDIUM",
      risk:     "Additional subdomains increase the attack surface. Some may host outdated or forgotten applications.",
      fixes: [
        { label: "Remove unused subdomains",
          code:  "Audit all DNS records and remove A/AAAA records for unused subdomains." },
        { label: "Use a wildcard certificate and monitor all subdomains",
          code:  "Ensure all active subdomains are patched, monitored, and have valid TLS certificates." }
      ]
    });
  }

  return result;
}

module.exports = testSubdomains;
