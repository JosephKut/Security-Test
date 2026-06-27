const tls = require("tls");
const { URL } = require("url");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const WEAK_CIPHERS = [
  "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON", "aNULL", "eNULL",
  "LOW", "MEDIUM", "CBC", "SHA1",
];

async function testSSLTLS(target, siteMap) {
  const result  = { name: "SSL / TLS Security", passed: true, issues: [] };

  let hostname, port;
  try {
    const parsed = new URL(target);
    hostname = parsed.hostname;
    port     = parsed.port || (parsed.protocol === "https:" ? 443 : 80);
  } catch {
    return result;
  }

  if (port === 80) {
    result.issues.push({
      title:    "Connection is Plain HTTP (Not HTTPS)",
      location: target,
      detail:   "Target is using HTTP on port 80. No encryption in transit.",
      severity: "HIGH",
      risk:     "All traffic is sent in plaintext — passwords, cookies, and data can be intercepted.",
      fixes: [
        { label: "Enforce HTTPS with a redirect",
          code:  "// Express.js HTTPS redirect\napp.use((req, res, next) => {\n  if (!req.secure && req.headers['x-forwarded-proto'] !== 'https') {\n    return res.redirect('https://' + req.headers.host + req.url);\n  }\n  next();\n});" }
      ]
    });
    result.passed = false;
    return result;
  }

  try {
    const cert = await new Promise((resolve, reject) => {
      const socket = tls.connect({ host: hostname, port, rejectUnauthorized: false, servername: hostname }, () => {
        const certInfo = {
          subject:         socket.getPeerCertificate().subject,
          issuer:          socket.getPeerCertificate().issuer,
          validFrom:       socket.getPeerCertificate().valid_from,
          validTo:         socket.getPeerCertificate().valid_to,
          fingerprint:     socket.getPeerCertificate().fingerprint,
          cipher:          socket.getCipher(),
          protocol:        socket.getProtocol(),
          authorized:      socket.authorized,
          authorizationError: socket.authorizationError,
        };
        socket.end();
        resolve(certInfo);
      });
      socket.on("error", reject);
      socket.setTimeout(10000, () => { socket.destroy(); reject(new Error("timeout")); });
    });
    await delay(100);

    const now = new Date();
    const expires = new Date(cert.validTo);

    if (cert.authorizationError) {
      result.passed = false;
      result.issues.push({
        title:    "SSL Certificate Validation Error",
        location: target,
        detail:   `Certificate error: ${cert.authorizationError}`,
        severity: "HIGH",
        risk:     "Self-signed or invalid certificates allow man-in-the-middle attacks.",
        fixes: [
          { label: "Use a valid certificate from a trusted CA",
            code:  "Use Let's Encrypt (free), certbot, or a commercial CA.\n# Certbot example:\nsudo certbot --nginx -d yoursite.com" }
          ]
      });
    }

    if (expires < new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000)) {
      result.passed = false;
      result.issues.push({
        title:    "SSL Certificate Expired",
        location: target,
        detail:   `Certificate expired ${Math.floor((now - expires) / (1000 * 60 * 60 * 24))} days ago (was valid until ${cert.validTo}).`,
        severity: "CRITICAL",
        risk:     "Expired certificates cause browser warnings and enable MITM attacks.",
        fixes: [
          { label: "Renew the certificate immediately",
            code:  "# Auto-renew with certbot:\nsudo certbot renew --quiet" }
        ]
      });
    } else if (expires < new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000)) {
      result.issues.push({
        title:    "SSL Certificate Expiring Soon",
        location: target,
        detail:   `Certificate expires on ${cert.validTo} (${Math.floor((expires - now) / (1000 * 60 * 60 * 24))} days).`,
        severity: "MEDIUM",
        risk:     "Service will become untrusted once the certificate expires.",
        fixes: [
          { label: "Set up auto-renewal",
            code:  "sudo crontab -e\n# Add: 0 0 * * * sudo certbot renew --quiet" }
        ]
      });
    }

    const protocol = cert.protocol;
    if (protocol && (protocol.includes("SSLv") || protocol.includes("TLSv1.0") || protocol.includes("TLSv1.1"))) {
      result.passed = false;
      result.issues.push({
        title:    `Outdated TLS Protocol: ${protocol}`,
        location: target,
        detail:   `Server negotiated ${protocol}. TLS 1.2+ is required for security compliance (PCI-DSS, NIST).`,
        severity: "HIGH",
        risk:     "Outdated TLS versions have known vulnerabilities (POODLE, BEAST, LUCKY13) and are deprecated.",
        fixes: [
          { label: "Disable old TLS versions — require TLS 1.2+",
            code:  "# Nginx:\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL:!MD5;" }
        ]
      });
    }

    const cipherName = cert.cipher && cert.cipher.name;
    if (cipherName) {
      const weakMatch = WEAK_CIPHERS.some(w => cipherName.toUpperCase().includes(w));
      if (weakMatch) {
        result.passed = false;
        result.issues.push({
          title:    `Weak Cipher Suite: ${cipherName}`,
          location: target,
          detail:   `Server uses weak cipher "${cipherName}". Modern ciphers (AEAD, GCM) are recommended.`,
          severity: "HIGH",
          risk:     "Weak ciphers can be broken by attackers to decrypt traffic.",
          fixes: [
            { label: "Configure strong ciphers only",
              code:  "# Nginx:\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;" }
          ]
        });
      }
    }

    if (result.issues.length === 0) {
      result.issues.push({
        title:    "SSL/TLS Configuration Looks Good",
        location: target,
        detail:   `Protocol: ${cert.protocol}, Cipher: ${cert.cipher ? cert.cipher.name : "N/A"}, Valid until: ${cert.validTo}.`,
        severity: "INFO",
        risk:     "SSL/TLS configuration appears secure.",
        fixes: []
      });
    }
  } catch (err) {
    result.issues.push({
      title:    "Could Not Check SSL/TLS",
      location: target,
      detail:   `Connection failed: ${err.message}. Site may not support HTTPS or is unreachable.`,
      severity: "INFO",
      risk:     "SSL/TLS configuration could not be verified.",
      fixes: []
    });
  }

  return result;
}

module.exports = testSSLTLS;
