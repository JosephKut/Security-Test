# 🛡️ Security Tester — VS Code Extension

Scan any website for **24 security vulnerabilities** directly from VS Code.
Pinpoints exact locations, explains the risk, and gives you ready-to-copy fix code.

---

## 📦 Installation

### Option A: Install from .vsix file
```
1. Open VS Code
2. Press Ctrl+Shift+P → "Extensions: Install from VSIX..."
3. Select security-tester-1.0.0.vsix
```

### Option B: Build and install yourself
```bash
npm install -g @vscode/vsce
cd security-tester-vscode
vsce package
code --install-extension security-tester-1.0.0.vsix
```

---

## 🚀 How to Use

1. Open VS Code
2. Press `Ctrl+Shift+P` (Command Palette)
3. Type **"Security Tester"** — you'll see:
   - `Security Tester: Run Full Scan (with Crawler)` — crawls all pages first
   - `Security Tester: Run Quick Scan (Root URL Only)` — fast, root only
   - `Security Tester: Open Last Report` — re-open previous results
4. Enter your target URL when prompted
5. Watch progress in the notification + Output Channel
6. HTML report opens automatically when done

---

## ⚙️ Settings

Go to `File → Preferences → Settings → Security Tester`:

| Setting | Default | Description |
|---|---|---|
| `securityTester.maxPages` | 100 | Max pages to crawl |
| `securityTester.maxDepth` | 4 | Max crawl depth |
| `securityTester.timeout` | 20 | Request timeout (seconds) |

---

## 🔍 What It Tests (24 Tests)

| Category | Tests |
|---|---|
| Injection (7) | SQL, XSS, Command, Directory Traversal, XXE, SSTI, Header Injection |
| Auth & Session (3) | Brute Force, JWT Security, CSRF |
| Access Control (3) | IDOR, Mass Assignment, Open Redirect |
| Infrastructure (4) | Exposed Panels, SSL/TLS, Subdomain Takeover, SSRF |
| Data & Config (7) | Security Headers, CORS, Sensitive Data, API Key Leaks, File Upload, Rate Limiting, Dependencies |

---

## 📋 Report Features

- 🔴 Color-coded severity badges (CRITICAL / HIGH / MEDIUM / LOW)
- 📍 Exact URL/parameter where issue was found
- ⚠️ Plain-English risk explanation
- 🔧 Copy-to-clipboard fix code for each issue
- Filter by: All / Failed / Passed
- Auto-expands failed tests

---

## ⚠️ Legal

Only test websites you **own** or have **written permission** to test.
This tool is for educational and authorized security testing only.

---

## 🧱 Project Structure

```
security-tester-vscode/
├── extension.js      ← VS Code entry point (activate, webview)
├── scanner.js        ← Orchestrates crawler + all 24 tests
├── crawler.js        ← Web crawler (discovers all pages)
├── package.json      ← VS Code extension manifest
├── images/
│   └── icon.png
└── tests/            ← All 24 security test modules
    ├── sqlInjection.js
    ├── xssTest.js
    └── ... (22 more)
```
