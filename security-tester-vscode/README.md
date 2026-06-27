# 🛡️ Security Tester — VS Code Extension

Scan any website for **24 security vulnerabilities** directly from VS Code.
Pinpoints exact locations, explains the risk, and gives you ready-to-copy fix code.

**Safe by design** — all tests use read-only detection payloads. No destructive SQL, no sleep commands, no reverse shells. Polite 100ms delay between every request.

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

### Via Activity Bar (Recommended)
Click the **🛡️ shield icon** in the left activity bar → the sidebar opens with three buttons:
- **🔍 Run Full Scan** — crawls site then runs all 24 tests
- **⚡ Run Quick Scan** — tests root URL only, skips crawl
- **📄 Open Last Report** — re-opens the previous scan's webview report

### Via Command Palette
1. Press `Ctrl+Shift+P`
2. Type **"Security Tester"** — you'll see the same three commands
3. Enter your target URL when prompted
4. Watch real-time progress in the **Output Channel** (`View → Output → "Security Tester"`)
5. Rich HTML report opens automatically when done

### Via Editor Title Bar
A shield icon also appears in the editor title bar for one-click full scan access.

---

## ⚙️ Settings

Go to `File → Preferences → Settings → Security Tester`:

| Setting | Default | Description |
|---|---|---|
| `securityTester.maxPages` | 100 | Max pages to crawl per scan |
| `securityTester.maxDepth` | 4 | Max crawl depth from root URL |
| `securityTester.timeout` | 20 | Request timeout in seconds |

---

## 🔍 What It Tests (24 Tests)

| Category | Tests |
|---|---|
| Injection (7) | SQL, XSS, Command Injection, Directory Traversal, XXE, SSTI, Header Injection |
| Auth & Session (3) | Brute Force & Default Creds, JWT Security, CSRF |
| Access Control (3) | Broken Access Control & IDOR, Mass Assignment, Open Redirect |
| Infrastructure (4) | Exposed Admin Panels & Files, SSL/TLS, Subdomain Enumeration, SSRF |
| Data & Config (7) | Security Headers, CORS, Sensitive Data Exposure, API Key Leaks, File Upload, Rate Limiting, Dependency Check |

---

## 📋 Report Features

- 🔴 Color-coded severity badges (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- 📍 Exact URL/parameter where the vulnerability was found
- ⚠️ Plain-English risk explanation
- 🔧 Copy-to-clipboard fix code for each issue
- 🔄 Filter by: All / Failed / Passed
- Auto-expands failed tests on load

## 📺 Output

Results appear in three places:
1. **Webview Report** — rich HTML report opens automatically after scan
2. **Output Channel** — `View → Output` → select "Security Tester" from the drop-down
3. **VS Code Notification** — pop-up with pass/fail summary + "View Report" button

---

## ⚠️ Legal

Only test websites you **own** or have **written permission** to test.
This tool is for educational and authorized security testing only.

---

## 🧱 Project Structure

```
security-tester-vscode/
├── extension.js              ← VS Code entry point (commands, webview, sidebar)
├── scanner.js                ← Orchestrates crawler + all 24 tests
├── crawler.js                ← Web crawler (BFS, discovers pages/forms/endpoints)
├── package.json              ← Extension manifest (commands, views, settings)
├── .vscodeignore             ← Files excluded from packaged .vsix
├── LICENSE                   ← MIT license
├── README.md
├── images/
│   ├── icon.png              ← Extension icon (128x128 shield)
│   └── activity-icon.svg     ← Activity bar icon (24x24 shield)
└── tests/                    ← All 24 security test modules
    ├── sqlInjection.js
    ├── xssTest.js
    ├── commandInjection.js
    ├── directoryTraversal.js
    ├── xxeTest.js
    ├── sstiTest.js
    ├── httpHeaderInjection.js
    ├── bruteForce.js
    ├── jwtTest.js
    ├── csrfTest.js
    ├── accessControl.js
    ├── massAssignmentTest.js
    ├── openRedirect.js
    ├── exposedPanels.js
    ├── sslTlsTest.js
    ├── subdomainTest.js
    ├── ssrfTest.js
    ├── headerCheck.js
    ├── corsTest.js
    ├── sensitiveDataTest.js
    ├── apiKeyLeaks.js
    ├── fileUploadTest.js
    ├── rateLimitTest.js
    └── dependencyCheck.js
```
