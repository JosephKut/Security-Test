/**
 * =============================================
 *  SECURITY TESTER — VS Code Extension
 *  Entry point — registers all commands
 * =============================================
 */

const vscode = require("vscode");
const { runScan } = require("./scanner");

// Output channel — persists across scans
let outputChannel;
// Store last results for re-opening report
let lastResults  = null;
let lastSiteMap  = null;
let lastTarget   = null;

class SecurityTesterTreeProvider {
  getTreeItem(element) { return element; }

  getChildren(element) {
    if (element) return [];
    const items = [
      new vscode.TreeItem("🔍 Run Full Scan", vscode.TreeItemCollapsibleState.None),
      new vscode.TreeItem("⚡ Run Quick Scan", vscode.TreeItemCollapsibleState.None),
      new vscode.TreeItem("📄 Open Last Report", vscode.TreeItemCollapsibleState.None),
    ];
    items[0].command = { command: "securityTester.run", title: "" };
    items[1].command = { command: "securityTester.runNoCrawl", title: "" };
    items[2].command = { command: "securityTester.openReport", title: "" };
    items[0].tooltip = "Crawl site and run all 24 tests";
    items[1].tooltip = "Test root URL only — skip crawling";
    items[2].tooltip = "Re-open the last scan report";
    return items;
  }
}

function activate(context) {
  outputChannel = vscode.window.createOutputChannel("Security Tester");

  vscode.window.registerTreeDataProvider("securityTester.mainView", new SecurityTesterTreeProvider());

  // ── Command 1: Full scan with crawler ──────────────────────
  const fullScanCmd = vscode.commands.registerCommand(
    "securityTester.run",
    async () => {
      const target = await promptForURL();
      if (!target) return;

      const config = vscode.workspace.getConfiguration("securityTester");
      await executeScan(target, {
        crawl:    true,
        maxPages: config.get("maxPages", 100),
        maxDepth: config.get("maxDepth", 4),
        timeout:  config.get("timeout", 10) * 1000,
      });
    }
  );

  // ── Command 2: Quick scan (no crawler) ─────────────────────
  const quickScanCmd = vscode.commands.registerCommand(
    "securityTester.runNoCrawl",
    async () => {
      const target = await promptForURL();
      if (!target) return;

      const config = vscode.workspace.getConfiguration("securityTester");
      await executeScan(target, {
        crawl:   false,
        timeout: config.get("timeout", 10) * 1000,
      });
    }
  );

  // ── Command 3: Re-open last report ─────────────────────────
  const openReportCmd = vscode.commands.registerCommand(
    "securityTester.openReport",
    () => {
      if (!lastResults) {
        vscode.window.showInformationMessage("No scan results yet. Run a scan first.");
        return;
      }
      showReportPanel(lastTarget, lastResults, lastSiteMap);
    }
  );

  context.subscriptions.push(fullScanCmd, quickScanCmd, openReportCmd);
  outputChannel.appendLine("✅ Security Tester activated. Use Command Palette → 'Security Tester: Run Full Scan'");
}

// ── Prompt user for target URL ──────────────────────────────
async function promptForURL() {
  const input = await vscode.window.showInputBox({
    prompt:      "Enter the URL to scan",
    placeHolder: "https://yoursite.com",
    validateInput: (val) => {
      try { new URL(val); return null; }
      catch { return "Please enter a valid URL (e.g. https://yoursite.com)"; }
    }
  });
  return input?.trim();
}

// ── Main scan executor ──────────────────────────────────────
async function executeScan(target, options) {
  outputChannel.clear();
  outputChannel.show(true);
  outputChannel.appendLine(`\n🔍 Security Tester`);
  outputChannel.appendLine(`   Target : ${target}`);
  outputChannel.appendLine(`   Mode   : ${options.crawl ? `Full crawl (depth=${options.maxDepth}, max=${options.maxPages} pages)` : "Quick scan (root URL only)"}`);
  outputChannel.appendLine(`   Tests  : 24\n`);

  // Create progress panel
  await vscode.window.withProgress(
    {
      location:    vscode.ProgressLocation.Notification,
      title:       "Security Tester",
      cancellable: false,
    },
    async (progress) => {
      try {
        progress.report({ message: "Starting scan..." });

        const { results, siteMap } = await runScan(target, options, {
          onCrawlStart: () => {
            progress.report({ message: "Crawling site pages..." });
            outputChannel.appendLine("   🕷️  Crawling site...");
          },
          onCrawlDone: (sm) => {
            outputChannel.appendLine(`   ✅ Crawl complete: ${sm.pages.length} pages, ${sm.forms.length} forms, ${sm.endpoints.length} endpoints\n`);
            outputChannel.appendLine("   🛡️  Running security tests...\n");
          },
          onTestStart: (name, num, total) => {
            const pad = String(num).padStart(2, "0");
            outputChannel.append(`   [${pad}/${total}] ${name}...`);
            progress.report({ message: `Running ${name}...`, increment: Math.floor(100 / total) });
          },
          onTestDone: (result) => {
            outputChannel.appendLine(result.passed ? " ✅" : " ❌");
          },
        });

        // Cache for re-open
        lastResults = results;
        lastSiteMap = siteMap;
        lastTarget  = target;

        const passed = results.filter(r => r.passed).length;
        const failed = results.filter(r => !r.passed).length;

        outputChannel.appendLine(`\n${"=".repeat(55)}`);
        outputChannel.appendLine(failed === 0
          ? "  ✅  ALL TESTS PASSED"
          : `  ❌  ${failed} test(s) failed — see report for details`);
        outputChannel.appendLine("=".repeat(55));

        // Show report panel
        showReportPanel(target, results, siteMap);

        // Status bar notification
        if (failed === 0) {
          vscode.window.showInformationMessage(`✅ Security scan complete — all tests passed!`, "View Report")
            .then(sel => sel && showReportPanel(target, results, siteMap));
        } else {
          vscode.window.showWarningMessage(`⚠️ Security scan found ${failed} issue(s)`, "View Report")
            .then(sel => sel && showReportPanel(target, results, siteMap));
        }

      } catch (err) {
        outputChannel.appendLine(`\n❌ Scan failed: ${err.message}`);
        vscode.window.showErrorMessage(`Security Tester failed: ${err.message}`);
      }
    }
  );
}

// ── Webview report panel ────────────────────────────────────
function showReportPanel(target, results, siteMap) {
  const panel = vscode.window.createWebviewPanel(
    "securityReport",
    `Security Report — ${new URL(target).hostname}`,
    vscode.ViewColumn.One,
    { enableScripts: true, retainContextWhenHidden: true }
  );

  panel.webview.html = generateHTML(target, results, siteMap);

  // Handle copy-to-clipboard from webview
  panel.webview.onDidReceiveMessage(async (msg) => {
    if (msg.command === "copy") {
      await vscode.env.clipboard.writeText(msg.text);
      vscode.window.showInformationMessage("✅ Fix code copied to clipboard!");
    }
  });
}

// ── HTML Report Generator ───────────────────────────────────
function generateHTML(target, results, siteMap) {
  const date   = new Date().toLocaleDateString();
  const time   = new Date().toLocaleTimeString();
  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;
  const total  = results.length;
  const score  = Math.round((passed / total) * 100);

  const scoreColor = score === 100 ? "#22c55e" : score >= 70 ? "#f59e0b" : "#ef4444";

  // Build issues HTML
  function issuesHTML(issues) {
    if (!issues || issues.length === 0)
      return `<div class="no-issues">✅ No issues found</div>`;

    return issues.map((issue, i) => {
      const severityClass = {
        CRITICAL: "sev-critical", HIGH: "sev-high",
        MEDIUM: "sev-medium",    LOW: "sev-low", INFO: "sev-info"
      }[issue.severity] || "sev-info";

      const fixesHTML = (issue.fixes || []).map((fix, fi) => `
        <div class="fix-block">
          <div class="fix-label">🔧 ${fix.label}</div>
          <div class="fix-code-wrap">
            <pre class="fix-code" id="fix-${i}-${fi}">${escapeHTML(fix.code)}</pre>
            <button class="copy-btn" onclick="copyFix('fix-${i}-${fi}')">Copy</button>
          </div>
        </div>
      `).join("");

      return `
        <div class="issue">
          <div class="issue-header">
            <span class="severity ${severityClass}">${issue.severity || "INFO"}</span>
            <span class="issue-title">${escapeHTML(issue.title)}</span>
          </div>
          <div class="issue-body">
            <div class="issue-row"><span class="label">📍 Location</span><code class="location">${escapeHTML(issue.location)}</code></div>
            <div class="issue-row"><span class="label">🔎 Detail</span><span>${escapeHTML(issue.detail)}</span></div>
            <div class="issue-row"><span class="label">⚠️ Risk</span><span class="risk">${escapeHTML(issue.risk)}</span></div>
            ${fixesHTML ? `<div class="fixes">${fixesHTML}</div>` : ""}
          </div>
        </div>
      `;
    }).join("");
  }

  // Build test results HTML
  const testsHTML = results.map(r => {
    const icon   = r.passed ? "✅" : "❌";
    const cls    = r.passed ? "test-pass" : "test-fail";
    const issues = issuesHTML(r.issues);

    return `
      <div class="test-card ${cls}">
        <div class="test-header" onclick="toggleTest(this)">
          <span class="test-icon">${icon}</span>
          <span class="test-name">${escapeHTML(r.name)}</span>
          <span class="issue-count">${r.issues?.length > 0 ? `${r.issues.length} issue(s)` : "Clean"}</span>
          <span class="chevron">▼</span>
        </div>
        <div class="test-body">
          ${issues}
        </div>
      </div>
    `;
  }).join("");

  // Site map summary
  const siteMapHTML = siteMap ? `
    <div class="sitemap-card">
      <h3>🕷️ Crawler Results</h3>
      <div class="sitemap-grid">
        <div class="stat"><span class="stat-num">${siteMap.pages?.length || 0}</span><span class="stat-label">Pages</span></div>
        <div class="stat"><span class="stat-num">${siteMap.endpoints?.length || 0}</span><span class="stat-label">Endpoints</span></div>
        <div class="stat"><span class="stat-num">${siteMap.forms?.length || 0}</span><span class="stat-label">Forms</span></div>
        <div class="stat"><span class="stat-num">${siteMap.paramUrls?.length || 0}</span><span class="stat-label">Param URLs</span></div>
      </div>
    </div>
  ` : `<div class="sitemap-card"><p>Quick scan — crawler disabled</p></div>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0f0f0f; color: #e2e8f0; padding: 24px; }

  /* Header */
  .header { background: #1a1a2e; border: 1px solid #2d2d5b; border-radius: 12px;
             padding: 24px; margin-bottom: 24px; }
  .header h1 { font-size: 22px; color: #a78bfa; margin-bottom: 8px; }
  .header .meta { color: #94a3b8; font-size: 13px; }

  /* Score ring */
  .score-section { display: flex; align-items: center; gap: 32px; margin-top: 16px; }
  .score-ring { width: 80px; height: 80px; border-radius: 50%;
                border: 6px solid ${scoreColor}; display: flex; align-items: center;
                justify-content: center; font-size: 20px; font-weight: 700;
                color: ${scoreColor}; flex-shrink: 0; }
  .score-stats { display: flex; gap: 24px; }
  .score-stat { text-align: center; }
  .score-stat .num { font-size: 28px; font-weight: 700; }
  .score-stat .lbl { font-size: 12px; color: #64748b; margin-top: 2px; }
  .pass-num { color: #22c55e; }
  .fail-num { color: #ef4444; }

  /* Sitemap card */
  .sitemap-card { background: #1a1a2e; border: 1px solid #2d2d5b; border-radius: 10px;
                  padding: 16px; margin-bottom: 20px; }
  .sitemap-card h3 { font-size: 14px; color: #94a3b8; margin-bottom: 12px; }
  .sitemap-grid { display: flex; gap: 24px; }
  .stat { text-align: center; }
  .stat-num { display: block; font-size: 22px; font-weight: 700; color: #a78bfa; }
  .stat-label { font-size: 11px; color: #64748b; }

  /* Filter bar */
  .filter-bar { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .filter-btn { padding: 6px 14px; border-radius: 20px; border: 1px solid #334155;
                background: #1e293b; color: #94a3b8; cursor: pointer; font-size: 12px;
                transition: all 0.15s; }
  .filter-btn:hover, .filter-btn.active { background: #7c3aed; border-color: #7c3aed; color: #fff; }

  /* Test cards */
  .test-card { border-radius: 10px; margin-bottom: 10px; overflow: hidden;
               border: 1px solid #1e293b; }
  .test-card.test-fail { border-color: #7f1d1d; }
  .test-card.test-pass { border-color: #14532d; }
  .test-header { display: flex; align-items: center; gap: 10px; padding: 12px 16px;
                 cursor: pointer; background: #1e293b; user-select: none; }
  .test-card.test-fail .test-header { background: #1c0a0a; }
  .test-card.test-pass .test-header { background: #0a1c0a; }
  .test-header:hover { filter: brightness(1.15); }
  .test-name { flex: 1; font-weight: 600; font-size: 14px; }
  .test-icon { font-size: 16px; }
  .issue-count { font-size: 12px; color: #64748b; }
  .chevron { color: #475569; font-size: 10px; transition: transform 0.2s; }
  .test-header.open .chevron { transform: rotate(180deg); }
  .test-body { display: none; padding: 12px 16px; background: #0f172a;
               border-top: 1px solid #1e293b; }
  .test-body.visible { display: block; }

  /* No issues */
  .no-issues { color: #22c55e; padding: 8px 0; font-size: 13px; }

  /* Issues */
  .issue { background: #1a1a2e; border: 1px solid #2d2d5b; border-radius: 8px;
           margin-bottom: 10px; overflow: hidden; }
  .issue-header { display: flex; align-items: center; gap: 10px; padding: 10px 14px;
                  background: #12122a; }
  .issue-title { font-weight: 600; font-size: 13px; }
  .issue-body { padding: 12px 14px; display: flex; flex-direction: column; gap: 8px; }
  .issue-row { display: flex; flex-direction: column; gap: 3px; }
  .label { font-size: 11px; color: #64748b; font-weight: 600; text-transform: uppercase; }
  .location { font-family: monospace; font-size: 12px; color: #fbbf24;
              background: #1e1b00; padding: 4px 8px; border-radius: 4px;
              word-break: break-all; white-space: pre-wrap; }
  .risk { color: #fca5a5; font-size: 13px; }

  /* Severity badges */
  .severity { padding: 2px 8px; border-radius: 4px; font-size: 10px;
              font-weight: 700; letter-spacing: 0.05em; white-space: nowrap; }
  .sev-critical { background: #7f1d1d; color: #fca5a5; }
  .sev-high     { background: #7c2d12; color: #fdba74; }
  .sev-medium   { background: #78350f; color: #fcd34d; }
  .sev-low      { background: #1e3a5f; color: #93c5fd; }
  .sev-info     { background: #1e293b; color: #94a3b8; }

  /* Fixes */
  .fixes { margin-top: 8px; }
  .fix-block { margin-bottom: 10px; }
  .fix-label { font-size: 12px; color: #a78bfa; font-weight: 600; margin-bottom: 4px; }
  .fix-code-wrap { position: relative; }
  .fix-code { background: #0d1117; border: 1px solid #21262d; border-radius: 6px;
              padding: 10px 12px; font-size: 12px; font-family: 'Fira Code', Consolas,
              monospace; color: #e6edf3; overflow-x: auto; white-space: pre; line-height: 1.6; }
  .copy-btn { position: absolute; top: 6px; right: 6px; background: #21262d;
              border: 1px solid #30363d; color: #c9d1d9; padding: 3px 10px;
              border-radius: 4px; cursor: pointer; font-size: 11px; }
  .copy-btn:hover { background: #7c3aed; border-color: #7c3aed; color: #fff; }

  /* Footer */
  .footer { margin-top: 32px; text-align: center; color: #475569; font-size: 12px; }
</style>
</head>
<body>

<div class="header">
  <h1>🛡️ Security Report</h1>
  <div class="meta">Target: <strong>${escapeHTML(target)}</strong> &nbsp;|&nbsp; ${date} at ${time}</div>
  <div class="score-section">
    <div class="score-ring">${score}%</div>
    <div class="score-stats">
      <div class="score-stat"><div class="num pass-num">${passed}</div><div class="lbl">Passed</div></div>
      <div class="score-stat"><div class="num fail-num">${failed}</div><div class="lbl">Failed</div></div>
      <div class="score-stat"><div class="num">${total}</div><div class="lbl">Total Tests</div></div>
    </div>
  </div>
</div>

${siteMapHTML}

<div class="filter-bar">
  <button class="filter-btn active" onclick="filterTests('all', this)">All (${total})</button>
  <button class="filter-btn" onclick="filterTests('fail', this)">❌ Failed (${failed})</button>
  <button class="filter-btn" onclick="filterTests('pass', this)">✅ Passed (${passed})</button>
</div>

<div id="tests-container">
  ${testsHTML}
</div>

<div class="footer">Security Tester Extension — Educational Use Only &nbsp;|&nbsp; Only test systems you own or have permission to test</div>

<script>
  const vscode = acquireVsCodeApi();

  // Toggle test card open/close
  function toggleTest(header) {
    header.classList.toggle('open');
    const body = header.nextElementSibling;
    body.classList.toggle('visible');
  }

  // Auto-expand failed tests on load
  document.querySelectorAll('.test-card.test-fail .test-header').forEach(h => {
    h.classList.add('open');
    h.nextElementSibling.classList.add('visible');
  });

  // Filter tests
  function filterTests(type, btn) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.test-card').forEach(card => {
      if (type === 'all')  card.style.display = '';
      if (type === 'fail') card.style.display = card.classList.contains('test-fail') ? '' : 'none';
      if (type === 'pass') card.style.display = card.classList.contains('test-pass') ? '' : 'none';
    });
  }

  // Copy fix code to clipboard via VS Code API
  function copyFix(id) {
    const code = document.getElementById(id)?.innerText || '';
    vscode.postMessage({ command: 'copy', text: code });
  }
</script>
</body>
</html>`;
}

function escapeHTML(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function deactivate() {}

module.exports = { activate, deactivate };
