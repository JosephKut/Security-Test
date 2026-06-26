const fs = require("fs");
const path = require("path");

function printDivider(char = "-", len = 60) {
  console.log(char.repeat(len));
}

function generateReport(target, results, siteMap = null) {
  const date = new Date().toISOString().split("T")[0];
  const time = new Date().toLocaleTimeString();

  const passed  = results.filter((r) => r.passed).length;
  const failed  = results.filter((r) => !r.passed).length;
  const total   = results.length;

  // ── Console Header ──────────────────────────────────────────
  console.log("\n");
  printDivider("=");
  console.log("         🛡️   SECURITY TEST REPORT  v2");
  printDivider("=");
  console.log(`  Target  : ${target}`);
  console.log(`  Date    : ${date} at ${time}`);
  console.log(`  Result  : ${passed}/${total} tests passed`);
  printDivider("=");

  let fileContent = `SECURITY TEST REPORT v2\n${"=".repeat(60)}\nTarget : ${target}\nDate   : ${date} at ${time}\nResult : ${passed}/${total} tests passed\n${"=".repeat(60)}\n\n`;

  for (const result of results) {
    const icon   = result.passed ? "✅" : "❌";
    const status = result.passed ? "PASSED" : "FAILED";

    console.log(`\n${icon}  ${result.name.toUpperCase()}  [${status}]`);
    fileContent += `[${status}] ${result.name}\n`;

    if (result.issues.length === 0) {
      console.log("     No issues found. This test passed.");
      fileContent += "  No issues found.\n\n";
      continue;
    }

    for (const issue of result.issues) {
      // If issue is a simple string (old format), print it plainly
      if (typeof issue === "string") {
        console.log(`\n  ⚠️  ${issue}`);
        fileContent += `  - ${issue}\n`;
        continue;
      }

      // Rich issue format
      printDivider("-", 58);
      console.log(`\n  🔴 ISSUE   : ${issue.title}`);
      if (issue.severity) console.log(`     SEVERITY : ${issue.severity}`);
      console.log(`     LOCATION : ${issue.location}`);
      console.log(`     DETAIL   : ${issue.detail}`);
      console.log(`\n  ⚠️  RISK    : ${issue.risk}`);

      fileContent += `\n  ISSUE    : ${issue.title}\n`;
      if (issue.severity) fileContent += `  SEVERITY : ${issue.severity}\n`;
      fileContent += `  LOCATION : ${issue.location}\n`;
      fileContent += `  DETAIL   : ${issue.detail}\n`;
      fileContent += `  RISK     : ${issue.risk}\n`;

      if (issue.fixes && issue.fixes.length > 0) {
        console.log(`\n  🔧 HOW TO FIX:`);
        fileContent += `\n  HOW TO FIX:\n`;

        for (const fix of issue.fixes) {
          console.log(`\n     ── ${fix.label} ──`);
          const codeLines = fix.code.split("\n");
          for (const line of codeLines) {
            console.log(`        ${line}`);
          }
          fileContent += `\n  [${fix.label}]\n`;
          for (const line of fix.code.split("\n")) {
            fileContent += `    ${line}\n`;
          }
        }
      }
      console.log("");
      fileContent += "\n" + "-".repeat(58) + "\n";
    }
  }

  // ── Summary ──────────────────────────────────────────────────
  printDivider("=");
  if (failed === 0) {
    console.log("  ✅  ALL TESTS PASSED — System looks secure!");
  } else {
    console.log(`  ❌  ${failed} TEST(S) FAILED — Fix all issues before deploying.`);
    console.log(`  ✅  ${passed} test(s) passed.`);
  }
  printDivider("=");

  fileContent += `\n${"=".repeat(60)}\n`;
  fileContent += failed === 0
    ? "OVERALL: ALL TESTS PASSED ✅\n"
    : `OVERALL: ${failed} ISSUE(S) FOUND ❌ — Fix before deployment\n`;
  fileContent += `${"=".repeat(60)}\n`;

  // ── Save Report ───────────────────────────────────────────────
  const reportDir = path.join(__dirname);
  const filename  = `report_${date}.txt`;
  const filepath  = path.join(reportDir, filename);
  fs.writeFileSync(filepath, fileContent);
  console.log(`\n  📄 Full report saved to: ${filepath}\n`);
}

module.exports = generateReport;
