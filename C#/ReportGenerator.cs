namespace SecurityTester;

public static class ReportGenerator
{
    private static void Divider(char c = '-', int len = 60)
        => Console.WriteLine(new string(c, len));

    public static void Generate(string target, List<TestResult> results, SiteMap? siteMap = null)
    {
        var date   = DateTime.Now.ToString("yyyy-MM-dd");
        var time   = DateTime.Now.ToString("hh:mm:ss tt");
        int passed = results.Count(r => r.Passed);
        int failed = results.Count(r => !r.Passed);
        int total  = results.Count;

        // ── Console Header ────────────────────────────────────────
        Console.WriteLine();
        Divider('=');
        Console.WriteLine("        🛡️   SECURITY TEST REPORT  v1 (C#)");
        Divider('=');
        Console.WriteLine($"  Target  : {target}");
        Console.WriteLine($"  Date    : {date} at {time}");
        Console.WriteLine($"  Result  : {passed}/{total} tests passed");
        if (siteMap != null)
            Console.WriteLine($"  Crawled : {siteMap.Pages.Count} pages | {siteMap.Endpoints.Count} endpoints | {siteMap.Forms.Count} forms");
        Divider('=');

        // ── File content builder ──────────────────────────────────
        var file = new System.Text.StringBuilder();
        file.AppendLine("SECURITY TEST REPORT (C#)");
        file.AppendLine(new string('=', 60));
        file.AppendLine($"Target : {target}");
        file.AppendLine($"Date   : {date} at {time}");
        file.AppendLine($"Result : {passed}/{total} tests passed");
        if (siteMap != null)
            file.AppendLine($"Crawled: {siteMap.Pages.Count} pages | {siteMap.Endpoints.Count} endpoints | {siteMap.Forms.Count} forms");
        file.AppendLine(new string('=', 60));
        file.AppendLine();

        foreach (var result in results)
        {
            var icon   = result.Passed ? "✅" : "❌";
            var status = result.Passed ? "PASSED" : "FAILED";

            Console.WriteLine($"\n{icon}  {result.Name.ToUpper()}  [{status}]");
            file.AppendLine($"[{status}] {result.Name}");

            if (result.Issues.Count == 0)
            {
                Console.WriteLine("     No issues found. This test passed.");
                file.AppendLine("  No issues found.");
                file.AppendLine();
                continue;
            }

            foreach (var issue in result.Issues)
            {
                Divider('-', 58);
                Console.WriteLine($"\n  🔴 ISSUE    : {issue.Title}");
                Console.WriteLine($"     SEVERITY : {issue.Severity}");
                Console.WriteLine($"     LOCATION : {issue.Location}");
                Console.WriteLine($"     DETAIL   : {issue.Detail}");
                Console.WriteLine($"\n  ⚠️  RISK     : {issue.Risk}");

                file.AppendLine($"\n  ISSUE    : {issue.Title}");
                file.AppendLine($"  SEVERITY : {issue.Severity}");
                file.AppendLine($"  LOCATION : {issue.Location}");
                file.AppendLine($"  DETAIL   : {issue.Detail}");
                file.AppendLine($"  RISK     : {issue.Risk}");

                if (issue.Fixes.Count > 0)
                {
                    Console.WriteLine("\n  🔧 HOW TO FIX:");
                    file.AppendLine("\n  HOW TO FIX:");

                    foreach (var fix in issue.Fixes)
                    {
                        Console.WriteLine($"\n     ── {fix.Label} ──");
                        foreach (var line in fix.Code.Split('\n'))
                            Console.WriteLine($"        {line}");

                        file.AppendLine($"\n  [{fix.Label}]");
                        foreach (var line in fix.Code.Split('\n'))
                            file.AppendLine($"    {line}");
                    }
                }

                Console.WriteLine();
                file.AppendLine(new string('-', 58));
            }
        }

        // ── Summary ───────────────────────────────────────────────
        Divider('=');
        if (failed == 0)
            Console.WriteLine("  ✅  ALL TESTS PASSED — System looks secure!");
        else
        {
            Console.WriteLine($"  ❌  {failed} TEST(S) FAILED — Fix all issues before deploying.");
            Console.WriteLine($"  ✅  {passed} test(s) passed.");
        }
        Divider('=');

        file.AppendLine(new string('=', 60));
        file.AppendLine(failed == 0
            ? "OVERALL: ALL TESTS PASSED ✅"
            : $"OVERALL: {failed} ISSUE(S) FOUND ❌ — Fix before deployment");
        file.AppendLine(new string('=', 60));

        // ── Save to file ──────────────────────────────────────────
        var reportDir  = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Report");
        Directory.CreateDirectory(reportDir);
        var reportPath = Path.Combine(reportDir, $"report_{date}.txt");
        System.IO.File.WriteAllText(reportPath, file.ToString());
        Console.WriteLine($"\n  📄 Report saved to: {reportPath}\n");
    }
}
