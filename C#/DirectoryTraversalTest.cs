namespace SecurityTester.Tests;

public class DirectoryTraversalTest
{
    private record TraversalPath(string Path, string Description);

    private static readonly List<TraversalPath> Paths = new()
    {
        new("/../../../etc/passwd",             "Linux system user file"),
        new("/../../windows/win.ini",           "Windows config file"),
        new("/?file=../../../../etc/passwd",    "Query param file inclusion"),
        new("/?page=../../../etc/shadow",       "Linux shadow password file"),
        new("/static/../../../etc/passwd",      "Static folder bypass"),
        new("/%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL-encoded traversal"),
    };

    private static readonly (string Signature, string File)[] Signatures =
    {
        ("root:x:0:0",   "/etc/passwd"),
        ("[extensions]", "windows/win.ini"),
        ("daemon:",      "/etc/passwd"),
        ("/bin/bash",    "/etc/passwd"),
        ("nobody:x:",    "/etc/passwd"),
    };

    public static async Task<TestResult> RunAsync(string target, HttpClient client, SiteMap? siteMap = null)
    {
        var result = new TestResult { Name = "Directory Traversal" };
        var baseUrl = target.TrimEnd('/');

        foreach (var traversal in Paths)
        {
            var testUrl = $"{baseUrl}{traversal.Path}";

            try
            {
                    var response = await client.GetAsync(testUrl);
                    var body     = (await response.Content.ReadAsStringAsync()).ToLower();
                    await Task.Delay(100);

                foreach (var (sig, file) in Signatures)
                {
                    if (body.Contains(sig.ToLower()))
                    {
                        result.Passed = false;
                        result.Issues.Add(new SecurityIssue
                        {
                            Title    = "Directory Traversal — Sensitive File Exposed",
                            Location = $"Traversal path : {traversal.Path}\n" +
                                       $"   Full URL     : {testUrl}\n" +
                                       $"   Exposed file : {file} ({traversal.Description})",
                            Detail   = $"Signature \"{sig}\" found in response, confirming " +
                                       $"the server returned contents of a sensitive system file.",
                            Severity = "CRITICAL",
                            Risk     = "Attackers can read any file on your server — including " +
                                       "passwords, private keys, config files, and source code.",
                            Fixes    = new()
                            {
                                new() {
                                    Label = "C# / ASP.NET — validate and sanitize file paths",
                                    Code  = "// ❌ VULNERABLE\nvar file = Request.Query[\"file\"];\nSystem.IO.File.ReadAllText(file);\n\n" +
                                            "// ✅ SAFE — resolve and check it stays in allowed folder\nvar baseDir  = Path.GetFullPath(\"./public\");\nvar requested = Path.GetFullPath(Path.Combine(baseDir, userInput));\n\n" +
                                            "if (!requested.StartsWith(baseDir))\n    return Forbid(); // Block traversal attempt\n\nvar content = System.IO.File.ReadAllText(requested);"
                                },
                                new() {
                                    Label = "C# — use a whitelist of allowed files",
                                    Code  = "// ✅ SAFEST — never trust user input for file names\nvar allowed = new Dictionary<string, string>\n{\n" +
                                            "    { \"report\",   \"./files/report.pdf\" },\n" +
                                            "    { \"manual\",   \"./files/manual.pdf\" }\n};\n\n" +
                                            "if (!allowed.TryGetValue(Request.Query[\"name\"], out var path))\n    return NotFound();\n\nreturn File(path, \"application/pdf\");"
                                },
                                new() {
                                    Label = "Nginx — block traversal patterns at server level",
                                    Code  = "location ~* (\\.\\./|%2e%2e) {\n    return 403;\n}"
                                }
                            }
                        });
                        break;
                    }
                }
            }
            catch { /* Timeout or connection error — skip */ }
        }

        return result;
    }
}
