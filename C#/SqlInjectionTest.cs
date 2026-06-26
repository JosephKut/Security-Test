namespace SecurityTester.Tests;

public class SqlInjectionTest
{
    private static readonly string[] Payloads =
    {
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT null, username, password FROM users --",
        "1' AND SLEEP(3) --",
        "admin'--"
    };

    private static readonly string[] ErrorSignatures =
    {
        "sql syntax", "mysql_fetch", "ora-", "syntax error",
        "unclosed quotation", "sqlite", "pg_query"
    };

    private static readonly string[] CommonParams =
        { "id", "search", "q", "user", "page", "cat", "item", "ref" };

    // Build all URLs to inject into — root common params + every crawled param URL
    private static List<string> BuildTargets(string target, SiteMap? siteMap)
    {
        var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Always test root with common params
        foreach (var p in CommonParams)
            targets.Add($"{target}?{p}=1");

        if (siteMap == null) return targets.ToList();

        // Every crawled URL that has query params
        foreach (var page in siteMap.ParamUrls)
            targets.Add(page.Url);

        // Every crawled endpoint with common params injected
        foreach (var ep in siteMap.Endpoints)
            foreach (var p in CommonParams)
                targets.Add($"{ep}?{p}=1");

        return targets.ToList();
    }

    public static async Task<TestResult> RunAsync(string target, HttpClient client, SiteMap? siteMap = null)
    {
        var result  = new TestResult { Name = "SQL Injection" };
        var targets = BuildTargets(target.TrimEnd('/'), siteMap);

        foreach (var baseUrl in targets)
        {
            foreach (var payload in Payloads)
            {
                try
                {
                    // Inject payload into every existing query param
                    var uri = new Uri(baseUrl);
                    var qs  = System.Web.HttpUtility.ParseQueryString(uri.Query);
                    foreach (var key in qs.AllKeys) qs[key] = payload;

                    var testUrl = $"{uri.GetLeftPart(UriPartial.Path)}?{qs}";
                    var res     = await client.GetAsync(testUrl);
                    var body    = (await res.Content.ReadAsStringAsync()).ToLower();

                    foreach (var sig in ErrorSignatures)
                    {
                        if (body.Contains(sig))
                        {
                            result.Passed = false;
                            result.Issues.Add(new SecurityIssue
                            {
                                Title    = "SQL Injection Vulnerability Detected",
                                Location = $"URL: {testUrl}",
                                Detail   = $"DB error \"{sig}\" exposed with payload: {payload}",
                                Severity = "CRITICAL",
                                Risk     = "Attackers can read, modify, or delete your entire database.",
                                Fixes    = new()
                                {
                                    new() { Label = "C# — use parameterized queries",
                                            Code  = "// ❌ VULNERABLE\nvar cmd = new SqlCommand(\"SELECT * FROM users WHERE id = \" + id);\n\n// ✅ SAFE\nvar cmd = new SqlCommand(\"SELECT * FROM users WHERE id = @id\", conn);\ncmd.Parameters.AddWithValue(\"@id\", id);" },
                                    new() { Label = "C# — use Entity Framework (safest)",
                                            Code  = "// EF Core handles parameterization automatically\nvar user = context.Users.FirstOrDefault(u => u.Id == id);" }
                                }
                            });
                            goto nextTarget;
                        }
                    }
                }
                catch { }
            }
            nextTarget:;
        }

        return result;
    }
}
