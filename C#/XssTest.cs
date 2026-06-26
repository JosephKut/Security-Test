namespace SecurityTester.Tests;

public class XssTest
{
    private static readonly string[] Payloads =
    {
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'><svg onload=alert(1)>",
        "<body onload=alert(1)>"
    };

    private static readonly string[] CommonParams =
        { "q", "search", "name", "msg", "input", "query", "text", "s" };

    private static List<string> BuildTargets(string target, SiteMap? siteMap)
    {
        var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var p in CommonParams)
            targets.Add($"{target}?{p}=test");

        if (siteMap == null) return targets.ToList();

        foreach (var page in siteMap.ParamUrls)
            targets.Add(page.Url);

        foreach (var ep in siteMap.Endpoints)
            foreach (var p in CommonParams)
                targets.Add($"{ep}?{p}=test");

        return targets.ToList();
    }

    public static async Task<TestResult> RunAsync(string target, HttpClient client, SiteMap? siteMap = null)
    {
        var result  = new TestResult { Name = "Cross-Site Scripting (XSS)" };
        var targets = BuildTargets(target.TrimEnd('/'), siteMap);

        foreach (var baseUrl in targets)
        {
            foreach (var payload in Payloads)
            {
                try
                {
                    var uri = new Uri(baseUrl);
                    var qs  = System.Web.HttpUtility.ParseQueryString(uri.Query);
                    foreach (var key in qs.AllKeys) qs[key] = payload;

                    var testUrl = $"{uri.GetLeftPart(UriPartial.Path)}?{qs}";
                    var res     = await client.GetAsync(testUrl);
                    var body    = await res.Content.ReadAsStringAsync();

                    if (body.Contains(payload))
                    {
                        result.Passed = false;
                        result.Issues.Add(new SecurityIssue
                        {
                            Title    = "Reflected XSS Vulnerability",
                            Location = $"URL: {testUrl}",
                            Detail   = $"Payload \"{payload}\" returned unescaped in response.",
                            Severity = "HIGH",
                            Risk     = "Attackers inject scripts into victims' browsers — stealing sessions or cookies.",
                            Fixes    = new()
                            {
                                new() { Label = "C# — HTML-encode all output",
                                        Code  = "using System.Text.Encodings.Web;\n\n// ❌ VULNERABLE\nResponse.Write(\"<p>\" + userInput + \"</p>\");\n\n// ✅ SAFE\nResponse.Write(\"<p>\" + HtmlEncoder.Default.Encode(userInput) + \"</p>\");" },
                                new() { Label = "Razor — never use Html.Raw with user input",
                                        Code  = "// ❌ DANGEROUS\n@Html.Raw(userInput)\n\n// ✅ SAFE — Razor escapes automatically\n@userInput" }
                            }
                        });
                        goto nextTarget;
                    }
                }
                catch { }
            }
            nextTarget:;
        }

        return result;
    }
}
