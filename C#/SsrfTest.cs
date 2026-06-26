namespace SecurityTester.Tests;

public class SsrfTest
{
    private static readonly string[] SsrfParams =
        { "url", "uri", "src", "source", "dest", "destination",
          "redirect", "proxy", "fetch", "load", "link", "host", "callback" };

    private record SsrfTarget(string Url, string Label, string? Marker);
    private static readonly List<SsrfTarget> Targets = new()
    {
        new("http://169.254.169.254/latest/meta-data/", "AWS Metadata Service",    "ami-id"),
        new("http://169.254.169.254/latest/meta-data/iam/", "AWS IAM Credentials","security-credentials"),
        new("http://localhost/",                         "Localhost Internal",      null),
        new("http://127.0.0.1/",                         "Loopback Internal",       null),
        new("http://localhost:27017/",                   "Local MongoDB",           "mongodb"),
        new("http://localhost:6379/",                    "Local Redis",             "redis"),
    };

    public static async Task<TestResult> RunAsync(string target, HttpClient client, SiteMap? siteMap = null)
    {
        var result  = new TestResult { Name = "Server-Side Request Forgery (SSRF)" };
        var baseUrl = target.TrimEnd('/');

        // Build probe bases — root + all crawled param endpoints
        var probeBases = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { baseUrl };
        if (siteMap?.ParamUrls != null)
        {
            foreach (var p in siteMap.ParamUrls)
            {
                try
                {
                    var u = new Uri(p.Url);
                    probeBases.Add($"{u.Scheme}://{u.Host}{u.AbsolutePath}");
                }
                catch { }
            }
        }

        foreach (var probeBase in probeBases)
        foreach (var param in SsrfParams)
        {
            foreach (var ssrfTarget in Targets)
            {
                var testUrl = $"{baseUrl}?{param}={Uri.EscapeDataString(ssrfTarget.Url)}";
                try
                {
                    var res    = await client.GetAsync(testUrl);
                    var body   = (await res.Content.ReadAsStringAsync()).ToLower();
                    int status = (int)res.StatusCode;
                    if (status == 404) continue;

                    bool triggered = ssrfTarget.Marker != null
                        ? body.Contains(ssrfTarget.Marker.ToLower())
                        : (status == 200 && body.Length > 100 &&
                           (body.Contains("localhost") || body.Contains("html") || body.Contains("server")));

                    if (triggered)
                    {
                        result.Passed = false;
                        result.Issues.Add(new SecurityIssue
                        {
                            Title    = $"SSRF Vulnerability — {ssrfTarget.Label} Accessible",
                            Location = $"Parameter \"?{param}=\" at {baseUrl}",
                            Detail   = $"Server fetched internal URL \"{ssrfTarget.Url}\" and returned contents (HTTP {status}).",
                            Severity = ssrfTarget.Label.Contains("AWS") ? "CRITICAL" : "HIGH",
                            Risk     = "Attackers trick your server into fetching internal systems — stealing cloud credentials or mapping your private network.",
                            Fixes    = new()
                            {
                                new() { Label = "C# — validate URLs against strict allowlist",
                                        Code  = "private static readonly string[] AllowedHosts = { \"api.service.com\", \"cdn.yoursite.com\" };\n\nbool IsSafeUrl(string inputUrl)\n{\n    if (!Uri.TryCreate(inputUrl, UriKind.Absolute, out var uri)) return false;\n    var blocked = new[] { \"localhost\", \"127.0.0.1\", \"0.0.0.0\", \"169.254.169.254\" };\n    if (blocked.Any(b => uri.Host.StartsWith(b))) return false;\n    return AllowedHosts.Contains(uri.Host);\n}" },
                                new() { Label = "Block metadata IP at network/firewall level",
                                        Code  = "# Linux iptables:\niptables -A OUTPUT -d 169.254.169.254 -j DROP\niptables -A OUTPUT -d 169.254.0.0/16  -j DROP" }
                            }
                        });
                        goto nextParam;
                    }
                }
                catch { }
            }
            nextParam:;
        }

        return result;
    }
}
