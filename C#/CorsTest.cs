namespace SecurityTester.Tests;

public class CorsTest
{
    private static readonly string[] Endpoints =
        { "", "/api", "/api/users", "/api/data" };

    public static async Task<TestResult> RunAsync(string target, HttpClient client, SiteMap? siteMap = null)
    {
        var result     = new TestResult { Name = "CORS Misconfiguration" };
        var baseUrl    = target.TrimEnd('/');
        var evilOrigin = "https://evil-attacker.com";

        foreach (var endpoint in Endpoints)
        {
            var url = $"{baseUrl}{endpoint}";
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Options, url);
                request.Headers.Add("Origin", evilOrigin);
                request.Headers.Add("Access-Control-Request-Method", "GET");

                    var res = await client.SendAsync(request);
                    await Task.Delay(100);
                    if (!res.Headers.TryGetValues("access-control-allow-origin", out var acao)) continue;

                var origin = string.Join("", acao);
                res.Headers.TryGetValues("access-control-allow-credentials", out var acac);
                var credentials = string.Join("", acac ?? Array.Empty<string>());

                if ((origin == "*" || origin == evilOrigin) && credentials == "true")
                {
                    result.Passed = false;
                    result.Issues.Add(new SecurityIssue
                    {
                        Title    = "CRITICAL CORS — Any Origin + Credentials Allowed",
                        Location = url,
                        Detail   = $"Access-Control-Allow-Origin: {origin}\nAccess-Control-Allow-Credentials: true",
                        Severity = "CRITICAL",
                        Risk     = "Any website can make authenticated requests to your API — reading private data or taking over accounts.",
                        Fixes    = new()
                        {
                            new() { Label = "C# / ASP.NET Core — whitelist specific origins",
                                    Code  = "// In Program.cs:\nbuilder.Services.AddCors(options =>\n{\n    options.AddPolicy(\"SafeCors\", policy =>\n    {\n        policy.WithOrigins(\"https://yoursite.com\", \"https://app.yoursite.com\")\n              .AllowCredentials()\n              .AllowAnyMethod()\n              .AllowAnyHeader();\n    });\n});\napp.UseCors(\"SafeCors\");" },
                            new() { Label = "Never combine wildcard with credentials",
                                    Code  = "// ❌ EXTREMELY DANGEROUS\npolicy.AllowAnyOrigin().AllowCredentials();\n\n// ✅ SAFE\npolicy.WithOrigins(\"https://yoursite.com\").AllowCredentials();" }
                        }
                    });
                }
                else if (origin == "*")
                {
                    result.Issues.Add(new SecurityIssue
                    {
                        Title    = "CORS Allows All Origins (Wildcard)",
                        Location = url,
                        Detail   = "Access-Control-Allow-Origin: * — any website can read this API's responses.",
                        Severity = "MEDIUM",
                        Risk     = "Fine for public APIs. Dangerous if any sensitive data is returned.",
                        Fixes    = new()
                        {
                            new() { Label = "Restrict to known origins if response has sensitive data",
                                    Code  = "policy.WithOrigins(\"https://yoursite.com\");" }
                        }
                    });
                }
                else if (origin == evilOrigin)
                {
                    result.Passed = false;
                    result.Issues.Add(new SecurityIssue
                    {
                        Title    = "CORS Reflects Arbitrary Origin",
                        Location = url,
                        Detail   = $"Server reflected evil origin: Access-Control-Allow-Origin: {origin}",
                        Severity = "HIGH",
                        Risk     = "Server blindly allows any origin — effectively wildcard but works with credentials too.",
                        Fixes    = new()
                        {
                            new() { Label = "Validate origin strictly before reflecting",
                                    Code  = "var allowed = new HashSet<string> { \"https://yoursite.com\" };\nif (allowed.Contains(request.Headers[\"Origin\"].ToString()))\n    response.Headers.Add(\"Access-Control-Allow-Origin\", request.Headers[\"Origin\"]);" }
                        }
                    });
                }
            }
            catch { }
        }

        return result;
    }
}
