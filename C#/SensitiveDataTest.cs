using System.Text.RegularExpressions;

namespace SecurityTester.Tests;

public class SensitiveDataTest
{
    private record SensitivePattern(string Name, string Pattern);

    private static readonly List<SensitivePattern> Patterns = new()
    {
        new("Plain-text Password",      @"[""']?password[""']?\s*[:=]\s*[""'][^""']{3,}[""']"),
        new("Credit Card Number",       @"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
        new("Stack Trace / File Path",  @"at\s+\w+.*\.(cs|js):\d+|/home/|/var/www/|C:\\Users\\"),
        new("Database Connection String",@"mongodb://|mysql://|postgres://|Server=.*;Database="),
        new("Internal IP Address",      @"\b(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)\d+\.\d+\b"),
        new("JWT Token in Response",    @"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
    };

    private static readonly string[] CookieFlags = { "httponly", "secure" };

    public static async Task<TestResult> RunAsync(string target, HttpClient client, SiteMap? siteMap = null)
    {
        var result  = new TestResult { Name = "Sensitive Data Exposure" };
        var baseUrl = target.TrimEnd('/');
        // Use crawled pages if available, otherwise fall back to common paths
        var pages = siteMap?.Pages.Select(p => p.Url).ToArray()
                    ?? new[] { baseUrl, $"{baseUrl}/api", $"{baseUrl}/api/users", $"{baseUrl}/login" };

        foreach (var page in pages)
        {
            try
            {
                    var res  = await client.GetAsync(page);
                    var body = await res.Content.ReadAsStringAsync();
                    await Task.Delay(100);
                    if ((int)res.StatusCode == 404) continue;

                foreach (var p in Patterns)
                {
                    var match = Regex.Match(body, p.Pattern, RegexOptions.IgnoreCase);
                    if (!match.Success) continue;

                    var raw    = match.Value;
                    var masked = raw.Length > 10 ? raw[..6] + "..." + raw[^4..] : "****";

                    result.Passed = false;
                    result.Issues.Add(new SecurityIssue
                    {
                        Title    = $"Sensitive Data Exposed: {p.Name}",
                        Location = page,
                        Detail   = $"Pattern matched in response: \"{masked}\"",
                        Severity = p.Name.Contains("Password") || p.Name.Contains("Card") ? "CRITICAL" : "HIGH",
                        Risk     = $"Exposing {p.Name.ToLower()} gives attackers direct access to credentials or system internals.",
                        Fixes    = new()
                        {
                            new() { Label = "C# — never return sensitive fields in API responses",
                                    Code  = "// ❌ VULNERABLE — returns everything including password hash\nreturn Ok(user);\n\n// ✅ SAFE — use a DTO (Data Transfer Object)\npublic record UserDto(int Id, string Name, string Email);\nreturn Ok(new UserDto(user.Id, user.Name, user.Email));" },
                            new() { Label = "Use [JsonIgnore] on sensitive model properties",
                                    Code  = "public class User\n{\n    public int    Id    { get; set; }\n    public string Name  { get; set; } = \"\";\n    public string Email { get; set; } = \"\";\n\n    [JsonIgnore]  // Never serialized\n    public string PasswordHash { get; set; } = \"\";\n\n    [JsonIgnore]\n    public string ResetToken { get; set; } = \"\";\n}" },
                            new() { Label = "Never expose stack traces in production",
                                    Code  = "// In Program.cs:\nif (!app.Environment.IsDevelopment())\n{\n    app.UseExceptionHandler(\"/error\");\n}\n\n// Error controller:\n[Route(\"error\")]\npublic IActionResult Error() => Problem(\"An error occurred.\");" }
                        }
                    });
                }

                // Check cookie flags
                if (res.Headers.TryGetValues("Set-Cookie", out var cookies))
                {
                    foreach (var cookie in cookies)
                    {
                        var cl = cookie.ToLower();
                        foreach (var flag in CookieFlags)
                        {
                            if (!cl.Contains(flag))
                            {
                                result.Passed = false;
                                result.Issues.Add(new SecurityIssue
                                {
                                    Title    = $"Cookie Missing \"{flag}\" Flag",
                                    Location = $"Set-Cookie header at {page}",
                                    Detail   = $"Cookie set without \"{flag}\": {cookie.Split(';')[0]}",
                                    Severity = "MEDIUM",
                                    Risk     = flag == "httponly"
                                        ? "JavaScript can read the cookie — XSS can steal session tokens."
                                        : "Cookie sent over plain HTTP — can be intercepted.",
                                    Fixes    = new()
                                    {
                                        new() { Label = "C# — set all security flags on cookies",
                                                Code  = "builder.Services.ConfigureApplicationCookie(options =>\n{\n    options.Cookie.HttpOnly  = true;\n    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;\n    options.Cookie.SameSite  = SameSiteMode.Strict;\n});" }
                                    }
                                });
                            }
                        }
                    }
                }
            }
            catch { }
        }

        return result;
    }
}
