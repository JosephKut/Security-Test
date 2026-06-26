/**
 * =============================================
 *  SECURITY TESTER — C# / .NET 8  (v5 — Crawler)
 *  Educational Use Only
 *  Only test systems you own or have permission
 * =============================================
 *
 *  Setup:
 *    dotnet build
 *
 *  Run:
 *    dotnet run -- https://yoursite.com
 *
 *  Options:
 *    --no-crawl     Skip crawler, test root URL only
 *    --depth=N      Set crawl depth (default: 4)
 *    --pages=N      Max pages to crawl (default: 100)
 *
 *  Examples:
 *    dotnet run -- https://yoursite.com
 *    dotnet run -- https://yoursite.com --depth=2 --pages=30
 *    dotnet run -- https://yoursite.com --no-crawl
 * =============================================
 */

using SecurityTester;
using SecurityTester.Tests;

// ── Parse arguments ───────────────────────────────────────────
var target   = args.FirstOrDefault(a => a.StartsWith("http")) ?? "http://localhost:5000";
var noCrawl  = args.Contains("--no-crawl");
var depthArg = args.FirstOrDefault(a => a.StartsWith("--depth="));
var pagesArg = args.FirstOrDefault(a => a.StartsWith("--pages="));
var maxDepth = depthArg != null ? int.Parse(depthArg.Split('=')[1]) : 4;
var maxPages = pagesArg != null ? int.Parse(pagesArg.Split('=')[1]) : 100;

if (!Uri.TryCreate(target, UriKind.Absolute, out _))
{
    Console.WriteLine("❌ Invalid URL. Usage: dotnet run -- https://yoursite.com");
    return;
}

Console.WriteLine("\n🔍 Security Tester v5 — C# Full Scan with Crawler");
Console.WriteLine($"   Target : {target}");
Console.WriteLine($"   Mode   : {(noCrawl ? "No crawl (root URL only)" : $"Crawl enabled (depth={maxDepth}, max={maxPages} pages)")}");
Console.WriteLine($"   Tests  : 24\n");

// ── HTTP Client ───────────────────────────────────────────────
var handler = new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
    AllowAutoRedirect = true,
    MaxAutomaticRedirections = 3,
};
using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
http.DefaultRequestHeaders.Add("User-Agent", "SecurityTester/1.0 (Educational)");

// ── Step 1: Crawl ─────────────────────────────────────────────
SiteMap? siteMap = null;

if (!noCrawl)
{
    var crawler = new Crawler(http, maxPages: maxPages, maxDepth: maxDepth, verbose: true);
    siteMap     = await crawler.CrawlAsync(target);

    Console.WriteLine($"   📋 Site map summary:");
    Console.WriteLine($"      Pages found     : {siteMap.Pages.Count}");
    Console.WriteLine($"      Forms found     : {siteMap.Forms.Count}");
    Console.WriteLine($"      Endpoints       : {siteMap.Endpoints.Count}");
    Console.WriteLine($"      URLs with params: {siteMap.ParamUrls.Count}");
    Console.WriteLine();
}

// ── Step 2: Run all 24 tests ──────────────────────────────────
Console.WriteLine("   🛡️  Running security tests...\n");

var tests = new (string Name, Func<Task<TestResult>> Run)[]
{
    // Injection
    ("SQL Injection",                  () => SqlInjectionTest.RunAsync(target, http, siteMap)),
    ("XSS (Cross-Site Scripting)",     () => XssTest.RunAsync(target, http, siteMap)),
    ("Command Injection",              () => CommandInjectionTest.RunAsync(target, http, siteMap)),
    ("Directory Traversal",            () => DirectoryTraversalTest.RunAsync(target, http, siteMap)),
    ("XXE (XML External Entity)",      () => XxeTest.RunAsync(target, http, siteMap)),
    ("SSTI (Template Injection)",      () => SstiTest.RunAsync(target, http, siteMap)),
    ("HTTP Header Injection / CRLF",   () => HttpHeaderInjectionTest.RunAsync(target, http, siteMap)),

    // Authentication & Session
    ("Brute Force & Default Creds",    () => BruteForceTest.RunAsync(target, http, siteMap)),
    ("JWT Token Security",             () => JwtTest.RunAsync(target, http, siteMap)),
    ("CSRF",                           () => CsrfTest.RunAsync(target, http, siteMap)),

    // Access Control
    ("Broken Access Control & IDOR",   () => AccessControlTest.RunAsync(target, http, siteMap)),
    ("Mass Assignment",                () => MassAssignmentTest.RunAsync(target, http, siteMap)),
    ("Open Redirect",                  () => OpenRedirectTest.RunAsync(target, http, siteMap)),

    // Infrastructure & Network
    ("Exposed Admin Panels & Files",   () => ExposedPanelsTest.RunAsync(target, http, siteMap)),
    ("SSL / TLS Security",             () => SslTlsTest.RunAsync(target, http, siteMap)),
    ("Subdomain Enumeration",          () => SubdomainTest.RunAsync(target, http, siteMap)),
    ("SSRF",                           () => SsrfTest.RunAsync(target, http, siteMap)),

    // Data & Configuration
    ("Security Headers",               () => HeaderCheckTest.RunAsync(target, http, siteMap)),
    ("CORS Misconfiguration",          () => CorsTest.RunAsync(target, http, siteMap)),
    ("Sensitive Data Exposure",        () => SensitiveDataTest.RunAsync(target, http, siteMap)),
    ("API Key / Secret Leaks",         () => ApiKeyLeakTest.RunAsync(target, http, siteMap)),
    ("File Upload Vulnerabilities",    () => FileUploadTest.RunAsync(target, http, siteMap)),
    ("Rate Limiting / DoS",            () => RateLimitTest.RunAsync(target, http, siteMap)),
    ("Vulnerable Dependencies",        () => DependencyCheckTest.RunAsync(target, http, siteMap)),
};

var results = new List<TestResult>();

foreach (var (name, run) in tests)
{
    var num = $"[{(results.Count + 1).ToString().PadLeft(2, '0')}/{tests.Length}]";
    Console.Write($"   {num} {name}...");
    try
    {
        var result = await run();
        results.Add(result);
        Console.WriteLine(result.Passed ? " ✅" : " ❌");
    }
    catch (Exception ex)
    {
        Console.WriteLine(" ⚠️  Error");
        results.Add(new TestResult
        {
            Name   = name,
            Passed = false,
            Issues = new()
            {
                new SecurityIssue
                {
                    Title    = "Test threw an exception",
                    Location = target,
                    Detail   = ex.Message,
                    Severity = "N/A",
                    Risk     = "Could not complete this test.",
                    Fixes    = new()
                }
            }
        });
    }
}

// ── Step 3: Report ────────────────────────────────────────────
ReportGenerator.Generate(target, results, siteMap);
